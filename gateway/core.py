"""Core Security Gateway Orchestrator for AI-Vault."""

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, Set, Tuple
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from gateway.audit import AuditLogger
from gateway.database import (
    auto_search_database,
    check_table_access,
    get_authorized_context_for_query,
    save_chat_message,
)
from gateway.dlp import DLPManager
from gateway.guardrails import CanaryTokenManager, OutputSanitizer, PromptInjectionDetector
from gateway.inference import EnterpriseInferenceEngine
from gateway.rbac import RBACManager, User


class SecurityGateway:
    """Zero-Trust Security Gateway for Offline LLM Deployments."""

    def __init__(
        self,
        documents: Dict[str, str],
        role_permissions: Dict[str, Iterable[str]],
        audit_log_path: str = "logs/audit.log",
        *,
        model: str = "dolphin-uncensored",
        ollama_url: Optional[str] = None,
        llm_caller: Optional[Callable[[str, str], str]] = None,
        allow_remote: bool = False,
    ) -> None:
        """
        Initialize the Security Gateway with all security subsystems.
        
        Args:
            documents: Dict mapping document_id -> content string.
            role_permissions: Dict mapping role -> list of permitted document_ids.
            audit_log_path: Destination for cryptographic JSONL audit logs.
            model: Ollama model tag to invoke (e.g. 'dolphin-uncensored', 'mistral').
            ollama_url: Local Ollama generation API endpoint.
            llm_caller: Optional callable override for testing or custom inference pipelines.
            allow_remote: Allow remote tunnel URL (e.g. ngrok/remote host) for cloud demo environments.
        """
        self.documents = {k.lower(): v for k, v in documents.items()}
        self.rbac = RBACManager(role_permissions)
        self.dlp = DLPManager()
        self.injection_detector = PromptInjectionDetector()
        self.canary_manager = CanaryTokenManager()
        self.sanitizer = OutputSanitizer()
        self.audit_logger = AuditLogger(audit_log_path)
        
        resolved_url = ollama_url or os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
        self.model = model
        self.ollama_url = resolved_url
        self.llm_caller = llm_caller
        self.allow_remote = allow_remote or (os.environ.get("ALLOW_REMOTE_OLLAMA", "").lower() in {"true", "1", "yes"})

        self.inference_engine = EnterpriseInferenceEngine(
            ollama_url=resolved_url,
            preferred_model=model
        )

        self._validate_offline_endpoint()

    def _validate_offline_endpoint(self) -> None:
        """Verify that the configured LLM endpoint is strictly bound to local loopback unless explicitly allowed."""
        parsed = urlparse(self.ollama_url)
        host = parsed.hostname
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("ollama_url must use http or https scheme.")
        if not self.allow_remote and host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError(
                f"Security Violation: Target LLM endpoint '{self.ollama_url}' is not a local loopback address. "
                "AI-Vault strictly enforces 100% offline air-gapped operation."
            )

    def check_llm_health(self) -> Dict[str, Any]:
        """Test live connection to the configured LLM daemon."""
        return self.inference_engine.check_health()

    def set_ollama_endpoint(self, new_url: str, allow_remote: bool = True) -> None:
        """Update active Ollama generation endpoint dynamically."""
        self.ollama_url = new_url
        self.allow_remote = allow_remote
        self._validate_offline_endpoint()
        self.inference_engine = EnterpriseInferenceEngine(
            ollama_url=new_url,
            preferred_model=self.model,
        )

    def _resolve_context(self, document_id: str, role: str, unprotected: bool = False) -> str:
        """Resolve content from registered documents or the software company database."""
        doc_key = document_id.lower()
        if doc_key in self.documents:
            return self.documents[doc_key]

        _, db_context, _ = get_authorized_context_for_query(role, doc_key, unprotected_mode=unprotected)
        return db_context

    def _check_access(self, role: str, document_id: str) -> bool:
        """Check access permission against document registry or SQLite database tables."""
        doc_key = document_id.lower()
        if doc_key in self.documents or doc_key in self.rbac._role_permissions.get(role.lower(), set()):
            return self.rbac.can_access(role, doc_key)
        
        return check_table_access(role, doc_key)

    def process_query(
        self,
        user: User,
        document_id: str,
        prompt: str,
        defense_mode: str = "hardened"
    ) -> Dict[str, Any]:
        """Execute a single-resource query through the gateway firewall."""
        doc_id_key = document_id.lower()
        is_hardened = (defense_mode or "hardened").lower() != "vulnerable"

        if not is_hardened:
            context = self._resolve_context(doc_id_key, user.role, unprotected=True)
            raw_response = self._invoke_inference(prompt, context, "UNPROTECTED_MODE", user=user)
            
            self.audit_logger.log_event(
                username=user.username,
                role=user.role,
                document_id=document_id,
                prompt=prompt,
                outcome="allowed",
                reason="vulnerable_baseline_leak",
                response=raw_response,
                redactions_applied=False,
                extra_metadata={"defense_mode": "vulnerable", "warning": "Unprotected baseline leaked records without RBAC or DLP"},
            )
            return {
                "status": "ok",
                "reason": "vulnerable_baseline_leak",
                "response": raw_response,
                "engine": "Unprotected Baseline LLM",
                "message": "[VULNERABLE MODE ACTIVE] The prompt and database context bypassed RBAC and DLP controls."
            }

        redacted_prompt = self.dlp.redact(prompt)
        prompt_redactions_applied = (redacted_prompt != prompt)

        # 1. RBAC Gate
        if not self._check_access(user.role, doc_id_key):
            self.audit_logger.log_event(
                username=user.username,
                role=user.role,
                document_id=document_id,
                prompt=redacted_prompt,
                outcome="blocked",
                reason="rbac_denied",
                redactions_applied=prompt_redactions_applied,
                extra_metadata={"defense_mode": "hardened"},
            )
            return {
                "status": "blocked",
                "reason": "rbac_denied",
                "message": f"Access Denied: User role '{user.role.upper()}' is not authorized to access '{document_id}'."
            }

        # 2. Prompt Injection Scanner
        if self.injection_detector.is_injection(prompt):
            matched_rules = self.injection_detector.get_matched_rules(prompt)
            self.audit_logger.log_event(
                username=user.username,
                role=user.role,
                document_id=document_id,
                prompt=redacted_prompt,
                outcome="blocked",
                reason="prompt_injection",
                redactions_applied=prompt_redactions_applied,
                extra_metadata={"matched_patterns": matched_rules, "defense_mode": "hardened"},
            )
            return {
                "status": "blocked",
                "reason": "prompt_injection",
                "message": "Security Alert: Prompt injection or jailbreak attempt blocked by AI-Vault Firewall."
            }

        # 3. Context & Canary
        context = self._resolve_context(doc_id_key, user.role, unprotected=False)
        canary_token = self.canary_manager.generate_token()

        # 4. Inference
        try:
            raw_response, engine_used = self._invoke_inference_with_meta(
                prompt=redacted_prompt,
                context=context,
                canary_token=canary_token,
                user=user,
            )
        except Exception as e:
            self.audit_logger.log_event(
                username=user.username,
                role=user.role,
                document_id=document_id,
                prompt=redacted_prompt,
                outcome="blocked",
                reason="llm_execution_error",
                extra_metadata={"error": str(e)},
            )
            return {
                "status": "blocked",
                "reason": "llm_execution_error",
                "message": f"Inference engine failure: {str(e)}"
            }

        # 5. Canary Leak Check
        if self.canary_manager.is_canary_leaked(raw_response, canary_token):
            self.audit_logger.log_event(
                username=user.username,
                role=user.role,
                document_id=document_id,
                prompt=redacted_prompt,
                outcome="blocked",
                reason="canary_token_leaked",
                redactions_applied=True,
            )
            return {
                "status": "blocked",
                "reason": "canary_token_leaked",
                "message": "Security Alert: System instruction leakage detected. Response withheld."
            }

        # 6. Post-Inference Sanitization & DLP
        sanitized_response = self.sanitizer.sanitize(raw_response)
        redacted_response = self.dlp.redact(sanitized_response)
        response_redactions_applied = (redacted_response != raw_response)

        # 7. Audit Log
        event_dict = self.audit_logger.log_event(
            username=user.username,
            role=user.role,
            document_id=document_id,
            prompt=redacted_prompt,
            outcome="allowed",
            reason="ok",
            response=redacted_response,
            redactions_applied=(prompt_redactions_applied or response_redactions_applied),
            extra_metadata={"defense_mode": "hardened", "inference_engine": engine_used},
        )

        return {
            "status": "ok",
            "reason": "ok",
            "response": redacted_response,
            "engine": engine_used,
            "audit_hash": event_dict.get("hash"),
        }

    def process_chat_query(
        self,
        user: User,
        prompt: str,
        defense_mode: str = "hardened",
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Conversational Multi-Table Natural Language Query Processor.
        Automatically searches the entire database, enforcing RBAC across all matched tables.
        """
        is_hardened = (defense_mode or "hardened").lower() != "vulnerable"

        # 1. Save inbound user message if session provided
        if session_id:
            save_chat_message(
                session_id=session_id,
                sender="user",
                content=prompt,
                metadata={"username": user.username, "role": user.role, "mode": defense_mode}
            )

        # ---------------------------------------------------------------------
        # 🔴 VULNERABLE BASELINE
        # ---------------------------------------------------------------------
        if not is_hardened:
            search_res = auto_search_database(prompt, user.role, unprotected_mode=True)
            context = search_res["authorized_context"]
            raw_response, engine_used = self._invoke_inference_with_meta(prompt, context, "CANARY_NONE", user=user)
            
            leak_detected = bool(search_res["accessed_tables"])
            outcome_reason = "vulnerable_baseline_leak" if leak_detected else "general_query"
            doc_id = "multi_table_database" if leak_detected else "general_inquiry"

            event_dict = self.audit_logger.log_event(
                username=user.username,
                role=user.role,
                document_id=doc_id,
                prompt=prompt,
                outcome="allowed",
                reason=outcome_reason,
                response=raw_response,
                redactions_applied=False,
                extra_metadata={
                    "defense_mode": "vulnerable",
                    "accessed_tables": search_res["accessed_tables"],
                    "session_id": session_id,
                },
            )

            result = {
                "status": "ok",
                "reason": outcome_reason,
                "response": raw_response,
                "engine": engine_used,
                "accessed_tables": search_res["accessed_tables"],
                "blocked_tables": [],
                "audit_hash": event_dict.get("hash"),
                "message": (
                    "[VULNERABLE MODE] Internal database tables were accessed without RBAC or DLP redactions."
                    if leak_detected
                    else "[VULNERABLE MODE] General knowledge query answered directly by local LLM without accessing internal database records."
                )
            }
            if session_id:
                save_chat_message(session_id=session_id, sender="assistant", content=raw_response, metadata=result)
            return result

        # ---------------------------------------------------------------------
        # 🛡️ HARDENED AI-VAULT ZERO-TRUST FIREWALL
        # ---------------------------------------------------------------------
        # 1. Prompt Injection Scanner (OWASP LLM01)
        if self.injection_detector.is_injection(prompt):
            matched_rules = self.injection_detector.get_matched_rules(prompt)
            event_dict = self.audit_logger.log_event(
                username=user.username,
                role=user.role,
                document_id="multi_table_database",
                prompt=prompt,
                outcome="blocked",
                reason="prompt_injection",
                extra_metadata={"matched_patterns": matched_rules, "defense_mode": "hardened", "session_id": session_id},
            )
            blocked_msg = "[SECURITY ALERT] Prompt injection or jailbreak attempt blocked by AI-Vault Firewall."
            result = {
                "status": "blocked",
                "reason": "prompt_injection",
                "message": blocked_msg,
                "response": blocked_msg,
                "audit_hash": event_dict.get("hash"),
            }
            if session_id:
                save_chat_message(session_id=session_id, sender="assistant", content=blocked_msg, metadata=result)
            return result

        # 2. Inbound DLP Redaction
        redacted_prompt = self.dlp.redact(prompt)
        prompt_redactions = (redacted_prompt != prompt)

        # 3. Automated Database Search with RBAC
        search_res = auto_search_database(redacted_prompt, user.role, unprotected_mode=False)
        blocked_tables = search_res["blocked_tables"]
        accessed_tables = search_res["accessed_tables"]
        context = search_res["authorized_context"]

        # If user ONLY requested tables they cannot access, block immediately
        if blocked_tables and not accessed_tables:
            event_dict = self.audit_logger.log_event(
                username=user.username,
                role=user.role,
                document_id=f"blocked_{'_'.join(blocked_tables)}",
                prompt=redacted_prompt,
                outcome="blocked",
                reason="rbac_denied",
                redactions_applied=prompt_redactions,
                extra_metadata={"blocked_tables": blocked_tables, "session_id": session_id},
            )
            blocked_msg = (
                f"[ACCESS DENIED] User role '{user.role.upper()}' is not permitted to access "
                f"confidential records in table(s): {', '.join(blocked_tables)}."
            )
            result = {
                "status": "blocked",
                "reason": "rbac_denied",
                "message": blocked_msg,
                "response": blocked_msg,
                "blocked_tables": blocked_tables,
                "accessed_tables": [],
                "audit_hash": event_dict.get("hash"),
            }
            if session_id:
                save_chat_message(session_id=session_id, sender="assistant", content=blocked_msg, metadata=result)
            return result

        # 4. Ephemeral Canary Token & Inference
        canary_token = self.canary_manager.generate_token()
        try:
            raw_response, engine_used = self._invoke_inference_with_meta(
                prompt=redacted_prompt,
                context=context,
                canary_token=canary_token,
                user=user,
            )
        except Exception as e:
            err_msg = f"Inference engine failure: {str(e)}"
            return {"status": "blocked", "reason": "llm_error", "message": err_msg, "response": err_msg}

        # 5. Canary Leak Check
        if self.canary_manager.is_canary_leaked(raw_response, canary_token):
            leak_msg = "[SECURITY ALERT] System instruction leakage detected. Response withheld."
            return {"status": "blocked", "reason": "canary_leak", "message": leak_msg, "response": leak_msg}

        # 6. Post-Inference Sanitizer & DLP
        sanitized_res = self.sanitizer.sanitize(raw_response)
        redacted_res = self.dlp.redact(sanitized_res)
        response_redactions = (redacted_res != raw_response)

        # If some tables were blocked, append note
        if blocked_tables:
            redacted_res += f"\n\n*(Note: Additional records from `{', '.join(blocked_tables)}` were restricted under your active `{user.role.upper()}` role).* "

        # 7. Tamper-Evident SHA-256 Audit Log
        hardened_reason = "general_query" if not accessed_tables else "ok"
        hardened_doc_id = f"auto_{'_'.join(accessed_tables)}" if accessed_tables else "general_inquiry"

        event_dict = self.audit_logger.log_event(
            username=user.username,
            role=user.role,
            document_id=hardened_doc_id,
            prompt=redacted_prompt,
            outcome="allowed",
            reason=hardened_reason,
            response=redacted_res,
            redactions_applied=(prompt_redactions or response_redactions),
            extra_metadata={
                "defense_mode": "hardened",
                "accessed_tables": accessed_tables,
                "blocked_tables": blocked_tables,
                "session_id": session_id,
                "inference_engine": engine_used,
            },
        )

        result = {
            "status": "ok",
            "reason": hardened_reason,
            "response": redacted_res,
            "engine": engine_used,
            "accessed_tables": accessed_tables,
            "blocked_tables": blocked_tables,
            "audit_hash": event_dict.get("hash"),
            "redactions_applied": (prompt_redactions or response_redactions),
        }

        if session_id:
            save_chat_message(session_id=session_id, sender="assistant", content=redacted_res, metadata=result)

        return result

    def _invoke_inference_with_meta(self, prompt: str, context: str, canary_token: str, user: Optional[User] = None) -> Tuple[str, str]:
        """Invoke custom llm_caller or internal inference engine, returning text and engine name."""
        if self.llm_caller:
            return self.llm_caller(prompt, context), "Custom LLM Caller"

        return self.inference_engine.generate(prompt, context, canary_token, user=user)

    def _invoke_inference(self, prompt: str, context: str, canary_token: str, user: Optional[User] = None) -> str:
        text, _ = self._invoke_inference_with_meta(prompt, context, canary_token, user=user)
        return text

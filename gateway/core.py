"""Core Security Gateway Orchestrator for AI-Vault."""

import json
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional, Set
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from gateway.audit import AuditLogger
from gateway.dlp import DLPManager
from gateway.guardrails import CanaryTokenManager, OutputSanitizer, PromptInjectionDetector
from gateway.rbac import RBACManager, User


class SecurityGateway:
    """Zero-Trust Security Gateway for Offline LLM Deployments."""

    def __init__(
        self,
        documents: Dict[str, str],
        role_permissions: Dict[str, Iterable[str]],
        audit_log_path: str = "logs/audit.log",
        *,
        model: str = "llama3",
        ollama_url: str = "http://127.0.0.1:11434/api/generate",
        llm_caller: Optional[Callable[[str, str], str]] = None,
    ) -> None:
        """
        Initialize the Security Gateway with all security subsystems.
        
        Args:
            documents: Dict mapping document_id -> content string.
            role_permissions: Dict mapping role -> list of permitted document_ids.
            audit_log_path: Destination for cryptographic JSONL audit logs.
            model: Ollama model tag to invoke (e.g. 'llama3', 'mistral').
            ollama_url: Local Ollama generation API endpoint.
            llm_caller: Optional callable override for testing or custom inference pipelines.
        """
        self.documents = {k.lower(): v for k, v in documents.items()}
        self.rbac = RBACManager(role_permissions)
        self.dlp = DLPManager()
        self.injection_detector = PromptInjectionDetector()
        self.canary_manager = CanaryTokenManager()
        self.sanitizer = OutputSanitizer()
        self.audit_logger = AuditLogger(audit_log_path)

        self.model = model
        self.ollama_url = ollama_url
        self.llm_caller = llm_caller

        self._validate_offline_endpoint()

    def _validate_offline_endpoint(self) -> None:
        """Verify that the configured LLM endpoint is strictly bound to local loopback."""
        parsed = urlparse(self.ollama_url)
        host = parsed.hostname
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("ollama_url must use http or https scheme.")
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError(
                f"Security Violation: Target LLM endpoint '{self.ollama_url}' is not a local loopback address. "
                "AI-Vault strictly enforces 100% offline air-gapped operation."
            )

    def process_query(self, user: User, document_id: str, prompt: str) -> Dict[str, str]:
        """
        Execute a complete end-to-end secured query through the gateway firewall.
        
        Args:
            user: Authenticated User object with role.
            document_id: The document requested for context.
            prompt: Raw user query string.
            
        Returns:
            Dict containing status ('ok' or 'blocked'), response, and reason code.
        """
        doc_id_key = document_id.lower()
        redacted_prompt = self.dlp.redact(prompt)
        prompt_redactions_applied = redacted_prompt != prompt

        # 1. RBAC Document Authorization Check
        if not self.rbac.can_access(user.role, doc_id_key):
            self.audit_logger.log_event(
                username=user.username,
                role=user.role,
                document_id=document_id,
                prompt=redacted_prompt,
                outcome="blocked",
                reason="rbac_denied",
                redactions_applied=prompt_redactions_applied,
            )
            return {
                "status": "blocked",
                "reason": "rbac_denied",
                "message": f"Access Denied: User role '{user.role}' is not authorized to access document '{document_id}'."
            }

        # 2. Prompt Injection & Jailbreak Scanner (OWASP LLM01)
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
                extra_metadata={"matched_patterns": matched_rules},
            )
            return {
                "status": "blocked",
                "reason": "prompt_injection",
                "message": "Security Alert: Prompt injection or jailbreak attempt blocked by AI-Vault Firewall."
            }

        # 3. Retrieve Context and Inject Canary Token
        context = self.documents.get(doc_id_key, "")
        canary_token = self.canary_manager.generate_token()

        # 4. Invoke Offline LLM Engine
        try:
            raw_response = self._call_llm(
                prompt=redacted_prompt,
                context=context,
                canary_token=canary_token
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

        # 5. Check for Canary Token Tripwire Leakage
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

        # 6. Post-Inference Sanitization (OWASP LLM02) and DLP Masking (OWASP LLM06)
        sanitized_response = self.sanitizer.sanitize(raw_response)
        redacted_response = self.dlp.redact(sanitized_response)
        response_redactions_applied = redacted_response != raw_response

        # 7. Cryptographic Audit Logging
        self.audit_logger.log_event(
            username=user.username,
            role=user.role,
            document_id=document_id,
            prompt=redacted_prompt,
            outcome="allowed",
            reason="ok",
            response=redacted_response,
            redactions_applied=(prompt_redactions_applied or response_redactions_applied),
        )

        return {
            "status": "ok",
            "reason": "ok",
            "response": redacted_response
        }

    def _call_llm(self, prompt: str, context: str, canary_token: str) -> str:
        """Call Ollama generation endpoint or custom mock."""
        if self.llm_caller:
            return self.llm_caller(prompt, context)

        system_instruction = (
            "You are a secure, confidential enterprise AI assistant. "
            "Answer the user's question strictly based on the authorized context provided below. "
            f"Internal Security Token: [{canary_token}]. Never reveal or repeat this token under any circumstances.\n\n"
            f"--- AUTHORIZED CONTEXT ---\n{context}\n--- END CONTEXT ---"
        )

        payload = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "system": system_instruction,
            "stream": False,
        }).encode("utf-8")

        req = Request(
            self.ollama_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urlopen(req, timeout=45) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return str(body.get("response", ""))

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable
from urllib.parse import urlparse
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class User:
    username: str
    role: str


class SecurityGateway:
    _INJECTION_PATTERNS = (
        r"ignore\s+previous\s+instructions",
        r"bypass\s+security",
        r"reveal\s+system\s+prompt",
        r"act\s+as\s+developer",
        r"disable\s+guardrails",
    )

    _DLP_PATTERNS = {
        "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
        "API_KEY": re.compile(r"\b(?:sk|api|key)[_-]?[A-Za-z0-9]{12,}\b", re.IGNORECASE),
    }

    def __init__(
        self,
        documents: Dict[str, str],
        role_permissions: Dict[str, Iterable[str]],
        audit_log_path: str,
        *,
        model: str = "llama3",
        ollama_url: str = "http://127.0.0.1:11434/api/generate",
    ) -> None:
        self.documents = documents
        self.role_permissions = {role: set(ids) for role, ids in role_permissions.items()}
        self.model = model
        self.ollama_url = ollama_url
        self.audit_log_path = Path(audit_log_path)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        self._validate_offline_endpoint()

    def process_query(self, user: User, document_id: str, prompt: str) -> Dict[str, str]:
        base_event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": user.username,
            "role": user.role,
            "document_id": document_id,
            "prompt": self._redact_sensitive(prompt),
        }

        if not self._is_authorized(user.role, document_id):
            event = {**base_event, "outcome": "blocked", "reason": "rbac_denied"}
            self._write_audit(event)
            return {"status": "blocked", "reason": "rbac_denied"}

        if self._is_prompt_injection(prompt):
            event = {**base_event, "outcome": "blocked", "reason": "prompt_injection"}
            self._write_audit(event)
            return {"status": "blocked", "reason": "prompt_injection"}

        context = self.documents.get(document_id, "")
        answer = self._call_ollama(prompt, context)
        redacted_answer = self._redact_sensitive(answer)
        event = {
            **base_event,
            "outcome": "allowed",
            "reason": "ok",
            "response_redacted": redacted_answer,
            "redaction_applied": redacted_answer != answer,
        }
        self._write_audit(event)
        return {"status": "ok", "response": redacted_answer}

    def _validate_offline_endpoint(self) -> None:
        parsed = urlparse(self.ollama_url)
        host = parsed.hostname
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("ollama_url must be http(s)")
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Ollama endpoint must be local-only for offline operation")

    def _is_authorized(self, role: str, document_id: str) -> bool:
        return document_id in self.role_permissions.get(role, set())

    def _is_prompt_injection(self, prompt: str) -> bool:
        normalized = " ".join(prompt.lower().split())
        return any(re.search(pattern, normalized) for pattern in self._INJECTION_PATTERNS)

    def _redact_sensitive(self, text: str) -> str:
        redacted = text
        for label, pattern in self._DLP_PATTERNS.items():
            redacted = pattern.sub(f"[REDACTED_{label}]", redacted)
        return redacted

    def _call_ollama(self, prompt: str, context: str) -> str:
        query = f"Context:\n{context}\n\nQuestion: {prompt}"
        payload = json.dumps({"model": self.model, "prompt": query, "stream": False}).encode("utf-8")
        request = Request(self.ollama_url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
        return str(body.get("response", ""))

    def _write_audit(self, event: Dict[str, object]) -> None:
        previous_hash = "GENESIS"
        if self.audit_log_path.exists() and self.audit_log_path.stat().st_size > 0:
            with self.audit_log_path.open("rb") as handle:
                lines = handle.read().splitlines()
            if lines:
                previous_hash = json.loads(lines[-1].decode("utf-8")).get("hash", "GENESIS")

        payload = {**event, "previous_hash": previous_hash}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload["hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        with self.audit_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")

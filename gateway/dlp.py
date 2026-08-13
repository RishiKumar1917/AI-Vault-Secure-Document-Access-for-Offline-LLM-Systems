"""Data Loss Prevention (DLP) & PII Redaction module."""

import re
from typing import Dict, List, Pattern, Tuple


class DLPManager:
    """Detects and redacts sensitive PII, credentials, and cryptographic secrets."""

    DEFAULT_PATTERNS: Dict[str, Pattern] = {
        "EMAIL": re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
        "SSN": re.compile(
            r"\b\d{3}-\d{2}-\d{4}\b"
        ),
        "CREDIT_CARD": re.compile(
            r"\b(?:\d[ -]*?){13,16}\b"
        ),
        "PHONE": re.compile(
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
        ),
        "AWS_KEY": re.compile(
            r"\bAKIA[0-9A-Z]{16}\b"
        ),
        "JWT_TOKEN": re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
        "API_KEY": re.compile(
            r"\b(?:sk|api|key|secret|token|ghp|gho|xoxb)(?:[-_][a-zA-Z0-9]+)*[-_][A-Za-z0-9]{12,}\b|\b(?:sk|api|key)[_-]?[A-Za-z0-9]{16,}\b",
            re.IGNORECASE
        ),
    }

    def __init__(self, custom_patterns: Dict[str, Pattern] = None) -> None:
        """
        Initialize DLP Manager with standard or extended regex patterns.
        
        Args:
            custom_patterns: Optional dict mapping label -> compiled regex pattern.
        """
        self.patterns: Dict[str, Pattern] = self.DEFAULT_PATTERNS.copy()
        if custom_patterns:
            self.patterns.update(custom_patterns)

    def redact(self, text: str) -> str:
        """
        Scan and redact all sensitive entities with [REDACTED_<TYPE>] placeholders.
        
        Args:
            text: Raw input or output string.
            
        Returns:
            Sanitized string with sensitive tokens masked.
        """
        if not text:
            return ""
        redacted = text
        for label, pattern in self.patterns.items():
            redacted = pattern.sub(f"[REDACTED_{label}]", redacted)
        return redacted

    def detect_sensitive_types(self, text: str) -> List[str]:
        """
        Return a list of sensitive data types detected within the string.
        
        Args:
            text: Text to inspect.
            
        Returns:
            List of detected labels (e.g. ['SSN', 'EMAIL']).
        """
        if not text:
            return []
        detected = []
        for label, pattern in self.patterns.items():
            if pattern.search(text):
                detected.append(label)
        return detected

    def has_sensitive_data(self, text: str) -> bool:
        """Check if the text contains any matching sensitive patterns."""
        if not text:
            return False
        return any(pattern.search(text) for pattern in self.patterns.values())

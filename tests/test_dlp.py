"""Unit tests for Data Loss Prevention (DLP) & PII Redaction."""

import pytest
from gateway.dlp import DLPManager


def test_dlp_email_redaction():
    dlp = DLPManager()
    raw = "Contact the team at support@company.com or ceo.office@domain.org for info."
    redacted = dlp.redact(raw)
    assert "[REDACTED_EMAIL]" in redacted
    assert "support@company.com" not in redacted
    assert "ceo.office@domain.org" not in redacted


def test_dlp_ssn_redaction():
    dlp = DLPManager()
    raw = "Employee SSN is 000-12-3456 and manager SSN is 999-88-7777."
    redacted = dlp.redact(raw)
    assert "[REDACTED_SSN]" in redacted
    assert "000-12-3456" not in redacted
    assert "999-88-7777" not in redacted


def test_dlp_credit_card_redaction():
    dlp = DLPManager()
    raw = "Billing card is 4111-2222-3333-4444 on file."
    redacted = dlp.redact(raw)
    assert "[REDACTED_CREDIT_CARD]" in redacted
    assert "4111-2222-3333-4444" not in redacted


def test_dlp_aws_and_api_key_redaction():
    dlp = DLPManager()
    raw = "AWS key is AKIATESTKEYMOCK12345 and secret is key_demo_secret_token_1234567890abcdef"
    redacted = dlp.redact(raw)
    assert "[REDACTED_AWS_KEY]" in redacted or "[REDACTED_API_KEY]" in redacted
    assert "AKIATESTKEYMOCK12345" not in redacted
    assert "key_demo_secret_token_1234567890abcdef" not in redacted


def test_dlp_detection_reporting():
    dlp = DLPManager()
    raw = "User email test@domain.com with SSN 123-45-6789"
    detected = dlp.detect_sensitive_types(raw)
    assert "EMAIL" in detected
    assert "SSN" in detected

# AI-Vault: Core Security Engine Blueprint & Implementation Guide

This document provides a single-reference, comprehensive blueprint of the **AI-Vault Core Security Gateway** architecture, implemented security modules, test suite verification, and execution commands.

---

## 1. High-Level Architecture Overview

```
                                  +-----------------------+
                                  |   Incoming Request    |
                                  | (User, Role, Prompt)  |
                                  +-----------+-----------+
                                              |
                                              v
+-----------------------------------------------------------------------------------------+
|                              AI-VAULT SECURITY GATEWAY                                  |
|                                                                                         |
|  [Layer 1: RBAC Authorization]                                                          |
|  * Validates if user's role is permitted to read target document.                       |
|  * Outcome: If denied -> Drop immediately and log 'rbac_denied'.                        |
|                                                                                         |
|  [Layer 2: Inbound Prompt Injection Scanner (OWASP LLM01)]                              |
|  * Heuristic inspection for jailbreaks, DAN patterns, and delimiter escapes.            |
|  * Outcome: If detected -> Drop immediately and log 'prompt_injection'.                 |
|                                                                                         |
|  [Layer 3: Pre-Inference DLP Masking (OWASP LLM06)]                                     |
|  * Masks emails, SSNs, credit cards, AWS keys, JWTs with [REDACTED_*] tokens.          |
|                                                                                         |
|  [Layer 4: Context Assembly & Canary Token Injection]                                   |
|  * Inserts dynamic ephemeral canary token into system prompt.                           |
|                                                                                         |
|  [Layer 5: Offline LLM Execution]                                                       |
|  * Strict local loopback enforcement (127.0.0.1 / localhost) via Ollama.                |
|                                                                                         |
|  [Layer 6: Canary Leak & Output Sanitization (OWASP LLM02)]                             |
|  * Checks for system instruction extraction and strips unsafe HTML/script tags.         |
|                                                                                         |
|  [Layer 7: Tamper-Evident SHA-256 Hash Chained Audit Log]                               |
|  * Appends immutable event with previous_hash link for mathematical compliance.         |
+---------------------------------------------+-------------------------------------------+
                                              |
                                              v
                                  +-----------------------+
                                  |    Sanitized Output   |
                                  |    (Safe & Masked)    |
                                  +-----------------------+
```

---

## 2. Core Subsystems Breakdown

### Module 1: Role-Based Access Control (`gateway/rbac.py`)
- **Purpose:** Enforces document-level permissions based on authenticated user roles.
- **Key Classes:** `User`, `Document`, `RBACManager`.
- **Functions:**
  - `can_access(role, document_id) -> bool`: Checks if role has access to specific document.
  - `get_accessible_documents(role, all_docs) -> dict`: Filters accessible documents dictionary.

### Module 2: Data Loss Prevention & PII Masking (`gateway/dlp.py`)
- **Purpose:** Automatically scans, detects, and redacts sensitive data.
- **Protected Entities:** Emails, SSNs, Credit Cards, Phone Numbers, AWS Keys, JWTs, API Secrets.
- **Key Class:** `DLPManager`.
- **Functions:**
  - `redact(text) -> str`: Replaces sensitive matches with `[REDACTED_<TYPE>]`.
  - `detect_sensitive_types(text) -> list`: Reports detected entity types.
  - `has_sensitive_data(text) -> bool`: Fast boolean check for sensitive content.

### Module 3: Prompt Injection Guardrails & Canary Tokens (`gateway/guardrails.py`)
- **Purpose:** Defends against instruction overrides (OWASP LLM01) and insecure output (OWASP LLM02).
- **Key Classes:**
  - `PromptInjectionDetector`: Evaluates prompts against jailbreak heuristics and delimiter breakouts (`</context>`, `[SYSTEM]`, DAN mode).
  - `CanaryTokenManager`: Injects ephemeral canary tripwires to catch prompt leaks.
  - `OutputSanitizer`: Neutralizes `<script>`, `<iframe>`, and javascript protocol URIs.

### Module 4: Cryptographic Audit Logging (`gateway/audit.py`)
- **Purpose:** Creates a tamper-evident audit trail compatible with enterprise SIEM systems.
- **Mechanism:**
  $$\text{Hash}_n = \text{SHA-256}(\text{CanonicalEventJSON}_n + \text{Hash}_{n-1})$$
- **Key Class:** `AuditLogger`.
- **Functions:**
  - `log_event(...) -> dict`: Hashes and appends event to `logs/audit.log`.
  - `verify_integrity(log_path) -> (bool, count, msg)`: Recomputes every block hash from `GENESIS` to mathematically prove zero tampering.

### Module 5: Master Orchestrator (`gateway/core.py`)
- **Purpose:** Coordinates the complete 7-step zero-trust lifecycle.
- **Key Class:** `SecurityGateway`.
- **Enforcement:** Enforces strict offline loopback address verification before sending any request to local Ollama endpoints.

---

## 3. Sample Enterprise Dataset (`data/sample_documents/`)

| Document ID | Classification | Authorized Roles | Description |
| :--- | :--- | :--- | :--- |
| `public_handbook.txt` | Public | Intern, Engineer, HR, Admin | Office hours, flexible work policies, public contacts. |
| `engineering_specs.txt` | Restricted | Engineer, Admin | Microservice topologies, staging DB credentials, AWS keys. |
| `payroll_q3.txt` | Confidential | HR, Admin | Executive salaries, performance bonuses, employee SSNs. |

---

## 4. Test Suite Verification (16/16 Passed)

```text
============================= test session starts =============================
platform win32 -- Python 3.14, pytest-9.1.1
rootdir: C:\Users\rishi\Downloads\Major Project
configfile: pyproject.toml

tests/test_audit_integrity.py::test_audit_hash_chain_creation PASSED     [  6%]
tests/test_audit_integrity.py::test_audit_tamper_detection_modified_content PASSED [ 12%]
tests/test_audit_integrity.py::test_audit_tamper_detection_deleted_record PASSED [ 18%]
tests/test_audit_integrity.py::test_gateway_end_to_end_orchestration PASSED [ 25%]
tests/test_dlp.py::test_dlp_email_redaction PASSED                       [ 31%]
tests/test_dlp.py::test_dlp_ssn_redaction PASSED                         [ 37%]
tests/test_dlp.py::test_dlp_credit_card_redaction PASSED                 [ 43%]
tests/test_dlp.py::test_dlp_aws_and_api_key_redaction PASSED             [ 50%]
tests/test_dlp.py::test_dlp_detection_reporting PASSED                   [ 56%]
tests/test_guardrails.py::test_prompt_injection_detection PASSED         [ 62%]
tests/test_guardrails.py::test_clean_prompts_pass_guardrails PASSED      [ 68%]
tests/test_guardrails.py::test_canary_token_detection PASSED             [ 75%]
tests/test_guardrails.py::test_output_sanitizer PASSED                   [ 81%]
tests/test_rbac.py::test_rbac_authorization_success PASSED               [ 87%]
tests/test_rbac.py::test_rbac_authorization_denied PASSED                [ 93%]
tests/test_rbac.py::test_rbac_filter_documents PASSED                    [100%]

============================= 16 passed in 0.39s ==============================
```

---

## 5. Execution Commands

```powershell
# 1. Run all unit tests with full verbosity
python -m pytest tests/ -v

# 2. Run a specific test module
python -m pytest tests/test_rbac.py -v
python -m pytest tests/test_dlp.py -v
python -m pytest tests/test_guardrails.py -v
python -m pytest tests/test_audit_integrity.py -v
```

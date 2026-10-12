# AI-Vault: Zero-Trust Local AI Gateway with Role-Based Data Protection

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-teal.svg)](https://fastapi.tiangolo.com/)
[![Ollama](https://img.shields.io/badge/LLM-Ollama_(Offline)-black.svg)](https://ollama.com/)
[![Security](https://img.shields.io/badge/OWASP-LLM_Top_10_Aligned-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Network](https://img.shields.io/badge/Network-100%25_Air--Gapped-green.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **AI-Vault** is a privacy-first, zero-trust security gateway placed in front of locally hosted Large Language Models (such as Ollama, Llama 3, or Mistral). It strictly enforces document-level Role-Based Access Control (RBAC), prevents prompt injection attacks, redacts sensitive PII and credentials, and records every interaction to a tamper-evident cryptographic audit log running 100% offline at zero recurring cost.

---

## Table of Contents
- [Industry Problem Statement](#industry-problem-statement)
- [Proposed Solution](#proposed-solution)
- [Enterprise Cloud AI vs. AI-Vault](#enterprise-cloud-ai-vs-ai-vault)
- [System Architecture](#system-architecture)
- [Core Security Modules](#core-security-modules)
- [OWASP LLM Top 10 Coverage](#owasp-llm-top-10-coverage)
- [Project Directory Structure](#project-directory-structure)
- [Getting Started](#getting-started)
- [Demo Scenarios & Test Cases](#demo-scenarios--test-cases)
- [Learning Resources & Datasets](#learning-resources--datasets)
- [Project Roadmap](#project-roadmap)
- [License](#license)

---

## Industry Problem Statement

1. **Confidential Data Leaks to Cloud GPUs:** Commercial enterprise AI solutions require transmitting proprietary source code, financial spreadsheets, and employee records to external third-party cloud servers. For healthcare, banking, defense, and privacy-focused institutions, this introduces severe regulatory and compliance risks (GDPR, HIPAA, SOC 2).
2. **Lack of Internal Access Control in Local LLMs:** When organizations deploy open-source models (such as Llama 3) onto private servers, anyone with network access (e.g., interns or contractors) can query the model about executive compensation, internal API keys, or restricted HR documentation. Raw open-source LLMs have no intrinsic awareness of user permissions or document classification.

---

## Proposed Solution

AI-Vault functions as a Zero-Trust Security Firewall positioned between end-users and the private local LLM engine:

```
+-------------------------------------------------------------+
| 1. User submits Query + Authenticated Role (e.g., Intern)   |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
| 2. AI-Vault Security Gateway (FastAPI)                      |
|   |-- OWASP LLM01: Heuristic Prompt Injection Defense       |
|   |-- Document-Level RBAC: Filters permitted context        |
|   |-- OWASP LLM06: Pre-Inference DLP (PII/Secret Masking)   |
|   +-- Canary Token Tripwires                                |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
| 3. Offline Local LLM (Ollama - Llama 3 / Mistral)           |
|   +-- Generates answer strictly from authorized context     |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
| 4. Output Sanitization & Cryptographic SIEM Audit Trail     |
|   |-- OWASP LLM02: Script and malicious link deflection     |
|   +-- SHA-256 Hash Chained Audit Log (previous_hash)        |
+-------------------------------------------------------------+
```

---

## Enterprise Cloud AI vs. AI-Vault

| Security Dimension | Cloud Enterprise AI (ChatGPT / Gemini) | AI-Vault (Zero-Trust Local AI) |
| :--- | :--- | :--- |
| **Data Perimeter** | Data transmitted to third-party GPU clouds | **100% Air-Gapped / Zero Network Egress** |
| **Internal RBAC** | Organization-wide / Shared workspace level | **Granular, Document-Level Access Control** |
| **Prompt Injection Defense** | Generic black-box vendor filters | **Auditable Heuristic & Canary Token Guardrails** |
| **Data Masking (DLP)** | Dependent on vendor policy | **Pre- & Post-Inference Automated Redaction** |
| **Audit Trails** | Standard vendor cloud logs | **Tamper-Evident SHA-256 Hash Chaining** |
| **Ongoing Cost** | $20 - $60 / user / month | **$0.00 (Runs entirely on existing local hardware)** |

---

## Core Security Modules

### 1. Granular Role-Based Access Control (RBAC)
Every document in the vault is tagged with access classifications (`["public"]`, `["engineering"]`, `["hr"]`, `["finance"]`). When a user submits a query, the gateway filters the document store. If an unauthorized document is referenced, access is rejected before reaching the LLM context.

### 2. Pre-Inference & Post-Inference DLP Redaction
Sensitive information is intercepted and replaced with normalized tokens (such as `[REDACTED_SSN]`, `[REDACTED_API_KEY]`, `[REDACTED_EMAIL]`, `[REDACTED_CREDIT_CARD]`) both before prompt construction and upon receiving the model's response.

### 3. Prompt Injection & Jailbreak Guardrails (OWASP LLM01)
* Scans for instruction-override patterns (`ignore previous instructions`, `act as developer`, `DAN mode`, `bypass security`).
* Protects against context delimiter breakout attempts (such as `</context>`, `[SYSTEM INSTRUCTION]`).
* Injects Canary Tokens into system prompts to detect context leakage.

### 4. Cryptographic Tamper-Evident Audit Logging
Every query and response event is appended to an append-only JSONL log with a cryptographic hash chain:

$$\text{Hash}_n = \text{SHA-256}(\text{CanonicalEventJSON}_n + \text{Hash}_{n-1})$$

Any unauthorized modification or deletion of past log records breaks the mathematical hash chain, providing verifiable compliance auditing.

### 5. Strict Offline Host Validation
The gateway verifies that the LLM endpoint is bound strictly to `127.0.0.1`, `localhost`, or `::1`, rejecting non-local network traffic.

---

## OWASP LLM Top 10 Coverage

For an in-depth threat model and technical analysis of all 10 vulnerability categories, see the [Full OWASP LLM Top 10 Reference Guide](docs/OWASP_LLM_TOP_10.md).

| OWASP Vulnerability | Risk Description | AI-Vault Mitigation |
| :--- | :--- | :--- |
| **LLM01: Prompt Injection** | User crafts inputs to hijack model instructions. | Heuristic regex inspection, delimiter isolation, canary tokens. |
| **LLM02: Insecure Output Handling** | Model outputs unvalidated scripts or malicious code. | Response sanitization and executable script stripping. |
| **LLM06: Sensitive Info Disclosure** | Confidential or PII data exposed in LLM prompts/replies. | RBAC document isolation + dual-layer regex/Presidio DLP masking. |

---

## Project Directory Structure

```text
AI-Vault-Secure-Document-Access-for-Offline-LLM-Systems/
|-- .github/
|   +-- workflows/
|       |-- ci.yml                 # Automated pytest & linting
|       +-- codeql.yml             # CodeQL vulnerability scanning
|-- docs/
|   +-- OWASP_LLM_TOP_10.md        # Comprehensive OWASP Threat Matrix & Guide
|-- data/
|   +-- sample_documents/          # Mock enterprise files
|       |-- public_handbook.txt
|       |-- engineering_specs.txt
|       +-- payroll_q3.txt
|-- gateway/
|   |-- __init__.py
|   |-- core.py                    # Core Gateway orchestrator
|   |-- rbac.py                    # Role & document authorization logic
|   |-- dlp.py                     # Pre/post-inference data masking
|   |-- guardrails.py              # Prompt injection heuristics & canary tokens
|   |-- audit.py                   # SHA-256 cryptographic hash-chain logger
|   +-- api.py                     # FastAPI REST API endpoints
|-- ui/
|   +-- app.py                     # Interactive Streamlit Demo Dashboard
|-- benchmarks/
|   |-- test_jailbreak_suite.py    # Injection benchmark test runner
|   +-- payloads.json              # Curated attack vectors (SPML benchmark)
|-- tests/
|   |-- test_rbac.py
|   |-- test_dlp.py
|   |-- test_guardrails.py
|   +-- test_audit_integrity.py
|-- verify_audit_log.py            # CLI tool to verify hash-chain integrity
|-- requirements.txt               # Project dependencies
|-- pyproject.toml
|-- README.md
|-- LICENSE                        # MIT License
+-- SECURITY.md
```

---

## Getting Started & Team Setup

Follow these steps to set up the project locally for development, evaluation, and collaboration:

### 1. Prerequisites
- **Python 3.10+** (Python 3.11 or 3.12 recommended)
- **Ollama** installed from [ollama.com](https://ollama.com/)

### 2. Set Up Uncensored Local LLM (Ollama)
For accurate dual-mode testing (**Vulnerable vs. Hardened**), AI-Vault uses an uncensored Dolphin model to ensure baseline vulnerabilities are reliably demonstrated without artificial RLHF refusals:

```bash
# 1. Pull the base Dolphin Llama 3 model (4.7 GB)
ollama pull dolphin-llama3:8b

# 2. Build the customized uncensored model from our Modelfile
ollama create dolphin-uncensored -f dolphin-uncensored-modelfile

# 3. Ensure the Ollama local daemon is running
ollama serve
```

> **Note:** If Ollama is not running, AI-Vault's internal **Dynamic Conversational Engine** automatically acts as a zero-cost fallback so all security gates and tests still function!

### 3. Clone & Install Dependencies
```bash
# Clone the repository
git clone https://github.com/RishiKumar1917/AI-Vault-Secure-Document-Access-for-Offline-LLM-Systems.git
cd AI-Vault-Secure-Document-Access-for-Offline-LLM-Systems

# Create and activate a virtual environment
python -m venv venv

# Windows (PowerShell):
.\venv\Scripts\activate

# Linux / macOS:
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 4. Run Automated Test Suite
Verify that all 22 security tests pass on your machine:
```bash
python -m pytest tests/ -v
```

### 5. Launch the Streamlit Interactive Demo UI
```bash
streamlit run ui/app.py
```
Open your browser at `http://localhost:8501`:
* **Persona Selector:** Toggle between Priya Sharma (Intern, Noida), Arjun Mehta (Engineer, Pune), Pooja Iyer (HR, Bengaluru), Ananya Deshmukh (CEO), and Kabir Sen (DevSecOps, Gurgaon).
* **Security Posture:** Switch between **Hardened (AI-Vault Protected)** and **Vulnerable (Baseline Leak)**.
* **Database Explorer:** Browse live rows across all 9 enterprise tables.
* **Audit Ledger:** Inspect cryptographic SHA-256 event blocks and verify mathematical ledger integrity.

### 6. (Optional) Run the FastAPI REST Gateway
```bash
uvicorn gateway.api:app --host 127.0.0.1 --port 8000 --reload
```
Interactive OpenAPI documentation available at: `http://127.0.0.1:8000/docs`

---

## Enterprise Database & Humanized Indian Dataset

AI-Vault includes an embedded **9-table SQLite Relational Database** (`data/software_company.db`) with **SQLite FTS5 (BM25 ranked full-text search)**, fully humanized with realistic corporate identities, Indian Rupee compensation packages, employee age, office locations, and Indian mobile numbers:

| Table | Classification | Permitted Roles | Content Highlights |
| :--- | :--- | :--- | :--- |
| `company_policies` | PUBLIC | All Roles | PTO, 40-hr hybrid schedule, air-gap AI policies, ₹75,000 home office stipend |
| `public_employee_directory` | INTERNAL | All Roles | 10 Indian employee profiles with **age**, **location** (Bengaluru, Mumbai, Pune, Hyderabad, Noida), and contact numbers |
| `customer_support_tickets` | INTERNAL | All Roles | Real partner tickets (HDFC, Apollo, Tata, Reliance), webhook latency bugs |
| `engineering_projects` | RESTRICTED | Engineer, Exec, Admin | Microservice topologies, staging DB strings, AWS keys, UPI payment gateway |
| `security_incident_reports` | RESTRICTED | Engineer, Admin | CVE audit reports (`CVE-2025-39182`), lead responders (Kabir Sen, Vikram Patel) |
| `employee_payroll` | CONFIDENTIAL | HR, Exec, Admin | Base salaries in **INR** (₹55 Lakhs to ₹4.8 Lakhs), bonuses, PAN cards, direct deposits |
| `performance_reviews` | CONFIDENTIAL | HR, Exec, Admin | Manager ratings, flight risks, promotion readiness flags |
| `client_contracts_nda` | CONFIDENTIAL | Exec, Admin | Enterprise contracts in **₹ Crores** (₹3.40 Cr value, ₹10 Cr liquidated damages) |
| `cloud_infrastructure_keys` | TOP_SECRET | Admin Only | AWS master IAM roles, SSH bastion hosts, K8s cluster secrets |

---

## Project Roadmap

- [x] Document & Table-Level RBAC Pre-Filtering
- [x] OWASP LLM01 Prompt Injection & Jailbreak Heuristics
- [x] Pre-Inference & Post-Inference DLP Masking (OWASP LLM06)
- [x] Cryptographic SHA-256 Hash-Chained Audit Ledger
- [x] FastAPI REST Gateway with OpenAPI documentation
- [x] Interactive Streamlit Enterprise Dashboard
- [x] Canary Token Tripwire Leakage Detection
- [x] SQLite FTS5 (BM25) Full-Text Search Retrieval
- [x] Uncensored Local LLM Integration (`dolphin-uncensored:latest`)
- [ ] Human-in-the-Loop (HITL) Autonomous Action Gating
- [ ] Automated 100-Payload Adversarial Benchmark Matrix (`benchmarks/`)

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for full details.

# 🛠️ Curated Developer Resources & Dataset Guide for AI-Vault

This guide lists **100% free and open-source tools, datasets, libraries, and tutorials** to build every layer of **AI-Vault**.

---

## 1. 🧠 Local LLM Execution & Model Serving

| Resource | Documentation & Links | What to Use It For |
| :--- | :--- | :--- |
| **Ollama** | [Official Website](https://ollama.com/) • [GitHub Repo](https://github.com/ollama/ollama) • [API Docs](https://github.com/ollama/ollama/blob/main/docs/api.md) | Download and serve open-source models (`llama3.1:8b`, `mistral:7b`, `phi3:mini`) locally via REST API at `http://127.0.0.1:11434`. |
| **Llama 3.1 Model Card** | [Meta Llama 3 on HuggingFace](https://huggingface.co/meta-llama/Meta-Llama-3.1-8B-Instruct) | Understanding model context windows, prompt formatting, and system prompt tags. |
| **Ollama Python SDK** | [Ollama Python GitHub](https://github.com/ollama/ollama-python) | Official Python binding for calling Ollama natively in Python without raw HTTP requests. |

---

## 2. 🛡️ LLM Security & Guardrails

| Resource | Documentation & Links | What to Use It For |
| :--- | :--- | :--- |
| **OWASP Top 10 for LLMs** | [OWASP Official Site](https://owasp.org/www-project-top-10-for-large-language-model-applications/) • [GitHub](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications) | The gold-standard taxonomy for LLM vulnerabilities (LLM01 Prompt Injection, LLM02 Insecure Output, LLM06 Sensitive Data Disclosure). |
| **PortSwigger LLM Security Labs** | [Free PortSwigger Web Security Academy: LLM Attacks](https://portswigger.net/web-security/llm-attacks) | Interactive browser labs demonstrating prompt injection, jailbreaks, and insecure output handling. |
| **NeMo Guardrails (NVIDIA)** | [NeMo Guardrails Docs](https://github.com/NVIDIA/NeMo-Guardrails) | Reference architecture for building programmable guardrails and input/output rails. |
| **Llama Guard (Meta)** | [Llama Guard Documentation](https://llama.meta.com/docs/model-cards-and-prompt-formats/llama-guard-3-8b/) | State-of-the-art model-based safety classifier for inputs and outputs. |

---

## 3. 🔒 Data Loss Prevention (DLP) & PII Redaction

| Resource | Documentation & Links | What to Use It For |
| :--- | :--- | :--- |
| **Microsoft Presidio** | [Presidio Documentation](https://microsoft.github.io/presidio/) • [GitHub Repo](https://github.com/microsoft/presidio) | Open-source Python library by Microsoft for contextual PII detection and anonymization (SSNs, phone numbers, passport IDs, credit cards). |
| **Python `re` Module** | [Python Regular Expressions](https://docs.python.org/3/library/re.html) | High-speed heuristic regex masking for API keys, AWS tokens, JWTs, and email addresses. |
| **TruffleHog Regex Patterns** | [TruffleHog GitHub](https://github.com/trufflesecurity/trufflehog) | Reference collection of regex patterns for scanning 800+ secret types (OpenAI keys, GitHub tokens, AWS credentials). |

---

## 4. 📊 Free Datasets & Benchmark Attack Vectors

| Dataset | Source / Link | Purpose in AI-Vault |
| :--- | :--- | :--- |
| **SPML Prompt Injection Benchmark** | [HuggingFace - Deepset SPML Dataset](https://huggingface.co/datasets/deepset/prompt-injections) | 600+ real-world jailbreak payloads and prompt injections to benchmark your gateway firewall. |
| **Enron Email Dataset** | [Kaggle Enron Dataset](https://www.kaggle.com/datasets/wcukierski/enron-email-dataset) | Real enterprise email corpus containing employee names, emails, and sensitive communications for testing DLP filters. |
| **SEC EDGAR 10-K Filings** | [SEC Free Database](https://www.sec.gov/edgar/searchedgar/companysearch) | Realistic corporate balance sheets and public vs. private financial statements for RBAC testing. |
| **Synthetic Corporate Documents** | Auto-generated in Python | 3 mock files: `public_handbook.txt`, `engineering_specs.txt`, `payroll_q3.txt`. |

---

## 5. 🌐 Web & API Frameworks

| Framework | Documentation & Links | What to Use It For |
| :--- | :--- | :--- |
| **FastAPI** | [FastAPI Official Docs](https://fastapi.tiangolo.com/) • [Tutorial](https://fastapi.tiangolo.com/tutorial/) | High-performance async Python backend with automatic OpenAPI / Swagger interactive documentation at `/docs`. |
| **Streamlit** | [Streamlit Official Docs](https://docs.streamlit.io/) • [Gallery](https://streamlit.io/gallery) | Pure-Python interactive UI for creating the Role-Switching demo dashboard in < 100 lines of code. |
| **Pydantic** | [Pydantic V2 Docs](https://docs.pydantic.dev/latest/) | Strict type checking and request validation for incoming API payloads. |

---

## 6. ⛓️ Cryptographic Audit Trails & SIEM

| Topic | Documentation & Links | What to Use It For |
| :--- | :--- | :--- |
| **SHA-256 Hash Chaining** | [Python `hashlib`](https://docs.python.org/3/library/hashlib.html) | Chaining block hashes `hash_n = sha256(event_n + hash_n-1)` to provide tamper-evident mathematical proof. |
| **JSON Lines (JSONL)** | [jsonlines.org](https://jsonlines.org/) | Standard industry format for high-throughput, append-only log files compatible with SIEM solutions (Splunk, Elastic). |

---

## 7. 🚀 Suggested Step-by-Step Implementation Flow

```
Step 1: Install Ollama & Pull Model (`ollama pull llama3`)
   ↓
Step 2: Build & test `gateway/dlp.py` (PII & Secret regex scanner)
   ↓
Step 3: Build & test `gateway/guardrails.py` (Prompt injection blocker)
   ↓
Step 4: Build & test `gateway/rbac.py` & `gateway/audit.py` (Access control & Hash chain)
   ↓
Step 5: Wrap with FastAPI (`gateway/api.py`)
   ↓
Step 6: Build Streamlit Demo UI (`ui/app.py`)
   ↓
Step 7: Run evaluation benchmarks against HuggingFace injection dataset (`benchmarks/test_jailbreak_suite.py`)
```

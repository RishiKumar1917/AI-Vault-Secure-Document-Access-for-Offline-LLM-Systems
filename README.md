# AI-Vault-Secure-Document-Access-for-Offline-LLM-Systems

Secure Document Access for Offline LLM Systems.

## Security gateway features

- **RBAC**: document-level authorization by user role.
- **Prompt-injection detection**: blocks known jailbreak/instruction-override patterns.
- **DLP redaction**: redacts sensitive data patterns (email, SSN, credit card, API-like keys) from prompts and model responses.
- **Secure audit logs**: every query is appended to an audit log with a hash chain (`previous_hash` + `hash`) for tamper-evident records.
- **Offline LLM execution**: only local Ollama endpoints (`127.0.0.1`, `localhost`, `::1`) are accepted.

## Quick usage

```python
from ai_vault_security_gateway import SecurityGateway, User

gateway = SecurityGateway(
    documents={"finance": "confidential numbers"},
    role_permissions={"admin": ["finance"], "analyst": []},
    audit_log_path="audit/audit.log",
)

result = gateway.process_query(User("alice", "admin"), "finance", "Summarize this")
print(result)
```

## Run tests

```bash
python -m unittest discover -s . -p "tests_test_*.py"
```

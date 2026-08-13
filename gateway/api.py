"""FastAPI REST API Layer for AI-Vault Security Gateway."""

from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, status
from pydantic import BaseModel, Field

from gateway.audit import AuditLogger
from gateway.core import SecurityGateway
from gateway.rbac import User

app = FastAPI(
    title="AI-Vault Security Gateway API",
    description="Zero-Trust Local AI Gateway with Role-Based Access Control, DLP, and Cryptographic Auditing.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Load sample documents from data directory
DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "sample_documents"
DOCUMENTS: Dict[str, str] = {}
if DATA_DIR.exists():
    for file_path in DATA_DIR.glob("*.txt"):
        doc_id = file_path.stem.lower()
        DOCUMENTS[doc_id] = file_path.read_text(encoding="utf-8")
else:
    DOCUMENTS = {
        "public_handbook": "AI-Vault Public Employee Handbook & Office Guidelines.",
        "engineering_specs": "Confidential Engineering Architecture & Infrastructure configs.",
        "payroll_q3": "Confidential Q3 Executive Payroll & Compensation Report.",
    }

ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "intern": ["public_handbook"],
    "engineer": ["public_handbook", "engineering_specs"],
    "hr": ["public_handbook", "payroll_q3"],
    "executive": ["public_handbook", "payroll_q3", "engineering_specs"],
    "admin": ["public_handbook", "payroll_q3", "engineering_specs"],
}

# Initialize shared SecurityGateway instance
AUDIT_LOG_FILE = "logs/audit.log"
gateway = SecurityGateway(
    documents=DOCUMENTS,
    role_permissions=ROLE_PERMISSIONS,
    audit_log_path=AUDIT_LOG_FILE,
)


# --- Pydantic Data Schemas ---

class QueryRequest(BaseModel):
    username: str = Field(..., description="Unique identifier of the user", example="alice")
    role: str = Field(..., description="Role assigned to user (intern, engineer, hr, executive, admin)", example="hr")
    document_id: str = Field(..., description="Target document ID to query", example="payroll_q3")
    prompt: str = Field(..., description="User query or instruction", example="What are the executive salaries?")


class QueryResponse(BaseModel):
    status: str = Field(..., description="Outcome status: 'ok' or 'blocked'")
    reason: str = Field(..., description="Reason code (e.g. 'ok', 'rbac_denied', 'prompt_injection')")
    response: Optional[str] = Field(None, description="Sanitized LLM response if allowed")
    message: Optional[str] = Field(None, description="Security alert message if blocked")


class DocumentItem(BaseModel):
    id: str
    title: str
    is_accessible: bool


class AuditVerifyResponse(BaseModel):
    is_valid: bool
    records_verified: int
    message: str


# --- API Endpoints ---

@app.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """Health check endpoint confirming gateway status and offline loopback enforcement."""
    return {
        "status": "healthy",
        "offline_enforced": True,
        "model": gateway.model,
        "ollama_endpoint": gateway.ollama_url,
        "documents_loaded": len(DOCUMENTS),
    }


@app.get("/v1/documents", response_model=List[DocumentItem], tags=["Documents"])
def list_documents(role: Optional[str] = Query(None, description="Filter accessible documents by role")) -> List[DocumentItem]:
    """List all available documents in the vault, indicating role accessibility."""
    results = []
    user_role = (role or "").lower()
    for doc_id in sorted(DOCUMENTS.keys()):
        title = doc_id.replace("_", " ").title()
        is_accessible = gateway.rbac.can_access(user_role, doc_id) if user_role else True
        results.append(DocumentItem(id=doc_id, title=title, is_accessible=is_accessible))
    return results


@app.post("/v1/query", response_model=QueryResponse, tags=["Security Gateway"])
def process_query(request: QueryRequest) -> QueryResponse:
    """
    Process a user query through the full Zero-Trust Security Pipeline:
    1. RBAC Document Authorization
    2. Prompt Injection Scanner (OWASP LLM01)
    3. Pre-Inference DLP Masking (OWASP LLM06)
    4. Offline LLM Execution with Canary Tripwire
    5. Output Sanitization (OWASP LLM02) & Cryptographic Audit Logging
    """
    user = User(username=request.username, role=request.role.lower())
    result = gateway.process_query(
        user=user,
        document_id=request.document_id,
        prompt=request.prompt
    )

    return QueryResponse(
        status=result["status"],
        reason=result["reason"],
        response=result.get("response"),
        message=result.get("message"),
    )


@app.get("/v1/audit/logs", tags=["Audit & Compliance"])
def get_audit_logs(limit: int = Query(50, ge=1, le=500)) -> List[Dict[str, Any]]:
    """Retrieve recent cryptographic audit log entries from the JSONL record."""
    log_path = Path(AUDIT_LOG_FILE)
    if not log_path.exists():
        return []

    entries = []
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries[-limit:]


@app.post("/v1/audit/verify", response_model=AuditVerifyResponse, tags=["Audit & Compliance"])
def verify_audit_integrity() -> AuditVerifyResponse:
    """Mathematically verify the SHA-256 hash chain across all recorded audit entries."""
    is_valid, count, message = AuditLogger.verify_integrity(AUDIT_LOG_FILE)
    return AuditVerifyResponse(
        is_valid=is_valid,
        records_verified=count,
        message=message,
    )

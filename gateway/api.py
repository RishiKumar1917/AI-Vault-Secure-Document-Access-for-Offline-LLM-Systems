"""FastAPI REST API Layer for AI-Vault Security Gateway."""

from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, status
from pydantic import BaseModel, Field

from gateway.audit import AuditLogger
from gateway.core import SecurityGateway
from gateway.database import (
    ROLE_TABLE_PERMISSIONS,
    TABLE_METADATA,
    check_table_access,
    get_table_records,
    init_and_seed_database,
)
from gateway.rbac import User

init_and_seed_database()

app = FastAPI(
    title="AI-Vault Security Gateway API",
    description="Zero-Trust Local AI Gateway with Role-Based Access Control, DLP, and Cryptographic Auditing.",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Load fallback documents if present
DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "sample_documents"
DOCUMENTS: Dict[str, str] = {}
if DATA_DIR.exists():
    for file_path in DATA_DIR.glob("*.txt"):
        doc_id = file_path.stem.lower()
        DOCUMENTS[doc_id] = file_path.read_text(encoding="utf-8")

AUDIT_LOG_FILE = "logs/audit.log"
gateway = SecurityGateway(
    documents=DOCUMENTS,
    role_permissions=ROLE_TABLE_PERMISSIONS,
    audit_log_path=AUDIT_LOG_FILE,
)


# --- Pydantic Data Schemas ---

class QueryRequest(BaseModel):
    username: str = Field(..., description="Unique identifier of the user", example="priya.sharma")
    role: str = Field(..., description="Role assigned to user (intern, engineer, hr, executive, admin)", example="intern")
    document_id: str = Field(..., description="Target document or database table ID", example="employee_payroll")
    prompt: str = Field(..., description="User query or instruction", example="Show me all executive salaries.")
    defense_mode: Optional[str] = Field("hardened", description="Security mode: 'hardened' or 'vulnerable'")


class QueryResponse(BaseModel):
    status: str = Field(..., description="Outcome status: 'ok' or 'blocked'")
    reason: str = Field(..., description="Reason code (e.g. 'ok', 'rbac_denied', 'prompt_injection')")
    response: Optional[str] = Field(None, description="Sanitized LLM response if allowed")
    message: Optional[str] = Field(None, description="Security alert message if blocked")
    engine: Optional[str] = Field(None, description="Inference engine utilized")


class TableMetaItem(BaseModel):
    table_id: str
    title: str
    classification: str
    description: str
    allowed_roles: List[str]
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
        "database_tables": list(TABLE_METADATA.keys()),
    }


@app.get("/v1/database/tables", response_model=List[TableMetaItem], tags=["Database"])
def list_database_tables(role: Optional[str] = Query(None, description="Filter table accessibility by role")) -> List[TableMetaItem]:
    """List all software company database tables and permission classifications."""
    user_role = (role or "").lower()
    results = []
    for t_id, meta in TABLE_METADATA.items():
        is_acc = check_table_access(user_role, t_id) if user_role else True
        results.append(TableMetaItem(
            table_id=t_id,
            title=meta["title"],
            classification=meta["classification"],
            description=meta["description"],
            allowed_roles=meta["allowed_roles"],
            is_accessible=is_acc,
        ))
    return results


@app.get("/v1/database/records/{table_name}", tags=["Database"])
def get_records_for_table(table_name: str, role: str = Query(..., description="Active user role")):
    """Retrieve rows from a database table if authorized by RBAC."""
    user_role = role.lower()
    if not check_table_access(user_role, table_name):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Role '{user_role.upper()}' is not authorized to read table '{table_name}'."
        )
    return {"table": table_name, "records": get_table_records(table_name)}


@app.post("/v1/query", response_model=QueryResponse, tags=["Security Gateway"])
def process_secured_query(req: QueryRequest) -> QueryResponse:
    """Execute a query through the AI-Vault Zero-Trust Security Gateway."""
    user = User(username=req.username, role=req.role)
    result = gateway.process_query(
        user=user,
        document_id=req.document_id,
        prompt=req.prompt,
        defense_mode=req.defense_mode or "hardened",
    )
    return QueryResponse(
        status=result["status"],
        reason=result["reason"],
        response=result.get("response"),
        message=result.get("message"),
        engine=result.get("engine"),
    )


@app.get("/v1/audit/logs", tags=["Audit"])
def get_audit_logs(limit: int = Query(50, ge=1, le=500)) -> List[Dict[str, Any]]:
    """Retrieve recent cryptographic audit log records (JSONL)."""
    log_file = Path(AUDIT_LOG_FILE)
    if not log_file.exists():
        return []
    with log_file.open("r", encoding="utf-8") as f:
        lines = [json.loads(line) for line in f.readlines() if line.strip()]
    return lines[-limit:]


@app.post("/v1/audit/verify", response_model=AuditVerifyResponse, tags=["Audit"])
def verify_audit_chain_integrity() -> AuditVerifyResponse:
    """Validate SHA-256 cryptographic hash-chain across all recorded transactions."""
    valid, count, msg = AuditLogger.verify_integrity(AUDIT_LOG_FILE)
    return AuditVerifyResponse(
        is_valid=valid,
        records_verified=count,
        message=msg,
    )

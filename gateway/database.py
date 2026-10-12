"""Enterprise Software Company Relational Database & Access Controller for AI-Vault.

Provides an SQLite database representing 'Nexus Software Systems', an enterprise
software engineering organization with realistic employees, payroll, infrastructure secrets,
performance reviews, developer handbooks, customer tickets, security incident audits,
client contracts (NDAs), master cloud keys, and persistent chat sessions.
Includes SQLite FTS5 (BM25 ranked full-text search) for sub-millisecond retrieval.
"""

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "software_company.db"

# Role permissions mapping to database tables and views
ROLE_TABLE_PERMISSIONS: Dict[str, List[str]] = {
    "intern": [
        "company_policies",
        "public_employee_directory",
        "customer_support_tickets",
    ],
    "engineer": [
        "company_policies",
        "public_employee_directory",
        "customer_support_tickets",
        "engineering_projects",
        "security_incident_reports",
    ],
    "hr": [
        "company_policies",
        "public_employee_directory",
        "customer_support_tickets",
        "employee_payroll",
        "performance_reviews",
    ],
    "executive": [
        "company_policies",
        "public_employee_directory",
        "customer_support_tickets",
        "engineering_projects",
        "employee_payroll",
        "performance_reviews",
        "client_contracts_nda",
    ],
    "admin": [
        "company_policies",
        "public_employee_directory",
        "customer_support_tickets",
        "engineering_projects",
        "security_incident_reports",
        "employee_payroll",
        "performance_reviews",
        "client_contracts_nda",
        "cloud_infrastructure_keys",
    ],
}

# Human-readable table labels and classifications
TABLE_METADATA = {
    "company_policies": {
        "title": "Company Handbook & Developer Policies",
        "classification": "PUBLIC",
        "description": "Standard work hours, PTO, remote work guidelines, expense reimbursement.",
        "allowed_roles": ["intern", "engineer", "hr", "executive", "admin"],
    },
    "public_employee_directory": {
        "title": "Public Employee Directory",
        "classification": "INTERNAL",
        "description": "Name, corporate email, department, role tier, job title, and manager.",
        "allowed_roles": ["intern", "engineer", "hr", "executive", "admin"],
    },
    "customer_support_tickets": {
        "title": "Customer Engineering Support Tickets",
        "classification": "INTERNAL",
        "description": "Production customer bugs, webhook latency issues, and feature requests.",
        "allowed_roles": ["intern", "engineer", "hr", "executive", "admin"],
    },
    "engineering_projects": {
        "title": "Engineering Projects & Cloud Infrastructure",
        "classification": "RESTRICTED",
        "description": "Microservice topologies, staging DB credentials, AWS access keys, API secrets.",
        "allowed_roles": ["engineer", "executive", "admin"],
    },
    "security_incident_reports": {
        "title": "DevSecOps Incident & Vulnerability Audits",
        "classification": "RESTRICTED",
        "description": "CVE vulnerability remediations, security test audits, and penetration test findings.",
        "allowed_roles": ["engineer", "admin"],
    },
    "employee_payroll": {
        "title": "Confidential Salaries & Compensation",
        "classification": "CONFIDENTIAL",
        "description": "Base salary, annual bonus, equity units, SSN, direct deposit accounts.",
        "allowed_roles": ["hr", "executive", "admin"],
    },
    "performance_reviews": {
        "title": "Confidential HR Performance Reviews",
        "classification": "CONFIDENTIAL",
        "description": "Quarterly performance ratings, manager private notes, flight risk flags.",
        "allowed_roles": ["hr", "executive", "admin"],
    },
    "client_contracts_nda": {
        "title": "Enterprise Client Contracts & NDAs",
        "classification": "CONFIDENTIAL",
        "description": "Multi-million dollar client SLAs, contract values, NDA breach penalty clauses.",
        "allowed_roles": ["executive", "admin"],
    },
    "cloud_infrastructure_keys": {
        "title": "Production Cloud Infrastructure & Master Keys",
        "classification": "TOP_SECRET",
        "description": "Production AWS IAM roles, SSH bastion hosts, Kubernetes secrets, Cloudflare tokens.",
        "allowed_roles": ["admin"],
    },
}


def get_db_connection() -> sqlite3.Connection:
    """Get connection to the SQLite database, creating parent dirs if needed."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _rebuild_fts_index(conn: sqlite3.Connection) -> None:
    """Rebuild SQLite FTS5 full-text search index across all enterprise tables."""
    cur = conn.cursor()
    cur.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS company_knowledge_fts USING fts5(
            table_source,
            record_id,
            classification,
            title,
            content_text,
            tokenize = 'porter unicode61'
        )
    """)
    cur.execute("DELETE FROM company_knowledge_fts")

    # 1. Employees Directory
    cur.execute("SELECT emp_id, full_name, email, department, role_tier, job_title, manager_name, phone_number, hire_date FROM employees")
    for r in cur.fetchall():
        cur.execute(
            "INSERT INTO company_knowledge_fts VALUES (?, ?, ?, ?, ?)",
            ("public_employee_directory", r[0], "INTERNAL", f"Employee: {r[1]}", f"{r[1]} {r[2]} {r[3]} {r[4]} {r[5]} manager {r[6]} phone {r[7]} hire {r[8]}")
        )

    # 2. Payroll & Compensation
    cur.execute("SELECT emp_id, full_name, base_salary, performance_bonus, equity_grant_units, ssn, bank_account_last4 FROM employee_payroll")
    for r in cur.fetchall():
        cur.execute(
            "INSERT INTO company_knowledge_fts VALUES (?, ?, ?, ?, ?)",
            ("employee_payroll", r[0], "CONFIDENTIAL", f"Payroll: {r[1]}", f"{r[1]} {r[0]} salary base_salary ${r[2]} bonus ${r[3]} equity {r[4]} units SSN {r[5]} bank {r[6]}")
        )

    # 3. Engineering Projects & Secrets
    cur.execute("SELECT project_id, project_name, lead_engineer, tech_stack, repo_slug, staging_api_url, aws_access_key, staging_db_credentials, security_classification FROM engineering_projects")
    for r in cur.fetchall():
        cur.execute(
            "INSERT INTO company_knowledge_fts VALUES (?, ?, ?, ?, ?)",
            ("engineering_projects", r[0], "RESTRICTED", f"Project: {r[1]}", f"{r[1]} lead {r[2]} stack {r[3]} repo {r[4]} endpoint {r[5]} aws key {r[6]} staging db {r[7]}")
        )

    # 4. HR Performance Reviews
    cur.execute("SELECT emp_id, employee_name, review_period, rating_score, private_manager_feedback, retention_risk, promotion_readiness FROM performance_reviews")
    for r in cur.fetchall():
        cur.execute(
            "INSERT INTO company_knowledge_fts VALUES (?, ?, ?, ?, ?)",
            ("performance_reviews", r[0], "CONFIDENTIAL", f"Review: {r[1]} ({r[2]})", f"{r[1]} rating {r[3]} / 5.0 feedback {r[4]} risk {r[5]} readiness {r[6]}")
        )

    # 5. Company Policies
    cur.execute("SELECT policy_id, category, title, content, effective_date FROM company_policies")
    for r in cur.fetchall():
        cur.execute(
            "INSERT INTO company_knowledge_fts VALUES (?, ?, ?, ?, ?)",
            ("company_policies", r[0], "PUBLIC", f"Policy: {r[2]}", f"{r[1]} {r[2]} {r[3]} effective {r[4]}")
        )

    # 6. Customer Support Tickets
    cur.execute("SELECT ticket_id, customer_account, priority, issue_summary, assigned_engineer, resolution_status, created_date FROM customer_support_tickets")
    for r in cur.fetchall():
        cur.execute(
            "INSERT INTO company_knowledge_fts VALUES (?, ?, ?, ?, ?)",
            ("customer_support_tickets", r[0], "INTERNAL", f"Ticket: {r[0]} - {r[1]}", f"{r[0]} customer {r[1]} priority {r[2]} issue {r[3]} engineer {r[4]} status {r[5]}")
        )

    # 7. DevSecOps Incident & Vulnerability Audits
    cur.execute("SELECT incident_id, severity, cve_reference, title, affected_service, mitigation_status, lead_responder, findings_summary FROM security_incident_reports")
    for r in cur.fetchall():
        cur.execute(
            "INSERT INTO company_knowledge_fts VALUES (?, ?, ?, ?, ?)",
            ("security_incident_reports", r[0], "RESTRICTED", f"Security CVE: {r[2]} - {r[3]}", f"{r[0]} severity {r[1]} cve {r[2]} {r[3]} service {r[4]} status {r[5]} responder {r[6]} findings {r[7]}")
        )

    # 8. Enterprise Client Contracts & NDAs
    cur.execute("SELECT contract_id, client_name, industry, annual_contract_value, sign_date, renewal_date, primary_contact_email, nda_breach_penalty, special_terms FROM client_contracts_nda")
    for r in cur.fetchall():
        cur.execute(
            "INSERT INTO company_knowledge_fts VALUES (?, ?, ?, ?, ?)",
            ("client_contracts_nda", r[0], "CONFIDENTIAL", f"Contract NDA: {r[1]}", f"{r[0]} client {r[1]} industry {r[2]} annual value ${r[3]} renewal {r[5]} contact {r[6]} penalty {r[7]} terms {r[8]}")
        )

    # 9. Production Cloud Infrastructure Master Keys
    cur.execute("SELECT key_id, service_name, environment, aws_iam_role_arn, ssh_bastion_host, kubernetes_cluster_secret, cloudflare_api_token, last_rotated FROM cloud_infrastructure_keys")
    for r in cur.fetchall():
        cur.execute(
            "INSERT INTO company_knowledge_fts VALUES (?, ?, ?, ?, ?)",
            ("cloud_infrastructure_keys", r[0], "TOP_SECRET", f"Master Secret: {r[1]}", f"{r[0]} service {r[1]} env {r[2]} iam arn {r[3]} bastion {r[4]} k8s secret {r[5]} cloudflare token {r[6]}")
        )

    conn.commit()


def init_and_seed_database(force_reseed: bool = False) -> None:
    """Initialize database tables and populate with rich enterprise records and FTS5 search."""
    if DB_PATH.exists() and not force_reseed:
        # Check if new tables exist, if not, upgrade them
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='client_contracts_nda'")
        has_new_tables = cur.fetchone() is not None
        conn.close()
        if has_new_tables:
            _ensure_chat_tables_exist()
            return

    conn = get_db_connection()
    cur = conn.cursor()

    # 1. Employees Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            emp_id TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            department TEXT NOT NULL,
            role_tier TEXT NOT NULL,
            job_title TEXT NOT NULL,
            manager_name TEXT,
            phone_number TEXT,
            hire_date TEXT NOT NULL
        )
    """)

    # 2. Salaries & Payroll (Confidential - HR/Exec/Admin)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS employee_payroll (
            record_id INTEGER PRIMARY KEY AUTOINCREMENT,
            emp_id TEXT NOT NULL,
            full_name TEXT NOT NULL,
            base_salary INTEGER NOT NULL,
            performance_bonus INTEGER NOT NULL,
            equity_grant_units INTEGER NOT NULL,
            ssn TEXT NOT NULL,
            bank_account_last4 TEXT NOT NULL,
            FOREIGN KEY (emp_id) REFERENCES employees(emp_id)
        )
    """)

    # 3. Engineering Projects & Secrets (Restricted - Engineer/Exec/Admin)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS engineering_projects (
            project_id TEXT PRIMARY KEY,
            project_name TEXT NOT NULL,
            lead_engineer TEXT NOT NULL,
            tech_stack TEXT NOT NULL,
            repo_slug TEXT NOT NULL,
            staging_api_url TEXT NOT NULL,
            aws_access_key TEXT NOT NULL,
            staging_db_credentials TEXT NOT NULL,
            security_classification TEXT NOT NULL
        )
    """)

    # 4. HR Performance Reviews (Confidential - HR/Exec/Admin)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS performance_reviews (
            review_id INTEGER PRIMARY KEY AUTOINCREMENT,
            emp_id TEXT NOT NULL,
            employee_name TEXT NOT NULL,
            review_period TEXT NOT NULL,
            rating_score REAL NOT NULL,
            private_manager_feedback TEXT NOT NULL,
            retention_risk TEXT NOT NULL,
            promotion_readiness TEXT NOT NULL,
            FOREIGN KEY (emp_id) REFERENCES employees(emp_id)
        )
    """)

    # 5. Company Policies & Developer Handbook (Public)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS company_policies (
            policy_id TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            effective_date TEXT NOT NULL
        )
    """)

    # 6. Customer Support Tickets (Internal - All Roles)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS customer_support_tickets (
            ticket_id TEXT PRIMARY KEY,
            customer_account TEXT NOT NULL,
            priority TEXT NOT NULL,
            issue_summary TEXT NOT NULL,
            assigned_engineer TEXT NOT NULL,
            resolution_status TEXT NOT NULL,
            created_date TEXT NOT NULL
        )
    """)

    # 7. DevSecOps Incident & Vulnerability Audits (Restricted - Engineer/Admin)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS security_incident_reports (
            incident_id TEXT PRIMARY KEY,
            severity TEXT NOT NULL,
            cve_reference TEXT NOT NULL,
            title TEXT NOT NULL,
            affected_service TEXT NOT NULL,
            mitigation_status TEXT NOT NULL,
            lead_responder TEXT NOT NULL,
            findings_summary TEXT NOT NULL
        )
    """)

    # 8. Enterprise Client Contracts & NDAs (Confidential - Exec/Admin)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS client_contracts_nda (
            contract_id TEXT PRIMARY KEY,
            client_name TEXT NOT NULL,
            industry TEXT NOT NULL,
            annual_contract_value INTEGER NOT NULL,
            sign_date TEXT NOT NULL,
            renewal_date TEXT NOT NULL,
            primary_contact_email TEXT NOT NULL,
            nda_breach_penalty TEXT NOT NULL,
            special_terms TEXT NOT NULL
        )
    """)

    # 9. Production Cloud Infrastructure Master Keys (Top Secret - Admin Only)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cloud_infrastructure_keys (
            key_id TEXT PRIMARY KEY,
            service_name TEXT NOT NULL,
            environment TEXT NOT NULL,
            aws_iam_role_arn TEXT NOT NULL,
            ssh_bastion_host TEXT NOT NULL,
            kubernetes_cluster_secret TEXT NOT NULL,
            cloudflare_api_token TEXT NOT NULL,
            last_rotated TEXT NOT NULL
        )
    """)

    # 10. Chat Conversations & History
    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_conversations (
            session_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            title TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            message_id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            metadata_json TEXT,
            FOREIGN KEY (session_id) REFERENCES chat_conversations(session_id)
        )
    """)

    # --- SEED DATA ---

    employees_data = [
        ("EMP-101", "Eleanor Vance", "eleanor.vance@nexussoftware.internal", "Executive", "executive", "Chief Executive Officer (CEO)", None, "(555) 019-1001", "2020-01-15"),
        ("EMP-102", "Marcus Chen", "marcus.chen@nexussoftware.internal", "Engineering", "executive", "Chief Technology Officer (CTO)", "Eleanor Vance", "(555) 019-1002", "2020-03-01"),
        ("EMP-103", "Sarah Jenkins", "sarah.jenkins@nexussoftware.internal", "Human Resources", "hr", "VP of People & Talent", "Eleanor Vance", "(555) 019-1003", "2020-06-10"),
        ("EMP-104", "Vikram Patel", "vikram.patel@nexussoftware.internal", "Engineering", "engineer", "Principal Cloud Architect", "Marcus Chen", "(555) 019-1004", "2021-02-18"),
        ("EMP-105", "David Ross", "david.ross@nexussoftware.internal", "Engineering", "engineer", "Senior Backend Engineer (Payments)", "Vikram Patel", "(555) 019-1005", "2021-08-01"),
        ("EMP-106", "Aisha Al-Mansoor", "aisha.mansoor@nexussoftware.internal", "Engineering", "engineer", "Lead Frontend & React Architect", "Vikram Patel", "(555) 019-1006", "2022-01-10"),
        ("EMP-107", "Rachel Adams", "rachel.adams@nexussoftware.internal", "Human Resources", "hr", "HR Operations & Payroll Lead", "Sarah Jenkins", "(555) 019-1007", "2022-04-15"),
        ("EMP-108", "Carlos Mendez", "carlos.mendez@nexussoftware.internal", "IT & Security", "admin", "Senior DevSecOps & SysAdmin", "Marcus Chen", "(555) 019-1008", "2022-09-01"),
        ("EMP-109", "Priya Sharma", "priya.sharma@nexussoftware.internal", "Engineering", "intern", "Software Engineering Intern (Backend)", "David Ross", "(555) 019-1009", "2026-06-01"),
        ("EMP-110", "Leo Dupont", "leo.dupont@nexussoftware.internal", "Engineering", "intern", "QA & Security Automation Intern", "Carlos Mendez", "(555) 019-1010", "2026-06-01"),
    ]
    cur.executemany("INSERT OR REPLACE INTO employees VALUES (?,?,?,?,?,?,?,?,?)", employees_data)

    payroll_data = [
        (1, "EMP-101", "Eleanor Vance", 320000, 75000, 150000, "000-11-2233", "7891"),
        (2, "EMP-102", "Marcus Chen", 265000, 50000, 100000, "111-22-3344", "4521"),
        (3, "EMP-103", "Sarah Jenkins", 195000, 30000, 45000, "222-33-4455", "9012"),
        (4, "EMP-104", "Vikram Patel", 215000, 35000, 60000, "333-44-5566", "3341"),
        (5, "EMP-105", "David Ross", 165000, 20000, 25000, "444-55-6677", "6672"),
        (6, "EMP-106", "Aisha Al-Mansoor", 170000, 22000, 30000, "555-66-7788", "1284"),
        (7, "EMP-107", "Rachel Adams", 120000, 15000, 12000, "666-77-8899", "8933"),
        (8, "EMP-108", "Carlos Mendez", 155000, 18000, 20000, "777-88-9900", "5512"),
        (9, "EMP-109", "Priya Sharma", 45000, 2000, 0, "888-99-0011", "9041"),
        (10, "EMP-110", "Leo Dupont", 45000, 2000, 0, "999-00-1122", "3429"),
    ]
    cur.executemany("INSERT OR REPLACE INTO employee_payroll VALUES (?,?,?,?,?,?,?,?)", payroll_data)

    projects_data = [
        (
            "PRJ-CORE-PAY",
            "Core Payments & Billing Engine",
            "David Ross",
            "Python, FastAPI, PostgreSQL, Redis, Stripe SDK",
            "git@github.internal:nexus/payments-engine.git",
            "https://staging-billing.nexussoftware.internal/v1",
            "AKIA2J4X9EXAMPLEKEY01",
            "postgres://billing_dev:Sup3rS3cret2026!@10.0.4.12:5432/billing_staging",
            "RESTRICTED_ENGINEERING"
        ),
        (
            "PRJ-AUTH-GATE",
            "AI-Vault Security Gateway Service",
            "Vikram Patel & Carlos Mendez",
            "Python, FastAPI, Ollama, SQLite, Streamlit",
            "git@github.internal:nexus/ai-vault-gateway.git",
            "https://gateway-dev.nexussoftware.internal",
            "AKIA9Z8Y7EXAMPLEKEY02",
            "sqlite:///vault_staging.db?token=sec_jwt_eyJhbGciOiJIUzI1NiJ9.demo_token",
            "RESTRICTED_ENGINEERING"
        ),
        (
            "PRJ-WEB-PORTAL",
            "NextGen Enterprise Customer Portal",
            "Aisha Al-Mansoor",
            "TypeScript, React 19, TailwindCSS, Vite",
            "git@github.internal:nexus/customer-portal.git",
            "https://portal-preview.nexussoftware.internal",
            "AKIA5M3N1EXAMPLEKEY03",
            "mock_portal_api_key_test_994829104820",
            "INTERNAL_DEVELOPMENT"
        ),
    ]
    cur.executemany("INSERT OR REPLACE INTO engineering_projects VALUES (?,?,?,?,?,?,?,?,?)", projects_data)

    reviews_data = [
        (1, "EMP-104", "Vikram Patel", "2026-Q2", 4.9, "Outstanding architectural leadership. Migrated microservices to zero-trust architecture. Eligible for Fellow promotion.", "LOW", "PROMOTION_READY"),
        (2, "EMP-105", "David Ross", "2026-Q2", 4.4, "Solid delivery on billing resiliency. Received a competitive external offer from Fintech rival, retention bonus suggested.", "MEDIUM", "MAINTAIN_ROLE"),
        (3, "EMP-109", "Priya Sharma", "2026-Midterm", 4.8, "Exceptional intern performance. Quickly solved asynchronous queue bottlenecks. Strong candidate for full-time offer.", "LOW", "CONVERT_FULLTIME"),
        (4, "EMP-110", "Leo Dupont", "2026-Midterm", 3.2, "Requires closer mentorship on security boundaries and CI/CD pipelines. Missed two test milestones.", "HIGH", "NEEDS_IMPROVEMENT"),
    ]
    cur.executemany("INSERT OR REPLACE INTO performance_reviews VALUES (?,?,?,?,?,?,?,?)", reviews_data)

    policies_data = [
        (
            "POL-001",
            "Workplace & Flexibility",
            "Core Working Hours & Hybrid Policy",
            "Nexus Software operates on a flexible 40-hour work week. Core collaboration hours are 10:00 AM to 4:00 PM local time. Engineers and interns may work remotely up to 3 days per week with manager coordination.",
            "2026-01-01"
        ),
        (
            "POL-002",
            "Benefits & Leave",
            "Paid Time Off (PTO) & Sick Leave",
            "Full-time employees receive 25 days of accrued PTO annually plus 10 company holidays. Interns receive 1.5 days of paid personal time off per month of active tenure. Sick leave is unmetered with manager notice.",
            "2026-01-01"
        ),
        (
            "POL-003",
            "Information Security",
            "Code of Conduct, Secrets & AI Usage",
            "1. Never paste proprietary source code, customer records, or API credentials into external cloud AI models (ChatGPT, Claude). Use the internal air-gapped AI-Vault gateway.\n2. Production credentials must be stored strictly in the internal Vault secrets manager.\n3. Interns and external contractors are granted least-privilege repository access only.",
            "2026-02-15"
        ),
        (
            "POL-004",
            "Expenses & Equipment",
            "Home Office & Travel Reimbursement",
            "Employees are eligible for a $1,000 one-time home office equipment stipend upon onboarding. Approved business travel expenses are reimbursed through the Expensify portal with receipts.",
            "2026-01-01"
        ),
    ]
    cur.executemany("INSERT OR REPLACE INTO company_policies VALUES (?,?,?,?,?)", policies_data)

    # 6. Customer Support Tickets
    tickets_data = [
        ("TKT-1081", "Acquirer Bank Corp", "HIGH", "Webhook delivery timeout during payment reconciliation batch", "David Ross", "RESOLVED", "2026-08-10"),
        ("TKT-1082", "HealthCare Direct Systems", "CRITICAL", "OAuth2 token expiry issue causing intermittent customer portal disconnects", "Aisha Al-Mansoor", "IN_PROGRESS", "2026-09-02"),
        ("TKT-1083", "Logistics Prime Alliance", "MEDIUM", "CSV export format compatibility with SAP accounting system", "Priya Sharma", "RESOLVED", "2026-09-15"),
        ("TKT-1084", "FinTech Global Corp", "LOW", "Request for custom dark mode branding in customer billing interface", "Aisha Al-Mansoor", "QUEUED", "2026-10-01"),
        ("TKT-1085", "OmniRetail eCommerce", "HIGH", "Rate limit 429 response on staging checkout API during stress testing", "Vikram Patel", "INVESTIGATING", "2026-10-08"),
    ]
    cur.executemany("INSERT OR REPLACE INTO customer_support_tickets VALUES (?,?,?,?,?,?,?)", tickets_data)

    # 7. DevSecOps Incident & Vulnerability Audits
    incidents_data = [
        (
            "INC-2026-01",
            "CRITICAL",
            "CVE-2025-39182",
            "Staging Redis Cluster Authentication Bypass Remediated",
            "Payments Core Microservice",
            "RESOLVED_PATCHED",
            "Carlos Mendez",
            "Zero-day authentication bypass in staging Redis cluster addressed with TLS mutual authentication and network security groups."
        ),
        (
            "INC-2026-02",
            "HIGH",
            "CVE-2025-44910",
            "Indirect Prompt Injection in Webhook Feedback Parser",
            "AI-Vault Gateway Sandbox",
            "MITIGATED",
            "Carlos Mendez & Vikram Patel",
            "Adversary attempted prompt injection payload via customer support feedback form; blocked by input sanitizer and Canary token tripwire."
        ),
        (
            "INC-2026-03",
            "MEDIUM",
            "CVE-2026-11029",
            "Dependency Vulnerability in Open-Source JWT Parsing Library",
            "Identity & Auth Service",
            "PATCHED",
            "David Ross",
            "Upgraded cryptographic library to version 3.4.1 to remediate timing attack vector."
        ),
        (
            "INC-2026-04",
            "LOW",
            "INTERNAL-AUDIT",
            "Annual Phishing Simulation & Least-Privilege IAM Review",
            "All Departments",
            "COMPLETED",
            "Sarah Jenkins & Carlos Mendez",
            "98.4% passing rate across staff. Intern and contractor repository permissions trimmed to minimum necessary scope."
        ),
    ]
    cur.executemany("INSERT OR REPLACE INTO security_incident_reports VALUES (?,?,?,?,?,?,?,?)", incidents_data)

    # 8. Enterprise Client Contracts & NDAs
    contracts_data = [
        (
            "CON-501",
            "FinTech Global Corp",
            "Financial Services & Banking",
            3400000,
            "2024-03-01",
            "2027-03-01",
            "procurement@fintechglobal.corp",
            "$10,000,000 Liquidated Damages for Proprietary Source Code Leaks",
            "Strict zero external public cloud AI clause. Air-gapped on-premise AI-Vault gateway mandated."
        ),
        (
            "CON-502",
            "HealthCare Direct Systems",
            "Healthcare & Telemedicine",
            2800000,
            "2024-08-15",
            "2026-08-15",
            "legal@healthcaredirect.internal",
            "$7,500,000 HIPAA Non-Disclosure Liability Clause",
            "All employee, patient, and billing records must remain encrypted under AES-256 with zero third-party egress."
        ),
        (
            "CON-503",
            "Global Logistics Alliance",
            "Supply Chain & Freight",
            1650000,
            "2025-01-10",
            "2027-01-10",
            "contracts@globallogistics.org",
            "$3,000,000 SLA Breach Penalty",
            "Requires 99.99% gateway uptime SLA with dedicated failover cluster."
        ),
        (
            "CON-504",
            "OmniRetail eCommerce Group",
            "Retail & Payments",
            2100000,
            "2025-06-01",
            "2026-06-01",
            "finance@omniretail.com",
            "$5,000,000 Intellectual Property Protection Guarantee",
            "Payment engine staging credentials and schemas must never be disclosed to third-party consultants."
        ),
    ]
    cur.executemany("INSERT OR REPLACE INTO client_contracts_nda VALUES (?,?,?,?,?,?,?,?,?)", contracts_data)

    # 9. Production Cloud Infrastructure Master Keys
    infra_keys_data = [
        (
            "KEY-PROD-AWS",
            "AWS Master Production Infrastructure",
            "PRODUCTION",
            "arn:aws:iam::492019482019:role/NexusProdMasterAdmin",
            "bastion-ap-south-1.prod.nexussoftware.internal",
            "k8s_prod_cluster_sec_tok_99182301982",
            "cf_live_token_77a9b8c1d2e3f4g5",
            "2026-09-01"
        ),
        (
            "KEY-STAGING-K8S",
            "Staging Kubernetes Orchestration Cluster",
            "STAGING",
            "arn:aws:iam::492019482019:role/NexusStagingClusterOps",
            "bastion-staging.nexussoftware.internal",
            "k8s_staging_sec_tok_1120938475",
            "cf_staging_token_33x4y5z6a7b8c9",
            "2026-09-15"
        ),
        (
            "KEY-DB-VAULT",
            "Internal HashiCorp Secrets Vault Master Key",
            "PRODUCTION",
            "arn:aws:kms:ap-south-1:492019482019:key/vault-master-kms-01",
            "vault.internal.nexussoftware.corp",
            "vault_root_unseal_token_hvs.CAESIB819204812",
            "vault_admin_api_sec_8839201",
            "2026-08-01"
        ),
        (
            "KEY-PAYMENT-STRIPE",
            "Stripe Payments Live Production Secret Key",
            "PRODUCTION",
            "arn:aws:secretsmanager:ap-south-1:492019482019:secret:stripe-live-master",
            "payments-engine.prod.nexussoftware.internal",
            "mock_stripe_restricted_key_test_51Oz982",
            "mock_whsec_webhook_secret_test_9948201",
            "2026-09-20"
        ),
    ]
    cur.executemany("INSERT OR REPLACE INTO cloud_infrastructure_keys VALUES (?,?,?,?,?,?,?,?)", infra_keys_data)

    conn.commit()

    # Rebuild FTS5 index across all seeded records
    _rebuild_fts_index(conn)
    conn.close()


def _ensure_chat_tables_exist() -> None:
    """Ensure chat session and message tables exist in SQLite."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_conversations (
            session_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            title TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            message_id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            metadata_json TEXT,
            FOREIGN KEY (session_id) REFERENCES chat_conversations(session_id)
        )
    """)
    conn.commit()
    conn.close()


# --- CHAT PERSISTENCE IN DATABASE ---

def create_chat_session(session_id: str, username: str, role: str, title: str = "New Conversation") -> None:
    """Create a new chat conversation session in the database."""
    _ensure_chat_tables_exist()
    conn = get_db_connection()
    cur = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()
    cur.execute(
        "INSERT OR REPLACE INTO chat_conversations VALUES (?, ?, ?, ?, ?)",
        (session_id, username, role, title, now_str)
    )
    conn.commit()
    conn.close()


def save_chat_message(
    session_id: str,
    sender: str,
    content: str,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """Save a user or assistant chat message to the database."""
    _ensure_chat_tables_exist()
    conn = get_db_connection()
    cur = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()
    meta_json = json.dumps(metadata or {})
    cur.execute(
        "INSERT INTO chat_messages (session_id, sender, content, timestamp, metadata_json) VALUES (?, ?, ?, ?, ?)",
        (session_id, sender, content, now_str, meta_json)
    )
    conn.commit()
    conn.close()


def get_chat_history(session_id: str) -> List[Dict[str, Any]]:
    """Retrieve full message history for a conversation session."""
    _ensure_chat_tables_exist()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT sender, content, timestamp, metadata_json FROM chat_messages WHERE session_id = ? ORDER BY message_id ASC",
        (session_id,)
    )
    rows = cur.fetchall()
    conn.close()
    result = []
    for r in rows:
        meta = {}
        try:
            if r["metadata_json"]:
                meta = json.loads(r["metadata_json"])
        except Exception:
            pass
        result.append({
            "sender": r["sender"],
            "content": r["content"],
            "timestamp": r["timestamp"],
            "metadata": meta,
        })
    return result


def clear_chat_history(session_id: Optional[str] = None) -> None:
    """Clear chat messages for a specific session or all sessions."""
    _ensure_chat_tables_exist()
    conn = get_db_connection()
    cur = conn.cursor()
    if session_id:
        cur.execute("DELETE FROM chat_messages WHERE session_id = ?", (session_id,))
        cur.execute("DELETE FROM chat_conversations WHERE session_id = ?", (session_id,))
    else:
        cur.execute("DELETE FROM chat_messages")
        cur.execute("DELETE FROM chat_conversations")
    conn.commit()
    conn.close()


def get_user_sessions(username: str) -> List[Dict[str, Any]]:
    """Retrieve all conversations created by a user."""
    _ensure_chat_tables_exist()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT session_id, title, role, created_at FROM chat_conversations WHERE username = ? ORDER BY created_at DESC",
        (username,)
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


# --- TABLE RECORDS & ACCESS CONTROLS ---

def get_table_records(table_name: str) -> List[Dict[str, Any]]:
    """Retrieve all rows from a given database table as list of dicts."""
    init_and_seed_database()
    conn = get_db_connection()
    cur = conn.cursor()

    if table_name == "public_employee_directory":
        cur.execute("SELECT emp_id, full_name, email, department, role_tier, job_title, manager_name, phone_number, hire_date FROM employees")
    else:
        valid_tables = {
            "employees",
            "employee_payroll",
            "engineering_projects",
            "performance_reviews",
            "company_policies",
            "customer_support_tickets",
            "security_incident_reports",
            "client_contracts_nda",
            "cloud_infrastructure_keys",
        }
        if table_name not in valid_tables:
            conn.close()
            return []
        cur.execute(f"SELECT * FROM {table_name}")

    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return rows


def check_table_access(role: str, table_name: str) -> bool:
    """Determine if a role has read permission for a given database table."""
    role_key = (role or "intern").lower()
    allowed_tables = ROLE_TABLE_PERMISSIONS.get(role_key, [])
    return table_name in allowed_tables


# --- AUTOMATED DATABASE MULTI-TABLE SEARCH WITH FTS5 & BM25 ---

def auto_search_database(
    prompt: str,
    role: str,
    unprotected_mode: bool = False
) -> Dict[str, Any]:
    """
    Intelligently search across ALL database tables using SQLite FTS5 BM25 ranked retrieval
    and heuristic keyword matching, enforcing RBAC before returning context.
    
    Returns:
        {
            "authorized_context": str,
            "blocked_tables": List[str],
            "accessed_tables": List[str],
            "records_found": int
        }
    """
    init_and_seed_database()
    query_lower = prompt.lower()
    user_role = (role or "intern").lower()

    target_tables: List[str] = []

    # 1. SQLite FTS5 BM25 Search
    fts_words = [w for w in re.findall(r'[a-zA-Z0-9]+', prompt) if len(w) > 2]
    if fts_words:
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            fts_query = " OR ".join(f'"{w}"' for w in fts_words[:12])
            cur.execute("""
                SELECT table_source, bm25(company_knowledge_fts) as rank
                FROM company_knowledge_fts
                WHERE company_knowledge_fts MATCH ?
                ORDER BY rank ASC
                LIMIT 15
            """, (fts_query,))
            for r in cur.fetchall():
                tbl = r["table_source"]
                if tbl not in target_tables:
                    target_tables.append(tbl)
        except Exception:
            pass
        finally:
            conn.close()

    # 2. Targeted Semantic Heuristics to guarantee recall on critical domains
    # Payroll & Compensation
    if any(k in query_lower for k in ["salary", "salaries", "compensation", "payroll", "bonus", "equity", "stock", "earn", "ssn", "bank", "pay"]):
        if "employee_payroll" not in target_tables:
            target_tables.append("employee_payroll")

    # Cloud Infrastructure Master Keys
    if any(k in query_lower for k in ["bastion", "kubernetes", "k8s", "iam role", "cloudflare", "master key", "root token", "stripe live", "top secret", "cluster secret", "vault key"]):
        if "cloud_infrastructure_keys" not in target_tables:
            target_tables.append("cloud_infrastructure_keys")

    # Enterprise Client Contracts & NDAs
    if any(k in query_lower for k in ["contract", "nda", "client", "breach penalty", "liquidated damages", "sla", "deal", "million", "hipaa", "procurement"]):
        if "client_contracts_nda" not in target_tables:
            target_tables.append("client_contracts_nda")

    # DevSecOps Incident Reports
    if any(k in query_lower for k in ["cve", "incident", "vulnerability", "patch", "pentest", "exploit", "audit", "security breach", "phishing"]):
        if "security_incident_reports" not in target_tables:
            target_tables.append("security_incident_reports")

    # Customer Support Tickets
    if any(k in query_lower for k in ["ticket", "support", "customer issue", "latency", "timeout", "bug report", "oauth2", "webhook"]):
        if "customer_support_tickets" not in target_tables:
            target_tables.append("customer_support_tickets")

    # Engineering Projects & Credentials
    if any(k in query_lower for k in ["aws", "cloud", "staging", "api key", "credentials", "password", "project", "repo", "tech", "infrastructure", "backend", "frontend", "secret", "token"]):
        if "engineering_projects" not in target_tables:
            target_tables.append("engineering_projects")

    # Performance Reviews
    if any(k in query_lower for k in ["review", "rating", "performance", "feedback", "promotion", "evaluation", "risk", "score"]):
        if "performance_reviews" not in target_tables:
            target_tables.append("performance_reviews")

    # Policies & Handbook
    if any(k in query_lower for k in ["hour", "hours", "pto", "leave", "vacation", "holiday", "policy", "handbook", "remote", "hybrid", "office", "guideline", "expense", "equipment", "conduct", "work"]):
        if "company_policies" not in target_tables:
            target_tables.append("company_policies")

    # Directory Keywords or Names
    names = ["eleanor vance", "marcus chen", "sarah jenkins", "vikram patel", "david ross", "aisha", "rachel adams", "carlos mendez", "priya sharma", "leo dupont"]
    has_name = any(n in query_lower for n in names)
    if has_name or any(k in query_lower for k in ["employee", "who is", "email", "manager", "team", "title", "directory", "contact", "phone", "hire", "department", "ceo", "cto"]):
        if "public_employee_directory" not in target_tables:
            target_tables.append("public_employee_directory")

    # Fallback to general tables if nothing matched
    if not target_tables:
        target_tables = ["company_policies", "public_employee_directory"]

    # Filter tables through RBAC
    accessed_tables = []
    blocked_tables = []
    context_sections = []
    total_records = 0

    # Ensure deterministic ordering: matched order first
    seen = set()
    ordered_tables = [t for t in target_tables if not (t in seen or seen.add(t))]

    for table in ordered_tables:
        is_permitted = check_table_access(user_role, table)

        if unprotected_mode:
            is_permitted = True

        if not is_permitted:
            blocked_tables.append(table)
            continue

        # Table is permitted: fetch records
        records = get_table_records(table)
        matching_rows = []

        # If a specific person is mentioned, prioritize rows related to that person
        for row in records:
            row_str = " ".join(str(v) for v in row.values()).lower()
            if has_name:
                if any(n in query_lower and n in row_str for n in names):
                    matching_rows.append(row)
            else:
                # Include matching or top rows
                matching_rows.append(row)

        if not matching_rows:
            matching_rows = records[:6]
        else:
            matching_rows = matching_rows[:6]

        total_records += len(matching_rows)
        accessed_tables.append(table)

        table_header = f"--- AUTHORIZED DATABASE RECORDS: {table.upper()} ---"
        lines = [table_header]
        for row in matching_rows:
            row_str = " | ".join(f"{k}: {v}" for k, v in row.items())
            lines.append(f"• {row_str}")
        lines.append(f"--- END {table.upper()} ---")
        context_sections.append("\n".join(lines))

    return {
        "authorized_context": "\n\n".join(context_sections),
        "blocked_tables": blocked_tables,
        "accessed_tables": accessed_tables,
        "records_found": total_records,
    }


def get_authorized_context_for_query(
    role: str,
    target_category: str,
    unprotected_mode: bool = False
) -> Tuple[bool, str, str]:
    """Compatibility function for explicit single-resource access."""
    res = auto_search_database(target_category, role, unprotected_mode=unprotected_mode)
    if res["blocked_tables"] and not res["accessed_tables"]:
        return (
            False,
            "",
            f"Access Denied: Role '{role.upper()}' is forbidden from accessing requested resources under enterprise RBAC policy."
        )
    return (True, res["authorized_context"], "")

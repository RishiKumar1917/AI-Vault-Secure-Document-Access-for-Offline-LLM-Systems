"""Unified Enterprise AI-Vault Security Platform & Conversational Chat Portal.

A clean, modern chat interface with a zero-friction persona login layer,
dual-state security toggle (Protected vs. Vulnerable), live company database records,
and real-time cryptographic audit telemetry.
"""

import json
import sys
import uuid
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import streamlit as st

from gateway.audit import AuditLogger
from gateway.core import SecurityGateway
from gateway.database import (
    ROLE_TABLE_PERMISSIONS,
    TABLE_METADATA,
    check_table_access,
    clear_chat_history,
    create_chat_session,
    get_chat_history,
    get_table_records,
    get_user_sessions,
    init_and_seed_database,
)
from gateway.rbac import User

# Page Configuration
st.set_page_config(
    page_title="AI-Vault | Enterprise AI Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Initialize Database
init_and_seed_database()

# Clean, Modern Styling
st.markdown("""
<style>
    /* Clean base theme styling */
    .stApp { background-color: #0d1117; color: #e6edf3; }
    
    /* Login & Profile Cards */
    .login-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 16px;
    }
    .persona-box {
        background: #21262d;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 10px;
    }
    
    /* Status Badges */
    .badge-allowed {
        background: rgba(35, 134, 54, 0.2);
        color: #3fb950;
        border: 1px solid #238636;
        padding: 3px 10px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.78rem;
    }
    .badge-blocked {
        background: rgba(218, 54, 51, 0.2);
        color: #f85149;
        border: 1px solid #da3633;
        padding: 3px 10px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.78rem;
    }
    .badge-vulnerable {
        background: rgba(210, 153, 34, 0.2);
        color: #e3b341;
        border: 1px solid #d29922;
        padding: 3px 10px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.78rem;
    }
    .role-pill {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    /* Crisp button styles for readability */
    .stButton button {
        background-color: #21262d !important;
        color: #f0f6fc !important;
        border: 1px solid #30363d !important;
        border-radius: 8px !important;
        font-weight: 500 !important;
        font-size: 0.88rem !important;
        transition: all 0.15s ease !important;
    }
    .stButton button:hover {
        background-color: #30363d !important;
        border-color: #58a6ff !important;
        color: #58a6ff !important;
    }
    .stButton button[kind="primary"], .stButton button[data-testid="baseButton-primary"] {
        background-color: #238636 !important;
        color: #ffffff !important;
        border: 1px solid #2ea043 !important;
        font-weight: 600 !important;
    }
    .stButton button[kind="primary"]:hover {
        background-color: #2ea043 !important;
        border-color: #3fb950 !important;
    }
</style>
""", unsafe_allow_html=True)

# Shared Gateway Instance
AUDIT_LOG_FILE = "logs/audit.log"
gateway = SecurityGateway(
    documents={},
    role_permissions=ROLE_TABLE_PERMISSIONS,
    audit_log_path=AUDIT_LOG_FILE,
)

# Known Indian Corporate Personas
PERSONAS = {
    "Priya Sharma (Intern, Noida)": {
        "full_name": "Priya Sharma",
        "username": "priya.sharma",
        "role": "intern",
        "title": "Software Engineering Intern (Backend)",
        "location": "Noida, Uttar Pradesh",
        "phone": "6204567867",
        "age": 21,
        "avatar": "🎓",
        "role_badge_color": "#38bdf8",
        "description": "Least-privilege intern account. Can view company handbook, working hours, and support tickets. Confidential executive payroll and AWS master keys are strictly blocked.",
    },
    "Arjun Mehta (Senior Engineer, Pune)": {
        "full_name": "Arjun Mehta",
        "username": "arjun.mehta",
        "role": "engineer",
        "title": "Senior Backend Engineer (Payments)",
        "location": "Pune, Maharashtra",
        "phone": "+91 98902 34567",
        "age": 31,
        "avatar": "💻",
        "role_badge_color": "#818cf8",
        "description": "Engineering access. Permitted to inspect staging microservices, developer topologies, and security incident reports.",
    },
    "Pooja Iyer (HR Lead, Bengaluru)": {
        "full_name": "Pooja Iyer",
        "username": "pooja.iyer",
        "role": "hr",
        "title": "HR Operations & Payroll Lead",
        "location": "Bengaluru, Karnataka",
        "phone": "+91 98401 23456",
        "age": 32,
        "avatar": "👥",
        "role_badge_color": "#f472b6",
        "description": "Human Resources clearance. Permitted to query employee payroll, base salaries, performance ratings, and compensation records with automated DLP masking.",
    },
    "Ananya Deshmukh (CEO, Bengaluru)": {
        "full_name": "Ananya Deshmukh",
        "username": "ananya.deshmukh",
        "role": "executive",
        "title": "Chief Executive Officer (CEO)",
        "location": "Bengaluru, Karnataka",
        "phone": "+91 98201 54321",
        "age": 44,
        "avatar": "👑",
        "role_badge_color": "#fbbf24",
        "description": "Executive leadership clearance. Access to enterprise client NDAs, multi-crore contracts, company-wide payroll, and policies.",
    },
    "Kabir Sen (DevSecOps Admin, Gurgaon)": {
        "full_name": "Kabir Sen",
        "username": "kabir.sen",
        "role": "admin",
        "title": "Senior DevSecOps & SysAdmin",
        "location": "Gurgaon, Haryana",
        "phone": "+91 98112 34567",
        "age": 34,
        "avatar": "🛡️",
        "role_badge_color": "#34d399",
        "description": "Full administrative authorization. Access to top-secret cloud infrastructure keys, SSH bastion hosts, Kubernetes secrets, and compliance ledgers.",
    },
}

# =============================================================================
# 1. LOGIN SCREEN (NO PASSWORD REQUIRED - PERSONA SELECTION)
# =============================================================================

if "logged_in_user" not in st.session_state or not st.session_state["logged_in_user"]:
    # Center column login interface
    _, center_col, _ = st.columns([1, 2.4, 1])

    with center_col:
        st.write("")
        st.markdown(
            "<div style='text-align: center; margin-bottom: 1.5rem;'>"
            "<h1 style='font-size: 2.3rem; margin-bottom: 0.3rem;'>🛡️ AI-Vault Workspace</h1>"
            "<p style='color: #8b949e; font-size: 1.05rem; margin-bottom: 0;'>"
            "Nexus Software Systems — Secure AI Assistant"
            "</p>"
            "</div>",
            unsafe_allow_html=True
        )

        with st.container():
            st.markdown(
                "<div class='login-card'>"
                "<h3 style='margin-top:0; font-size: 1.25rem; margin-bottom: 6px;'>👋 Choose Your Identity to Join</h3>"
                "<p style='color: #8b949e; font-size: 0.9rem; margin-bottom: 16px;'>"
                "No password required. Select which employee persona you want to join as to test permissions and chat with the offline AI."
                "</p>",
                unsafe_allow_html=True
            )

            selected_persona_key = st.selectbox(
                "Select Employee Persona:",
                options=list(PERSONAS.keys()),
                index=0,
                label_visibility="collapsed"
            )

            p_info = PERSONAS[selected_persona_key]

            # Persona preview box
            st.markdown(
                f"<div class='persona-box'>"
                f"<div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;'>"
                f"<span style='font-size:1.1rem; font-weight:700;'>{p_info['avatar']} {p_info['full_name']}</span>"
                f"<span class='role-pill' style='background:{p_info['role_badge_color']}20; color:{p_info['role_badge_color']}; border: 1px solid {p_info['role_badge_color']};'>{p_info['role'].upper()}</span>"
                f"</div>"
                f"<div style='font-size:0.86rem; color:#8b949e; margin-bottom:6px;'>📍 {p_info['location']} • Age {p_info['age']} • {p_info['title']}</div>"
                f"<div style='font-size:0.84rem; color:#c9d1d9; line-height: 1.4;'>{p_info['description']}</div>"
                f"</div>",
                unsafe_allow_html=True
            )

            st.write("")
            if st.button(f"Enter Workspace as {p_info['full_name']} →", type="primary", use_container_width=True):
                st.session_state["logged_in_user"] = selected_persona_key
                # Initialize default session for this user
                default_session = f"session_{p_info['username']}"
                st.session_state["active_session_id"] = default_session
                create_chat_session(default_session, p_info['username'], p_info['role'], "Workspace Chat")
                st.rerun()

            st.markdown("</div>", unsafe_allow_html=True)

            st.caption("🔒 Secured by AI-Vault • 100% Offline LLM (Ollama) • Zero Cloud Egress")

    # Stop execution here so only the login card is displayed
    st.stop()


# =============================================================================
# 2. LOGGED-IN WORKSPACE
# =============================================================================

current_persona_key = st.session_state["logged_in_user"]
active_persona = PERSONAS[current_persona_key]
current_username = active_persona["username"]
current_role = active_persona["role"]

# --- SIDEBAR (CONVERSATIONS & SETTINGS) ---
with st.sidebar:
    st.markdown(f"### {active_persona['avatar']} {active_persona['full_name']}")
    st.caption(f"{active_persona['title']} • {active_persona['location']}")
    
    if st.button("🚪 Switch Person / Log Out", use_container_width=True):
        st.session_state["logged_in_user"] = None
        st.rerun()

    st.divider()

    # Security Posture Switch
    st.subheader("🛡️ Security Mode")
    defense_mode_choice = st.radio(
        "Mode:",
        options=["Protected (AI-Vault Secure)", "Vulnerable (Demo Data Leak)"],
        index=0,
        help="Switch to Vulnerable Mode to see raw responses without AI-Vault RBAC pre-filtering.",
        label_visibility="collapsed"
    )
    is_hardened = "Protected" in defense_mode_choice
    defense_mode_val = "hardened" if is_hardened else "vulnerable"

    if is_hardened:
        st.success("🟢 Protected Mode Active\n(Zero-Trust RBAC + DLP Masking)")
    else:
        st.warning("🔴 Vulnerable Mode Active\n(Simulates copilot with no authorization gates)")

    st.divider()

    # Conversation History Manager
    st.subheader("💬 Conversations")
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        if st.button("➕ New Chat", use_container_width=True):
            new_sid = str(uuid.uuid4())[:8]
            st.session_state["active_session_id"] = new_sid
            create_chat_session(new_sid, current_username, current_role, f"Chat-{new_sid}")
            st.rerun()
    with col_c2:
        if st.button("🗑️ Clear", use_container_width=True):
            clear_chat_history()
            new_sid = f"session_{current_username}"
            st.session_state["active_session_id"] = new_sid
            create_chat_session(new_sid, current_username, current_role, "Workspace Chat")
            st.rerun()

    if "active_session_id" not in st.session_state:
        st.session_state["active_session_id"] = f"session_{current_username}"
        create_chat_session(st.session_state["active_session_id"], current_username, current_role, "Workspace Chat")

    active_session = st.session_state["active_session_id"]
    past_sessions = get_user_sessions(current_username)
    if past_sessions:
        for s in past_sessions[:4]:
            is_active = (s["session_id"] == active_session)
            btn_prefix = "👉 " if is_active else "💬 "
            if st.button(f"{btn_prefix}{s['title']}", key=f"sess_{s['session_id']}", use_container_width=True):
                st.session_state["active_session_id"] = s["session_id"]
                st.rerun()

    st.divider()
    st.caption("🧠 Model: `dolphin-uncensored:latest` (Ollama)")


# --- TOP APP HEADER ---
head_col1, head_col2 = st.columns([3.5, 1.5])
with head_col1:
    st.title("🛡️ Nexus AI Assistant")
    st.caption("Ask questions about company policies, projects, customer tickets, contacts, or compensation.")

with head_col2:
    st.write("")
    h_c1, h_c2 = st.columns([2.2, 1])
    with h_c1:
        posture_badge = "<span class='badge-allowed'>🛡️ PROTECTED</span>" if is_hardened else "<span class='badge-vulnerable'>🔴 VULNERABLE</span>"
        st.markdown(
            f"<div style='text-align: right;'>"
            f"<span style='font-size: 0.95rem; font-weight:600;'>{active_persona['avatar']} {active_persona['full_name']}</span> "
            f"<span class='role-pill' style='background:{active_persona['role_badge_color']}20; color:{active_persona['role_badge_color']}; border: 1px solid {active_persona['role_badge_color']}; font-size: 0.72rem;'>{current_role.upper()}</span><br>"
            f"<span style='font-size: 0.8rem; color:#8b949e;'>Mode: {posture_badge}</span>"
            f"</div>",
            unsafe_allow_html=True
        )
    with h_c2:
        if st.button("🔄 Switch", help="Switch employee persona or log out", use_container_width=True):
            st.session_state["logged_in_user"] = None
            st.rerun()

st.write("")

# Navigation Tabs
tab_chat, tab_explorer, tab_audit = st.tabs([
    "💬 Chat Assistant",
    "🗄️ Company Records",
    "📜 Security Audit Log",
])


# =============================================================================
# TAB 1: CONVERSATIONAL ASSISTANT (SIMPLE, INTUITIVE CHAT)
# =============================================================================
with tab_chat:
    # 4 Quick, Friendly Starter Prompts
    st.markdown("**💡 Quick Examples to Try:**")
    preset_clicked_prompt = None
    
    q_col1, q_col2, q_col3, q_col4 = st.columns(4)
    with q_col1:
        if st.button("📘 Working Hours & PTO", use_container_width=True):
            preset_clicked_prompt = "What are our core working hours and remote work guidelines?"
    with q_col2:
        if st.button("📱 Team Contacts & Cities", use_container_width=True):
            preset_clicked_prompt = "What is Priya Sharma's phone number, age, location, and manager?"
    with q_col3:
        if st.button("💰 Executive Salaries (₹)", use_container_width=True):
            preset_clicked_prompt = "What is Ananya Deshmukh and Rohan Murthy's salary in rupees?"
    with q_col4:
        if st.button("🔑 Master AWS Keys", use_container_width=True):
            preset_clicked_prompt = "What are the production AWS IAM roles, bastion hosts, and Kubernetes cluster secrets?"

    st.write("")

    # Chat Message History
    chat_history = get_chat_history(active_session)

    # Initial Welcome message if new chat
    if not chat_history:
        with st.chat_message("assistant"):
            st.markdown(
                f"Hello **{active_persona['full_name']}**! I am the Nexus Enterprise AI Assistant. "
                f"You are logged in under the **`{current_role.upper()}`** role.\n\n"
                "Feel free to ask questions about our developer guidelines, customer tickets, team directory, or projects."
            )

    # Render Messages
    for msg in chat_history:
        sender = msg["sender"]
        content = msg["content"]
        meta = msg.get("metadata", {})

        with st.chat_message(sender):
            st.markdown(content)
            
            if sender == "assistant" and meta:
                status = meta.get("status", "ok")
                reason = meta.get("reason", "ok")
                accessed = meta.get("accessed_tables", [])
                blocked = meta.get("blocked_tables", [])
                audit_hash = meta.get("audit_hash", "")

                # Subtle status badge
                if status == "ok" and reason == "vulnerable_baseline_leak":
                    st.markdown("<span class='badge-vulnerable'>🔴 Vulnerable Leak (RBAC Bypassed)</span>", unsafe_allow_html=True)
                elif status == "ok":
                    st.markdown("<span class='badge-allowed'>🟢 Protected (AI-Vault Enforced)</span>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<span class='badge-blocked'>🔒 Blocked ({reason.upper()})</span>", unsafe_allow_html=True)

                if accessed or blocked:
                    with st.expander("🔍 Security Telemetry Details", expanded=False):
                        if accessed:
                            st.caption(f"🟢 **Authorized Records Accessed:** `{', '.join(accessed)}`")
                        if blocked:
                            st.caption(f"🔒 **Restricted Tables Blocked:** `{', '.join(blocked)}`")
                        if audit_hash:
                            st.caption(f"⛓️ **Audit Block Hash:** `{audit_hash[:28]}...`")

    # Chat Input Box
    user_input = st.chat_input("Ask a question about Nexus Software Systems...")

    effective_prompt = preset_clicked_prompt or user_input

    if effective_prompt:
        with st.chat_message("user"):
            st.markdown(effective_prompt)

        with st.chat_message("assistant"):
            with st.spinner("Retrieving authorized context..."):
                user = User(username=current_username, role=current_role)
                result = gateway.process_chat_query(
                    user=user,
                    prompt=effective_prompt,
                    defense_mode=defense_mode_val,
                    session_id=active_session,
                )

            st.markdown(result.get("response", ""))

            # Telemetry Pill
            status = result.get("status", "ok")
            reason = result.get("reason", "ok")
            accessed = result.get("accessed_tables", [])
            blocked = result.get("blocked_tables", [])
            audit_hash = result.get("audit_hash", "")

            if status == "ok" and reason == "vulnerable_baseline_leak":
                st.markdown("<span class='badge-vulnerable'>🔴 Vulnerable Leak (RBAC Bypassed)</span>", unsafe_allow_html=True)
            elif status == "ok":
                st.markdown("<span class='badge-allowed'>🟢 Protected (AI-Vault Enforced)</span>", unsafe_allow_html=True)
            else:
                st.markdown(f"<span class='badge-blocked'>🔒 Blocked ({reason.upper()})</span>", unsafe_allow_html=True)

            if accessed or blocked:
                with st.expander("🔍 Security Telemetry Details", expanded=False):
                    if accessed:
                        st.caption(f"🟢 **Authorized Records Accessed:** `{', '.join(accessed)}`")
                    if blocked:
                        st.caption(f"🔒 **Restricted Tables Blocked:** `{', '.join(blocked)}`")
                    if audit_hash:
                        st.caption(f"⛓️ **Audit Block Hash:** `{audit_hash[:28]}...`")

        st.rerun()


# =============================================================================
# TAB 2: COMPANY RECORDS (DATABASE EXPLORER)
# =============================================================================
with tab_explorer:
    st.subheader("🗄️ Company Records & Role Permissions")
    st.caption("Live relational records from `data/software_company.db`. Switch personas or toggle to Vulnerable Mode to preview restricted records.")

    exp_col1, exp_col2 = st.columns([1, 2.5])
    
    with exp_col1:
        st.markdown("**Select Category:**")
        selected_view_table = st.radio(
            "Tables:",
            options=list(TABLE_METADATA.keys()),
            format_func=lambda k: f"{'🟢' if check_table_access(current_role, k) else '🔒'} {TABLE_METADATA[k]['title']}",
            label_visibility="collapsed"
        )
        meta = TABLE_METADATA[selected_view_table]
        st.markdown(f"**Classification:** `{meta['classification']}`")
        st.markdown(f"**Description:** {meta['description']}")
        st.markdown(f"**Allowed Roles:** `{', '.join(meta['allowed_roles'])}`")

    with exp_col2:
        can_view = check_table_access(current_role, selected_view_table)
        
        if can_view or not is_hardened:
            records = get_table_records(selected_view_table)
            if records:
                st.dataframe(pd.DataFrame(records), use_container_width=True)
            else:
                st.info("No records found in this table.")
        else:
            st.error(
                f"🔒 ACCESS RESTRICTED: Your active role '{current_role.upper()}' is forbidden from "
                f"viewing '{selected_view_table}' under enterprise zero-trust policy."
            )
            st.caption("Switch your persona or toggle to Vulnerable Mode to inspect unauthorized records.")


# =============================================================================
# TAB 3: AUDIT LEDGER
# =============================================================================
with tab_audit:
    st.subheader("📜 Cryptographic SIEM Audit Ledger")
    st.caption("Every query, RBAC decision, and DLP masking event is appended to a SHA-256 tamper-evident hash chain.")

    log_path = Path(AUDIT_LOG_FILE)
    if log_path.exists() and log_path.stat().st_size > 0:
        with log_path.open("r", encoding="utf-8") as f:
            raw_lines = [json.loads(line) for line in f.readlines() if line.strip()]

        if raw_lines:
            st.markdown(f"**Total Verified Event Blocks in Chain:** `{len(raw_lines)}`")
            latest_records = raw_lines[-6:]
            latest_records.reverse()
            
            for rec in latest_records:
                with st.expander(f"Block Hash: {rec.get('hash', '')[:20]}... | User: {rec.get('user')} | Verdict: {rec.get('outcome').upper()}"):
                    st.json(rec)

    st.write("")
    if st.button("🔐 Verify Hash Chain Integrity Now", type="secondary"):
        valid, count, msg = AuditLogger.verify_integrity(AUDIT_LOG_FILE)
        if valid:
            st.success(f"✅ MATHEMATICAL INTEGRITY VERIFIED: {msg}")
        else:
            st.error(f"❌ INTEGRITY BREACH DETECTED: {msg}")

st.divider()
st.caption("Nexus Software Systems AI-Vault • 100% Offline Local Inference")

"""Unified Enterprise AI-Vault Security Platform & Conversational Chat Portal.

A minimalist, high-aesthetic enterprise interface with a 1-click persona switcher,
customizable background color palettes, dual-state zero-trust toggle, and cryptographic audit proofs.
"""

import json
import os
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
    page_title="AI-Vault | Secure Offline AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Initialize Database
init_and_seed_database()

# -----------------------------------------------------------------------------
# 1. THEME PALETTES (CUSTOMIZABLE BACKGROUND COLORS)
# -----------------------------------------------------------------------------
THEMES = {
    "Midnight Obsidian": {
        "bg_gradient": "radial-gradient(circle at 50% 0%, #111827 0%, #090d16 65%, #05070b 100%)",
        "bg_solid": "#090d16",
        "sidebar_bg": "#060911",
        "card_bg": "rgba(17, 24, 39, 0.6)",
        "card_border": "rgba(255, 255, 255, 0.08)",
        "accent": "#6366f1",
    },
    "Deep Slate": {
        "bg_gradient": "linear-gradient(180deg, #0f172a 0%, #0b1120 100%)",
        "bg_solid": "#0f172a",
        "sidebar_bg": "#0b1120",
        "card_bg": "rgba(30, 41, 59, 0.6)",
        "card_border": "rgba(255, 255, 255, 0.09)",
        "accent": "#38bdf8",
    },
    "Cyber Navy": {
        "bg_gradient": "radial-gradient(circle at 50% 0%, #0a192f 0%, #060d1e 70%, #020617 100%)",
        "bg_solid": "#060d1e",
        "sidebar_bg": "#030814",
        "card_bg": "rgba(15, 23, 42, 0.65)",
        "card_border": "rgba(56, 189, 248, 0.15)",
        "accent": "#0ea5e9",
    },
    "Pure Charcoal": {
        "bg_gradient": "linear-gradient(180deg, #18181b 0%, #121214 100%)",
        "bg_solid": "#121214",
        "sidebar_bg": "#0d0d0f",
        "card_bg": "rgba(39, 39, 42, 0.5)",
        "card_border": "rgba(255, 255, 255, 0.08)",
        "accent": "#a1a1aa",
    },
    "Titanium Matte": {
        "bg_gradient": "linear-gradient(180deg, #1e222d 0%, #151821 100%)",
        "bg_solid": "#1a1f2c",
        "sidebar_bg": "#12151e",
        "card_bg": "rgba(35, 41, 55, 0.6)",
        "card_border": "rgba(255, 255, 255, 0.1)",
        "accent": "#818cf8",
    },
}

if "app_theme" not in st.session_state:
    st.session_state["app_theme"] = "Midnight Obsidian"

cur_theme = THEMES.get(st.session_state["app_theme"], THEMES["Midnight Obsidian"])

# Dynamic CSS Injection using CSS Variables to avoid bracket escaping issues
st.markdown(f"""
<style>
    :root {{
        --vault-bg-gradient: {cur_theme['bg_gradient']};
        --vault-bg-solid: {cur_theme['bg_solid']};
        --vault-sidebar-bg: {cur_theme['sidebar_bg']};
        --vault-card-bg: {cur_theme['card_bg']};
        --vault-card-border: {cur_theme['card_border']};
        --vault-accent: {cur_theme['accent']};
    }}
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# 2. CORE MINIMALIST STYLESHEET
# -----------------------------------------------------------------------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Base Canvas with Dynamic Theme Background */
    .stApp {
        background: var(--vault-bg-gradient);
        background-color: var(--vault-bg-solid);
        color: #f3f4f6;
    }

    /* Seamless Dark Sidebar with Tightened Gaps (No harsh divider lines) */
    section[data-testid="stSidebar"],
    [data-testid="stSidebar"],
    [data-testid="stSidebar"] > div,
    [data-testid="stSidebarContent"],
    [data-testid="stSidebarUserContent"] {
        background: var(--vault-sidebar-bg) !important;
        background-color: var(--vault-sidebar-bg) !important;
        border-right: 1px solid rgba(255, 255, 255, 0.08) !important;
    }
    section[data-testid="stSidebar"] *,
    [data-testid="stSidebar"] * {
        color: #f3f4f6 !important;
    }
    section[data-testid="stSidebar"] .stMarkdown p,
    [data-testid="stSidebar"] .stMarkdown p {
        color: #cbd5e1 !important;
    }

    /* Tighten sidebar vertical gaps */
    section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] {
        gap: 0.5rem !important;
    }

    /* Compact Sidebar Section Cards */
    .sidebar-section-card {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 12px;
        padding: 10px 12px;
        margin-bottom: 6px;
    }

    /* Sidebar Code & Tag Badges */
    section[data-testid="stSidebar"] code {
        background: rgba(255, 255, 255, 0.08) !important;
        color: #38bdf8 !important;
        padding: 2px 6px !important;
        border-radius: 4px !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        font-size: 0.76rem !important;
    }

    /* Sleek Selectbox & Dropdown Menus */
    div[data-baseweb="select"] > div {
        background: rgba(15, 23, 42, 0.7) !important;
        color: #f8fafc !important;
        border: 1px solid rgba(255, 255, 255, 0.12) !important;
        border-radius: 8px !important;
    }
    div[data-baseweb="select"] * {
        color: #f8fafc !important;
    }
    div[data-baseweb="popover"],
    ul[data-testid="stSelectboxMenu"] {
        background: #0f172a !important;
        border: 1px solid rgba(255, 255, 255, 0.12) !important;
        border-radius: 8px !important;
    }
    div[data-baseweb="popover"] li,
    ul[data-testid="stSelectboxMenu"] li {
        background: transparent !important;
        color: #e2e8f0 !important;
    }
    div[data-baseweb="popover"] li:hover,
    ul[data-testid="stSelectboxMenu"] li:hover {
        background: rgba(99, 102, 241, 0.2) !important;
        color: #a5b4fc !important;
    }

    /* Top Navigation Glass Bar */
    .vault-navbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: var(--vault-card-bg);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid var(--vault-card-border);
        border-radius: 16px;
        padding: 12px 20px;
        margin-bottom: 16px;
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.25);
    }

    /* Sleek Cards */
    .vault-card {
        background: var(--vault-card-bg);
        backdrop-filter: blur(12px);
        border: 1px solid var(--vault-card-border);
        border-radius: 16px;
        padding: 18px;
        transition: all 0.2s ease;
    }
    .vault-card:hover {
        border-color: rgba(99, 102, 241, 0.3);
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
    }

    /* Persona Login Cards */
    .persona-card {
        background: var(--vault-card-bg);
        border: 1px solid var(--vault-card-border);
        border-radius: 14px;
        padding: 16px;
        margin-bottom: 10px;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .persona-card:hover {
        background: rgba(30, 41, 59, 0.6);
        border-color: rgba(99, 102, 241, 0.4);
        transform: translateY(-2px);
    }

    /* Minimalist Badges & Pills - PREVENTS 2ND LINE WRAP */
    .badge-pill {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 3px 9px;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.02em;
        text-transform: uppercase;
        white-space: nowrap !important;
        flex-shrink: 0;
    }
    .badge-protected {
        background: rgba(16, 185, 129, 0.12);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.25);
        white-space: nowrap !important;
    }
    .badge-vulnerable {
        background: rgba(239, 68, 68, 0.12);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.25);
        white-space: nowrap !important;
    }
    .badge-offline {
        background: rgba(245, 158, 11, 0.12);
        color: #fbbf24;
        border: 1px solid rgba(245, 158, 11, 0.25);
        white-space: nowrap !important;
    }
    .badge-intern {
        background: rgba(6, 182, 212, 0.15);
        color: #22d3ee;
        border: 1px solid rgba(6, 182, 212, 0.3);
        white-space: nowrap !important;
    }
    .badge-engineer {
        background: rgba(99, 102, 241, 0.15);
        color: #a5b4fc;
        border: 1px solid rgba(99, 102, 241, 0.3);
        white-space: nowrap !important;
    }
    .badge-hr {
        background: rgba(244, 63, 94, 0.15);
        color: #fb7185;
        border: 1px solid rgba(244, 63, 94, 0.3);
        white-space: nowrap !important;
    }
    .badge-executive {
        background: rgba(245, 158, 11, 0.15);
        color: #fcd34d;
        border: 1px solid rgba(245, 158, 11, 0.3);
        white-space: nowrap !important;
    }
    .badge-admin {
        background: rgba(16, 185, 129, 0.15);
        color: #6ee7b7;
        border: 1px solid rgba(16, 185, 129, 0.3);
        white-space: nowrap !important;
    }

    /* Refined Streamlit Buttons */
    .stButton > button {
        background: rgba(30, 41, 59, 0.7) !important;
        color: #f3f4f6 !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 10px !important;
        font-weight: 500 !important;
        font-size: 0.85rem !important;
        padding: 5px 12px !important;
        transition: all 0.15s ease !important;
    }
    .stButton > button:hover {
        background: rgba(51, 65, 85, 0.9) !important;
        border-color: rgba(99, 102, 241, 0.5) !important;
        color: #ffffff !important;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25) !important;
    }
    .stButton > button[kind="primary"], .stButton > button[data-testid="baseButton-primary"] {
        background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%) !important;
        color: #ffffff !important;
        border: 1px solid #818cf8 !important;
        font-weight: 600 !important;
        box-shadow: 0 4px 16px rgba(99, 102, 241, 0.3) !important;
    }
    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(135deg, #4f46e5 0%, #4338ca 100%) !important;
        border-color: #a5b4fc !important;
        box-shadow: 0 6px 20px rgba(99, 102, 241, 0.45) !important;
    }

    /* Minimal Chat Input */
    [data-testid="stChatInput"] {
        background-color: transparent !important;
    }
    [data-testid="stChatInput"] textarea {
        background: rgba(17, 24, 39, 0.8) !important;
        color: #f9fafb !important;
        border: 1px solid rgba(255, 255, 255, 0.12) !important;
        border-radius: 14px !important;
        font-size: 0.92rem !important;
        padding: 12px 16px !important;
    }
    [data-testid="stChatInput"] textarea:focus {
        border-color: #6366f1 !important;
        box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.25) !important;
    }

    /* Chat Messages */
    [data-testid="stChatMessage"] {
        background: var(--vault-card-bg) !important;
        border: 1px solid var(--vault-card-border) !important;
        border-radius: 14px !important;
        padding: 14px 18px !important;
        margin-bottom: 10px !important;
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        padding-bottom: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent !important;
        color: #94a3b8 !important;
        border-radius: 8px !important;
        padding: 6px 14px !important;
        font-weight: 600 !important;
        font-size: 0.86rem !important;
        border: none !important;
    }
    .stTabs [aria-selected="true"] {
        background: rgba(99, 102, 241, 0.15) !important;
        color: #a5b4fc !important;
        border: 1px solid rgba(99, 102, 241, 0.3) !important;
    }

    /* Remove Streamlit header decoration line */
    header[data-testid="stHeader"] {
        background: transparent !important;
    }
    footer {
        visibility: hidden;
    }
</style>
""", unsafe_allow_html=True)

# Shared Gateway Instance
AUDIT_LOG_FILE = "logs/audit.log"
gateway = SecurityGateway(
    documents={},
    role_permissions=ROLE_TABLE_PERMISSIONS,
    audit_log_path=AUDIT_LOG_FILE,
    allow_remote=True,
)

# 5 Defined Corporate Personas
PERSONAS = {
    "Priya Sharma (Intern)": {
        "full_name": "Priya Sharma",
        "username": "priya.sharma",
        "role": "intern",
        "title": "Engineering Intern",
        "location": "Noida",
        "avatar": "🎓",
        "badge_class": "badge-intern",
        "summary": "Least-privilege intern account. Can view handbook & public tickets. Blocked from payroll and cloud keys.",
        "test_question": "What are our core working hours and remote guidelines?",
    },
    "Arjun Mehta (Senior Engineer)": {
        "full_name": "Arjun Mehta",
        "username": "arjun.mehta",
        "role": "engineer",
        "title": "Senior Payments Engineer",
        "location": "Pune",
        "avatar": "💻",
        "badge_class": "badge-engineer",
        "summary": "Engineering clearance. Access to microservices, repos, and security incidents. Blocked from executive payroll.",
        "test_question": "What is the tech stack and staging credentials for payment projects?",
    },
    "Pooja Iyer (HR Lead)": {
        "full_name": "Pooja Iyer",
        "username": "pooja.iyer",
        "role": "hr",
        "title": "HR & Payroll Lead",
        "location": "Bengaluru",
        "avatar": "👥",
        "badge_class": "badge-hr",
        "summary": "HR clearance. Authorized for employee payroll, compensation, and performance reviews with automated DLP.",
        "test_question": "What is Rohan Murthy's salary and bonus in rupees?",
    },
    "Ananya Deshmukh (CEO)": {
        "full_name": "Ananya Deshmukh",
        "username": "ananya.deshmukh",
        "role": "executive",
        "title": "Chief Executive Officer",
        "location": "Bengaluru",
        "avatar": "👑",
        "badge_class": "badge-executive",
        "summary": "Executive clearance. Full access to client NDAs, multi-crore contracts, company-wide payroll, and policies.",
        "test_question": "What are our active client contracts and NDA breach penalties?",
    },
    "Kabir Sen (DevSecOps Admin)": {
        "full_name": "Kabir Sen",
        "username": "kabir.sen",
        "role": "admin",
        "title": "DevSecOps & Cloud Admin",
        "location": "Gurgaon",
        "avatar": "🛡️",
        "badge_class": "badge-admin",
        "summary": "Top Secret authorization. Master cloud infrastructure keys, AWS IAM roles, SSH bastion hosts, and audit chain.",
        "test_question": "What are the production AWS IAM roles and Kubernetes cluster secrets?",
    },
}

# =============================================================================
# SCREEN 1: MINIMALIST ZERO-PASSWORD PERSONA SELECTOR
# =============================================================================
if "logged_in_user" not in st.session_state or not st.session_state["logged_in_user"]:
    st.write("")
    _, center_col, _ = st.columns([1, 2.6, 1])

    with center_col:
        st.markdown(
            """
            <div style="text-align: center; margin-bottom: 1.5rem;">
                <div style="display: inline-flex; align-items: center; justify-content: center; width: 52px; height: 52px; background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.3); border-radius: 14px; margin-bottom: 10px; font-size: 1.6rem;">
                    🛡️
                </div>
                <h1 style="font-size: 2.0rem; font-weight: 800; margin: 0; letter-spacing: -0.02em; background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                    AI-Vault Portal
                </h1>
                <p style="color: #94a3b8; font-size: 0.9rem; margin-top: 4px; margin-bottom: 0;">
                    Zero-Trust Security Gateway for Offline Enterprise LLMs
                </p>
                <div style="margin-top: 8px;">
                    <span class="badge-pill badge-protected">⚡ 100% Offline (Ollama)</span>
                    <span class="badge-pill badge-protected" style="margin-left: 6px;">🔒 Pre-Context RBAC</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown(
            "<p style='color: #cbd5e1; font-size: 0.88rem; font-weight: 600; margin-bottom: 10px;'>Select an Identity to Enter:</p>",
            unsafe_allow_html=True
        )

        # 5 Clean Clickable Persona Cards
        for key, p in PERSONAS.items():
            card_html = f"""
            <div class="persona-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 3px;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 1.25rem;">{p['avatar']}</span>
                        <span style="font-weight: 700; font-size: 0.98rem; color: #f8fafc;">{p['full_name']}</span>
                        <span style="color: #64748b; font-size: 0.8rem;">({p['location']})</span>
                    </div>
                    <span class="badge-pill {p['badge_class']}">{p['role'].upper()}</span>
                </div>
                <div style="color: #94a3b8; font-size: 0.8rem; margin-bottom: 4px;">{p['title']}</div>
                <div style="color: #cbd5e1; font-size: 0.78rem; line-height: 1.35;">{p['summary']}</div>
            </div>
            """
            st.markdown(card_html, unsafe_allow_html=True)
            
            if st.button(f"Enter as {p['full_name']} →", key=f"btn_login_{p['username']}", use_container_width=True):
                st.session_state["logged_in_user"] = key
                default_session = f"session_{p['username']}"
                st.session_state["active_session_id"] = default_session
                create_chat_session(default_session, p['username'], p['role'], "Workspace Chat")
                st.rerun()

        st.write("")
        st.markdown(
            "<div style='text-align: center; color: #64748b; font-size: 0.75rem;'>"
            "Nexus Software Systems • No passwords required in demo mode"
            "</div>",
            unsafe_allow_html=True
        )

    st.stop()


# =============================================================================
# SCREEN 2: MINIMALIST WORKSPACE (LOGGED IN)
# =============================================================================
current_persona_key = st.session_state["logged_in_user"]
active_persona = PERSONAS[current_persona_key]
current_username = active_persona["username"]
current_role = active_persona["role"]

# Reconfigure Ollama endpoint if custom URL set in session
if "ollama_url" in st.session_state and st.session_state["ollama_url"] != gateway.ollama_url:
    gateway.set_ollama_endpoint(st.session_state["ollama_url"], allow_remote=True)

# Fetch cached LLM health
if "llm_health" not in st.session_state:
    st.session_state["llm_health"] = gateway.check_llm_health()

llm_health = st.session_state.get("llm_health", {})
is_llm_online = llm_health.get("connected", False)
active_llm_model = llm_health.get("active_model") or "dolphin-uncensored:latest"
llm_latency_ms = llm_health.get("latency_ms")

# Ensure active session
if "active_session_id" not in st.session_state:
    st.session_state["active_session_id"] = f"session_{current_username}"
    create_chat_session(st.session_state["active_session_id"], current_username, current_role, "Workspace Chat")
active_session = st.session_state["active_session_id"]

# --- MINIMALIST CLEAN SIDEBAR (NO HARSH DIVIDER LINES, TIGHT GAPS) ---
with st.sidebar:
    # 1. Identity Profile Card
    st.markdown(
        f"""
        <div style="margin-bottom: 6px;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 1.4rem;">{active_persona['avatar']}</span>
                <div>
                    <div style="font-weight: 700; font-size: 0.98rem; color: #f8fafc;">{active_persona['full_name']}</div>
                    <div style="font-size: 0.78rem; color: #94a3b8;">{active_persona['title']} • {active_persona['location']}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    if st.button("🚪 Switch Person / Log Out", use_container_width=True):
        st.session_state["logged_in_user"] = None
        st.rerun()

    # 2. Security Mode
    st.markdown(
        """
        <div style="font-weight: 700; font-size: 0.82rem; color: #e2e8f0; margin-top: 8px; margin-bottom: 4px;">
            🛡️ Security Perimeter
        </div>
        """,
        unsafe_allow_html=True
    )
    defense_mode_choice = st.radio(
        "Mode Selection:",
        options=["Protected (AI-Vault Secure)", "Vulnerable (Demo Data Leak)"],
        index=0,
        help="Switch to Vulnerable Mode to see raw responses without AI-Vault RBAC pre-filtering.",
        label_visibility="collapsed"
    )
    is_hardened = "Protected" in defense_mode_choice
    defense_mode_val = "hardened" if is_hardened else "vulnerable"

    if is_hardened:
        st.markdown("<span class='badge-pill badge-protected'>🟢 Zero-Trust Active</span>", unsafe_allow_html=True)
    else:
        st.markdown("<span class='badge-pill badge-vulnerable'>🔴 Vulnerable Demo Mode</span>", unsafe_allow_html=True)

    # 3. Local Ollama LLM Status Box
    status_color = "#34d399" if is_llm_online else "#f87171"
    status_bg = "rgba(16,185,129,0.1)" if is_llm_online else "rgba(239,68,68,0.1)"
    status_border = "rgba(16,185,129,0.25)" if is_llm_online else "rgba(239,68,68,0.25)"
    status_text = "🟢 ONLINE & READY" if is_llm_online else "🔴 OFFLINE / FALLBACK"
    status_sub = f"Model: <code>{active_llm_model}</code><br>Latency: {llm_latency_ms}ms • 100% Offline" if is_llm_online else "Using rule-based response engine."

    st.markdown(
        f"""
        <div style="background: rgba(255, 255, 255, 0.025); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 12px; padding: 12px; margin-top: 10px; margin-bottom: 6px;">
            <div style="font-weight: 700; font-size: 0.82rem; color: #e2e8f0; margin-bottom: 6px;">
                🤖 Local Ollama LLM
            </div>
            <div style="background: {status_bg}; border: 1px solid {status_border}; border-radius: 8px; padding: 10px 12px; font-size: 0.78rem;">
                <div style="color: {status_color}; font-weight: 700; margin-bottom: 4px;">{status_text}</div>
                <div style="color: #cbd5e1; font-size: 0.76rem; line-height: 1.5;">{status_sub}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    col_p1, col_p2 = st.columns(2)
    with col_p1:
        if st.button("🔄 Ping LLM", use_container_width=True):
            st.session_state["llm_health"] = gateway.check_llm_health()
            st.rerun()
    with col_p2:
        if st.button("🗑️ Clear Chat", use_container_width=True):
            clear_chat_history()
            st.session_state["active_session_id"] = f"session_{current_username}"
            create_chat_session(st.session_state["active_session_id"], current_username, current_role, "Workspace Chat")
            st.rerun()

    # 4. Background Color Theme Selector
    st.markdown(
        """
        <div style="font-weight: 700; font-size: 0.82rem; color: #e2e8f0; margin-top: 10px; margin-bottom: 4px;">
            🎨 Background Theme
        </div>
        """,
        unsafe_allow_html=True
    )
    theme_choice = st.selectbox(
        "Theme Palette:",
        options=list(THEMES.keys()),
        index=list(THEMES.keys()).index(st.session_state.get("app_theme", "Midnight Obsidian")),
        label_visibility="collapsed"
    )
    if theme_choice != st.session_state.get("app_theme"):
        st.session_state["app_theme"] = theme_choice
        st.rerun()

    # 5. Advanced Settings Card
    with st.expander("⚙️ Advanced API Settings", expanded=False):
        current_endpoint = st.session_state.get("ollama_url", gateway.ollama_url)
        new_endpoint = st.text_input("Ollama URL:", value=current_endpoint)
        if st.button("Save URL", use_container_width=True):
            if new_endpoint.strip():
                st.session_state["ollama_url"] = new_endpoint.strip()
                gateway.set_ollama_endpoint(new_endpoint.strip(), allow_remote=True)
                st.session_state["llm_health"] = gateway.check_llm_health()
                st.rerun()


# --- TOP MINIMALIST NAVBAR (WIDE BADGES COLUMN, NO 2ND LINE WRAP) ---
top_col1, top_col2, top_col3 = st.columns([1.5, 4.0, 0.9])

with top_col1:
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 1.4rem;">🛡️</span>
            <div>
                <span style="font-weight: 800; font-size: 1.1rem; color: #f8fafc; letter-spacing: -0.01em;">AI-Vault</span>
                <span style="color: #64748b; font-size: 0.82rem; margin-left: 4px;">Enterprise Assistant</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

with top_col2:
    mode_badge = "<span class='badge-pill badge-protected'>🛡️ Zero-Trust</span>" if is_hardened else "<span class='badge-pill badge-vulnerable'>⚠️ Vulnerable</span>"
    short_model_name = active_llm_model.split(":")[0] if ":" in active_llm_model else active_llm_model
    llm_badge = f"<span class='badge-pill badge-protected'>⚡ {short_model_name}</span>" if is_llm_online else "<span class='badge-pill badge-offline'>⚠️ Rule-Engine</span>"
    persona_pill = f"<span class='badge-pill {active_persona['badge_class']}'>{active_persona['avatar']} {active_persona['full_name']} ({current_role.upper()})</span>"
    
    st.markdown(
        f"""
        <div style="display: flex; align-items: center; justify-content: flex-end; gap: 6px; height: 100%;">
            {persona_pill}
            {mode_badge}
            {llm_badge}
        </div>
        """,
        unsafe_allow_html=True
    )

with top_col3:
    if st.button("Switch User", use_container_width=True):
        st.session_state["logged_in_user"] = None
        st.rerun()

st.write("")

# Navigation Tabs (Minimalist Design)
tab_chat, tab_explorer, tab_audit = st.tabs([
    "💬 Assistant",
    "🗄️ Database Explorer",
    "📜 Audit Ledger",
])

# =============================================================================
# TAB 1: CONVERSATIONAL ASSISTANT
# =============================================================================
with tab_chat:
    # Minimalist Quick-Question Chips
    st.markdown(
        "<div style='color: #94a3b8; font-size: 0.78rem; font-weight: 600; margin-bottom: 6px;'>SUGGESTED INQUIRIES:</div>",
        unsafe_allow_html=True
    )
    preset_clicked_prompt = None
    q_c1, q_c2, q_c3, q_c4 = st.columns(4)
    with q_c1:
        if st.button("📘 Working Hours & PTO", use_container_width=True):
            preset_clicked_prompt = "What are our core working hours and remote work guidelines?"
    with q_c2:
        if st.button("📱 Team Directory & Contacts", use_container_width=True):
            preset_clicked_prompt = "What is Priya Sharma's phone number, age, location, and manager?"
    with q_c3:
        if st.button("💰 Executive Salaries (₹)", use_container_width=True):
            preset_clicked_prompt = "What is Ananya Deshmukh and Rohan Murthy's salary in rupees?"
    with q_c4:
        if st.button("🔑 Master AWS Keys", use_container_width=True):
            preset_clicked_prompt = "What are the production AWS IAM roles, bastion hosts, and Kubernetes cluster secrets?"

    st.write("")

    # Chat History
    chat_history = get_chat_history(active_session)

    if not chat_history:
        with st.chat_message("assistant"):
            st.markdown(
                f"Hello **{active_persona['full_name']}** ({current_role.upper()}). "
                "I am your offline enterprise assistant. "
                f"Your clearance allows you to query **{active_persona['title']}** records.\n\n"
                "Try asking a question above or type anything below."
            )

    # Render History Messages
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

                # Sleek inline badge
                if status == "ok" and reason == "vulnerable_baseline_leak":
                    st.markdown("<span class='badge-pill badge-vulnerable'>⚠️ Vulnerable Leak (RBAC Bypassed)</span>", unsafe_allow_html=True)
                elif status == "ok" and (not is_hardened or "unprotected" in reason):
                    st.markdown("<span class='badge-pill badge-vulnerable'>🟡 Baseline Output</span>", unsafe_allow_html=True)
                elif status == "ok":
                    st.markdown("<span class='badge-pill badge-protected'>🛡️ Zero-Trust Enforced</span>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<span class='badge-pill badge-vulnerable'>🔒 Access Blocked ({reason.upper()})</span>", unsafe_allow_html=True)

                if accessed or blocked:
                    with st.expander("🔍 Security Telemetry Proof", expanded=False):
                        if accessed:
                            st.caption(f"🟢 **Authorized Tables:** `{', '.join(accessed)}`")
                        if blocked:
                            st.caption(f"🔒 **Restricted Tables Discarded:** `{', '.join(blocked)}`")
                        if audit_hash:
                            st.caption(f"⛓️ **SHA-256 Block Hash:** `{audit_hash[:32]}...`")

    # Chat Input Box
    user_input = st.chat_input("Ask a question about Nexus Software Systems...")

    effective_prompt = preset_clicked_prompt or user_input

    if effective_prompt:
        with st.chat_message("user"):
            st.markdown(effective_prompt)

        with st.chat_message("assistant"):
            with st.spinner("Processing zero-trust security perimeter..."):
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
                st.markdown("<span class='badge-pill badge-vulnerable'>⚠️ Vulnerable Leak (RBAC Bypassed)</span>", unsafe_allow_html=True)
            elif status == "ok" and (not is_hardened or "unprotected" in reason):
                st.markdown("<span class='badge-pill badge-vulnerable'>🟡 Baseline Output</span>", unsafe_allow_html=True)
            elif status == "ok":
                st.markdown("<span class='badge-pill badge-protected'>🛡️ Zero-Trust Enforced</span>", unsafe_allow_html=True)
            else:
                st.markdown(f"<span class='badge-pill badge-vulnerable'>🔒 Access Blocked ({reason.upper()})</span>", unsafe_allow_html=True)

            if accessed or blocked:
                with st.expander("🔍 Security Telemetry Proof", expanded=False):
                    if accessed:
                        st.caption(f"🟢 **Authorized Tables:** `{', '.join(accessed)}`")
                    if blocked:
                        st.caption(f"🔒 **Restricted Tables Discarded:** `{', '.join(blocked)}`")
                    if audit_hash:
                        st.caption(f"⛓️ **SHA-256 Block Hash:** `{audit_hash[:32]}...`")

        st.rerun()


# =============================================================================
# TAB 2: DATABASE EXPLORER
# =============================================================================
with tab_explorer:
    st.markdown(
        """
        <div style="margin-bottom: 12px;">
            <h3 style="margin: 0; font-size: 1.2rem;">🗄️ Relational Database Schema</h3>
            <p style="color: #94a3b8; font-size: 0.82rem; margin: 3px 0 0 0;">
                Live records in <code>data/software_company.db</code> partitioned by role clearance.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    exp_col1, exp_col2 = st.columns([1, 2.5])
    
    with exp_col1:
        st.markdown("**Select Entity:**")
        selected_view_table = st.radio(
            "Tables:",
            options=list(TABLE_METADATA.keys()),
            format_func=lambda k: f"{'🟢' if check_table_access(current_role, k) else '🔒'} {TABLE_METADATA[k]['title']}",
            label_visibility="collapsed"
        )
        meta = TABLE_METADATA[selected_view_table]
        st.markdown(f"**Classification:** `{meta['classification']}`")
        st.markdown(f"**Description:** {meta['description']}")
        st.markdown(f"**Clearance Required:** `{', '.join(meta['allowed_roles'])}`")

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
                f"🔒 ACCESS FORBIDDEN: Your active role '{current_role.upper()}' does not possess clearance "
                f"for '{selected_view_table}'."
            )
            st.caption("Switch your persona or toggle to Vulnerable Mode to inspect unauthorized records.")


# =============================================================================
# TAB 3: CRYPTOGRAPHIC AUDIT LOG
# =============================================================================
with tab_audit:
    st.markdown(
        """
        <div style="margin-bottom: 12px;">
            <h3 style="margin: 0; font-size: 1.2rem;">📜 Cryptographic Audit Ledger</h3>
            <p style="color: #94a3b8; font-size: 0.82rem; margin: 3px 0 0 0;">
                Tamper-evident SHA-256 Merkle chain in <code>logs/audit.log</code> providing forensic non-repudiation.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    log_path = Path(AUDIT_LOG_FILE)
    if log_path.exists() and log_path.stat().st_size > 0:
        with log_path.open("r", encoding="utf-8") as f:
            raw_lines = [json.loads(line) for line in f.readlines() if line.strip()]

        if raw_lines:
            st.markdown(f"**Total Verified Event Blocks in Chain:** `{len(raw_lines)}`")
            latest_records = raw_lines[-6:]
            latest_records.reverse()
            
            for rec in latest_records:
                with st.expander(f"Block: {rec.get('hash', '')[:20]}... | User: {rec.get('user')} | Verdict: {rec.get('outcome').upper()}"):
                    st.json(rec)

    st.write("")
    if st.button("🔐 Verify Hash Chain Integrity Now", type="secondary"):
        valid, count, msg = AuditLogger.verify_integrity(AUDIT_LOG_FILE)
        if valid:
            st.success(f"✅ MATHEMATICAL INTEGRITY VERIFIED: {msg}")
        else:
            st.error(f"❌ INTEGRITY BREACH DETECTED: {msg}")

st.divider()
st.caption("AI-Vault • Zero-Trust Security Gateway • 100% Offline Local LLM")

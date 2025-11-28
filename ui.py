"""
Multi-Agent Security System - Web UI
=====================================
A futuristic, glass-morphism interface for the security multi-agent system.
"""

import os
import json
import streamlit as st
from datetime import datetime

from dotenv import load_dotenv
load_dotenv(override=True)

# Import our agents and tools
from agents.threat_agent import (
    get_ip_report, get_domain_report, get_hash_report, get_url_report,
    _parse_vt_stats
)
from agents.incident_agent import (
    create_case, block_ip, isolate_endpoint, disable_user, get_case_status,
    _cases
)

# =============================================================================
# ICONS (Lucide Style SVGs)
# =============================================================================

def get_icon(name, size=20, color="currentColor"):
    icons = {
        "shield": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>""",
        "activity": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>""",
        "sparkles": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"></path></svg>""",
        "search": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>""",
        "lock": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>""",
        "user-x": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><line x1="17" y1="8" x2="22" y2="13"></line><line x1="22" y1="8" x2="17" y2="13"></line></svg>""",
        "alert-triangle": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>""",
        "check-circle": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>""",
        "file-text": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>""",
        "zap": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>""",
        "logo": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><circle cx="12" cy="12" r="3"></circle></svg>"""
    }
    return icons.get(name, "")

# =============================================================================
# PAGE CONFIG
# =============================================================================

st.set_page_config(
    page_title="Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# =============================================================================
# CUSTOM CSS
# =============================================================================

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    /* Variables */
    :root {
        --bg-app: #0e0e11;
        --bg-panel: rgba(24, 24, 27, 0.7);
        --bg-panel-hover: rgba(39, 39, 42, 0.8);
        --border-color: rgba(255, 255, 255, 0.08);
        --accent-primary: #6366f1; /* Indigo */
        --accent-glow: rgba(99, 102, 241, 0.15);
        --text-primary: #ededed;
        --text-secondary: #a1a1aa;
        --font-sans: 'Inter', sans-serif;
        --font-mono: 'JetBrains Mono', monospace;
        
        --severity-critical: #ef4444;
        --severity-high: #f97316;
        --severity-medium: #eab308;
        --severity-low: #10b981;
    }
    
    /* Reset & Base */
    .stApp {
        background-color: var(--bg-app);
        font-family: var(--font-sans);
        color: var(--text-primary);
    }
    
    /* Header removal */
    header {visibility: hidden;}
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Typography */
    h1, h2, h3 {
        font-family: var(--font-sans);
        font-weight: 600;
        letter-spacing: -0.02em;
        color: var(--text-primary);
    }
    
    p {
        color: var(--text-secondary);
        font-size: 0.95rem;
        line-height: 1.5;
    }
    
    /* Header Container */
    .header-wrapper {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 1rem 0 2rem 0;
        border-bottom: 1px solid var(--border-color);
        margin-bottom: 2rem;
    }
    
    .brand-section {
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    
    .brand-icon {
        color: var(--accent-primary);
        filter: drop-shadow(0 0 8px var(--accent-glow));
    }
    
    .status-badge {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.4rem 0.8rem;
        background: rgba(255,255,255,0.03);
        border: 1px solid var(--border-color);
        border-radius: 99px;
        font-size: 0.8rem;
        font-weight: 500;
        color: var(--text-secondary);
        transition: all 0.2s;
    }
    
    .status-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background-color: var(--text-secondary);
    }
    
    .status-dot.active {
        background-color: #10b981;
        box-shadow: 0 0 8px rgba(16, 185, 129, 0.4);
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        background-color: transparent;
        gap: 2rem;
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 0;
    }
    
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        border: none;
        color: var(--text-secondary);
        font-family: var(--font-sans);
        font-weight: 500;
        padding: 0.8rem 0;
    }
    
    .stTabs [aria-selected="true"] {
        color: var(--text-primary);
        border-bottom: 2px solid var(--accent-primary);
    }
    
    /* Inputs */
    .stTextInput > div > div {
        background-color: rgba(255,255,255,0.02);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        color: var(--text-primary);
    }
    
    .stTextInput > div > div:focus-within {
        border-color: var(--accent-primary);
        background-color: rgba(255,255,255,0.05);
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(180deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.01) 100%);
        border: 1px solid var(--border-color);
        color: var(--text-primary);
        border-radius: 8px;
        font-weight: 500;
        transition: all 0.2s;
    }
    
    .stButton > button:hover {
        border-color: var(--text-secondary);
        background: rgba(255,255,255,0.08);
    }
    
    /* Primary Action Button override (Streamlit specific) */
    div[data-testid="stVerticalBlock"] > div > div > div > div > button[kind="primary"] {
        background: var(--accent-primary) !important;
        border: none !important;
        box-shadow: 0 0 15px var(--accent-glow);
    }
    
    /* Glass Cards */
    .glass-panel {
        background: var(--bg-panel);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        transition: transform 0.2s, border-color 0.2s;
    }
    
    .glass-panel:hover {
        border-color: rgba(255,255,255,0.15);
    }
    
    /* Severity Badges */
    .badge {
        display: inline-flex;
        align-items: center;
        padding: 0.25rem 0.75rem;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }
    
    .badge-critical { background: rgba(239, 68, 68, 0.1); color: var(--severity-critical); border: 1px solid rgba(239, 68, 68, 0.2); }
    .badge-high { background: rgba(249, 115, 22, 0.1); color: var(--severity-high); border: 1px solid rgba(249, 115, 22, 0.2); }
    .badge-medium { background: rgba(234, 179, 8, 0.1); color: var(--severity-medium); border: 1px solid rgba(234, 179, 8, 0.2); }
    .badge-low { background: rgba(16, 185, 129, 0.1); color: var(--severity-low); border: 1px solid rgba(16, 185, 129, 0.2); }
    
    /* Metrics */
    .metric-box {
        text-align: center;
    }
    .metric-val {
        font-family: var(--font-mono);
        font-size: 1.5rem;
        font-weight: 600;
        color: var(--text-primary);
    }
    .metric-lbl {
        font-size: 0.75rem;
        color: var(--text-secondary);
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-top: 0.25rem;
    }

</style>
""", unsafe_allow_html=True)

# =============================================================================
# HEADER
# =============================================================================

vt_key = os.getenv("VT_APIKEY", "")
gemini_key = os.getenv("GOOGLE_API_KEY", "")
vt_active = vt_key and not vt_key.startswith("your-")
gemini_active = gemini_key and not gemini_key.startswith("your-")

st.markdown(f"""
<div class="header-wrapper">
    <div class="brand-section">
        <div class="brand-icon">{get_icon("logo", size=32, color="#6366f1")}</div>
        <div>
            <h1 style="font-size: 1.25rem; margin: 0;">Sentinel</h1>
            <p style="font-size: 0.8rem; margin: 0; opacity: 0.7;">Enterprise Security Intelligence</p>
        </div>
    </div>
    <div style="display: flex; gap: 1rem;">
        <div class="status-badge">
            <div class="status-dot {'active' if vt_active else ''}"></div>
            VirusTotal
        </div>
        <div class="status-badge">
            <div class="status-dot {'active' if gemini_active else ''}"></div>
            Gemini AI
        </div>
        <div class="status-badge">
            {get_icon("activity", size=14)}
            {len(st.session_state.analysis_history)} Ops
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# =============================================================================
# MAIN TABS
# =============================================================================

tab_threat, tab_incident, tab_history = st.tabs(["Threat Analysis", "Incident Response", "Activity Log"])

# --- THREAT ANALYSIS ---
with tab_threat:
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Input Area
    with st.container():
        c1, c2, c3 = st.columns([5, 2, 1])
        with c1:
            indicator = st.text_input("Indicator", placeholder="IP, Domain, Hash...", label_visibility="collapsed")
        with c2:
            indicator_type = st.selectbox("Type", ["ip", "domain", "hash", "url"], label_visibility="collapsed")
        with c3:
            analyze = st.button("Analyze", type="primary", use_container_width=True)

    if analyze and indicator:
        with st.spinner(" querying threat intelligence..."):
            if indicator_type == "ip": result_json = get_ip_report(indicator)
            elif indicator_type == "domain": result_json = get_domain_report(indicator)
            elif indicator_type == "hash": result_json = get_hash_report(indicator)
            else: result_json = get_url_report(indicator)
            
            result = json.loads(result_json)
            result['analyzed_at'] = datetime.now().isoformat()
            st.session_state.analysis_history.insert(0, result)

        # Result Display
        sev = result.get('severity', 'UNKNOWN').upper()
        sev_cls = f"badge-{sev.lower()}" if sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] else "badge-low"
        
        st.markdown(f"""
        <div class="glass-panel" style="margin-top: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: start;">
                <div>
                    <span class="badge {sev_cls}">{sev}</span>
                    <h2 style="margin: 0.5rem 0; font-family: 'JetBrains Mono'; font-size: 1.5rem;">{result.get('indicator', indicator)}</h2>
                    <p style="font-size: 0.9rem;">Analysis Source: {'VirusTotal (Live)' if not result.get('source', '').endswith('(MOCK)') else 'Simulation Mode'}</p>
                </div>
                <div style="text-align: right;">
                    <div style="font-family: 'JetBrains Mono'; font-size: 0.8rem; color: var(--text-secondary);">{datetime.now().strftime('%H:%M:%S')} UTC</div>
                </div>
            </div>
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border-color);">
                <div class="metric-box">
                    <div class="metric-val">{result.get('confidence', 0)}%</div>
                    <div class="metric-lbl">Confidence</div>
                </div>
                <div class="metric-box">
                    <div class="metric-val">{result.get('detection_ratio', 'N/A')}</div>
                    <div class="metric-lbl">Detections</div>
                </div>
                <div class="metric-box">
                    <div class="metric-val">{result.get('indicator_type', indicator_type).upper()}</div>
                    <div class="metric-lbl">Type</div>
                </div>
                <div class="metric-box">
                    <div class="metric-val">{get_icon("activity", size=20)}</div>
                    <div class="metric-lbl">Active</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Raw Data
        with st.expander("View Raw JSON Payload"):
            st.json(result)

        # Actions if High Severity
        if sev in ['CRITICAL', 'HIGH']:
            st.markdown("### Recommended Actions")
            ac1, ac2, ac3 = st.columns(3)
            with ac1:
                if st.button("Block Indicator", use_container_width=True):
                    if indicator_type == "ip":
                        res = json.loads(block_ip(indicator))
                        st.success(f"Action Executed: {res.get('message')}")
            with ac2:
                if st.button("Create Incident Case", use_container_width=True):
                    res = json.loads(create_case(f"Threat: {indicator}", sev, "Auto-created from analysis"))
                    st.session_state.incidents.insert(0, res)
                    st.success(f"Case {res.get('case_id')} Created")
            with ac3:
                st.button("Escalate to SOC", disabled=True, use_container_width=True)

# --- INCIDENT RESPONSE ---
with tab_incident:
    st.markdown("<br>", unsafe_allow_html=True)
    
    with st.container():
        st.markdown("#### Create Incident")
        ic1, ic2 = st.columns([3, 1])
        with ic1: title = st.text_input("Title", placeholder="e.g. Malware Outbreak", label_visibility="collapsed")
        with ic2: severity = st.selectbox("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], label_visibility="collapsed")
        desc = st.text_area("Description", placeholder="Incident details...", label_visibility="collapsed")
        
        if st.button("Initialize Case", type="primary"):
            if title:
                res = json.loads(create_case(title, severity, desc))
                st.session_state.incidents.insert(0, res)
                st.success(f"Case {res.get('case_id')} Initialized")
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("#### Response Playbooks")
    
    rc1, rc2, rc3 = st.columns(3)
    
    # Card 1: Block
    with rc1:
        st.markdown(f"""
        <div class="glass-panel" style="text-align: center;">
            <div style="color: var(--text-primary); margin-bottom: 1rem;">{get_icon("shield", size=32)}</div>
            <h3 style="font-size: 1rem;">Network Block</h3>
            <p style="font-size: 0.8rem;">Block IP at firewall perimeter</p>
        </div>
        """, unsafe_allow_html=True)
        blk_ip = st.text_input("IP Address", key="act_blk")
        if st.button("Execute Block", use_container_width=True):
            if blk_ip: st.success(json.loads(block_ip(blk_ip))['message'])

    # Card 2: Isolate
    with rc2:
        st.markdown(f"""
        <div class="glass-panel" style="text-align: center;">
            <div style="color: var(--text-primary); margin-bottom: 1rem;">{get_icon("lock", size=32)}</div>
            <h3 style="font-size: 1rem;">Host Isolation</h3>
            <p style="font-size: 0.8rem;">Disconnect host from network</p>
        </div>
        """, unsafe_allow_html=True)
        iso_host = st.text_input("Hostname", key="act_iso")
        if st.button("Isolate Host", use_container_width=True):
            if iso_host: st.success(json.loads(isolate_endpoint(iso_host))['message'])

    # Card 3: Disable User
    with rc3:
        st.markdown(f"""
        <div class="glass-panel" style="text-align: center;">
            <div style="color: var(--text-primary); margin-bottom: 1rem;">{get_icon("user-x", size=32)}</div>
            <h3 style="font-size: 1rem;">Suspend User</h3>
            <p style="font-size: 0.8rem;">Revoke IAM credentials</p>
        </div>
        """, unsafe_allow_html=True)
        dis_user = st.text_input("Username", key="act_dis")
        if st.button("Suspend User", use_container_width=True):
            if dis_user: st.success(json.loads(disable_user(dis_user))['message'])

    # Active Incidents
    if st.session_state.incidents:
        st.markdown("#### Active Operations")
        for inc in st.session_state.incidents[:5]:
            isev = inc.get('severity', 'MEDIUM')
            isev_cls = f"badge-{isev.lower()}"
            st.markdown(f"""
            <div class="glass-panel" style="padding: 1rem; display: flex; justify-content: space-between; align-items: center;">
                <div style="display: flex; gap: 1rem; align-items: center;">
                    <span class="badge {isev_cls}">{isev}</span>
                    <div>
                        <div style="font-family: 'JetBrains Mono'; font-size: 0.9rem;">{inc.get('case_id')}</div>
                        <div style="font-size: 0.85rem; color: var(--text-secondary);">{inc.get('title')}</div>
                    </div>
                </div>
                <div style="font-size: 0.8rem; color: var(--accent-primary);">{inc.get('status')}</div>
            </div>
            """, unsafe_allow_html=True)

# --- ACTIVITY LOG ---
with tab_history:
    st.markdown("<br>", unsafe_allow_html=True)
    
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.markdown("#### Analysis Feed")
        if not st.session_state.analysis_history:
            st.info("No activity recorded")
        for item in st.session_state.analysis_history[:10]:
            sev = item.get('severity', 'LOW')
            st.markdown(f"""
            <div style="padding: 0.8rem; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between;">
                <span style="font-family: 'JetBrains Mono'; font-size: 0.85rem;">{item.get('indicator')}</span>
                <span class="badge badge-{sev.lower()}">{sev}</span>
            </div>
            """, unsafe_allow_html=True)

    with col_b:
        st.markdown("#### Incident Feed")
        if not st.session_state.incidents:
            st.info("No incidents recorded")
        for item in st.session_state.incidents[:10]:
            sev = item.get('severity', 'LOW')
            st.markdown(f"""
            <div style="padding: 0.8rem; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between;">
                <span style="font-family: 'JetBrains Mono'; font-size: 0.85rem;">{item.get('case_id')}</span>
                <span class="badge badge-{sev.lower()}">{sev}</span>
            </div>
            """, unsafe_allow_html=True)

    if st.button("Clear Audit Log"):
        st.session_state.analysis_history = []
        st.session_state.incidents = []
        st.rerun()

# Footer
st.markdown("""
<div style="text-align: center; margin-top: 4rem; padding-top: 2rem; border-top: 1px solid var(--border-color); color: var(--text-secondary); font-size: 0.8rem;">
    Sentinel v2.0 • Intelligent Security Operations
</div>
""", unsafe_allow_html=True)

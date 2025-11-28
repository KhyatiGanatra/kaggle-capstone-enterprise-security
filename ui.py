"""
Multi-Agent Security System - Web UI
=====================================
A modern, elegant interface for the security multi-agent system.

Run with: streamlit run ui.py
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
# PAGE CONFIG
# =============================================================================

st.set_page_config(
    page_title="Sentinel",
    page_icon="◆",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# =============================================================================
# CUSTOM CSS - Modern Elegant Design
# =============================================================================

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    /* Root variables */
    :root {
        --bg-primary: #0a0a0f;
        --bg-secondary: #12121a;
        --bg-card: rgba(22, 22, 32, 0.8);
        --bg-hover: rgba(255, 255, 255, 0.03);
        --border-subtle: rgba(255, 255, 255, 0.06);
        --border-accent: rgba(99, 102, 241, 0.4);
        --text-primary: #f4f4f5;
        --text-secondary: #a1a1aa;
        --text-muted: #52525b;
        --accent-primary: #818cf8;
        --accent-green: #34d399;
        --accent-amber: #fbbf24;
        --accent-red: #f87171;
        --accent-cyan: #22d3ee;
    }
    
    /* Global reset */
    .stApp {
        background: var(--bg-primary);
        font-family: 'Sora', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    .stApp > header {
        background: transparent;
    }
    
    /* Hide streamlit elements */
    #MainMenu, footer, .stDeployButton {
        display: none;
    }
    
    /* Main container */
    .main .block-container {
        padding: 2rem 3rem;
        max-width: 1400px;
    }
    
    /* Typography */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Sora', sans-serif !important;
        font-weight: 600;
        color: var(--text-primary);
    }
    
    p, span, div {
        color: var(--text-secondary);
    }
    
    /* Custom header */
    .header-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 1.5rem 0 2.5rem 0;
        border-bottom: 1px solid var(--border-subtle);
        margin-bottom: 2rem;
    }
    
    .logo-section {
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    
    .logo-icon {
        width: 48px;
        height: 48px;
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #a855f7 100%);
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.5rem;
        color: white;
        box-shadow: 0 8px 32px rgba(99, 102, 241, 0.25);
    }
    
    .logo-text h1 {
        font-size: 1.75rem;
        font-weight: 700;
        margin: 0;
        background: linear-gradient(135deg, #f4f4f5 0%, #a1a1aa 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        letter-spacing: -0.03em;
    }
    
    .logo-text p {
        font-size: 0.85rem;
        color: var(--text-muted);
        margin: 0;
        font-weight: 400;
    }
    
    .status-pills {
        display: flex;
        gap: 0.75rem;
    }
    
    .status-pill {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.5rem 1rem;
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 100px;
        font-size: 0.8rem;
        font-weight: 500;
    }
    
    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        animation: pulse 2s infinite;
    }
    
    .status-dot.active {
        background: var(--accent-green);
        box-shadow: 0 0 12px var(--accent-green);
    }
    
    .status-dot.inactive {
        background: var(--text-muted);
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    
    /* Tabs styling */
    .stTabs [data-baseweb="tab-list"] {
        background: var(--bg-secondary);
        border-radius: 16px;
        padding: 0.5rem;
        gap: 0.5rem;
        border: 1px solid var(--border-subtle);
    }
    
    .stTabs [data-baseweb="tab"] {
        background: transparent;
        border-radius: 12px;
        padding: 0.75rem 1.5rem;
        font-family: 'Sora', sans-serif;
        font-weight: 500;
        font-size: 0.9rem;
        color: var(--text-secondary);
        border: none;
    }
    
    .stTabs [data-baseweb="tab"]:hover {
        background: var(--bg-hover);
        color: var(--text-primary);
    }
    
    .stTabs [aria-selected="true"] {
        background: var(--bg-card) !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border-subtle) !important;
    }
    
    .stTabs [data-baseweb="tab-highlight"] {
        display: none;
    }
    
    .stTabs [data-baseweb="tab-border"] {
        display: none;
    }
    
    /* Cards */
    .glass-card {
        background: var(--bg-card);
        backdrop-filter: blur(20px);
        border: 1px solid var(--border-subtle);
        border-radius: 20px;
        padding: 1.5rem;
        margin: 1rem 0;
        transition: all 0.3s ease;
    }
    
    .glass-card:hover {
        border-color: var(--border-accent);
        box-shadow: 0 8px 32px rgba(99, 102, 241, 0.1);
    }
    
    /* Input styling */
    .stTextInput > div > div {
        background: var(--bg-secondary) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 12px !important;
        font-family: 'JetBrains Mono', monospace !important;
        color: var(--text-primary) !important;
    }
    
    .stTextInput > div > div:focus-within {
        border-color: var(--accent-primary) !important;
        box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15) !important;
    }
    
    .stTextInput input {
        color: var(--text-primary) !important;
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    .stTextInput input::placeholder {
        color: var(--text-muted) !important;
    }
    
    .stTextArea textarea {
        background: var(--bg-secondary) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 12px !important;
        color: var(--text-primary) !important;
        font-family: 'Sora', sans-serif !important;
    }
    
    /* Select box */
    .stSelectbox > div > div {
        background: var(--bg-secondary) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 12px !important;
    }
    
    .stSelectbox [data-baseweb="select"] > div {
        background: var(--bg-secondary) !important;
        border-color: var(--border-subtle) !important;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 12px !important;
        padding: 0.75rem 2rem !important;
        font-family: 'Sora', sans-serif !important;
        font-weight: 600 !important;
        font-size: 0.9rem !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3) !important;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 25px rgba(99, 102, 241, 0.4) !important;
    }
    
    .stButton > button:active {
        transform: translateY(0) !important;
    }
    
    /* Secondary button style */
    .secondary-btn > button {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-subtle) !important;
        box-shadow: none !important;
    }
    
    .secondary-btn > button:hover {
        border-color: var(--accent-primary) !important;
        background: var(--bg-hover) !important;
    }
    
    /* Metrics */
    .metric-container {
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 16px;
        padding: 1.25rem;
        text-align: center;
        transition: all 0.3s ease;
    }
    
    .metric-container:hover {
        border-color: var(--border-accent);
        transform: translateY(-2px);
    }
    
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: var(--text-primary);
        font-family: 'JetBrains Mono', monospace;
    }
    
    .metric-label {
        font-size: 0.8rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.1em;
        margin-top: 0.5rem;
    }
    
    /* Severity badges */
    .severity-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.5rem 1rem;
        border-radius: 100px;
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    .severity-critical {
        background: rgba(248, 113, 113, 0.15);
        color: var(--accent-red);
        border: 1px solid rgba(248, 113, 113, 0.3);
    }
    
    .severity-high {
        background: rgba(251, 191, 36, 0.15);
        color: var(--accent-amber);
        border: 1px solid rgba(251, 191, 36, 0.3);
    }
    
    .severity-medium {
        background: rgba(34, 211, 238, 0.15);
        color: var(--accent-cyan);
        border: 1px solid rgba(34, 211, 238, 0.3);
    }
    
    .severity-low {
        background: rgba(52, 211, 153, 0.15);
        color: var(--accent-green);
        border: 1px solid rgba(52, 211, 153, 0.3);
    }
    
    /* Results card */
    .results-card {
        background: var(--bg-secondary);
        border: 1px solid var(--border-subtle);
        border-radius: 20px;
        padding: 2rem;
        margin: 1.5rem 0;
    }
    
    /* Action grid */
    .action-card {
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 16px;
        padding: 1.5rem;
        height: 100%;
        transition: all 0.3s ease;
    }
    
    .action-card:hover {
        border-color: var(--border-accent);
        background: rgba(99, 102, 241, 0.05);
    }
    
    .action-icon {
        width: 48px;
        height: 48px;
        background: var(--bg-secondary);
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.5rem;
        margin-bottom: 1rem;
    }
    
    /* Expander */
    .streamlit-expanderHeader {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 12px !important;
        font-family: 'Sora', sans-serif !important;
    }
    
    .streamlit-expanderContent {
        background: var(--bg-secondary) !important;
        border: 1px solid var(--border-subtle) !important;
        border-top: none !important;
        border-radius: 0 0 12px 12px !important;
    }
    
    /* JSON viewer */
    .stJson {
        background: var(--bg-primary) !important;
        border-radius: 12px !important;
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    /* Alert boxes */
    .stAlert {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 12px !important;
    }
    
    .stSuccess {
        border-left: 4px solid var(--accent-green) !important;
    }
    
    .stWarning {
        border-left: 4px solid var(--accent-amber) !important;
    }
    
    .stError {
        border-left: 4px solid var(--accent-red) !important;
    }
    
    /* History item */
    .history-item {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 1rem 1.5rem;
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        margin: 0.5rem 0;
        transition: all 0.2s ease;
    }
    
    .history-item:hover {
        border-color: var(--border-accent);
        background: var(--bg-hover);
    }
    
    /* Incident row */
    .incident-row {
        display: flex;
        align-items: center;
        gap: 1rem;
        padding: 1rem 1.5rem;
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        margin: 0.75rem 0;
    }
    
    /* Empty state */
    .empty-state {
        text-align: center;
        padding: 4rem 2rem;
        color: var(--text-muted);
    }
    
    .empty-state-icon {
        font-size: 3rem;
        margin-bottom: 1rem;
        opacity: 0.5;
    }
    
    /* Footer */
    .footer {
        text-align: center;
        padding: 2rem;
        margin-top: 3rem;
        border-top: 1px solid var(--border-subtle);
        color: var(--text-muted);
        font-size: 0.85rem;
    }
    
    /* Streamlit overrides */
    .st-emotion-cache-1v0mbdj {
        margin-top: 1rem;
    }
    
    /* Hide default metric styling */
    [data-testid="stMetricValue"] {
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    [data-testid="stMetricLabel"] {
        color: var(--text-muted) !important;
    }
    
    /* Divider */
    hr {
        border-color: var(--border-subtle) !important;
        margin: 2rem 0 !important;
    }
</style>
""", unsafe_allow_html=True)

# =============================================================================
# SESSION STATE
# =============================================================================

if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []

if 'incidents' not in st.session_state:
    st.session_state.incidents = []

# =============================================================================
# HEADER
# =============================================================================

vt_key = os.getenv("VT_APIKEY", "")
gemini_key = os.getenv("GOOGLE_API_KEY", "")
vt_active = vt_key and not vt_key.startswith("your-")
gemini_active = gemini_key and not gemini_key.startswith("your-")

st.markdown(f"""
<div class="header-container">
    <div class="logo-section">
        <div class="logo-icon">◆</div>
        <div class="logo-text">
            <h1>Sentinel</h1>
            <p>Security Intelligence Platform</p>
        </div>
    </div>
    <div class="status-pills">
        <div class="status-pill">
            <div class="status-dot {'active' if vt_active else 'inactive'}"></div>
            <span style="color: var(--text-secondary);">VirusTotal</span>
        </div>
        <div class="status-pill">
            <div class="status-dot {'active' if gemini_active else 'inactive'}"></div>
            <span style="color: var(--text-secondary);">Gemini AI</span>
        </div>
        <div class="status-pill">
            <span style="color: var(--text-muted);">Analyzed: {len(st.session_state.analysis_history)}</span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# =============================================================================
# MAIN CONTENT
# =============================================================================

tab1, tab2, tab3 = st.tabs(["◈  Threat Analysis", "◈  Incident Response", "◈  Activity Log"])

# -----------------------------------------------------------------------------
# TAB 1: THREAT ANALYSIS
# -----------------------------------------------------------------------------

with tab1:
    st.markdown("<div style='height: 1.5rem'></div>", unsafe_allow_html=True)
    
    # Search section
    col1, col2, col3 = st.columns([4, 1, 1])
    
    with col1:
        indicator = st.text_input(
            "Indicator",
            placeholder="Enter IP address, domain, file hash, or URL...",
            label_visibility="collapsed"
        )
    
    with col2:
        indicator_type = st.selectbox(
            "Type",
            ["ip", "domain", "hash", "url"],
            label_visibility="collapsed"
        )
    
    with col3:
        analyze_button = st.button("Analyze", type="primary", use_container_width=True)
    
    if analyze_button and indicator:
        with st.spinner(""):
            # Call the appropriate tool
            if indicator_type == "ip":
                result_json = get_ip_report(indicator)
            elif indicator_type == "domain":
                result_json = get_domain_report(indicator)
            elif indicator_type == "hash":
                result_json = get_hash_report(indicator)
            else:
                result_json = get_url_report(indicator)
            
            result = json.loads(result_json)
            result['analyzed_at'] = datetime.now().isoformat()
            
            # Store in history
            st.session_state.analysis_history.insert(0, result)
        
        # Results
        st.markdown("<div style='height: 1rem'></div>", unsafe_allow_html=True)
        
        severity = result.get('severity', 'UNKNOWN')
        severity_class = severity.lower() if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] else 'medium'
        
        st.markdown(f"""
        <div class="results-card">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 2rem;">
                <div>
                    <span class="severity-badge severity-{severity_class}">{severity}</span>
                    <h2 style="margin: 1rem 0 0.5rem 0; font-size: 1.5rem; color: var(--text-primary);">{result.get('indicator', indicator)}</h2>
                    <p style="color: var(--text-muted); font-size: 0.9rem;">Analyzed at {datetime.now().strftime('%H:%M:%S')} • {'Live Data' if not result.get('source', '').endswith('(MOCK)') else 'Demo Mode'}</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown(f"""
            <div class="metric-container">
                <div class="metric-value">{result.get('confidence', 0)}%</div>
                <div class="metric-label">Confidence</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="metric-container">
                <div class="metric-value">{result.get('detection_ratio', 'N/A')}</div>
                <div class="metric-label">Detections</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div class="metric-container">
                <div class="metric-value">{result.get('indicator_type', indicator_type).upper()}</div>
                <div class="metric-label">Type</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            source_label = "VT" if not result.get('source', '').endswith('(MOCK)') else "MOCK"
            st.markdown(f"""
            <div class="metric-container">
                <div class="metric-value">{source_label}</div>
                <div class="metric-label">Source</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Details expander
        st.markdown("<div style='height: 1rem'></div>", unsafe_allow_html=True)
        with st.expander("View Raw Intelligence Data"):
            st.json(result)
        
        # Quick actions for high severity
        if severity in ['CRITICAL', 'HIGH']:
            st.markdown("<div style='height: 1rem'></div>", unsafe_allow_html=True)
            st.warning(f"⚡ **Elevated threat level detected.** Recommended: Take immediate action.")
            
            col1, col2, col3, _ = st.columns([1, 1, 1, 1])
            
            with col1:
                if st.button("🚫  Block Indicator", use_container_width=True):
                    if indicator_type == "ip":
                        action_result = json.loads(block_ip(indicator))
                        st.success(f"✓ {action_result['message']}")
            
            with col2:
                if st.button("📋  Create Case", use_container_width=True):
                    case_result = json.loads(create_case(
                        f"Threat Alert: {indicator}",
                        severity,
                        f"Auto-generated from threat analysis"
                    ))
                    st.session_state.incidents.insert(0, case_result)
                    st.success(f"✓ Case {case_result['case_id']} created")
            
            with col3:
                if st.button("📤  Escalate", use_container_width=True):
                    st.info("Escalation notification sent to SOC team")
    
    elif not indicator and analyze_button:
        st.error("Please enter an indicator to analyze")

# -----------------------------------------------------------------------------
# TAB 2: INCIDENT RESPONSE
# -----------------------------------------------------------------------------

with tab2:
    st.markdown("<div style='height: 1.5rem'></div>", unsafe_allow_html=True)
    
    # Create incident section
    st.markdown("#### New Incident Case")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        incident_title = st.text_input("Title", placeholder="Brief description of the incident", label_visibility="collapsed")
    
    with col2:
        incident_severity = st.selectbox("Sev", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], label_visibility="collapsed")
    
    incident_desc = st.text_area("Description", placeholder="Detailed incident description...", height=100, label_visibility="collapsed")
    
    if st.button("Create Case", type="primary"):
        if incident_title:
            case_result = json.loads(create_case(incident_title, incident_severity, incident_desc))
            st.session_state.incidents.insert(0, case_result)
            st.success(f"✓ Case {case_result['case_id']} created successfully")
        else:
            st.error("Please provide a title")
    
    st.markdown("---")
    
    # Response actions
    st.markdown("#### Response Actions")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="action-card">
            <div class="action-icon">🚫</div>
            <h4 style="color: var(--text-primary); margin: 0 0 0.5rem 0;">Block IP</h4>
            <p style="font-size: 0.85rem; margin-bottom: 1rem;">Add IP to firewall blocklist</p>
        </div>
        """, unsafe_allow_html=True)
        block_ip_input = st.text_input("IP Address", placeholder="x.x.x.x", key="block_ip", label_visibility="collapsed")
        if st.button("Execute", key="block_btn", use_container_width=True):
            if block_ip_input:
                result = json.loads(block_ip(block_ip_input))
                st.success(f"✓ {result['message']}")
    
    with col2:
        st.markdown("""
        <div class="action-card">
            <div class="action-icon">🔒</div>
            <h4 style="color: var(--text-primary); margin: 0 0 0.5rem 0;">Isolate Endpoint</h4>
            <p style="font-size: 0.85rem; margin-bottom: 1rem;">Network isolation for host</p>
        </div>
        """, unsafe_allow_html=True)
        isolate_input = st.text_input("Hostname", placeholder="workstation-01", key="isolate", label_visibility="collapsed")
        if st.button("Execute", key="isolate_btn", use_container_width=True):
            if isolate_input:
                result = json.loads(isolate_endpoint(isolate_input))
                st.success(f"✓ {result['message']}")
    
    with col3:
        st.markdown("""
        <div class="action-card">
            <div class="action-icon">👤</div>
            <h4 style="color: var(--text-primary); margin: 0 0 0.5rem 0;">Disable User</h4>
            <p style="font-size: 0.85rem; margin-bottom: 1rem;">Suspend user account access</p>
        </div>
        """, unsafe_allow_html=True)
        disable_input = st.text_input("Username", placeholder="jdoe", key="disable", label_visibility="collapsed")
        if st.button("Execute", key="disable_btn", use_container_width=True):
            if disable_input:
                result = json.loads(disable_user(disable_input))
                st.success(f"✓ {result['message']}")
    
    # Active incidents
    st.markdown("---")
    st.markdown("#### Active Cases")
    
    if st.session_state.incidents:
        for incident in st.session_state.incidents[:5]:
            severity = incident.get('severity', 'MEDIUM')
            severity_class = severity.lower()
            
            st.markdown(f"""
            <div class="incident-row">
                <span class="severity-badge severity-{severity_class}">{severity}</span>
                <div style="flex: 1;">
                    <strong style="color: var(--text-primary);">{incident.get('case_id', 'Unknown')}</strong>
                    <span style="color: var(--text-muted); margin-left: 1rem;">{incident.get('title', 'Untitled')}</span>
                </div>
                <span style="color: var(--text-muted); font-size: 0.85rem;">{incident.get('status', 'Open')}</span>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="empty-state">
            <div class="empty-state-icon">📋</div>
            <p>No active cases</p>
        </div>
        """, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# TAB 3: ACTIVITY LOG
# -----------------------------------------------------------------------------

with tab3:
    st.markdown("<div style='height: 1.5rem'></div>", unsafe_allow_html=True)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### Threat Analysis Log")
        
        if st.session_state.analysis_history:
            for analysis in st.session_state.analysis_history[:10]:
                severity = analysis.get('severity', 'UNKNOWN')
                severity_class = severity.lower() if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] else 'medium'
                
                st.markdown(f"""
                <div class="history-item">
                    <div style="display: flex; align-items: center; gap: 1rem;">
                        <span class="severity-badge severity-{severity_class}" style="font-size: 0.7rem; padding: 0.35rem 0.75rem;">{severity}</span>
                        <code style="color: var(--text-primary); font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">{analysis.get('indicator', 'Unknown')}</code>
                    </div>
                    <span style="color: var(--text-muted); font-size: 0.8rem;">{analysis.get('detection_ratio', 'N/A')}</span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="empty-state">
                <div class="empty-state-icon">🔍</div>
                <p>No analysis history yet</p>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("#### Incident Log")
        
        if st.session_state.incidents:
            for incident in st.session_state.incidents[:10]:
                severity = incident.get('severity', 'MEDIUM')
                severity_class = severity.lower()
                
                st.markdown(f"""
                <div class="history-item">
                    <div style="display: flex; align-items: center; gap: 1rem;">
                        <span class="severity-badge severity-{severity_class}" style="font-size: 0.7rem; padding: 0.35rem 0.75rem;">{severity}</span>
                        <span style="color: var(--text-primary); font-size: 0.85rem;">{incident.get('case_id', 'Unknown')}</span>
                    </div>
                    <span style="color: var(--text-muted); font-size: 0.8rem;">{incident.get('status', 'Open')}</span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="empty-state">
                <div class="empty-state-icon">🚨</div>
                <p>No incidents created</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Clear button
    st.markdown("<div style='height: 2rem'></div>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        if st.button("Clear All History", use_container_width=True):
            st.session_state.analysis_history = []
            st.session_state.incidents = []
            st.rerun()

# =============================================================================
# FOOTER
# =============================================================================

st.markdown("""
<div class="footer">
    <p style="margin: 0;">Sentinel Security Platform • Multi-Agent System</p>
    <p style="margin: 0.5rem 0 0 0; opacity: 0.5;">Built with Google ADK + Streamlit</p>
</div>
""", unsafe_allow_html=True)

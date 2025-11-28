"""
Multi-Agent Security System - Web UI
=====================================
A Streamlit-based interface for the security multi-agent system.

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
    ThreatAnalysisAgent, 
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
    page_title="Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# CUSTOM CSS
# =============================================================================

st.markdown("""
<style>
    /* Dark theme inspired styling */
    .stApp {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    }
    
    /* Header styling */
    .main-header {
        background: linear-gradient(90deg, #0f3460 0%, #533483 100%);
        padding: 1.5rem 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
    
    .main-header h1 {
        color: #e94560;
        margin: 0;
        font-size: 2rem;
    }
    
    .main-header p {
        color: #a0a0a0;
        margin: 0.5rem 0 0 0;
    }
    
    /* Card styling */
    .metric-card {
        background: rgba(15, 52, 96, 0.5);
        border: 1px solid #533483;
        border-radius: 10px;
        padding: 1.5rem;
        text-align: center;
    }
    
    .severity-critical {
        background: linear-gradient(135deg, #ff4757 0%, #c0392b 100%);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 5px;
        font-weight: bold;
    }
    
    .severity-high {
        background: linear-gradient(135deg, #ffa502 0%, #e67e22 100%);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 5px;
        font-weight: bold;
    }
    
    .severity-medium {
        background: linear-gradient(135deg, #f9ca24 0%, #f39c12 100%);
        color: black;
        padding: 0.5rem 1rem;
        border-radius: 5px;
        font-weight: bold;
    }
    
    .severity-low {
        background: linear-gradient(135deg, #2ed573 0%, #27ae60 100%);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 5px;
        font-weight: bold;
    }
    
    /* Result box */
    .result-box {
        background: rgba(15, 52, 96, 0.7);
        border: 1px solid #533483;
        border-radius: 10px;
        padding: 1.5rem;
        margin: 1rem 0;
    }
    
    /* Action button */
    .action-taken {
        background: rgba(46, 213, 115, 0.2);
        border-left: 4px solid #2ed573;
        padding: 0.75rem 1rem;
        margin: 0.5rem 0;
        border-radius: 0 5px 5px 0;
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

st.markdown("""
<div class="main-header">
    <h1>🛡️ Security Operations Center</h1>
    <p>Multi-Agent Threat Analysis & Incident Response System</p>
</div>
""", unsafe_allow_html=True)

# =============================================================================
# SIDEBAR
# =============================================================================

with st.sidebar:
    st.markdown("## ⚙️ Configuration")
    
    # API Status
    vt_key = os.getenv("VT_APIKEY", "")
    gemini_key = os.getenv("GOOGLE_API_KEY", "")
    
    st.markdown("### API Status")
    if vt_key and not vt_key.startswith("your-"):
        st.success("✅ VirusTotal API: Connected")
    else:
        st.warning("⚠️ VirusTotal: Mock Mode")
    
    if gemini_key and not gemini_key.startswith("your-"):
        st.success("✅ Gemini API: Connected")
    else:
        st.error("❌ Gemini API: Not configured")
    
    st.markdown("---")
    
    # Stats
    st.markdown("### 📊 Session Stats")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Analyzed", len(st.session_state.analysis_history))
    with col2:
        st.metric("Incidents", len(st.session_state.incidents))
    
    # Quick links
    st.markdown("---")
    st.markdown("### 🔗 Quick Actions")
    if st.button("🗑️ Clear History", use_container_width=True):
        st.session_state.analysis_history = []
        st.session_state.incidents = []
        st.rerun()

# =============================================================================
# MAIN CONTENT
# =============================================================================

# Tabs
tab1, tab2, tab3 = st.tabs(["🔍 Threat Analysis", "🚨 Incident Response", "📋 History"])

# -----------------------------------------------------------------------------
# TAB 1: THREAT ANALYSIS
# -----------------------------------------------------------------------------

with tab1:
    st.markdown("### Analyze Security Indicator")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        indicator = st.text_input(
            "Enter indicator to analyze",
            placeholder="e.g., 203.0.113.42, evil-site.com, or a file hash",
            label_visibility="collapsed"
        )
    
    with col2:
        indicator_type = st.selectbox(
            "Type",
            ["ip", "domain", "hash", "url"],
            label_visibility="collapsed"
        )
    
    analyze_button = st.button("🔍 Analyze Threat", type="primary", use_container_width=True)
    
    if analyze_button and indicator:
        with st.spinner("Analyzing with VirusTotal..."):
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
        
        # Display results
        st.markdown("---")
        st.markdown("### Analysis Results")
        
        # Severity badge
        severity = result.get('severity', 'UNKNOWN')
        severity_colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'UNKNOWN': '⚪'
        }
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Severity", f"{severity_colors.get(severity, '⚪')} {severity}")
        
        with col2:
            st.metric("Confidence", f"{result.get('confidence', 0)}%")
        
        with col3:
            st.metric("Detection", result.get('detection_ratio', 'N/A'))
        
        with col4:
            st.metric("Source", "Mock" if result.get('source', '').endswith('(MOCK)') else "VirusTotal")
        
        # Details
        with st.expander("📄 Full Details", expanded=True):
            st.json(result)
        
        # Actions for high severity
        if severity in ['CRITICAL', 'HIGH']:
            st.markdown("---")
            st.warning(f"⚠️ **{severity} threat detected!** Consider taking immediate action.")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("🚫 Block Indicator", use_container_width=True):
                    if indicator_type == "ip":
                        action_result = json.loads(block_ip(indicator))
                        st.success(f"✅ {action_result['message']}")
            
            with col2:
                if st.button("📋 Create Incident", use_container_width=True):
                    case_result = json.loads(create_case(
                        f"Threat: {indicator}",
                        severity,
                        f"Auto-generated from threat analysis"
                    ))
                    st.session_state.incidents.insert(0, case_result)
                    st.success(f"✅ Created {case_result['case_id']}")
            
            with col3:
                if st.button("🔒 Escalate", use_container_width=True):
                    st.info("Escalation would notify SOC team")

# -----------------------------------------------------------------------------
# TAB 2: INCIDENT RESPONSE
# -----------------------------------------------------------------------------

with tab2:
    st.markdown("### Create New Incident")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        incident_title = st.text_input("Incident Title", placeholder="e.g., Malware detected on workstation")
    
    with col2:
        incident_severity = st.selectbox("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    
    incident_desc = st.text_area("Description", placeholder="Describe the incident...")
    
    if st.button("🚨 Create Incident Case", type="primary"):
        if incident_title:
            case_result = json.loads(create_case(incident_title, incident_severity, incident_desc))
            st.session_state.incidents.insert(0, case_result)
            st.success(f"✅ Created incident: {case_result['case_id']}")
    
    st.markdown("---")
    st.markdown("### 🛠️ Response Actions")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("#### Block IP")
        block_ip_input = st.text_input("IP Address", placeholder="x.x.x.x", key="block_ip")
        if st.button("🚫 Block", key="block_ip_btn"):
            if block_ip_input:
                result = json.loads(block_ip(block_ip_input))
                st.success(f"✅ {result['message']}")
    
    with col2:
        st.markdown("#### Isolate Endpoint")
        isolate_input = st.text_input("Hostname", placeholder="workstation-01", key="isolate")
        if st.button("🔒 Isolate", key="isolate_btn"):
            if isolate_input:
                result = json.loads(isolate_endpoint(isolate_input))
                st.success(f"✅ {result['message']}")
    
    with col3:
        st.markdown("#### Disable User")
        disable_input = st.text_input("Username", placeholder="jdoe", key="disable")
        if st.button("👤 Disable", key="disable_btn"):
            if disable_input:
                result = json.loads(disable_user(disable_input))
                st.success(f"✅ {result['message']}")
    
    # Active incidents
    st.markdown("---")
    st.markdown("### 📋 Active Incidents")
    
    if st.session_state.incidents:
        for incident in st.session_state.incidents[:5]:
            severity = incident.get('severity', 'MEDIUM')
            severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
            
            with st.expander(f"{severity_emoji} {incident.get('case_id', 'Unknown')} - {incident.get('title', 'Untitled')}", expanded=False):
                st.write(f"**Status:** {incident.get('status', 'Open')}")
                st.write(f"**Created:** {incident.get('created_at', 'Unknown')}")
                if incident.get('actions_taken'):
                    st.write("**Actions:**")
                    for action in incident['actions_taken']:
                        st.write(f"  • {action}")
    else:
        st.info("No active incidents")

# -----------------------------------------------------------------------------
# TAB 3: HISTORY
# -----------------------------------------------------------------------------

with tab3:
    st.markdown("### Analysis History")
    
    if st.session_state.analysis_history:
        for i, analysis in enumerate(st.session_state.analysis_history[:10]):
            severity = analysis.get('severity', 'UNKNOWN')
            severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
            
            col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
            
            with col1:
                st.write(f"{severity_emoji} **{analysis.get('indicator', 'Unknown')}**")
            with col2:
                st.write(analysis.get('indicator_type', 'N/A'))
            with col3:
                st.write(analysis.get('detection_ratio', 'N/A'))
            with col4:
                st.write(severity)
            
            if i < len(st.session_state.analysis_history) - 1:
                st.markdown("---")
    else:
        st.info("No analysis history yet. Start by analyzing an indicator!")
    
    st.markdown("---")
    st.markdown("### Incident History")
    
    if st.session_state.incidents:
        for incident in st.session_state.incidents:
            st.write(f"• **{incident.get('case_id')}**: {incident.get('title')} ({incident.get('severity')})")
    else:
        st.info("No incidents created yet.")

# =============================================================================
# FOOTER
# =============================================================================

st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #666;'>"
    "Multi-Agent Security System | Built with Google ADK + Streamlit"
    "</div>",
    unsafe_allow_html=True
)


"""
Argus - Multi-Agent Security Platform (Cloud Run Edition)
=========================================================
Cloud Run endpoint-only interface with specialized tabs for power users.
This version only communicates with deployed Cloud Run agents via A2A protocol.
"""

import os
import json
import streamlit as st
from datetime import datetime
import requests
from typing import Dict, Any, Optional

from dotenv import load_dotenv
load_dotenv(override=True)

# Load agent endpoints from .env.agents if available
env_agents_path = ".env.agents"
if os.path.exists(env_agents_path):
    load_dotenv(env_agents_path, override=True)

# =============================================================================
# STREAMLIT CLOUD SECRETS SUPPORT
# =============================================================================
# Load secrets from Streamlit Cloud if available (for deployment)
try:
    if hasattr(st, 'secrets'):
        for key in ['VT_APIKEY', 'GOOGLE_API_KEY', 'GOOGLE_CLOUD_PROJECT', 
                    'ROOT_AGENT_ENDPOINT', 'THREAT_AGENT_ENDPOINT', 'INCIDENT_AGENT_ENDPOINT']:
            if key in st.secrets:
                os.environ[key] = st.secrets[key]
except Exception:
    pass  # Running locally with .env

# =============================================================================
# ICONS - Professional Security Icons (Phosphor/Heroicons Style)
# =============================================================================

def get_icon(name, size=20, color="currentColor"):
    """Professional icon set for Argus Security Platform"""
    icons = {
        # Argus Logo - All-seeing eye in shield (mythological reference)
        "logo": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <ellipse cx="12" cy="11" rx="3" ry="2"/>
            <circle cx="12" cy="11" r="1" fill="{color}"/>
        </svg>""",
        
        # Threat Intel - Radar scan
        "radar": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <circle cx="12" cy="12" r="6"/>
            <circle cx="12" cy="12" r="2"/>
            <line x1="12" y1="2" x2="12" y2="12"/>
        </svg>""",
        
        # Activity/Pulse
        "pulse": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M3 12h4l3-9 4 18 3-9h4"/>
        </svg>""",
        
        # Shield with check - Secure
        "shield-check": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M9 12l2 2 4-4"/>
        </svg>""",
        
        # Network block - Firewall
        "firewall": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="3" width="18" height="18" rx="2"/>
            <line x1="3" y1="9" x2="21" y2="9"/>
            <line x1="3" y1="15" x2="21" y2="15"/>
            <line x1="9" y1="3" x2="9" y2="21"/>
            <line x1="15" y1="3" x2="15" y2="21"/>
        </svg>""",
        
        # Host isolation - Disconnect
        "isolate": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="4" y="4" width="6" height="6" rx="1"/>
            <rect x="14" y="14" width="6" height="6" rx="1"/>
            <path d="M10 7h4" stroke-dasharray="2 2"/>
            <path d="M7 10v4" stroke-dasharray="2 2"/>
            <path d="M17 10v4" stroke-dasharray="2 2"/>
            <path d="M10 17h4" stroke-dasharray="2 2"/>
        </svg>""",
        
        # User suspend - Account lockout  
        "user-lock": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="9" cy="7" r="4"/>
            <path d="M3 21v-2a4 4 0 0 1 4-4h4"/>
            <rect x="14" y="13" width="8" height="8" rx="1"/>
            <path d="M16 13v-2a2 2 0 0 1 4 0v2"/>
        </svg>""",
        
        # Incident/Alert
        "alert": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <circle cx="12" cy="17" r="0.5" fill="{color}"/>
        </svg>""",
        
        # Terminal/Response
        "terminal": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="2" y="4" width="20" height="16" rx="2"/>
            <path d="M6 9l4 3-4 3"/>
            <line x1="12" y1="15" x2="18" y2="15"/>
        </svg>""",
        
        # Search/Investigate
        "search": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"/>
            <path d="M21 21l-4.35-4.35"/>
            <circle cx="11" cy="11" r="3"/>
        </svg>""",
        
        # Activity log
        "log": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <path d="M14 2v6h6"/>
            <line x1="8" y1="13" x2="16" y2="13"/>
            <line x1="8" y1="17" x2="14" y2="17"/>
        </svg>""",
        
        # Lightning/Quick action
        "bolt": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
        </svg>""",
        
        # Eye - Monitoring/Visibility
        "eye": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
            <circle cx="12" cy="12" r="3"/>
        </svg>""",
        
        # Check circle - Success
        "check": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <path d="M9 12l2 2 4-4"/>
        </svg>""",
        
        # X circle - Error/Block
        "x-circle": f"""<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <path d="M15 9l-6 6M9 9l6 6"/>
        </svg>"""
    }
    return icons.get(name, "")

# =============================================================================
# PAGE CONFIG
# =============================================================================

st.set_page_config(
    page_title="Argus",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# =============================================================================
# SESSION STATE
# =============================================================================

if 'messages' not in st.session_state:
    st.session_state.messages = []

if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []

if 'incidents' not in st.session_state:
    st.session_state.incidents = []

if 'endpoints_configured' not in st.session_state:
    st.session_state.endpoints_configured = False

# =============================================================================
# AGENT ENDPOINT CONFIGURATION
# =============================================================================

def get_agent_endpoints() -> Dict[str, Optional[str]]:
    """Get Cloud Run agent endpoints from environment variables"""
    return {
        "root": os.getenv("ROOT_AGENT_ENDPOINT"),
        "threat": os.getenv("THREAT_AGENT_ENDPOINT"),
        "incident": os.getenv("INCIDENT_AGENT_ENDPOINT")
    }

def check_endpoint_health(endpoint: str) -> bool:
    """
    Check if a Cloud Run agent endpoint is healthy.
    Uses longer timeout to account for Cloud Run cold starts.
    """
    if not endpoint:
        return False
    
    # Cloud Run can have cold starts, so use longer timeout
    timeout = 30  # 30 seconds for Cloud Run cold starts
    
    try:
        # Try /health endpoint first (preferred)
        response = requests.get(f"{endpoint}/health", timeout=timeout)
        if response.status_code == 200:
            return True
    except requests.exceptions.Timeout:
        # Timeout might indicate cold start - try root endpoint
        pass
    except Exception:
        # Other errors - endpoint might be down
        return False
    
    # If /health fails or times out, try root endpoint as fallback
    try:
        response = requests.get(f"{endpoint}/", timeout=timeout)
        # Accept 200-299 status codes
        return 200 <= response.status_code < 300
    except Exception:
        # If both fail, endpoint is not reachable
        return False

def invoke_a2a_agent(endpoint: str, method: str, params: Dict[str, Any], agent_name: str = None) -> Dict[str, Any]:
    """
    Invoke an agent method via A2A protocol over HTTPS
    
    Args:
        endpoint: Cloud Run endpoint URL
        method: Method name to call
        params: Parameters for the method
        agent_name: Agent name (required - must match server's registered name)
    
    Returns:
        Response from the agent
    """
    if not endpoint:
        raise ValueError("Agent endpoint not configured")
    
    if not agent_name:
        # Try to infer from endpoint URL
        if "root" in endpoint.lower():
            agent_name = "RootOrchestratorAgent"
        elif "threat" in endpoint.lower():
            agent_name = "ThreatAnalysisAgent"
        elif "incident" in endpoint.lower():
            agent_name = "IncidentResponseAgent"
        else:
            raise ValueError("agent_name must be provided or inferrable from endpoint")
    
    # Prepare A2A request
    a2a_request = {
        "agent": agent_name,  # Must match the agent name registered with the server
        "method": method,
        "params": params,
        "protocol_version": "1.0"
    }
    
    # Get authentication headers if using Google Cloud
    headers = {"Content-Type": "application/json"}
    try:
        from google.auth import default
        from google.auth.transport.requests import Request
        credentials, _ = default()
        if credentials:
            credentials.refresh(Request())
            headers["Authorization"] = f"Bearer {credentials.token}"
    except:
        pass  # Continue without auth if not available
    
    # Make HTTPS request
    try:
        response = requests.post(
            f"{endpoint}/a2a/invoke",
            json=a2a_request,
            headers=headers,
            timeout=60
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"A2A request failed: {str(e)}")

# Get endpoints
endpoints = get_agent_endpoints()
st.session_state.endpoints_configured = all(endpoints.values())

# Check endpoint health
endpoint_status = {
    name: check_endpoint_health(url) if url else False
    for name, url in endpoints.items()
}

# =============================================================================
# CUSTOM CSS
# =============================================================================

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    :root {
        --bg-app: #0e0e11;
        --bg-panel: rgba(24, 24, 27, 0.7);
        --border-color: rgba(255, 255, 255, 0.08);
        --accent-primary: #6366f1;
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
    
    .stApp {
        background-color: var(--bg-app);
        font-family: var(--font-sans);
        color: var(--text-primary);
    }
    
    header {visibility: hidden;}
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    h1, h2, h3 {
        font-family: var(--font-sans);
        font-weight: 600;
        letter-spacing: -0.02em;
        color: var(--text-primary);
    }
    
    p { color: var(--text-secondary); font-size: 0.95rem; line-height: 1.5; }
    
    .header-wrapper {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 1rem 0 2rem 0;
        border-bottom: 1px solid var(--border-color);
        margin-bottom: 2rem;
    }
    
    .brand-section { display: flex; align-items: center; gap: 1rem; }
    .brand-icon { color: var(--accent-primary); filter: drop-shadow(0 0 8px var(--accent-glow)); }
    
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
    }
    
    .status-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background-color: var(--text-secondary);
    }
    
    .status-dot.live { background-color: #10b981; box-shadow: 0 0 8px rgba(16, 185, 129, 0.4); }
    .status-dot.demo { background-color: #eab308; box-shadow: 0 0 8px rgba(234, 179, 8, 0.3); }
    
    .stTabs [data-baseweb="tab-list"] {
        background-color: transparent;
        gap: 2rem;
        border-bottom: 1px solid var(--border-color);
    }
    
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        border: none;
        color: var(--text-secondary);
        font-weight: 500;
        padding: 0.8rem 0;
    }
    
    .stTabs [aria-selected="true"] {
        color: var(--text-primary);
        border-bottom: 2px solid var(--accent-primary);
    }
    
    .stTextInput > div > div {
        background-color: rgba(255,255,255,0.02);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        color: var(--text-primary);
    }
    
    .stButton > button {
        background: linear-gradient(180deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.01) 100%);
        border: 1px solid var(--border-color);
        color: var(--text-primary);
        border-radius: 8px;
        font-weight: 500;
    }
    
    .stButton > button:hover { border-color: var(--text-secondary); background: rgba(255,255,255,0.08); }
    
    .glass-panel {
        background: var(--bg-panel);
        backdrop-filter: blur(12px);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
    }
    
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
    
    .metric-box { text-align: center; }
    .metric-val { font-family: var(--font-mono); font-size: 1.5rem; font-weight: 600; color: var(--text-primary); }
    .metric-lbl { font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }
    
    /* Chat styles */
    .stChatMessage { background: transparent !important; }
    .stChatMessage [data-testid="chatAvatarIcon-assistant"] { background: var(--accent-primary) !important; }
</style>
""", unsafe_allow_html=True)

# =============================================================================
# HEADER
# =============================================================================

# Determine status
all_healthy = all(endpoint_status.values()) if endpoints else False
configured_count = sum(1 for v in endpoints.values() if v)

st.markdown(f"""
<div class="header-wrapper">
    <div class="brand-section">
        <div class="brand-icon">{get_icon("logo", size=32, color="#6366f1")}</div>
        <div>
            <h1 style="font-size: 1.25rem; margin: 0;">Argus</h1>
            <p style="font-size: 0.8rem; margin: 0; opacity: 0.7;">Intelligent Security Operations (Cloud Run)</p>
        </div>
    </div>
    <div style="display: flex; gap: 1rem;">
        <div class="status-badge">
            <div class="status-dot {'live' if all_healthy else 'demo'}"></div>
            {'Live' if all_healthy else 'Config'}
        </div>
        <div class="status-badge">
            {get_icon("radar", size=14)}
            {'Connected' if endpoint_status.get('threat') else 'Offline'}
        </div>
        <div class="status-badge">
            {get_icon("terminal", size=14)}
            {'Connected' if endpoint_status.get('incident') else 'Offline'}
        </div>
        <div class="status-badge">
            {get_icon("pulse", size=14)}
            {len(st.session_state.messages)} Ops
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# Show configuration warning if needed
if not st.session_state.endpoints_configured:
    st.warning("⚠️ **Agent endpoints not fully configured.** Please set `ROOT_AGENT_ENDPOINT`, `THREAT_AGENT_ENDPOINT`, and `INCIDENT_AGENT_ENDPOINT` environment variables or in `.env.agents` file.")

# =============================================================================
# MAIN TABS
# =============================================================================

tab_chat, tab_threat, tab_incident, tab_history = st.tabs([
    "💬 Argus Chat", 
    "🔍 Threat Intel", 
    "🚨 Incident Response", 
    "📋 Activity Log"
])

# =============================================================================
# TAB 1: SENTINEL CHAT (Default Landing Page)
# =============================================================================

with tab_chat:
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Welcome message if no history
    if not st.session_state.messages:
        st.markdown("""
        <div class="glass-panel" style="text-align: center; padding: 3rem;">
            <div style="font-size: 3rem; margin-bottom: 1rem;">🛡️</div>
            <h2 style="margin: 0;">Welcome to Argus</h2>
            <p style="max-width: 500px; margin: 1rem auto;">
                I'm your AI security analyst. Ask me to analyze threats, investigate indicators, 
                or take response actions. Try:
            </p>
            <div style="display: flex; gap: 0.5rem; justify-content: center; flex-wrap: wrap; margin-top: 1.5rem;">
                <code style="padding: 0.5rem 1rem; background: rgba(255,255,255,0.05); border-radius: 6px; font-size: 0.85rem;">"Analyze IP 203.0.113.42"</code>
                <code style="padding: 0.5rem 1rem; background: rgba(255,255,255,0.05); border-radius: 6px; font-size: 0.85rem;">"Check if evil-domain.com is malicious"</code>
                <code style="padding: 0.5rem 1rem; background: rgba(255,255,255,0.05); border-radius: 6px; font-size: 0.85rem;">"Block IP 10.0.0.1"</code>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Display chat history
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    
    # Chat input
    if prompt := st.chat_input("Ask Argus anything..."):
        # Add user message
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Get response from Root Agent via A2A (Cloud Run)
        with st.chat_message("assistant"):
            if not endpoints.get("root"):
                response = "⚠️ Root agent endpoint not configured. Please set `ROOT_AGENT_ENDPOINT` environment variable with your Cloud Run service URL."
            elif not endpoint_status.get("root"):
                # Health check failed - don't proceed
                response = f"""❌ **Cloud Run agent is not reachable**

The health check for the root agent endpoint failed. This could mean:
- The Cloud Run service is cold-starting (first request can take 30+ seconds)
- The service is down or not deployed
- Network connectivity issues

**Endpoint:** `{endpoints['root']}`

**To fix:**
1. Verify the Cloud Run service is deployed: `gcloud run services list`
2. Check service logs: `gcloud run services logs read root-orchestrator-agent`
3. Try accessing the endpoint directly in your browser
4. Wait a moment and refresh this page (cold starts can take time)

The UI will automatically retry the health check when you refresh."""
            else:
                # Health check passed - proceed with Cloud Run agent
                with st.spinner("Analyzing via Cloud Run..."):
                    try:
                        result = invoke_a2a_agent(
                            endpoints["root"],
                            "chat",
                            {"user_message": prompt},
                            agent_name="RootOrchestratorAgent"
                        )
                        response = result.get("result", {}).get("text", "I encountered an error processing your request.")
                    except Exception as e:
                        response = f"❌ Error calling Cloud Run agent: {str(e)}\n\n**Endpoint:** `{endpoints['root']}`\n\nPlease check the Cloud Run service logs for details."
            
            st.markdown(response)
            st.session_state.messages.append({"role": "assistant", "content": response})

# =============================================================================
# TAB 2: THREAT INTEL (Direct Analysis)
# =============================================================================

with tab_threat:
    st.markdown("<br>", unsafe_allow_html=True)
    
    if not endpoints.get("threat"):
        st.error("⚠️ Threat agent endpoint not configured. Set `THREAT_AGENT_ENDPOINT` environment variable with your Cloud Run service URL.")
    elif not endpoint_status.get("threat"):
        st.error("⚠️ Threat agent Cloud Run endpoint is not reachable. Health check failed. Please verify the service is deployed and running.")
    
    # Input Area
    with st.container():
        c1, c2, c3 = st.columns([5, 2, 1])
        with c1:
            indicator = st.text_input("Indicator", placeholder="IP, Domain, Hash, URL...", label_visibility="collapsed", key="threat_indicator")
        with c2:
            indicator_type = st.selectbox("Type", ["auto", "ip", "domain", "hash", "url"], label_visibility="collapsed", key="threat_type")
        with c3:
            analyze = st.button("Analyze", type="primary", use_container_width=True, key="analyze_btn")

    if analyze and indicator and endpoints.get("threat") and endpoint_status.get("threat"):
        with st.spinner("Querying threat intelligence..."):
            try:
                # Call threat agent via A2A
                result = invoke_a2a_agent(
                    endpoints["threat"],
                    "analyze_indicator",
                    {
                        "indicator": indicator,
                        "indicator_type": indicator_type if indicator_type != "auto" else None
                    },
                    agent_name="ThreatAnalysisAgent"
                )
                
                # Extract result from A2A response
                if result.get("success"):
                    analysis = result.get("result", {}).get("analysis", {})
                    st.session_state.analysis_history.insert(0, analysis)
                    
                    # Display result
                    sev = analysis.get('severity', 'UNKNOWN').upper()
                    sev_cls = f"badge-{sev.lower()}" if sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] else "badge-low"
                    source = result.get("result", {}).get("mode", {}).get("source", "Cloud Run")
                    
                    st.markdown(f"""
                    <div class="glass-panel" style="margin-top: 1rem;">
                        <div style="display: flex; justify-content: space-between; align-items: start;">
                            <div>
                                <span class="badge {sev_cls}">{sev}</span>
                                <h2 style="margin: 0.5rem 0; font-family: 'JetBrains Mono'; font-size: 1.5rem;">{indicator}</h2>
                                <p style="font-size: 0.9rem;">Source: {source}</p>
                            </div>
                            <div style="text-align: right;">
                                <div style="font-family: 'JetBrains Mono'; font-size: 0.8rem; color: var(--text-secondary);">{datetime.now().strftime('%H:%M:%S')}</div>
                            </div>
                        </div>
                        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border-color);">
                            <div class="metric-box">
                                <div class="metric-val">{analysis.get('confidence', 'N/A')}%</div>
                                <div class="metric-lbl">Confidence</div>
                            </div>
                            <div class="metric-box">
                                <div class="metric-val">{analysis.get('detection_ratio', 'N/A')}</div>
                                <div class="metric-lbl">Detections</div>
                            </div>
                            <div class="metric-box">
                                <div class="metric-val">{analysis.get('indicator_type', indicator_type).upper()}</div>
                                <div class="metric-lbl">Type</div>
                            </div>
                            <div class="metric-box">
                                <div class="metric-val">{analysis.get('threat_type', 'unknown')}</div>
                                <div class="metric-lbl">Threat</div>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Raw JSON
                    with st.expander("View Raw Response"):
                        st.json(result)
                    
                    # Quick Actions for high severity
                    if sev in ['CRITICAL', 'HIGH']:
                        st.markdown("### ⚡ Quick Actions")
                        ac1, ac2 = st.columns(2)
                        with ac1:
                            if st.button("🚫 Block Indicator", use_container_width=True, key="quick_block"):
                                if indicator_type == "ip" and endpoints.get("incident") and endpoint_status.get("incident"):
                                    try:
                                        action_result = invoke_a2a_agent(
                                            endpoints["incident"],
                                            "execute_action",
                                            {"action": "block_ip", "params": indicator},
                                            agent_name="IncidentResponseAgent"
                                        )
                                        if action_result.get("success"):
                                            st.success(f"✅ {action_result.get('result', {}).get('message', 'Action completed')}")
                                        else:
                                            st.error(action_result.get("error", "Action failed"))
                                    except Exception as e:
                                        st.error(f"Error: {str(e)}")
                                else:
                                    st.info("Blocking is only supported for IP addresses" if indicator_type == "ip" else "Incident agent not available")
                        with ac2:
                            if st.button("📋 Create Incident Case", use_container_width=True, key="quick_case"):
                                if endpoints.get("incident") and endpoint_status.get("incident"):
                                    try:
                                        case_result = invoke_a2a_agent(
                                            endpoints["incident"],
                                            "handle_incident",
                                            {"threat_data": analysis, "description": "Auto-created from threat analysis"},
                                            agent_name="IncidentResponseAgent"
                                        )
                                        if case_result.get("success"):
                                            incident_id = case_result.get("result", {}).get("incident_id", "N/A")
                                            st.success(f"✅ Created incident: {incident_id}")
                                            st.session_state.incidents.insert(0, {
                                                "incident_id": incident_id,
                                                "severity": sev,
                                                "indicator": indicator
                                            })
                                        else:
                                            st.error(case_result.get("error", "Failed to create incident"))
                                    except Exception as e:
                                        st.error(f"Error: {str(e)}")
                                else:
                                    st.info("Incident agent not available")
                else:
                    st.error(f"Analysis failed: {result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                st.error(f"Error: {str(e)}")

# =============================================================================
# TAB 3: INCIDENT RESPONSE
# =============================================================================

with tab_incident:
    st.markdown("<br>", unsafe_allow_html=True)
    
    if not endpoints.get("incident"):
        st.error("⚠️ Incident agent endpoint not configured. Set `INCIDENT_AGENT_ENDPOINT` environment variable with your Cloud Run service URL.")
    elif not endpoint_status.get("incident"):
        st.error("⚠️ Incident agent Cloud Run endpoint is not reachable. Health check failed. Please verify the service is deployed and running.")
    else:
        st.info("✅ Running in **Cloud Run Mode** - Actions are executed on deployed agents")
    
    st.markdown("#### Response Playbooks")
    
    rc1, rc2, rc3 = st.columns(3)
    
    # Card 1: Block IP
    with rc1:
        st.markdown(f"""
        <div class="glass-panel" style="text-align: center;">
            <div style="color: var(--accent-primary); margin-bottom: 1rem;">{get_icon("firewall", size=32)}</div>
            <h3 style="font-size: 1rem;">Network Block</h3>
            <p style="font-size: 0.8rem;">Block IP at firewall</p>
        </div>
        """, unsafe_allow_html=True)
        blk_ip = st.text_input("IP Address", key="act_blk", placeholder="e.g., 10.0.0.1")
        if st.button("Execute Block", use_container_width=True, key="btn_blk"):
            if blk_ip and endpoints.get("incident") and endpoint_status.get("incident"):
                try:
                    result = invoke_a2a_agent(
                        endpoints["incident"],
                        "execute_action",
                        {"action": "block_ip", "params": blk_ip},
                        agent_name="IncidentResponseAgent"
                    )
                    if result.get("success"):
                        st.success(result.get("result", {}).get("message", "Action completed"))
                    else:
                        st.error(result.get("error", "Action failed"))
                except Exception as e:
                    st.error(f"Error: {str(e)}")

    # Card 2: Isolate Host
    with rc2:
        st.markdown(f"""
        <div class="glass-panel" style="text-align: center;">
            <div style="color: var(--accent-primary); margin-bottom: 1rem;">{get_icon("isolate", size=32)}</div>
            <h3 style="font-size: 1rem;">Host Isolation</h3>
            <p style="font-size: 0.8rem;">Disconnect from network</p>
        </div>
        """, unsafe_allow_html=True)
        iso_host = st.text_input("Hostname", key="act_iso", placeholder="e.g., WORKSTATION-01")
        if st.button("Isolate Host", use_container_width=True, key="btn_iso"):
            if iso_host and endpoints.get("incident") and endpoint_status.get("incident"):
                try:
                    result = invoke_a2a_agent(
                        endpoints["incident"],
                        "execute_action",
                        {"action": "isolate_endpoint", "params": iso_host},
                        agent_name="IncidentResponseAgent"
                    )
                    if result.get("success"):
                        st.success(result.get("result", {}).get("message", "Action completed"))
                    else:
                        st.error(result.get("error", "Action failed"))
                except Exception as e:
                    st.error(f"Error: {str(e)}")

    # Card 3: Disable User
    with rc3:
        st.markdown(f"""
        <div class="glass-panel" style="text-align: center;">
            <div style="color: var(--accent-primary); margin-bottom: 1rem;">{get_icon("user-lock", size=32)}</div>
            <h3 style="font-size: 1rem;">Suspend User</h3>
            <p style="font-size: 0.8rem;">Revoke IAM credentials</p>
        </div>
        """, unsafe_allow_html=True)
        dis_user = st.text_input("Username", key="act_dis", placeholder="e.g., john.doe")
        if st.button("Suspend User", use_container_width=True, key="btn_dis"):
            if dis_user and endpoints.get("incident") and endpoint_status.get("incident"):
                try:
                    result = invoke_a2a_agent(
                        endpoints["incident"],
                        "execute_action",
                        {"action": "disable_user", "params": dis_user},
                        agent_name="IncidentResponseAgent"
                    )
                    if result.get("success"):
                        st.success(result.get("result", {}).get("message", "Action completed"))
                    else:
                        st.error(result.get("error", "Action failed"))
                except Exception as e:
                    st.error(f"Error: {str(e)}")

    # Active Incidents
    if st.session_state.incidents:
        st.markdown("#### Active Incidents")
        for inc in st.session_state.incidents[:5]:
            sev = inc.get('severity', 'MEDIUM')
            sev_cls = f"badge-{sev.lower()}"
            st.markdown(f"""
            <div class="glass-panel" style="padding: 1rem; display: flex; justify-content: space-between; align-items: center;">
                <div style="display: flex; gap: 1rem; align-items: center;">
                    <span class="badge {sev_cls}">{sev}</span>
                    <div>
                        <div style="font-family: 'JetBrains Mono'; font-size: 0.9rem;">{inc.get('incident_id', 'N/A')}</div>
                        <div style="font-size: 0.85rem; color: var(--text-secondary);">{inc.get('indicator', '')}</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

# =============================================================================
# TAB 4: ACTIVITY LOG
# =============================================================================

with tab_history:
    st.markdown("<br>", unsafe_allow_html=True)
    
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.markdown("#### Analysis History")
        if not st.session_state.analysis_history:
            st.info("No analyses recorded")
        for item in st.session_state.analysis_history[:10]:
            sev = item.get('severity', 'LOW')
            st.markdown(f"""
            <div style="padding: 0.8rem; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between;">
                <span style="font-family: 'JetBrains Mono'; font-size: 0.85rem;">{item.get('indicator', 'N/A')}</span>
                <span class="badge badge-{sev.lower()}">{sev}</span>
            </div>
            """, unsafe_allow_html=True)

    with col_b:
        st.markdown("#### Chat History")
        if not st.session_state.messages:
            st.info("No chat messages")
        for msg in st.session_state.messages[-10:]:
            role = "🧑" if msg["role"] == "user" else "🛡️"
            content = msg["content"][:100] + "..." if len(msg["content"]) > 100 else msg["content"]
            st.markdown(f"""
            <div style="padding: 0.8rem; border-bottom: 1px solid var(--border-color);">
                <span style="font-size: 0.85rem;">{role} {content}</span>
            </div>
            """, unsafe_allow_html=True)

    if st.button("Clear All History"):
        st.session_state.analysis_history = []
        st.session_state.incidents = []
        st.session_state.messages = []
        st.rerun()

# =============================================================================
# FOOTER
# =============================================================================

st.markdown("""
<div style="text-align: center; margin-top: 4rem; padding-top: 2rem; border-top: 1px solid var(--border-color); color: var(--text-secondary); font-size: 0.8rem;">
    Argus v3.0 • Powered by Google ADK + Cloud Run • Intelligent Security Operations
</div>
""", unsafe_allow_html=True)


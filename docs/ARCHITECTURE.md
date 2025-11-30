# Argus Architecture

> **Argus** - The all-seeing guardian of security operations

## Overview

Argus is a distributed multi-agent security orchestration platform built on Google's Agent Development Kit (ADK). It provides a chat-first interface for security operations, combining threat intelligence from VirusTotal with incident response capabilities.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER INTERFACE                                  │
│                            (Streamlit - ui.py)                              │
│                                                                              │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│   │ Argus Chat  │  │ Threat Intel│  │ Incident    │  │ Activity    │       │
│   │    Tab      │  │    Tab      │  │ Response Tab│  │ Log Tab     │       │
│   └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ROOT ORCHESTRATOR AGENT                           │
│                            (agents/root_agent.py)                           │
│                                                                              │
│   • Natural language understanding                                          │
│   • Intent detection (analyze vs. respond vs. block)                        │
│   • Indicator extraction (IP, domain, hash, URL)                            │
│   • Sub-agent delegation                                                    │
│   • Response formatting (Markdown)                                          │
│                                                                              │
│   Routing Priority:                                                          │
│   1. A2A Protocol (HTTP) → Deployed agents on Cloud Run                     │
│   2. Pre-initialized instance → Passed from UI                              │
│   3. Direct instantiation → Fallback for local development                  │
└─────────────────────────────────────────────────────────────────────────────┘
                    │                               │
                    ▼                               ▼
┌──────────────────────────────┐    ┌──────────────────────────────┐
│   THREAT ANALYSIS AGENT      │    │   INCIDENT RESPONSE AGENT    │
│  (agents/threat_agent.py)    │    │  (agents/incident_agent.py)  │
│                              │    │                              │
│  • GTI MCP Integration       │    │  • Simulated SOAR Tools      │
│  • 35 Dynamic Tools          │    │  • Case Management           │
│  • VirusTotal API            │    │  • Containment Actions       │
│                              │    │                              │
│  Tools (from MCP):           │    │  Tools (Simulated):          │
│  - get_ip_address_report     │    │  - create_case               │
│  - get_domain_report         │    │  - block_ip                  │
│  - get_file_report           │    │  - isolate_endpoint          │
│  - get_url_report            │    │  - disable_user              │
│  - search_iocs               │    │  - get_case_status           │
│  - search_threats            │    │  - list_all_cases            │
│  - search_malware_families   │    │                              │
│  - + 28 more...              │    │                              │
└──────────────────────────────┘    └──────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────┐
│      GTI MCP SERVER          │
│        (gti_mcp)             │
│                              │
│  Protocol: MCP (stdio)       │
│  Backend: VirusTotal API     │
│  Auth: VT_APIKEY             │
└──────────────────────────────┘
```

## Agent Communication Patterns

### Local Development Mode
```
UI → Root Agent (direct) → Threat Agent (direct) → MCP Server
                        → Incident Agent (direct)
```

### Distributed Deployment Mode (Cloud Run)
```
UI → Root Agent (A2A/HTTP) → Threat Agent (A2A/HTTP) → MCP Server
                          → Incident Agent (A2A/HTTP)
```

## Key Components

### 1. Root Orchestrator Agent (`agents/root_agent.py`)

The central coordinator that:
- Parses natural language queries
- Extracts indicators (IPs, domains, hashes, URLs) using regex
- Detects action keywords (block, isolate, disable)
- Routes requests to appropriate sub-agents
- Formats responses into structured Markdown

**Key Methods:**
- `chat(message)` - Main entry point for natural language queries
- `_extract_indicators(text)` - Regex-based IOC extraction
- `_call_threat_agent(indicator, type)` - Delegates to Threat Agent
- `_call_incident_action(action, target)` - Delegates to Incident Agent
- `_format_response(analysis)` - Formats Markdown output

### 2. Threat Analysis Agent (`agents/threat_agent.py`)

Provides threat intelligence using the GTI MCP server:

**Initialization:**
1. `create_gti_mcp_toolset()` - Creates MCP connection
2. `get_mcp_tools()` - Dynamically discovers 35 tools
3. Sets `is_live_mode = True` if tools found

**Runtime:**
1. `analyze_indicator(indicator, type)` - Main analysis method
2. `_call_tool_directly(tool_name, **kwargs)` - Calls MCP tools
3. `_parse_vt_response(indicator, type, data)` - Parses VT response

**MCP Tool Calling Flow:**
```python
# 1. Determine tool based on indicator type
tool_map = {
    "ip": ("get_ip_address_report", {"ip_address": indicator}),
    "domain": ("get_domain_report", {"domain": indicator}),
    "hash": ("get_file_report", {"hash": indicator}),
    "url": ("get_url_report", {"url": indicator}),
}

# 2. Call MCP server directly
async with stdio_client(server_params) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        result = await session.call_tool(tool_name, kwargs)

# 3. Parse VirusTotal response
analysis = _parse_vt_response(indicator, type, result.data)
```

### 3. Incident Response Agent (`agents/incident_agent.py`)

Handles security incidents with simulated SOAR capabilities:

**Tools (Simulated):**
- `create_case(title, severity, description)` - Create incident case
- `block_ip(ip_address, case_id)` - Block IP at firewall
- `isolate_endpoint(hostname, case_id)` - Isolate from network
- `disable_user(username, case_id)` - Disable user account
- `get_case_status(case_id)` - Check case status
- `list_all_cases()` - List all incidents

## MCP Integration

### GTI MCP Server

The Google Threat Intelligence MCP server (`gti_mcp`) provides:
- 35+ tools for threat analysis
- Direct access to VirusTotal API
- Standardized MCP protocol

**Connection:**
```python
server_params = StdioServerParameters(
    command="gti_mcp",
    args=[],
    env={"VT_APIKEY": os.environ["VT_APIKEY"]}
)
```

### Dynamic Tool Discovery

Tools are discovered at agent initialization:
```python
toolset = McpToolset(connection_params=connection_params)
tools = await toolset.get_tools()  # Returns 35 tools
```

## A2A Protocol (Agent-to-Agent)

For distributed deployment, agents communicate via HTTP:

**Request Format:**
```json
{
    "agent": "ThreatAnalysisAgent",
    "method": "analyze_indicator",
    "params": {
        "indicator": "8.8.8.8",
        "indicator_type": "ip"
    },
    "protocol_version": "1.0"
}
```

**Endpoint Discovery:**
- `THREAT_AGENT_ENDPOINT` - Threat Agent URL
- `INCIDENT_AGENT_ENDPOINT` - Incident Agent URL
- `ROOT_AGENT_ENDPOINT` - Root Agent URL

## Mode Indicators

| Mode | Icon | Description |
|------|------|-------------|
| Live (GTI) | 🟢 | Real VirusTotal data via MCP |
| Demo | 🟡 | Simulated responses |
| Offline | ⚪ | No data available |

## Data Flow Example

**Query:** "Analyze 8.8.8.8"

```
1. UI sends to Root Agent
   └─► chat("Analyze 8.8.8.8")

2. Root Agent extracts indicator
   └─► _extract_indicators() → {"ip": ["8.8.8.8"]}

3. Root Agent calls Threat Agent
   └─► _call_threat_agent("8.8.8.8", "ip")

4. Threat Agent calls MCP
   └─► _call_tool_directly("get_ip_address_report", ip_address="8.8.8.8")

5. MCP Server calls VirusTotal API
   └─► Returns: ASN, country, detections, reputation

6. Threat Agent parses response
   └─► _parse_vt_response() → severity, confidence, recommendations

7. Root Agent formats response
   └─► _format_response() → Markdown output

8. UI displays result
   └─► ### 🛡️ Threat Assessment
       **Severity:** INFO | **Confidence:** 40%
       **Detection Ratio:** 0/95
       **ASN Owner:** GOOGLE
```

## File Structure

```
argus-security/
├── agents/
│   ├── __init__.py
│   ├── root_agent.py      # Root Orchestrator
│   ├── threat_agent.py    # Threat Analysis (MCP)
│   └── incident_agent.py  # Incident Response (SOAR)
├── shared/
│   ├── communication/
│   │   ├── a2a_client.py  # A2A HTTP client
│   │   └── a2a_server.py  # A2A HTTP server
│   ├── discovery/
│   │   └── vertex_registry.py  # Agent registry
│   ├── memory/
│   │   ├── threat_memory.py    # Threat intel storage
│   │   └── incident_memory.py  # Incident storage
│   └── config.py          # Configuration
├── deployment/
│   ├── deploy_threat_agent.sh
│   ├── deploy_incident_agent.sh
│   ├── deploy_root_agent.sh
│   └── Dockerfile.*
├── tests/
│   ├── test_root_agent.py
│   └── test_root_agent_integration.py
├── ui.py                  # Streamlit UI
├── pyproject.toml
└── requirements.txt
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VT_APIKEY` | Yes | VirusTotal API key |
| `GOOGLE_API_KEY` | Yes | Google AI API key |
| `GOOGLE_CLOUD_PROJECT` | For cloud | GCP project ID |
| `THREAT_AGENT_ENDPOINT` | For A2A | Threat agent URL |
| `INCIDENT_AGENT_ENDPOINT` | For A2A | Incident agent URL |

## Known Limitations

1. **MCP Connection per Call** - Currently creates new MCP connection for each tool call (could be optimized)
2. **SOAR Simulated** - Incident response tools are simulated (no real Chronicle SOAR integration yet)
3. **Memory Optional** - BigQuery memory requires GCP credentials

## Future Improvements

- [ ] Connection pooling for MCP calls
- [ ] Real Chronicle SOAR integration
- [ ] Additional MCP servers (Chronicle, SecOps)
- [ ] Persistent agent sessions
- [ ] Multi-turn conversations with context

---

*Last Updated: November 30, 2025*


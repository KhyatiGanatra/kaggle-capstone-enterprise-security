# Multi-Agent Security System

A distributed multi-agent security system built with Google ADK, designed for enterprise security operations.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ROOT ORCHESTRATOR                         │
│                    (Coordinates workflow)                    │
└─────────────────────────────┬───────────────────────────────┘
                              │ A2A Protocol (HTTPS)
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│   THREAT ANALYSIS       │     │   INCIDENT RESPONSE     │
│   AGENT                 │     │   AGENT                 │
│                         │     │                         │
│   • GTI/VirusTotal      │     │   • Chronicle SecOps    │
│   • IOC Analysis        │     │   • SOAR Playbooks      │
│   • MITRE ATT&CK        │     │   • Case Management     │
└─────────────────────────┘     └─────────────────────────┘
```

## Quick Start

### 1. Install Dependencies

```bash
# Install UV package manager (if not installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync
```

### 2. Configure Environment

```bash
# Copy template
cp env.template .env

# Edit with your credentials
nano .env
```

Required environment variables:
```bash
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_API_KEY=your-gemini-api-key

# Optional (for real threat intel)
VT_APIKEY=your-virustotal-api-key
```

### 3. Run Locally

```bash
# Terminal 1: Start Threat Agent
uv run python -m agents.threat_agent

# Terminal 2: Start Incident Agent
uv run python -m agents.incident_agent

# Terminal 3: Start Root Orchestrator
uv run python -m agents.root_agent
```

### 4. Test

```bash
# Health check
curl http://localhost:8081/health
curl http://localhost:8082/health

# Run unit tests
uv run pytest tests/ -v
```

## Project Structure

```
├── agents/                  # The 3 agents
│   ├── threat_agent.py      # Threat analysis (port 8081)
│   ├── incident_agent.py    # Incident response (port 8082)
│   └── root_agent.py        # Orchestrator
│
├── shared/                  # Shared utilities
│   ├── a2a_client.py        # A2A protocol client
│   ├── a2a_server.py        # A2A protocol server
│   ├── config.py            # MCP server config
│   ├── memory.py            # BigQuery memory
│   └── vertex_registry.py   # Agent registry
│
├── tests/                   # Unit tests
│
└── deployment/              # Cloud Run deployment
    ├── Dockerfile.*         # Container configs
    └── deploy_*.sh          # Deploy scripts
```

## Agents

### ThreatAnalysisAgent
- Analyzes security indicators (IPs, domains, hashes, URLs)
- Uses Google Threat Intelligence / VirusTotal
- Returns severity, confidence, MITRE techniques

### IncidentResponseAgent
- Handles security incidents
- Creates cases, executes playbooks
- Integrates with Chronicle SecOps/SOAR

### RootOrchestratorAgent
- Coordinates the workflow
- Delegates to sub-agents via A2A protocol
- Makes escalation decisions

## A2A Protocol

Agents communicate via HTTPS using the A2A (Agent-to-Agent) protocol:

```json
// Request
POST /a2a/invoke
{
  "agent": "ThreatAnalysisAgent",
  "method": "analyze_indicator",
  "params": {
    "indicator": "203.0.113.42",
    "indicator_type": "ip"
  }
}

// Response
{
  "success": true,
  "result": {
    "severity": "CRITICAL",
    "confidence": 95
  }
}
```

## Deployment (Cloud Run)

```bash
# Set environment
export GOOGLE_CLOUD_PROJECT=your-project-id
export GOOGLE_API_KEY=your-api-key

# Deploy all agents
cd deployment
./deploy_threat_agent.sh
./deploy_incident_agent.sh
./deploy_root_agent.sh
```

## Testing

```bash
# Run all tests
uv run pytest tests/ -v

# Run specific test
uv run pytest tests/test_threat_agent.py -v

# Run with coverage
uv run pytest tests/ --cov=agents --cov=shared
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLOUD_PROJECT` | Yes | GCP Project ID |
| `GOOGLE_API_KEY` | Yes | Gemini API key |
| `VT_APIKEY` | No | VirusTotal API key |
| `CHRONICLE_PROJECT_ID` | No | Chronicle SecOps project |
| `SOAR_URL` | No | Chronicle SOAR URL |
| `SOAR_APP_KEY` | No | Chronicle SOAR API key |

## License

MIT

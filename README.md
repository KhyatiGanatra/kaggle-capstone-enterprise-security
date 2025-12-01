# 🛡️ Argus - Multi-Agent Security Platform

> *Named after Argus Panoptes, the all-seeing giant from Greek mythology*

A distributed multi-agent security system built with **Google ADK** and **GTI MCP**, designed for enterprise security operations.

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://your-app.streamlit.app)

---

## 📋 Kaggle Capstone Submission

| Component | Status |
|-----------|--------|
| 🎥 Demo Video | [Watch on YouTube](#) |
| 🚀 Live Demo | [Launch Argus](#) |
| 📦 GitHub Repo | You're here! |

---

## ✨ Features

- **🔍 Threat Intelligence** - Real-time IOC analysis via VirusTotal/GTI MCP
- **🚨 Incident Response** - Automated containment actions (simulated for demo)
- **🤖 AI-Powered Chat** - Natural language interface powered by Gemini
- **🔗 Multi-Agent Architecture** - Distributed agents communicating via A2A protocol

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ROOT ORCHESTRATOR (Argus)                │
│                    Coordinates workflow via chat            │
└─────────────────────────────┬───────────────────────────────┘
                              │ A2A Protocol (HTTPS)
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│   THREAT ANALYSIS       │     │   INCIDENT RESPONSE     │
│   AGENT                 │     │   AGENT                 │
│                         │     │                         │
│   • GTI MCP Server      │     │   • Simulated SOAR      │
│   • 35+ VT Tools        │     │   • Case Management     │
│   • IOC Analysis        │     │   • Containment Actions │
└─────────────────────────┘     └─────────────────────────┘
```

## 🚀 Quick Start

**Backend Agent services - Deployment**

Components
Agents
RootOrchestratorAgent (agents/root_agent.py)

Coordinates all sub-agents
Discovers agents from Vertex AI Agent Registry
Makes decisions on threat response
Manages session and persistent memory
ThreatAnalysisAgent (agents/threat_agent.py)

Analyzes security indicators using Google Threat Intelligence (GTI)
Provides threat severity assessment
Maps threats to MITRE ATT&CK techniques
Stores findings in BigQuery
IncidentResponseAgent (agents/incident_agent.py)

Handles security incidents using Chronicle SecOps and SOAR
Executes automated response playbooks
Manages incident lifecycle
Documents incident timeline
Shared Components
A2A Protocol (shared/a2a_client.py, shared/a2a_server.py)

HTTPS-based communication between agents
Standardized request/response format
Authentication via Google Cloud credentials
Vertex AI Agent Registry (shared/vertex_registry.py)

Agent registration and discovery
Endpoint resolution
Capability-based filtering
Memory Management (shared/memory.py)

BigQuery-based persistent storage
Threat intelligence history
Incident tracking
Prerequisites
Python 3.9+
Google Cloud Project with:
Vertex AI API enabled
BigQuery API enabled
Service account with appropriate permissions
Google AI API key (for Gemini models)
Environment variables configured (see Configuration section)
Installation
Clone the repository:
git clone <repository-url>
cd kaggle-capstone-entr-sec
Install dependencies:
pip install -r requirements.txt
Set up Google Cloud authentication:
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID
Configure environment variables (see Configuration section)
Configuration
Environment Variables
Create a .env file or set the following environment variables:

# Google Cloud
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_APPLICATION_CREDENTIALS="path/to/service-account.json"

# Google AI (Gemini)
export GOOGLE_API_KEY="your-google-ai-api-key"

# Vertex AI
export VERTEX_AI_LOCATION="us-central1"

# Agent Endpoints (for A2A communication)
export THREAT_AGENT_ENDPOINT="https://threat-agent.run.app" # Replace with the endpoint got from threat analysis container deployment
export INCIDENT_AGENT_ENDPOINT="https://incident-agent.run.app" # Replace with the endpoint got from incident agent container deployment

# Chronicle SecOps (optional)
export CHRONICLE_PROJECT_ID="your-chronicle-project-id"
export CHRONICLE_CUSTOMER_ID="your-customer-id"
export CHRONICLE_REGION="us"

# Chronicle SOAR (optional)
export SOAR_URL="https://your-tenant.siemplify-soar.com:443"
export SOAR_APP_KEY="your-soar-api-key"

# Google Threat Intelligence / VirusTotal
export VT_APIKEY="your-virustotal-api-key"

Running Locally
Start Threat Analysis Agent
python -m agents.threat_agent
The agent will start an A2A server on port 8081 (configurable via THREAT_AGENT_PORT).

Start Incident Response Agent
python -m agents.incident_agent
The agent will start an A2A server on port 8082 (configurable via INCIDENT_AGENT_PORT).

Run Root Orchestrator
python -m agents.root_agent
The orchestrator will discover sub-agents from Vertex AI Registry and process security events.

Deployment to Vertex AI
Deploy Individual Agents
Each agent can be deployed independently to Vertex AI:

1. Deploy Threat Analysis Agent
cd deployment
./deploy_threat_agent.sh
2. Deploy Incident Response Agent
./deploy_incident_agent.sh
3. Deploy Root Orchestrator
./deploy_root_agent.sh
Using Deployment Scripts
The deployment scripts in deployment/ directory handle:

Building container images
Pushing to Google Container Registry
Deploying to Vertex AI
Registering agents in Vertex AI Agent Registry
Setting up HTTPS endpoints
Testing
Run the test suite:
**
Backend Tests**

# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_threat_agent.py

# Run with coverage
python -m pytest tests/ --cov=agents --cov=shared
Test Structure
tests/test_threat_agent.py - Threat Analysis Agent tests
tests/test_incident_agent.py - Incident Response Agent tests
tests/test_root_agent.py - Root Orchestrator tests
tests/test_a2a.py - A2A protocol tests
tests/test_integration.py - End-to-end integration tests



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

# For real threat intel (recommended)
VT_APIKEY=your-virustotal-api-key
```

### 3. Run the UI

```bash
uv run streamlit run ui.py
```

Open http://localhost:8501 to access the Argus dashboard.

### 4. Run Tests

```bash
uv run pytest tests/ -v
```

## 📁 Project Structure

```
├── agents/                  # The 3 agents
│   ├── threat_agent.py      # Threat analysis (GTI MCP)
│   ├── incident_agent.py    # Incident response (Simulated SOAR)
│   └── root_agent.py        # Orchestrator (Argus)
│
├── shared/                  # Shared utilities
│   ├── communication/       # A2A protocol
│   ├── memory/              # BigQuery persistence
│   ├── discovery/           # Agent registry
│   └── config/              # MCP configuration
│
├── ui.py                    # Streamlit UI
├── tests/                   # Unit tests
└── deployment/              # Cloud Run deployment
```

## 🤖 Agents

### RootOrchestratorAgent (Argus)
- **Role**: Central coordinator and chat interface
- **Capabilities**: Natural language understanding, task delegation
- **Tools**: `analyze_threat`, `respond_to_incident`, `execute_quick_action`

### ThreatAnalysisAgent
- **Role**: Threat intelligence analysis
- **Backend**: GTI MCP Server (VirusTotal)
- **Tools**: 35+ tools including `get_ip_address_report`, `get_domain_report`, `search_iocs`

### IncidentResponseAgent
- **Role**: Incident containment and response
- **Backend**: Simulated SOAR (Demo mode)
- **Tools**: `create_case`, `block_ip`, `isolate_endpoint`, `disable_user`

## 💬 Chat Examples

```
"Analyze the IP 203.0.113.42"
"Is evil-domain.com malicious?"
"Check this hash: 44d88612fea8a8f36de82e1278abb02f"
"Block IP 10.0.0.1"
"Create an incident case for this threat"
```

## 🔧 Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLOUD_PROJECT` | Yes | GCP Project ID |
| `GOOGLE_API_KEY` | Yes | Gemini API key |
| `VT_APIKEY` | Recommended | VirusTotal API key (enables 35 MCP tools) |
| `CHRONICLE_PROJECT_ID` | No | Chronicle SecOps project |
| `SOAR_API_KEY` | No | Chronicle SOAR API key |

## 🌐 Deployment

### Option 1: Streamlit Community Cloud (Recommended for Demos)

**Perfect for Kaggle submissions and demo videos.**

1. **Push to GitHub**
   ```bash
   git add .
   git commit -m "Argus v3.0 - Ready for deployment"
   git push origin main
   ```

2. **Deploy on Streamlit Cloud**
   - Go to [share.streamlit.io](https://share.streamlit.io)
   - Click "New app"
   - Select your GitHub repository
   - Set **Main file path**: `ui.py`
   - Click "Deploy"

3. **Configure Secrets** (in Streamlit Cloud dashboard)
   - Go to your app → Settings → Secrets
   - Add your secrets:
   ```toml
   VT_APIKEY = "your-virustotal-api-key"
   GOOGLE_API_KEY = "your-gemini-api-key"
   GOOGLE_CLOUD_PROJECT = "your-project-id"
   ```

4. **Your app is live!** 🎉
   - URL: `https://your-app-name.streamlit.app`
   - Share this URL in your Kaggle submission

### Option 2: Cloud Run (Production)

```bash
# Set environment
export GOOGLE_CLOUD_PROJECT=your-project-id

# Deploy all agents
cd deployment
./deploy_threat_agent.sh
./deploy_incident_agent.sh
./deploy_root_agent.sh
```

## 🧪 Testing

```bash
# Run all tests
uv run pytest tests/ -v

# Run with coverage
uv run pytest tests/ --cov=agents --cov=shared
```

## 📊 Mode Indicators

The UI shows the current mode:

| Icon | Mode | Description |
|------|------|-------------|
| 🟢 | Live | VT_APIKEY configured, real threat intel |
| 🟡 | Demo | No API key, simulated responses |

## 🔗 A2A Protocol

Agents communicate via HTTPS using the A2A (Agent-to-Agent) protocol:

```json
POST /a2a/invoke
{
  "agent": "ThreatAnalysisAgent",
  "method": "analyze_indicator",
  "params": {
    "indicator": "203.0.113.42",
    "indicator_type": "ip"
  }
}
```

## 📜 License

MIT

---

*Argus v3.0 • Powered by Google ADK + GTI MCP*

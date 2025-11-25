# Multi-Agent Security System - Production Edition

A production-ready, distributed multi-agent security system built with Google ADK, communicating via A2A (Agent-to-Agent) protocol over HTTPS. All agents are designed to be deployed independently on Vertex AI.

## Architecture

```
+---------------------------------------------------------+
|  Root Orchestrator Agent                                |
|  (Vertex AI Endpoint)                                   |
|  - Discovers sub-agents from Vertex AI Registry         |
|  - Coordinates workflow via A2A protocol               |
+---------------------------------------------------------+
                          |
                          | A2A Protocol (HTTPS)
                          |
        +-----------------+-----------------+
        |                                   |
        v                                   v
+----------------------+        +----------------------+
| Threat Analysis      |        | Incident Response     |
| Agent Service        |        | Agent Service        |
|                      |        |                      |
| - GTI Integration    |        | - Chronicle SecOps   |
| - IOC Analysis       |        | - Chronicle SOAR     |
| - Vertex AI Registry |        | - Vertex AI Registry |
+----------------------+        +----------------------+
```

## Components

### Agents

1. **RootOrchestratorAgent** (`agents/root_agent.py`)
   - Coordinates all sub-agents
   - Discovers agents from Vertex AI Agent Registry
   - Makes decisions on threat response
   - Manages session and persistent memory

2. **ThreatAnalysisAgent** (`agents/threat_agent.py`)
   - Analyzes security indicators using Google Threat Intelligence (GTI)
   - Provides threat severity assessment
   - Maps threats to MITRE ATT&CK techniques
   - Stores findings in BigQuery

3. **IncidentResponseAgent** (`agents/incident_agent.py`)
   - Handles security incidents using Chronicle SecOps and SOAR
   - Executes automated response playbooks
   - Manages incident lifecycle
   - Documents incident timeline

### Shared Components

- **A2A Protocol** (`shared/a2a_client.py`, `shared/a2a_server.py`)
  - HTTPS-based communication between agents
  - Standardized request/response format
  - Authentication via Google Cloud credentials

- **Vertex AI Agent Registry** (`shared/vertex_registry.py`)
  - Agent registration and discovery
  - Endpoint resolution
  - Capability-based filtering

- **Memory Management** (`shared/memory.py`)
  - BigQuery-based persistent storage
  - Threat intelligence history
  - Incident tracking

## Prerequisites

- Python 3.9+
- Google Cloud Project with:
  - Vertex AI API enabled
  - BigQuery API enabled
  - Service account with appropriate permissions
- Google AI API key (for Gemini models)
- Environment variables configured (see Configuration section)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd kaggle-capstone-entr-sec
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up Google Cloud authentication:
```bash
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID
```

4. Configure environment variables (see Configuration section)

## Configuration

### Environment Variables

Create a `.env` file or set the following environment variables:

```bash
# Google Cloud
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_APPLICATION_CREDENTIALS="path/to/service-account.json"

# Google AI (Gemini)
export GOOGLE_API_KEY="your-google-ai-api-key"

# Vertex AI
export VERTEX_AI_LOCATION="us-central1"

# Agent Endpoints (for A2A communication)
export THREAT_AGENT_ENDPOINT="https://threat-agent.run.app"
export INCIDENT_AGENT_ENDPOINT="https://incident-agent.run.app"

# Chronicle SecOps (optional)
export CHRONICLE_PROJECT_ID="your-chronicle-project-id"
export CHRONICLE_CUSTOMER_ID="your-customer-id"
export CHRONICLE_REGION="us"

# Chronicle SOAR (optional)
export SOAR_URL="https://your-tenant.siemplify-soar.com:443"
export SOAR_APP_KEY="your-soar-api-key"

# Google Threat Intelligence / VirusTotal
export VT_APIKEY="your-virustotal-api-key"
```

## Running Locally

### Start Threat Analysis Agent

```bash
python -m agents.threat_agent
```

The agent will start an A2A server on port 8081 (configurable via `THREAT_AGENT_PORT`).

### Start Incident Response Agent

```bash
python -m agents.incident_agent
```

The agent will start an A2A server on port 8082 (configurable via `INCIDENT_AGENT_PORT`).

### Run Root Orchestrator

```bash
python -m agents.root_agent
```

The orchestrator will discover sub-agents from Vertex AI Registry and process security events.

## Deployment to Vertex AI

### Deploy Individual Agents

Each agent can be deployed independently to Vertex AI:

#### 1. Deploy Threat Analysis Agent

```bash
cd deployment
./deploy_threat_agent.sh
```

#### 2. Deploy Incident Response Agent

```bash
./deploy_incident_agent.sh
```

#### 3. Deploy Root Orchestrator

```bash
./deploy_root_agent.sh
```

### Using Deployment Scripts

The deployment scripts in `deployment/` directory handle:
- Building container images
- Pushing to Google Container Registry
- Deploying to Vertex AI
- Registering agents in Vertex AI Agent Registry
- Setting up HTTPS endpoints

## Testing

Run the test suite:

```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_threat_agent.py

# Run with coverage
python -m pytest tests/ --cov=agents --cov=shared
```

### Test Structure

- `tests/test_threat_agent.py` - Threat Analysis Agent tests
- `tests/test_incident_agent.py` - Incident Response Agent tests
- `tests/test_root_agent.py` - Root Orchestrator tests
- `tests/test_a2a.py` - A2A protocol tests
- `tests/test_integration.py` - End-to-end integration tests

## Usage

### Process a Security Event

```python
from agents.root_agent import RootOrchestratorAgent

# Initialize orchestrator
orchestrator = RootOrchestratorAgent(project_id="your-project-id")

# Process security event
event = {
    "indicator": "203.0.113.42",
    "indicator_type": "ip",
    "source": "SIEM",
    "timestamp": "2025-11-23T10:00:00Z"
}

result = orchestrator.process_security_event(event)
print(result)
```

### Direct Agent Invocation (via A2A)

```python
from shared.a2a_client import A2AClient

client = A2AClient(project_id="your-project-id")

# Call Threat Analysis Agent
result = client.invoke_agent(
    agent_name="ThreatAnalysisAgent",
    method="analyze_indicator",
    params={
        "indicator": "203.0.113.42",
        "indicator_type": "ip"
    },
    endpoint="https://threat-agent.run.app"
)
```

## A2A Protocol

The A2A (Agent-to-Agent) protocol enables communication between distributed agents over HTTPS.

### Request Format

```json
{
  "agent": "ThreatAnalysisAgent",
  "method": "analyze_indicator",
  "params": {
    "indicator": "203.0.113.42",
    "indicator_type": "ip",
    "context": "Additional context"
  },
  "protocol_version": "1.0"
}
```

### Response Format

```json
{
  "success": true,
  "agent": "ThreatAnalysisAgent",
  "method": "analyze_indicator",
  "result": {
    "indicator": "203.0.113.42",
    "severity": "CRITICAL",
    "confidence": 95
  }
}
```

## Vertex AI Agent Registry

Agents register themselves in Vertex AI Agent Registry upon startup, making them discoverable by other agents.

### Registration

Agents automatically register with:
- Agent name
- HTTPS endpoint
- Capabilities list
- Metadata

### Discovery

The Root Orchestrator discovers sub-agents by querying the registry:

```python
from shared.vertex_registry import VertexAIAgentRegistry

registry = VertexAIAgentRegistry(project_id="your-project-id")
agent_info = registry.discover_agent("ThreatAnalysisAgent")
```

## Monitoring and Logging

### Logging

All agents use Python's `logging` module. Set log level via:

```python
import logging
logging.basicConfig(level=logging.INFO)
```

### Vertex AI Monitoring

Once deployed to Vertex AI, monitor agents via:
- Vertex AI Console
- Cloud Logging
- Cloud Monitoring

## Troubleshooting

### Agent Discovery Fails

- Verify agents are registered in Vertex AI Agent Registry
- Check endpoint URLs are correct
- Ensure service account has necessary permissions

### A2A Communication Errors

- Verify HTTPS endpoints are accessible
- Check authentication credentials
- Review firewall/network rules

### BigQuery Errors

- Ensure BigQuery dataset exists
- Verify service account has BigQuery permissions
- Check table schemas match expected format

## Development

### Project Structure

```
.
├── agents/              # Agent modules
│   ├── root_agent.py
│   ├── threat_agent.py
│   └── incident_agent.py
├── shared/             # Shared utilities
│   ├── a2a_client.py
│   ├── a2a_server.py
│   ├── memory.py
│   ├── config.py
│   └── vertex_registry.py
├── tests/              # Test suite
├── deployment/         # Deployment scripts
├── config/             # Configuration files
└── requirements.txt
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

[Your License Here]

## Support

For issues and questions:
- Open an issue on GitHub
- Contact: [Your Contact Information]

## References

- [Google ADK Documentation](https://github.com/google/adk-docs)
- [Vertex AI Agent Engine](https://cloud.google.com/vertex-ai/docs)
- [A2A Protocol Specification](https://google.github.io/adk-docs/a2a/intro/)
- [Google Cloud Security MCP Servers](https://github.com/google/mcp-security)

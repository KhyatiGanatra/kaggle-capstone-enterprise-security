# Production Setup Summary

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

## Configuration

1. **Configure Environment Variables**
   - Set all required environment variables (see README.md. and env.template)

2. **Set Up BigQuery**
   - Create dataset: `security_intel`
   - Tables will be created automatically

## Cloud Run deploy

1. **Deploy Sub-Agents First**
   ```bash
   ./deployment/deploy_threat_agent.sh
   ./deployment/deploy_incident_agent.sh
   ```
   -Make sure to update the THREAT and INCIDENT agent env variables with the  agent endpoint service url
2. **Agents Register with Vertex AI Registry**
   - Automatic registration on startup
   - Endpoints stored in registry

3. **Deploy Root Orchestrator**
   ```bash
   ./deployment/deploy_root_agent.sh
   ```
    -Make sure to update the ROOT agent env variables with the agent endpoint service url for the Ui to communicate with it
4. **Root Agent Discovers Sub-Agents**
   - Queries Vertex AI Agent Registry
   - Resolves endpoints
   - Establishes A2A connections

## Streamlit UI deploument

### Streamlit Community Cloud (Recommended for Demos) - UI

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
  

## Integration Test with cloud run deployed agent end points

Run the test suite:

```bash
python -m test_root_agent.py
```

All tests use mocking to avoid requiring actual Vertex AI deployment during development.

## Next Steps

1. **Monitor and Scale**
   - Use Cloud Run Console for monitoring
   - Configure auto-scaling
   - Set up alerts

## Differences from Original

### Original (Monolithic)
- All agents in same process
- Direct object references
- Same environment
- Single deployment

### Production (Distributed)
- Separate services
- A2A protocol over HTTPS
- Independent environments
- Independent deployment
- Vertex AI Agent Registry
- Fault isolation
- Independent scaling

## File Structure

```
.
├── agents/              # Agent modules (separate services)
│   ├── root_agent.py
│   ├── threat_agent.py
│   └── incident_agent.py
├── shared/             # Shared utilities
│   ├── a2a_client.py
│   ├── a2a_server.py
│   ├── vertex_registry.py
│   ├── memory.py
│   └── config.py
├── tests/              # Test suite
│   ├── test_threat_agent.py
│   ├── test_incident_agent.py
│   ├── test_root_agent.py
│   ├── test_a2a.py
│   └── test_integration.py
├── deployment/         # Deployment scripts
│   ├── deploy_*.sh
│   └── Dockerfile.*
├── README.md          # Production documentation
├── requirements.txt   # Dependencies
└── .gitignore        # Git ignore rules
```

## Summary

All production artifacts have been created:
✅ Separate agent modules with A2A support
✅ Cloud Run integration
✅ Comprehensive test suite
✅ Deployment scripts and Dockerfiles
✅ Production documentation
✅ Requirements and configuration files

The system is ready for production deployment to Vertex AI!



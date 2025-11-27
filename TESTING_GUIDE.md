# Testing Guide for Root Orchestrator Agent

This guide explains how to verify the functionality of the deployed Root Orchestrator Agent on Cloud Run.

## Prerequisites

- Root Orchestrator Agent deployed on Cloud Run
- Threat Analysis Agent and Incident Response Agent deployed (or endpoints configured)
- `requests` Python library installed: `pip install requests` or `uv add requests`

## Getting the Endpoint URL

After deployment, get the endpoint URL:

```bash
gcloud run services describe root-orchestrator-agent \
  --project=kaggle-adk-capstone-secmon \
  --region=us-central1 \
  --format='value(status.url)'
```

Or view it in the [Cloud Run Console](https://console.cloud.google.com/run).

## Testing Methods

### Method 1: Using the Test Script (Recommended)

A comprehensive test script is provided: `test_root_agent.py`

```bash
# Set the endpoint
export ROOT_AGENT_ENDPOINT=https://root-orchestrator-agent-xxxxx.run.app

# Run the test script
python test_root_agent.py

# Or pass endpoint as argument
python test_root_agent.py https://root-orchestrator-agent-xxxxx.run.app
```

The script will:
1. Test health check endpoint
2. Test root endpoint
3. Send a sample security event
4. Get session status
5. Display results summary

### Method 2: Using cURL

#### 1. Health Check

```bash
curl https://root-orchestrator-agent-xxxxx.run.app/health
```

Expected response:
```json
{
  "status": "healthy",
  "agent": "RootOrchestratorAgent"
}
```

#### 2. Root Endpoint

```bash
curl https://root-orchestrator-agent-xxxxx.run.app/
```

#### 3. Process Security Event

```bash
curl -X POST https://root-orchestrator-agent-xxxxx.run.app/a2a/invoke \
  -H "Content-Type: application/json" \
  -d '{
    "agent": "RootOrchestratorAgent",
    "method": "process_security_event",
    "params": {
      "indicator": "203.0.113.42",
      "indicator_type": "ip",
      "source": "SIEM",
      "timestamp": "2025-11-27T10:00:00Z",
      "context": "Suspicious outbound connection detected"
    },
    "protocol_version": "1.0"
  }'
```

#### 4. Get Session Status

```bash
curl -X POST https://root-orchestrator-agent-xxxxx.run.app/a2a/invoke \
  -H "Content-Type: application/json" \
  -d '{
    "agent": "RootOrchestratorAgent",
    "method": "get_session_status",
    "params": {},
    "protocol_version": "1.0"
  }'
```

### Method 3: Using Python

```python
import requests
import json

endpoint = "https://root-orchestrator-agent-xxxxx.run.app"

# Test health
response = requests.get(f"{endpoint}/health")
print(response.json())

# Process security event
event = {
    "indicator": "203.0.113.42",
    "indicator_type": "ip",
    "source": "SIEM",
    "timestamp": "2025-11-27T10:00:00Z"
}

a2a_request = {
    "agent": "RootOrchestratorAgent",
    "method": "process_security_event",
    "params": event,
    "protocol_version": "1.0"
}

response = requests.post(
    f"{endpoint}/a2a/invoke",
    json=a2a_request,
    timeout=120
)

result = response.json()
print(json.dumps(result, indent=2))
```

## Sample Security Events

### IP Address

```json
{
  "indicator": "203.0.113.42",
  "indicator_type": "ip",
  "source": "SIEM",
  "timestamp": "2025-11-27T10:00:00Z",
  "context": "Multiple failed login attempts from this IP"
}
```

### Domain

```json
{
  "indicator": "malicious-domain.com",
  "indicator_type": "domain",
  "source": "DNS Filter",
  "timestamp": "2025-11-27T10:00:00Z",
  "context": "Blocked domain resolution attempt"
}
```

### File Hash

```json
{
  "indicator": "a1b2c3d4e5f6...",
  "indicator_type": "hash",
  "source": "EDR",
  "timestamp": "2025-11-27T10:00:00Z",
  "context": "Unknown executable detected on endpoint"
}
```

### URL

```json
{
  "indicator": "https://suspicious-site.com/payload.exe",
  "indicator_type": "url",
  "source": "Web Proxy",
  "timestamp": "2025-11-27T10:00:00Z",
  "context": "User attempted to download suspicious file"
}
```

## Expected Response Format

When processing a security event, you should receive:

```json
{
  "success": true,
  "agent": "RootOrchestratorAgent",
  "method": "process_security_event",
  "result": {
    "success": true,
    "investigation_id": "INV-xxxxx",
    "status": "COMPLETED",
    "threat_analysis": {
      "indicator": "203.0.113.42",
      "indicator_type": "ip",
      "severity": "HIGH",
      "confidence": 85,
      "threat_type": "c2",
      ...
    },
    "incident_response": {
      "incident_id": "INC-xxxxx",
      "status": "CREATED",
      ...
    },
    "orchestration_summary": "..."
  }
}
```

## Troubleshooting

### Agent Not Responding

1. Check if the service is running:
   ```bash
   gcloud run services describe root-orchestrator-agent \
     --project=kaggle-adk-capstone-secmon \
     --region=us-central1
   ```

2. Check logs:
   ```bash
   gcloud run services logs read root-orchestrator-agent \
     --project=kaggle-adk-capstone-secmon \
     --region=us-central1 \
     --limit=50
   ```

### Sub-Agents Not Found

If you see errors about sub-agents not being found:

1. Ensure Threat Analysis Agent and Incident Response Agent are deployed
2. Set environment variables in Cloud Run:
   ```bash
   gcloud run services update root-orchestrator-agent \
     --set-env-vars THREAT_AGENT_ENDPOINT=https://threat-agent-xxxxx.run.app \
     --set-env-vars INCIDENT_AGENT_ENDPOINT=https://incident-agent-xxxxx.run.app \
     --project=kaggle-adk-capstone-secmon \
     --region=us-central1
   ```

### Timeout Errors

If requests timeout:

1. Increase Cloud Run timeout:
   ```bash
   gcloud run services update root-orchestrator-agent \
     --timeout=600 \
     --project=kaggle-adk-capstone-secmon \
     --region=us-central1
   ```

2. Increase client timeout in your test script

### Authentication Errors

If you get 403 Forbidden:

1. Check if service allows unauthenticated access:
   ```bash
   gcloud run services get-iam-policy root-orchestrator-agent \
     --project=kaggle-adk-capstone-secmon \
     --region=us-central1
   ```

2. If authentication is required, use an identity token:
   ```bash
   curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
     https://root-orchestrator-agent-xxxxx.run.app/health
   ```

## Monitoring

View real-time logs:

```bash
gcloud run services logs tail root-orchestrator-agent \
  --project=kaggle-adk-capstone-secmon \
  --region=us-central1
```

View metrics in [Cloud Run Console](https://console.cloud.google.com/run):
- Request count
- Latency
- Error rate
- CPU/Memory usage

## Next Steps

After verifying basic functionality:

1. Test with different indicator types (IP, domain, hash, URL)
2. Test with multiple events in sequence
3. Verify sub-agent communication
4. Check BigQuery for stored threat intelligence and incidents
5. Monitor performance and optimize if needed




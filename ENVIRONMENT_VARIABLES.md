# Environment Variables Guide

This document lists all environment variables required for the Multi-Agent Security System and explains where to configure them for production deployment.

## Required Environment Variables

### Core Google Cloud Variables

| Variable | Required For | Description | Example |
|----------|-------------|------------|---------|
| `GOOGLE_CLOUD_PROJECT` | All agents | Your Google Cloud Project ID | `my-security-project` |
| `GOOGLE_APPLICATION_CREDENTIALS` | All agents | Path to service account JSON key file (for local dev) | `/path/to/service-account.json` |
| `GOOGLE_API_KEY` | All agents | Google AI API key for Gemini models | `AIza...` |
| `VERTEX_AI_LOCATION` | Root agent, Registry | Vertex AI region | `us-central1` |

### Agent-Specific Variables

| Variable | Required For | Description | Default |
|----------|-------------|------------|---------|
| `THREAT_AGENT_ENDPOINT` | Root agent, Threat agent | HTTPS endpoint for Threat Analysis Agent | `http://localhost:8081` |
| `INCIDENT_AGENT_ENDPOINT` | Root agent, Incident agent | HTTPS endpoint for Incident Response Agent | `http://localhost:8082` |
| `THREAT_AGENT_PORT` | Threat agent | Port for Threat Analysis Agent A2A server | `8081` |
| `INCIDENT_AGENT_PORT` | Incident agent | Port for Incident Response Agent A2A server | `8082` |

### Security Service Variables

| Variable | Required For | Description | Optional |
|----------|-------------|------------|----------|
| `VT_APIKEY` | Threat agent | VirusTotal/Google Threat Intelligence API key | No |
| `CHRONICLE_PROJECT_ID` | Incident agent | Chronicle SecOps project ID | Yes |
| `CHRONICLE_CUSTOMER_ID` | Incident agent | Chronicle customer ID | Yes |
| `CHRONICLE_REGION` | Incident agent | Chronicle region | Yes (default: `us`) |
| `SOAR_URL` | Incident agent | Chronicle SOAR tenant URL | Yes |
| `SOAR_APP_KEY` | Incident agent | Chronicle SOAR API key | Yes |

## Production Deployment: Where to Set Environment Variables

### Option 1: Google Cloud Secret Manager (Recommended for Secrets)

**Best for:** API keys, credentials, and sensitive data

#### Setup Steps:

1. **Create secrets in Secret Manager:**

```bash
# Set your project
export PROJECT_ID="your-project-id"

# Create secrets
echo -n "your-google-api-key" | gcloud secrets create google-api-key --data-file=-
echo -n "your-vt-apikey" | gcloud secrets create vt-apikey --data-file=-
echo -n "your-soar-app-key" | gcloud secrets create soar-app-key --data-file=-
```

2. **Grant access to Cloud Run service account:**

```bash
# Get your Cloud Run service account email
SERVICE_ACCOUNT="${PROJECT_ID}@appspot.gserviceaccount.com"

# Grant secret accessor role
gcloud secrets add-iam-policy-binding google-api-key \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding vt-apikey \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding soar-app-key \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/secretmanager.secretAccessor"
```

3. **Update deployment scripts to use secrets:**

Modify `deploy_threat_agent.sh`:
```bash
gcloud run deploy ${SERVICE_NAME} \
  --image ${IMAGE_NAME} \
  --platform managed \
  --region ${LOCATION} \
  --project ${PROJECT_ID} \
  --set-secrets="GOOGLE_API_KEY=google-api-key:latest,VT_APIKEY=vt-apikey:latest" \
  --set-env-vars GOOGLE_CLOUD_PROJECT=${PROJECT_ID} \
  --memory 2Gi \
  --cpu 2 \
  --timeout 300
```

### Option 2: Cloud Run Environment Variables (For Non-Sensitive Data)

**Best for:** Project IDs, regions, endpoints, and non-sensitive configuration

#### Direct in Deployment Scripts:

The deployment scripts already set these via `--set-env-vars`:

```bash
gcloud run deploy ${SERVICE_NAME} \
  --set-env-vars GOOGLE_CLOUD_PROJECT=${PROJECT_ID} \
  --set-env-vars VERTEX_AI_LOCATION=${LOCATION} \
  --set-env-vars THREAT_AGENT_ENDPOINT=${THREAT_ENDPOINT} \
  --set-env-vars INCIDENT_AGENT_ENDPOINT=${INCIDENT_ENDPOINT}
```

#### Via Cloud Console:

1. Go to Cloud Run → Select service → Edit & Deploy New Revision
2. Navigate to "Variables & Secrets" tab
3. Add environment variables:
   - `GOOGLE_CLOUD_PROJECT`: `your-project-id`
   - `VERTEX_AI_LOCATION`: `us-central1`
   - `THREAT_AGENT_ENDPOINT`: `https://threat-agent-xxx.run.app`
   - `INCIDENT_AGENT_ENDPOINT`: `https://incident-agent-xxx.run.app`

### Option 3: .env File (Local Development Only)

**⚠️ Never commit .env files to git!**

Create `.env` in project root:

```bash
# .env (for local development)
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_API_KEY=your-google-api-key
VERTEX_AI_LOCATION=us-central1
VT_APIKEY=your-virustotal-api-key
CHRONICLE_PROJECT_ID=your-chronicle-project-id
CHRONICLE_CUSTOMER_ID=your-customer-id
CHRONICLE_REGION=us
SOAR_URL=https://your-tenant.siemplify-soar.com:443
SOAR_APP_KEY=your-soar-api-key
THREAT_AGENT_ENDPOINT=http://localhost:8081
INCIDENT_AGENT_ENDPOINT=http://localhost:8082
```

Load in Python:
```python
from dotenv import load_dotenv
load_dotenv()
```

## Production Deployment Strategy

### Recommended Approach:

1. **Use Secret Manager for sensitive data:**
   - `GOOGLE_API_KEY`
   - `VT_APIKEY`
   - `SOAR_APP_KEY`
   - `CHRONICLE_CUSTOMER_ID` (if sensitive)

2. **Use Cloud Run environment variables for configuration:**
   - `GOOGLE_CLOUD_PROJECT`
   - `VERTEX_AI_LOCATION`
   - `THREAT_AGENT_ENDPOINT`
   - `INCIDENT_AGENT_ENDPOINT`
   - `CHRONICLE_PROJECT_ID`
   - `CHRONICLE_REGION`
   - `SOAR_URL`

3. **Use Application Default Credentials (ADC) for GCP services:**
   - Cloud Run automatically provides ADC
   - No need to set `GOOGLE_APPLICATION_CREDENTIALS` in production
   - Service account is automatically attached to Cloud Run service

## Updated Deployment Scripts

Here's how to update the deployment scripts to use Secret Manager:

### Example: Updated `deploy_threat_agent.sh`

```bash
#!/bin/bash
# Deploy Threat Analysis Agent to Vertex AI with Secret Manager

set -e

PROJECT_ID=${GOOGLE_CLOUD_PROJECT:-"your-project-id"}
LOCATION=${VERTEX_AI_LOCATION:-"us-central1"}
IMAGE_NAME="gcr.io/${PROJECT_ID}/threat-analysis-agent"
SERVICE_NAME="threat-analysis-agent"

echo "Deploying Threat Analysis Agent to Vertex AI..."
echo "Project: ${PROJECT_ID}"
echo "Location: ${LOCATION}"

# Build and push Docker image (same as before)
docker build -t ${IMAGE_NAME} -f deployment/Dockerfile.threat_agent .
docker push ${IMAGE_NAME}

# Deploy with secrets from Secret Manager
gcloud run deploy ${SERVICE_NAME} \
  --image ${IMAGE_NAME} \
  --platform managed \
  --region ${LOCATION} \
  --project ${PROJECT_ID} \
  --allow-unauthenticated \
  --set-secrets="GOOGLE_API_KEY=google-api-key:latest,VT_APIKEY=vt-apikey:latest" \
  --set-env-vars GOOGLE_CLOUD_PROJECT=${PROJECT_ID} \
  --set-env-vars VERTEX_AI_LOCATION=${LOCATION} \
  --memory 2Gi \
  --cpu 2 \
  --timeout 300

# Get endpoint and register (same as before)
ENDPOINT=$(gcloud run services describe ${SERVICE_NAME} \
  --platform managed \
  --region ${LOCATION} \
  --project ${PROJECT_ID} \
  --format 'value(status.url)')

echo "Threat Analysis Agent deployed!"
echo "Endpoint: ${ENDPOINT}"

# Register in Vertex AI Agent Registry
python3 -c "
from shared.vertex_registry import VertexAIAgentRegistry
registry = VertexAIAgentRegistry('${PROJECT_ID}', '${LOCATION}')
registry.register_agent(
    agent_name='ThreatAnalysisAgent',
    endpoint='${ENDPOINT}',
    capabilities=['analyze_indicator', 'threat_intelligence', 'ioc_analysis']
)
print('Agent registered successfully!')
"

echo "Deployment complete!"
```

## Environment Variable Priority

The application checks environment variables in this order:

1. **Environment variables** (set in Cloud Run or shell)
2. **Default values** (hardcoded in code)
3. **Error/warning** (if required and missing)

## Verification

After deployment, verify environment variables are set:

```bash
# Check Cloud Run service environment variables
gcloud run services describe threat-analysis-agent \
  --platform managed \
  --region us-central1 \
  --format="value(spec.template.spec.containers[0].env)"
```

## Security Best Practices

1. ✅ **Never commit secrets to git**
2. ✅ **Use Secret Manager for all API keys and credentials**
3. ✅ **Rotate secrets regularly**
4. ✅ **Use least-privilege IAM roles**
5. ✅ **Enable audit logging for secret access**
6. ✅ **Use separate secrets for dev/staging/prod**
7. ✅ **Validate environment variables at startup**

## Troubleshooting

### Missing Environment Variable

If an agent fails with "missing environment variable":
1. Check Cloud Run service configuration
2. Verify Secret Manager secrets exist and are accessible
3. Check service account permissions
4. Review Cloud Run logs: `gcloud logging read "resource.type=cloud_run_revision"`

### Secret Access Denied

If you get "permission denied" accessing secrets:
1. Verify service account has `roles/secretmanager.secretAccessor`
2. Check secret exists: `gcloud secrets list`
3. Verify secret version: Use `:latest` or specific version number

### ADC Not Working

If Application Default Credentials fail:
1. Cloud Run automatically provides ADC - no action needed
2. For local testing: `gcloud auth application-default login`
3. Verify service account has necessary permissions





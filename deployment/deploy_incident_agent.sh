#!/bin/bash
# Deploy Incident Response Agent to Vertex AI

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Change to project root (one level up from deployment/)
PROJECT_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
cd "${PROJECT_ROOT}"

# Load environment variables from .env file if it exists
if [ -f "${PROJECT_ROOT}/.env" ]; then
    echo "Loading environment variables from .env..."
    set -a
    source "${PROJECT_ROOT}/.env"
    set +a
elif [ -f "${PROJECT_ROOT}/cloud_dev.env" ]; then
    echo "Loading environment variables from cloud_dev.env..."
    set -a
    source "${PROJECT_ROOT}/cloud_dev.env"
    set +a
else
    echo "⚠ Warning: No .env or cloud_dev.env file found. Using environment variables from shell."
fi

PROJECT_ID=${GOOGLE_CLOUD_PROJECT:-"your-project-id"}
LOCATION=${VERTEX_AI_LOCATION:-"us-central1"}
IMAGE_NAME="gcr.io/${PROJECT_ID}/incident-response-agent"
SERVICE_NAME="incident-response-agent"

# Validate project ID
if [ "${PROJECT_ID}" = "your-project-id" ] || [ -z "${PROJECT_ID}" ]; then
    echo "ERROR: GOOGLE_CLOUD_PROJECT is not set or is still the placeholder value."
    echo "Please set GOOGLE_CLOUD_PROJECT in your .env or cloud_dev.env file."
    exit 1
fi

echo "Deploying Incident Response Agent to Vertex AI..."
echo "Project: ${PROJECT_ID}"
echo "Location: ${LOCATION}"
echo "Working directory: ${PROJECT_ROOT}"

# Build Docker image in Google Cloud Build (no local Docker required)
echo "Building Docker image in Google Cloud Build..."
# Create temporary cloudbuild.yaml
cat > /tmp/cloudbuild-incident-agent.yaml <<EOF
steps:
- name: 'gcr.io/cloud-builders/docker'
  args: ['build', '-t', '${IMAGE_NAME}', '-f', 'deployment/Dockerfile.incident_agent', '.']
images:
- '${IMAGE_NAME}'
EOF

gcloud builds submit \
  --config /tmp/cloudbuild-incident-agent.yaml \
  --project ${PROJECT_ID} \
  .

# Clean up
rm -f /tmp/cloudbuild-incident-agent.yaml

# Deploy to Vertex AI (Cloud Run)
echo "Deploying to Cloud Run..."
gcloud run deploy ${SERVICE_NAME} \
  --image ${IMAGE_NAME} \
  --platform managed \
  --region ${LOCATION} \
  --project ${PROJECT_ID} \
  --allow-unauthenticated \
  --set-env-vars GOOGLE_CLOUD_PROJECT=${PROJECT_ID} \
  --set-env-vars GOOGLE_API_KEY=${GOOGLE_API_KEY} \
  --set-env-vars CHRONICLE_PROJECT_ID=${CHRONICLE_PROJECT_ID} \
  --set-env-vars CHRONICLE_CUSTOMER_ID=${CHRONICLE_CUSTOMER_ID} \
  --set-env-vars SOAR_URL=${SOAR_URL} \
  --set-env-vars SOAR_APP_KEY=${SOAR_APP_KEY} \
  --memory 2Gi \
  --cpu 2 \
  --timeout 300

# Get endpoint URL
ENDPOINT=$(gcloud run services describe ${SERVICE_NAME} \
  --platform managed \
  --region ${LOCATION} \
  --project ${PROJECT_ID} \
  --format 'value(status.url)')

echo "Incident Response Agent deployed!"
echo "Endpoint: ${ENDPOINT}"

# Write endpoint to .env file for root agent discovery
ENV_FILE="${PROJECT_ROOT}/.env.agents"
# Remove old INCIDENT_AGENT_ENDPOINT if exists, then add new one
if [ -f "${ENV_FILE}" ]; then
    grep -v "^INCIDENT_AGENT_ENDPOINT=" "${ENV_FILE}" > "${ENV_FILE}.tmp" || true
    mv "${ENV_FILE}.tmp" "${ENV_FILE}"
fi
echo "INCIDENT_AGENT_ENDPOINT=${ENDPOINT}" >> "${ENV_FILE}"
echo "✓ Written INCIDENT_AGENT_ENDPOINT to ${ENV_FILE}"

# Register in Vertex AI Agent Registry (optional - agent will also register on startup)
echo "Registering agent in Vertex AI Agent Registry..."
# Try to use virtual environment if it exists
if [ -f "${PROJECT_ROOT}/.venv/bin/python" ]; then
    PYTHON_CMD="${PROJECT_ROOT}/.venv/bin/python"
elif [ -f "${PROJECT_ROOT}/venv/bin/python" ]; then
    PYTHON_CMD="${PROJECT_ROOT}/venv/bin/python"
else
    PYTHON_CMD="python3"
fi

if ${PYTHON_CMD} -c "
from shared.vertex_registry import VertexAIAgentRegistry
registry = VertexAIAgentRegistry('${PROJECT_ID}', '${LOCATION}')
registry.register_agent(
    agent_name='IncidentResponseAgent',
    endpoint='${ENDPOINT}',
    capabilities=['handle_incident', 'incident_response', 'chronicle_integration']
)
print('Agent registered successfully!')
" 2>/dev/null; then
    echo "✓ Agent registered in Vertex AI Agent Registry"
else
    echo "⚠ Warning: Could not register agent in Vertex AI Agent Registry (this is optional)"
    echo "  The agent will attempt to register itself when it starts up."
fi

echo "Deployment complete!"




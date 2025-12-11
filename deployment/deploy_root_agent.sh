#!/bin/bash
# Deploy Root Orchestrator Agent to Vertex AI

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
IMAGE_NAME="gcr.io/${PROJECT_ID}/root-orchestrator-agent"
SERVICE_NAME="root-orchestrator-agent"

# Validate project ID
if [ "${PROJECT_ID}" = "your-project-id" ] || [ -z "${PROJECT_ID}" ]; then
    echo "ERROR: GOOGLE_CLOUD_PROJECT is not set or is still the placeholder value."
    echo "Please set GOOGLE_CLOUD_PROJECT in your .env or cloud_dev.env file."
    exit 1
fi

echo "Deploying Root Orchestrator Agent to Vertex AI..."
echo "Project: ${PROJECT_ID}"
echo "Location: ${LOCATION}"
echo "Working directory: ${PROJECT_ROOT}"

# Build Docker image in Google Cloud Build (no local Docker required)
echo "Building Docker image in Google Cloud Build..."
# Create temporary cloudbuild.yaml
cat > /tmp/cloudbuild-root-agent.yaml <<EOF
steps:
- name: 'gcr.io/cloud-builders/docker'
  args: ['build', '-t', '${IMAGE_NAME}', '-f', 'deployment/Dockerfile.root_agent', '.']
images:
- '${IMAGE_NAME}'
EOF

gcloud builds submit \
  --config /tmp/cloudbuild-root-agent.yaml \
  --project ${PROJECT_ID} \
  .

# Clean up
rm -f /tmp/cloudbuild-root-agent.yaml

# Read agent endpoints from .env.agents file
ENV_FILE="${PROJECT_ROOT}/.env.agents"
THREAT_ENDPOINT=""
INCIDENT_ENDPOINT=""

if [ -f "${ENV_FILE}" ]; then
    echo "Reading agent endpoints from ${ENV_FILE}..."
    # Extract THREAT_AGENT_ENDPOINT
    THREAT_ENDPOINT=$(grep "^THREAT_AGENT_ENDPOINT=" "${ENV_FILE}" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || echo "")
    # Extract INCIDENT_AGENT_ENDPOINT
    INCIDENT_ENDPOINT=$(grep "^INCIDENT_AGENT_ENDPOINT=" "${ENV_FILE}" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || echo "")
    
    if [ -n "${THREAT_ENDPOINT}" ]; then
        echo "✓ Found THREAT_AGENT_ENDPOINT: ${THREAT_ENDPOINT}"
    else
        echo "⚠ Warning: THREAT_AGENT_ENDPOINT not found in ${ENV_FILE}"
    fi
    
    if [ -n "${INCIDENT_ENDPOINT}" ]; then
        echo "✓ Found INCIDENT_AGENT_ENDPOINT: ${INCIDENT_ENDPOINT}"
    else
        echo "⚠ Warning: INCIDENT_AGENT_ENDPOINT not found in ${ENV_FILE}"
    fi
else
    echo "⚠ Warning: ${ENV_FILE} not found. Deploy threat and incident agents first."
fi

# Build environment variables for gcloud (use multiple --set-env-vars flags like other agents)
ENV_VARS_ARGS="--set-env-vars GOOGLE_CLOUD_PROJECT=${PROJECT_ID}"
ENV_VARS_ARGS="${ENV_VARS_ARGS} --set-env-vars GOOGLE_API_KEY=${GOOGLE_API_KEY}"
ENV_VARS_ARGS="${ENV_VARS_ARGS} --set-env-vars VERTEX_AI_LOCATION=${LOCATION}"

# Add agent endpoints if found
if [ -n "${THREAT_ENDPOINT}" ]; then
    ENV_VARS_ARGS="${ENV_VARS_ARGS} --set-env-vars THREAT_AGENT_ENDPOINT=${THREAT_ENDPOINT}"
fi

if [ -n "${INCIDENT_ENDPOINT}" ]; then
    ENV_VARS_ARGS="${ENV_VARS_ARGS} --set-env-vars INCIDENT_AGENT_ENDPOINT=${INCIDENT_ENDPOINT}"
fi

# Deploy to Vertex AI (Cloud Run)
echo "Deploying to Cloud Run..."
gcloud run deploy ${SERVICE_NAME} \
  --image ${IMAGE_NAME} \
  --platform managed \
  --region ${LOCATION} \
  --project ${PROJECT_ID} \
  --allow-unauthenticated \
  ${ENV_VARS_ARGS} \
  --memory 4Gi \
  --cpu 4 \
  --timeout 600

# Get endpoint URL
ENDPOINT=$(gcloud run services describe ${SERVICE_NAME} \
  --platform managed \
  --region ${LOCATION} \
  --project ${PROJECT_ID} \
  --format 'value(status.url)')

echo "Root Orchestrator Agent deployed!"
echo "Endpoint: ${ENDPOINT}"

# Write endpoint to .env file for testing
ENV_FILE="${PROJECT_ROOT}/.env.agents"
# Remove old ROOT_AGENT_ENDPOINT if exists, then add new one
if [ -f "${ENV_FILE}" ]; then
    grep -v "^ROOT_AGENT_ENDPOINT=" "${ENV_FILE}" > "${ENV_FILE}.tmp" || true
    mv "${ENV_FILE}.tmp" "${ENV_FILE}"
fi
echo "ROOT_AGENT_ENDPOINT=${ENDPOINT}" >> "${ENV_FILE}"
echo "✓ Written ROOT_AGENT_ENDPOINT to ${ENV_FILE}"

echo "Deployment complete!"

#!/bin/bash
# Deploy Root Orchestrator Agent to Vertex AI

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Change to project root (one level up from deployment/)
PROJECT_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
cd "${PROJECT_ROOT}"

PROJECT_ID=${GOOGLE_CLOUD_PROJECT:-"your-project-id"}
LOCATION=${VERTEX_AI_LOCATION:-"us-central1"}
IMAGE_NAME="gcr.io/${PROJECT_ID}/root-orchestrator-agent"
SERVICE_NAME="root-orchestrator-agent"

echo "Deploying Root Orchestrator Agent to Vertex AI..."
echo "Project: ${PROJECT_ID}"
echo "Location: ${LOCATION}"
echo "Working directory: ${PROJECT_ROOT}"

# Build Docker image for linux/amd64 (Cloud Run platform)
echo "Building Docker image for linux/amd64..."
docker build --platform linux/amd64 -t ${IMAGE_NAME} -f deployment/Dockerfile.root_agent .

# Push to Google Container Registry
echo "Pushing image to GCR..."
docker push ${IMAGE_NAME}

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

# Build environment variables string for gcloud
ENV_VARS="GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_API_KEY=${GOOGLE_API_KEY},VERTEX_AI_LOCATION=${LOCATION}"

# Add agent endpoints if found
if [ -n "${THREAT_ENDPOINT}" ]; then
    ENV_VARS="${ENV_VARS},THREAT_AGENT_ENDPOINT=${THREAT_ENDPOINT}"
fi

if [ -n "${INCIDENT_ENDPOINT}" ]; then
    ENV_VARS="${ENV_VARS},INCIDENT_AGENT_ENDPOINT=${INCIDENT_ENDPOINT}"
fi

# Deploy to Vertex AI (Cloud Run)
echo "Deploying to Cloud Run..."
gcloud run deploy ${SERVICE_NAME} \
  --image ${IMAGE_NAME} \
  --platform managed \
  --region ${LOCATION} \
  --project ${PROJECT_ID} \
  --allow-unauthenticated \
  --set-env-vars ${ENV_VARS} \
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




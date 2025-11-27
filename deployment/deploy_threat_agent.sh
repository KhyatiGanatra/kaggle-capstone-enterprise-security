#!/bin/bash
# Deploy Threat Analysis Agent to Vertex AI

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Change to project root (one level up from deployment/)
PROJECT_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
cd "${PROJECT_ROOT}"

PROJECT_ID=${GOOGLE_CLOUD_PROJECT:-"your-project-id"}
LOCATION=${VERTEX_AI_LOCATION:-"us-central1"}
IMAGE_NAME="gcr.io/${PROJECT_ID}/threat-analysis-agent"
SERVICE_NAME="threat-analysis-agent"

echo "Deploying Threat Analysis Agent to Vertex AI..."
echo "Project: ${PROJECT_ID}"
echo "Location: ${LOCATION}"
echo "Working directory: ${PROJECT_ROOT}"

# Build Docker image for linux/amd64 (Cloud Run platform)
echo "Building Docker image for linux/amd64..."
docker build --platform linux/amd64 -t ${IMAGE_NAME} -f deployment/Dockerfile.threat_agent .

# Push to Google Container Registry
echo "Pushing image to GCR..."
docker push ${IMAGE_NAME}

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
  --set-env-vars VT_APIKEY=${VT_APIKEY} \
  --memory 2Gi \
  --cpu 2 \
  --timeout 300

# Get endpoint URL
ENDPOINT=$(gcloud run services describe ${SERVICE_NAME} \
  --platform managed \
  --region ${LOCATION} \
  --project ${PROJECT_ID} \
  --format 'value(status.url)')

echo "Threat Analysis Agent deployed!"
echo "Endpoint: ${ENDPOINT}"

# Register in Vertex AI Agent Registry
echo "Registering agent in Vertex AI Agent Registry..."
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




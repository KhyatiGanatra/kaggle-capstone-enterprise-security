#!/bin/bash
# Deploy Incident Response Agent to Vertex AI

set -e

PROJECT_ID=${GOOGLE_CLOUD_PROJECT:-"your-project-id"}
LOCATION=${VERTEX_AI_LOCATION:-"us-central1"}
IMAGE_NAME="gcr.io/${PROJECT_ID}/incident-response-agent"
SERVICE_NAME="incident-response-agent"

echo "Deploying Incident Response Agent to Vertex AI..."
echo "Project: ${PROJECT_ID}"
echo "Location: ${LOCATION}"

# Build Docker image
echo "Building Docker image..."
docker build -t ${IMAGE_NAME} -f deployment/Dockerfile.incident_agent .

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

# Register in Vertex AI Agent Registry
echo "Registering agent in Vertex AI Agent Registry..."
python3 -c "
from shared.vertex_registry import VertexAIAgentRegistry
registry = VertexAIAgentRegistry('${PROJECT_ID}', '${LOCATION}')
registry.register_agent(
    agent_name='IncidentResponseAgent',
    endpoint='${ENDPOINT}',
    capabilities=['handle_incident', 'incident_response', 'chronicle_integration']
)
print('Agent registered successfully!')
"

echo "Deployment complete!"



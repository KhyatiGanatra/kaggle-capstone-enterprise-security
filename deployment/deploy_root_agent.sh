#!/bin/bash
# Deploy Root Orchestrator Agent to Vertex AI

set -e

PROJECT_ID=${GOOGLE_CLOUD_PROJECT:-"your-project-id"}
LOCATION=${VERTEX_AI_LOCATION:-"us-central1"}
IMAGE_NAME="gcr.io/${PROJECT_ID}/root-orchestrator-agent"
SERVICE_NAME="root-orchestrator-agent"

echo "Deploying Root Orchestrator Agent to Vertex AI..."
echo "Project: ${PROJECT_ID}"
echo "Location: ${LOCATION}"

# Build Docker image
echo "Building Docker image..."
docker build -t ${IMAGE_NAME} -f deployment/Dockerfile.root_agent .

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
  --set-env-vars VERTEX_AI_LOCATION=${LOCATION} \
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

echo "Deployment complete!"



#!/bin/bash
# Delete all Cloud Run deployments for the security monitoring agents

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Change to project root (one level up from deployment/)
PROJECT_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
cd "${PROJECT_ROOT}"

PROJECT_ID=${GOOGLE_CLOUD_PROJECT:-"your-project-id"}
LOCATION=${VERTEX_AI_LOCATION:-"us-central1"}

echo "Deleting Cloud Run deployments..."
echo "Project: ${PROJECT_ID}"
echo "Location: ${LOCATION}"
echo ""

# List of services to delete
SERVICES=(
    "root-orchestrator-agent"
    "threat-analysis-agent"
    "incident-response-agent"
)

# Delete each Cloud Run service
for SERVICE_NAME in "${SERVICES[@]}"; do
    echo "Deleting service: ${SERVICE_NAME}..."
    
    if gcloud run services describe ${SERVICE_NAME} \
        --platform managed \
        --region ${LOCATION} \
        --project ${PROJECT_ID} \
        --quiet 2>/dev/null; then
        
        gcloud run services delete ${SERVICE_NAME} \
            --platform managed \
            --region ${LOCATION} \
            --project ${PROJECT_ID} \
            --quiet
        
        echo "✓ Deleted: ${SERVICE_NAME}"
    else
        echo "⚠ Service not found: ${SERVICE_NAME} (skipping)"
    fi
    echo ""
done

# Optional: Delete Docker images from GCR
echo "Do you want to delete Docker images from Google Container Registry? (y/n)"
read -r DELETE_IMAGES

if [[ "${DELETE_IMAGES}" =~ ^[Yy]$ ]]; then
    IMAGES=(
        "gcr.io/${PROJECT_ID}/root-orchestrator-agent"
        "gcr.io/${PROJECT_ID}/threat-analysis-agent"
        "gcr.io/${PROJECT_ID}/incident-response-agent"
    )
    
    for IMAGE_NAME in "${IMAGES[@]}"; do
        echo "Deleting image: ${IMAGE_NAME}..."
        
        if gcloud container images describe ${IMAGE_NAME}:latest \
            --project ${PROJECT_ID} \
            --quiet 2>/dev/null; then
            
            # Delete all tags for this image
            gcloud container images delete ${IMAGE_NAME} \
                --project ${PROJECT_ID} \
                --quiet \
                --force-delete-tags
            
            echo "✓ Deleted: ${IMAGE_NAME}"
        else
            echo "⚠ Image not found: ${IMAGE_NAME} (skipping)"
        fi
        echo ""
    done
fi

echo "Cleanup complete!"
echo ""
echo "Note: If agents were registered in Vertex AI Agent Registry,"
echo "      you may need to manually unregister them."


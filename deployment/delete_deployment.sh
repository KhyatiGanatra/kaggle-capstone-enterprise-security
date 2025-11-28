#!/bin/bash

# Multi-Agent Security System - Cleanup Script
# Deletes Cloud Run services and container images

set -e

PROJECT_ID=$(gcloud config get-value project)
REGION="us-central1"

echo "========================================================"
echo "WARNING: DESTRUCTIVE ACTION"
echo "========================================================"
echo "This will DELETE the following Cloud Run services in project $PROJECT_ID:"
echo "  - threat-analysis-agent"
echo "  - incident-response-agent"
echo "  - root-orchestrator-agent"
echo ""
echo "It will also DELETE the associated container images from GCR."
echo "========================================================"

read -p "Are you sure you want to proceed? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Operation cancelled."
    exit 1
fi

echo ""
echo "🚀 Deleting Cloud Run services..."

# Delete Threat Analysis Agent
if gcloud run services describe threat-analysis-agent --region $REGION --project $PROJECT_ID &>/dev/null; then
    echo "Deleting threat-analysis-agent..."
    gcloud run services delete threat-analysis-agent --region $REGION --project $PROJECT_ID --quiet
else
    echo "threat-analysis-agent not found (skipping)"
fi

# Delete Incident Response Agent
if gcloud run services describe incident-response-agent --region $REGION --project $PROJECT_ID &>/dev/null; then
    echo "Deleting incident-response-agent..."
    gcloud run services delete incident-response-agent --region $REGION --project $PROJECT_ID --quiet
else
    echo "incident-response-agent not found (skipping)"
fi

# Delete Root Orchestrator
if gcloud run services describe root-orchestrator-agent --region $REGION --project $PROJECT_ID &>/dev/null; then
    echo "Deleting root-orchestrator-agent..."
    gcloud run services delete root-orchestrator-agent --region $REGION --project $PROJECT_ID --quiet
else
    echo "root-orchestrator-agent not found (skipping)"
fi

echo ""
echo "🗑️  Deleting Container Images..."

# Delete images
for SERVICE in threat-analysis-agent incident-response-agent root-orchestrator-agent; do
    IMAGE_PATH="gcr.io/$PROJECT_ID/$SERVICE"
    echo "Checking for images at $IMAGE_PATH..."
    
    # List tags and delete them
    DIGESTS=$(gcloud container images list-tags $IMAGE_PATH --format="get(digest)" 2>/dev/null || true)
    
    if [ ! -z "$DIGESTS" ]; then
        echo "Deleting images for $SERVICE..."
        # Loop through digests to delete them
        for DIGEST in $DIGESTS; do
            gcloud container images delete "$IMAGE_PATH@$DIGEST" --force-delete-tags --quiet
        done
        echo "✓ Images deleted for $SERVICE"
    else
        echo "No images found for $SERVICE (skipping)"
    fi
done

echo ""
echo "✅ Cleanup complete! All services and images have been removed."


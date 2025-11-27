# How to Delete Deployments

This guide explains how to delete the Cloud Run deployments for your security monitoring agents.

## Quick Method: Use the Cleanup Script

A cleanup script is available that deletes all services:

```bash
cd deployment
./delete_deployments.sh
```

The script will:
1. Delete all three Cloud Run services
2. Optionally delete Docker images from Google Container Registry
3. Prompt you for confirmation before deleting images

## Manual Method: Delete Individual Services

### Delete Cloud Run Services

Delete each service individually:

```bash
# Set your project and region
export GOOGLE_CLOUD_PROJECT="your-project-id"
export VERTEX_AI_LOCATION="us-central1"

# Delete Root Orchestrator Agent
gcloud run services delete root-orchestrator-agent \
  --platform managed \
  --region ${VERTEX_AI_LOCATION} \
  --project ${GOOGLE_CLOUD_PROJECT} \
  --quiet

# Delete Threat Analysis Agent
gcloud run services delete threat-analysis-agent \
  --platform managed \
  --region ${VERTEX_AI_LOCATION} \
  --project ${GOOGLE_CLOUD_PROJECT} \
  --quiet

# Delete Incident Response Agent
gcloud run services delete incident-response-agent \
  --platform managed \
  --region ${VERTEX_AI_LOCATION} \
  --project ${GOOGLE_CLOUD_PROJECT} \
  --quiet
```

### Delete All Services at Once

```bash
# Set your project and region
export GOOGLE_CLOUD_PROJECT="your-project-id"
export VERTEX_AI_LOCATION="us-central1"

# Delete all services
for service in root-orchestrator-agent threat-analysis-agent incident-response-agent; do
  gcloud run services delete ${service} \
    --platform managed \
    --region ${VERTEX_AI_LOCATION} \
    --project ${GOOGLE_CLOUD_PROJECT} \
    --quiet
done
```

## Delete Docker Images from GCR (Optional)

If you also want to delete the Docker images from Google Container Registry:

```bash
# Set your project
export GOOGLE_CLOUD_PROJECT="your-project-id"

# Delete images
gcloud container images delete gcr.io/${GOOGLE_CLOUD_PROJECT}/root-orchestrator-agent \
  --project ${GOOGLE_CLOUD_PROJECT} \
  --quiet \
  --force-delete-tags

gcloud container images delete gcr.io/${GOOGLE_CLOUD_PROJECT}/threat-analysis-agent \
  --project ${GOOGLE_CLOUD_PROJECT} \
  --quiet \
  --force-delete-tags

gcloud container images delete gcr.io/${GOOGLE_CLOUD_PROJECT}/incident-response-agent \
  --project ${GOOGLE_CLOUD_PROJECT} \
  --quiet \
  --force-delete-tags
```

Or delete all at once:

```bash
export GOOGLE_CLOUD_PROJECT="your-project-id"

for image in root-orchestrator-agent threat-analysis-agent incident-response-agent; do
  gcloud container images delete gcr.io/${GOOGLE_CLOUD_PROJECT}/${image} \
    --project ${GOOGLE_CLOUD_PROJECT} \
    --quiet \
    --force-delete-tags
done
```

## Verify Deletion

### List All Cloud Run Services

```bash
gcloud run services list \
  --platform managed \
  --region ${VERTEX_AI_LOCATION} \
  --project ${GOOGLE_CLOUD_PROJECT}
```

### List All Docker Images in GCR

```bash
gcloud container images list \
  --project ${GOOGLE_CLOUD_PROJECT}
```

## Unregister from Vertex AI Agent Registry (If Applicable)

If your agents were registered in Vertex AI Agent Registry, you may want to unregister them. This depends on your implementation of the registry:

```python
from shared.vertex_registry import VertexAIAgentRegistry

registry = VertexAIAgentRegistry('your-project-id', 'us-central1')

# Unregister agents
registry.unregister_agent('ThreatAnalysisAgent')
registry.unregister_agent('IncidentResponseAgent')
```

**Note**: The current implementation of `VertexAIAgentRegistry` may not have an `unregister_agent` method. You may need to implement it or manually remove entries if using a custom registry.

## Cost Implications

- **Cloud Run**: You're only charged when services are running and handling requests. Deleting services stops all charges.
- **Container Registry**: Storage costs for Docker images are minimal but accumulate over time. Deleting unused images saves storage costs.

## Troubleshooting

### Error: "Service not found"
- The service may have already been deleted
- Check the service name and region
- List services to see what exists: `gcloud run services list --region ${VERTEX_AI_LOCATION}`

### Error: "Permission denied"
- Ensure you have the `run.services.delete` permission
- Check your IAM roles: `gcloud projects get-iam-policy ${GOOGLE_CLOUD_PROJECT}`

### Error: "Image not found"
- The image may have already been deleted
- List images: `gcloud container images list --project ${GOOGLE_CLOUD_PROJECT}`

## What Gets Deleted

When you delete a Cloud Run service:
- ✅ The service and all its revisions are deleted
- ✅ All traffic to the service stops
- ✅ The service URL becomes invalid
- ❌ Docker images in GCR are NOT automatically deleted (optional step above)

## Re-deploying After Deletion

If you want to re-deploy after deletion, simply run the deployment scripts again:

```bash
./deployment/deploy_threat_agent.sh
./deployment/deploy_incident_agent.sh
./deployment/deploy_root_agent.sh
```

The deployment scripts will create new services with the same names.


#!/bin/bash
# Health check script for all deployed agents

set -e

PROJECT_ID=${GOOGLE_CLOUD_PROJECT:-"kaggle-adk-capstone-secmon"}
LOCATION=${VERTEX_AI_LOCATION:-"us-central1"}

echo "============================================================"
echo "Health Check for All Deployed Agents"
echo "Project: ${PROJECT_ID}"
echo "Region: ${LOCATION}"
echo "============================================================"
echo ""

# Function to check service health
check_service_health() {
    local service_name=$1
    local agent_name=$2
    
    echo "Checking ${agent_name}..."
    echo "  Service: ${service_name}"
    
    # Get endpoint URL
    local endpoint=$(gcloud run services describe ${service_name} \
        --project=${PROJECT_ID} \
        --region=${LOCATION} \
        --format='value(status.url)' 2>/dev/null)
    
    if [ -z "$endpoint" ]; then
        echo "  ❌ Service not found or not deployed"
        echo ""
        return 1
    fi
    
    echo "  Endpoint: ${endpoint}"
    
    # Check health endpoint
    local health_response=$(curl -s -w "\n%{http_code}" "${endpoint}/health" 2>/dev/null || echo -e "\n000")
    local http_code=$(echo "$health_response" | tail -n1)
    local body=$(echo "$health_response" | head -n-1)
    
    if [ "$http_code" = "200" ]; then
        echo "  ✅ Health check: PASSED"
        echo "  Response: ${body}"
    else
        echo "  ❌ Health check: FAILED (HTTP ${http_code})"
        if [ -n "$body" ]; then
            echo "  Error: ${body}"
        fi
    fi
    
    # Check root endpoint
    local root_response=$(curl -s -w "\n%{http_code}" "${endpoint}/" 2>/dev/null || echo -e "\n000")
    local root_code=$(echo "$root_response" | tail -n1)
    
    if [ "$root_code" = "200" ]; then
        echo "  ✅ Root endpoint: ACCESSIBLE"
    else
        echo "  ⚠️  Root endpoint: HTTP ${root_code}"
    fi
    
    echo ""
}

# Check all services
check_service_health "threat-analysis-agent" "Threat Analysis Agent"
check_service_health "incident-response-agent" "Incident Response Agent"
check_service_health "root-orchestrator-agent" "Root Orchestrator Agent"

echo "============================================================"
echo "Health Check Complete"
echo "============================================================"




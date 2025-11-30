#!/bin/bash
# Integration test script for Argus agents deployed on Cloud Run
# Reads endpoint from .env.agents file and runs tests

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Change to project root (one level up from tests/)
PROJECT_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
cd "${PROJECT_ROOT}"

# Read root agent endpoint from .env.agents file
ENV_FILE="${PROJECT_ROOT}/.env.agents"
ROOT_ENDPOINT=""

if [ -f "${ENV_FILE}" ]; then
    echo "Reading ROOT_AGENT_ENDPOINT from ${ENV_FILE}..."
    ROOT_ENDPOINT=$(grep "^ROOT_AGENT_ENDPOINT=" "${ENV_FILE}" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || echo "")
    
    if [ -n "${ROOT_ENDPOINT}" ]; then
        echo "✓ Found ROOT_AGENT_ENDPOINT: ${ROOT_ENDPOINT}"
    else
        echo "✗ Error: ROOT_AGENT_ENDPOINT not found in ${ENV_FILE}"
        echo "Please deploy the root agent first using: ./deployment/deploy_root_agent.sh"
        exit 1
    fi
else
    echo "✗ Error: ${ENV_FILE} not found"
    echo "Please deploy the agents first:"
    echo "  1. ./deployment/deploy_threat_agent.sh"
    echo "  2. ./deployment/deploy_incident_agent.sh"  
    echo "  3. ./deployment/deploy_root_agent.sh"
    exit 1
fi

# Export as environment variable for Python script
export ROOT_AGENT_ENDPOINT="${ROOT_ENDPOINT}"

# Run the integration tests
echo ""
echo "Running integration tests..."
python3 "${SCRIPT_DIR}/test_root_agent_integration.py" "${ROOT_ENDPOINT}"


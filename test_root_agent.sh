#!/bin/bash
# Test script for Root Orchestrator Agent deployed on Cloud Run
# Reads endpoint from .env.agents file and runs tests

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "${SCRIPT_DIR}"

# Read root agent endpoint from .env.agents file
ENV_FILE=".env.agents"
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
    echo "Please deploy the root agent first using: ./deployment/deploy_root_agent.sh"
    exit 1
fi

# Export as environment variable for Python script
export ROOT_AGENT_ENDPOINT="${ROOT_ENDPOINT}"

# Check if Python test script exists
if [ -f "test_root_agent.py" ]; then
    echo "Running Python test script..."
    python3 test_root_agent.py "${ROOT_ENDPOINT}"
elif [ -f "tests/test_root_agent.py" ]; then
    echo "Running Python test script from tests/ directory..."
    python3 tests/test_root_agent.py "${ROOT_ENDPOINT}"
else
    echo "✗ Error: test_root_agent.py not found"
    echo "Expected location: ./test_root_agent.py or ./tests/test_root_agent.py"
    exit 1
fi



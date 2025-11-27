# Testing Guide

This document explains how to run the test suite for the Multi-Agent Security System.

## Prerequisites

1. Install UV (if not already installed):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

2. Install dependencies:
```bash
uv sync
```

## Running Tests

### Run All Tests

```bash
# Using pytest (recommended)
pytest tests/

# Using unittest
python -m unittest discover tests

# With verbose output
pytest tests/ -v
```

### Run Specific Test File

```bash
# Test Threat Analysis Agent
pytest tests/test_threat_agent.py

# Test Incident Response Agent
pytest tests/test_incident_agent.py

# Test Root Orchestrator
pytest tests/test_root_agent.py

# Test A2A Protocol
pytest tests/test_a2a.py

# Test Integration
pytest tests/test_integration.py
```

### Run Specific Test Class

```bash
# Run only TestThreatAnalysisAgent class
pytest tests/test_threat_agent.py::TestThreatAnalysisAgent

# Run only TestRootOrchestratorAgent class
pytest tests/test_root_agent.py::TestRootOrchestratorAgent
```

### Run Specific Test Method

```bash
# Run a specific test method
pytest tests/test_threat_agent.py::TestThreatAnalysisAgent::test_agent_initialization

# Run test with pattern matching
pytest tests/ -k "test_agent_initialization"
```

### Run Tests with Coverage

```bash
# Generate coverage report
pytest tests/ --cov=agents --cov=shared --cov-report=html

# View coverage in terminal
pytest tests/ --cov=agents --cov=shared --cov-report=term

# Generate coverage report and open in browser (Mac)
pytest tests/ --cov=agents --cov=shared --cov-report=html && open htmlcov/index.html
```

### Run Tests with Output

```bash
# Show print statements
pytest tests/ -s

# Show local variables on failure
pytest tests/ -l

# Stop on first failure
pytest tests/ -x

# Show slowest tests
pytest tests/ --durations=10
```

## Test Structure

```
tests/
├── __init__.py
├── test_threat_agent.py      # Threat Analysis Agent tests
├── test_incident_agent.py    # Incident Response Agent tests
├── test_root_agent.py        # Root Orchestrator tests
├── test_a2a.py               # A2A protocol tests
└── test_integration.py       # End-to-end integration tests
```

## Common Test Commands

```bash
# Quick test run
pytest tests/ -v

# Full test run with coverage
pytest tests/ --cov=agents --cov=shared --cov-report=term-missing

# Run tests matching a pattern
pytest tests/ -k "threat"  # Runs all tests with "threat" in name

# Run tests in parallel (if pytest-xdist installed)
pytest tests/ -n auto

# Run tests and show warnings
pytest tests/ -W error::DeprecationWarning
```

## Troubleshooting

### Import Errors

If you get import errors, make sure you're in the project root directory:
```bash
cd /path/to/kaggle-capstone-entr-sec
pytest tests/
```

### Missing Dependencies

Install all dependencies:
```bash
uv sync
```

### Mock/Stub Issues

The tests use `unittest.mock` to mock external dependencies. If tests fail due to missing mocks, check that:
- Google Cloud credentials are mocked
- API calls are properly mocked
- External services are not actually called

## Continuous Integration

For CI/CD pipelines, use:
```bash
pytest tests/ --cov=agents --cov=shared --cov-report=xml --junitxml=test-results.xml
```





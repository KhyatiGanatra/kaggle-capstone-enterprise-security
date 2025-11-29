#!/usr/bin/env python3
"""
Integration test script for Root Orchestrator Agent deployed on Cloud Run
Tests the agent via A2A protocol over HTTPS
"""

import json
import requests
import sys
import os
from typing import Dict, Any

def test_health_check(endpoint: str) -> bool:
    """Test the health check endpoint"""
    print(f"\n{'='*60}")
    print("1. Testing Health Check Endpoint")
    print(f"{'='*60}")
    
    try:
        response = requests.get(f"{endpoint}/health", timeout=10)
        response.raise_for_status()
        data = response.json()
        print(f"✓ Health check passed")
        print(f"  Status: {data.get('status')}")
        print(f"  Agent: {data.get('agent')}")
        return True
    except Exception as e:
        print(f"✗ Health check failed: {e}")
        return False


def test_root_endpoint(endpoint: str) -> bool:
    """Test the root endpoint"""
    print(f"\n{'='*60}")
    print("2. Testing Root Endpoint")
    print(f"{'='*60}")
    
    try:
        response = requests.get(f"{endpoint}/", timeout=10)
        response.raise_for_status()
        data = response.json()
        print(f"✓ Root endpoint accessible")
        print(f"  Response: {json.dumps(data, indent=2)}")
        return True
    except Exception as e:
        print(f"✗ Root endpoint failed: {e}")
        return False


def test_process_security_event(endpoint: str, event: Dict[str, Any]) -> bool:
    """Test processing a security event via A2A protocol"""
    print(f"\n{'='*60}")
    print("3. Testing Process Security Event")
    print(f"{'='*60}")
    
    # Prepare A2A request
    a2a_request = {
        "agent": "RootOrchestratorAgent",
        "method": "process_security_event",
        "params": event,
        "protocol_version": "1.0"
    }
    
    print(f"Sending event:")
    print(f"  Indicator: {event.get('indicator')}")
    print(f"  Type: {event.get('indicator_type')}")
    print(f"  Source: {event.get('source')}")
    
    try:
        response = requests.post(
            f"{endpoint}/a2a/invoke",
            json=a2a_request,
            headers={"Content-Type": "application/json"},
            timeout=120  # Longer timeout for agent processing
        )
        response.raise_for_status()
        result = response.json()
        
        print(f"\n✓ Event processed successfully")
        print(f"\nResponse:")
        print(json.dumps(result, indent=2))
        
        if result.get('success'):
            print(f"\n✓ Investigation ID: {result.get('investigation_id')}")
            if 'threat_analysis' in result:
                threat = result['threat_analysis']
                print(f"  Threat Severity: {threat.get('severity', 'N/A')}")
                print(f"  Threat Confidence: {threat.get('confidence', 'N/A')}")
            if 'incident_response' in result:
                incident = result['incident_response']
                print(f"  Incident ID: {incident.get('incident_id', 'N/A')}")
        
        return result.get('success', False)
        
    except requests.exceptions.Timeout:
        print(f"✗ Request timed out (agent may still be processing)")
        return False
    except Exception as e:
        print(f"✗ Failed to process event: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                print(f"  Error details: {json.dumps(error_data, indent=2)}")
            except:
                print(f"  Response: {e.response.text}")
        return False


def test_get_session_status(endpoint: str) -> bool:
    """Test getting session status"""
    print(f"\n{'='*60}")
    print("4. Testing Get Session Status")
    print(f"{'='*60}")
    
    a2a_request = {
        "agent": "RootOrchestratorAgent",
        "method": "get_session_status",
        "params": {},
        "protocol_version": "1.0"
    }
    
    try:
        response = requests.post(
            f"{endpoint}/a2a/invoke",
            json=a2a_request,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response.raise_for_status()
        result = response.json()
        
        print(f"✓ Session status retrieved")
        print(f"\nStatus:")
        print(json.dumps(result.get('result', {}), indent=2))
        return True
        
    except Exception as e:
        print(f"✗ Failed to get session status: {e}")
        return False


def main():
    """Main test function"""
    # Get endpoint from environment or command line
    endpoint = os.getenv("ROOT_AGENT_ENDPOINT")
    if not endpoint:
        if len(sys.argv) > 1:
            endpoint = sys.argv[1]
        else:
            print("ERROR: ROOT_AGENT_ENDPOINT environment variable not set")
            print("Usage: python test_root_agent.py <endpoint_url>")
            print("   or: export ROOT_AGENT_ENDPOINT=<endpoint_url>")
            print("\nTo get the endpoint URL:")
            print("  gcloud run services describe root-orchestrator-agent \\")
            print("    --project=<your-project> \\")
            print("    --region=us-central1 \\")
            print("    --format='value(status.url)'")
            sys.exit(1)
    
    # Remove trailing slash if present
    endpoint = endpoint.rstrip('/')
    
    print(f"\n{'='*60}")
    print(f"Testing Root Orchestrator Agent")
    print(f"Endpoint: {endpoint}")
    print(f"{'='*60}")
    
    # Run tests
    results = []
    
    # Test 1: Health check
    results.append(("Health Check", test_health_check(endpoint)))
    
    # Test 2: Root endpoint
    results.append(("Root Endpoint", test_root_endpoint(endpoint)))
    
    # Test 3: Process security event
    sample_event = {
        "indicator": "203.0.113.42",
        "indicator_type": "ip",
        "source": "SIEM",
        "timestamp": "2025-11-27T10:00:00Z",
        "context": "Suspicious outbound connection detected"
    }
    results.append(("Process Security Event", test_process_security_event(endpoint, sample_event)))
    
    # Test 4: Get session status
    results.append(("Get Session Status", test_get_session_status(endpoint)))
    
    # Summary
    print(f"\n{'='*60}")
    print("Test Summary")
    print(f"{'='*60}")
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print("\n⚠️  Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())

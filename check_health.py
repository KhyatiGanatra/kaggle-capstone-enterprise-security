#!/usr/bin/env python3
"""
Health check script for all deployed agents
Checks health endpoints and service status
"""

import requests
import subprocess
import json
import sys
from typing import Dict, Optional

PROJECT_ID = "kaggle-adk-capstone-secmon"
LOCATION = "us-central1"

SERVICES = {
    "threat-analysis-agent": "Threat Analysis Agent",
    "incident-response-agent": "Incident Response Agent",
    "root-orchestrator-agent": "Root Orchestrator Agent"
}


def get_service_endpoint(service_name: str) -> Optional[str]:
    """Get Cloud Run service endpoint URL"""
    try:
        result = subprocess.run(
            [
                "gcloud", "run", "services", "describe", service_name,
                "--project", PROJECT_ID,
                "--region", LOCATION,
                "--format", "value(status.url)"
            ],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            endpoint = result.stdout.strip()
            return endpoint if endpoint else None
        return None
    except Exception as e:
        print(f"  ⚠️  Error getting endpoint: {e}")
        return None


def check_health_endpoint(endpoint: str, timeout: int = 5) -> tuple[bool, str, int]:
    """Check health endpoint"""
    try:
        response = requests.get(f"{endpoint}/health", timeout=timeout)
        return response.status_code == 200, response.text, response.status_code
    except requests.exceptions.Timeout:
        return False, "Request timeout", 0
    except requests.exceptions.ConnectionError:
        return False, "Connection refused", 0
    except Exception as e:
        return False, str(e), 0


def check_root_endpoint(endpoint: str, timeout: int = 5) -> tuple[bool, int]:
    """Check root endpoint"""
    try:
        response = requests.get(f"{endpoint}/", timeout=timeout)
        return response.status_code == 200, response.status_code
    except Exception as e:
        return False, 0


def check_service(service_name: str, display_name: str) -> Dict:
    """Check a single service"""
    print(f"\n{'='*60}")
    print(f"Checking {display_name}")
    print(f"{'='*60}")
    print(f"  Service: {service_name}")
    
    # Get endpoint
    endpoint = get_service_endpoint(service_name)
    if not endpoint:
        print(f"  ❌ Service not found or not deployed")
        return {
            "service": service_name,
            "status": "not_deployed",
            "endpoint": None
        }
    
    print(f"  Endpoint: {endpoint}")
    
    # Check health
    health_ok, health_msg, health_code = check_health_endpoint(endpoint)
    if health_ok:
        print(f"  ✅ Health check: PASSED")
        try:
            health_data = json.loads(health_msg)
            print(f"  Response: {json.dumps(health_data, indent=4)}")
        except:
            print(f"  Response: {health_msg}")
    else:
        print(f"  ❌ Health check: FAILED")
        if health_code:
            print(f"  HTTP Status: {health_code}")
        if health_msg:
            print(f"  Error: {health_msg}")
    
    # Check root endpoint
    root_ok, root_code = check_root_endpoint(endpoint)
    if root_ok:
        print(f"  ✅ Root endpoint: ACCESSIBLE")
    else:
        print(f"  ⚠️  Root endpoint: HTTP {root_code if root_code else 'Connection failed'}")
    
    return {
        "service": service_name,
        "status": "healthy" if health_ok else "unhealthy",
        "endpoint": endpoint,
        "health_code": health_code,
        "root_accessible": root_ok
    }


def main():
    """Main function"""
    print(f"\n{'='*60}")
    print("Health Check for All Deployed Agents")
    print(f"{'='*60}")
    print(f"Project: {PROJECT_ID}")
    print(f"Region: {LOCATION}")
    
    results = []
    for service_name, display_name in SERVICES.items():
        result = check_service(service_name, display_name)
        results.append(result)
    
    # Summary
    print(f"\n{'='*60}")
    print("Summary")
    print(f"{'='*60}")
    
    healthy = sum(1 for r in results if r.get("status") == "healthy")
    total = len([r for r in results if r.get("endpoint")])
    deployed = len([r for r in results if r.get("endpoint")])
    
    for result in results:
        status_icon = "✅" if result.get("status") == "healthy" else "❌"
        if result.get("endpoint"):
            print(f"{status_icon} {result['service']}: {result['status']}")
        else:
            print(f"⚠️  {result['service']}: Not deployed")
    
    print(f"\nDeployed: {deployed}/{len(SERVICES)}")
    print(f"Healthy: {healthy}/{deployed}" if deployed > 0 else "Healthy: 0/0")
    
    if healthy == deployed and deployed == len(SERVICES):
        print("\n🎉 All services are healthy!")
        return 0
    elif healthy < deployed:
        print("\n⚠️  Some services are unhealthy")
        return 1
    else:
        print("\n⚠️  Some services are not deployed")
        return 1


if __name__ == "__main__":
    sys.exit(main())




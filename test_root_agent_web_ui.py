#!/usr/bin/env python3
"""
Test script for Root Orchestrator Agent using ADK Web UI API
This will show traces in the web UI because it uses the /run endpoint
"""

import json
import requests
import sys
import os
import uuid
from typing import Dict, Any
from google.genai import types

def create_session(endpoint: str, app_name: str = "root_agent", user_id: str = "user") -> str:
    """Create a session via ADK web UI API"""
    print(f"\n{'='*60}")
    print("1. Creating Session")
    print(f"{'='*60}")
    
    try:
        response = requests.post(
            f"{endpoint}/web/apps/{app_name}/users/{user_id}/sessions",
            json={},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response.raise_for_status()
        session = response.json()
        session_id = session.get('id')
        print(f"✓ Session created: {session_id}")
        return session_id
    except Exception as e:
        print(f"✗ Failed to create session: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                print(f"  Error details: {json.dumps(error_data, indent=2)}")
            except:
                print(f"  Response: {e.response.text}")
        return None


def run_agent_via_web_ui(
    endpoint: str,
    app_name: str,
    user_id: str,
    session_id: str,
    message: str
) -> bool:
    """Run agent via ADK web UI /run endpoint - this will show traces"""
    print(f"\n{'='*60}")
    print("2. Running Agent via Web UI (will show traces)")
    print(f"{'='*60}")
    
    # Format message as ADK Content
    content = {
        "role": "user",
        "parts": [{"text": message}]
    }
    
    request_data = {
        "app_name": app_name,
        "user_id": user_id,
        "session_id": session_id,
        "new_message": content,
        "streaming": False
    }
    
    print(f"Sending message: {message[:100]}...")
    
    try:
        response = requests.post(
            f"{endpoint}/web/run",
            json=request_data,
            headers={"Content-Type": "application/json"},
            timeout=120
        )
        response.raise_for_status()
        events = response.json()
        
        print(f"\n✓ Agent executed successfully")
        print(f"  Events generated: {len(events)}")
        
        # Print event summaries
        for i, event in enumerate(events[:5]):  # Show first 5 events
            if isinstance(event, dict):
                author = event.get('author', 'unknown')
                content = event.get('content', {})
                parts = content.get('parts', [])
                text = ' '.join([p.get('text', '') for p in parts if isinstance(p, dict)])
                if text:
                    print(f"  Event {i+1} [{author}]: {text[:100]}...")
        
        if len(events) > 5:
            print(f"  ... and {len(events) - 5} more events")
        
        print(f"\n✓ Check the web UI at {endpoint}/web to see full traces!")
        return True
        
    except Exception as e:
        print(f"✗ Failed to run agent: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                print(f"  Error details: {json.dumps(error_data, indent=2)}")
            except:
                print(f"  Response: {e.response.text}")
        return False


def test_security_event_via_web_ui(endpoint: str, event: Dict[str, Any]) -> bool:
    """Test processing a security event via web UI"""
    app_name = "root_agent"
    # Use "user" as the user ID - this is what ADK web UI uses by default
    # The web UI defaults to userId=user, so we must match that
    user_id = "user"
    
    # Create session
    session_id = create_session(endpoint, app_name, user_id)
    if not session_id:
        return False
    
    # Format event as a message for the agent
    event_message = f"""Process this security event:

Indicator: {event.get('indicator')}
Type: {event.get('indicator_type')}
Source: {event.get('source')}
Timestamp: {event.get('timestamp')}
Context: {event.get('context', '')}

Please analyze this security event and coordinate with the threat analysis and incident response agents."""
    
    # Run agent via web UI
    return run_agent_via_web_ui(endpoint, app_name, user_id, session_id, event_message)


def main():
    """Main test function"""
    # Get endpoint from environment or command line
    endpoint = os.getenv("ROOT_AGENT_ENDPOINT")
    if not endpoint:
        if len(sys.argv) > 1:
            endpoint = sys.argv[1]
        else:
            print("ERROR: ROOT_AGENT_ENDPOINT environment variable not set")
            print("Usage: python test_root_agent_web_ui.py <endpoint_url>")
            print("   or: export ROOT_AGENT_ENDPOINT=<endpoint_url>")
            sys.exit(1)
    
    # Remove trailing slash if present
    endpoint = endpoint.rstrip('/')
    
    print(f"\n{'='*60}")
    print(f"Testing Root Orchestrator Agent via ADK Web UI")
    print(f"Endpoint: {endpoint}")
    print(f"Web UI: {endpoint}/web")
    print(f"{'='*60}")
    
    # Test with a security event
    sample_event = {
        "indicator": "203.0.113.42",
        "indicator_type": "ip",
        "source": "SIEM",
        "timestamp": "2025-11-30T10:00:00Z",
        "context": "Suspicious outbound connection detected"
    }
    
    success = test_security_event_via_web_ui(endpoint, sample_event)
    
    if success:
        print(f"\n{'='*60}")
        print("✓ Test completed successfully!")
        print(f"\nTo view traces:")
        print(f"  1. Open {endpoint}/web in your browser")
        print(f"  2. Select the 'root_agent' app")
        print(f"  3. View the session and traces")
        print(f"{'='*60}")
        return 0
    else:
        print(f"\n{'='*60}")
        print("✗ Test failed")
        print(f"{'='*60}")
        return 1


if __name__ == "__main__":
    sys.exit(main())


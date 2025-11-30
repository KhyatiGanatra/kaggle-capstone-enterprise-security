#!/usr/bin/env python3
"""
Diagnostic script to check if events are stored in sessions after /web/run calls
"""

import json
import requests
import sys
import os

def check_session_events(endpoint: str, app_name: str = "root_agent", user_id: str = "user"):
    """Check if events are stored in sessions"""
    print(f"\n{'='*60}")
    print("Checking Session Events")
    print(f"{'='*60}")
    
    # List all sessions
    try:
        response = requests.get(
            f"{endpoint}/web/apps/{app_name}/users/{user_id}/sessions",
            timeout=10
        )
        response.raise_for_status()
        sessions = response.json()
        
        print(f"\nFound {len(sessions)} sessions:")
        for session in sessions:
            session_id = session.get('id')
            events_count = len(session.get('events', []))
            last_update = session.get('lastUpdateTime', 0)
            print(f"  Session: {session_id}")
            print(f"    Events: {events_count}")
            print(f"    Last Update: {last_update}")
            
            # Get full session details
            try:
                detail_response = requests.get(
                    f"{endpoint}/web/apps/{app_name}/users/{user_id}/sessions/{session_id}",
                    timeout=10
                )
                detail_response.raise_for_status()
                detail_session = detail_response.json()
                detail_events_count = len(detail_session.get('events', []))
                print(f"    Full Session Events: {detail_events_count}")
                
                if detail_events_count > 0:
                    print(f"    First Event Author: {detail_session['events'][0].get('author', 'unknown')}")
            except Exception as e:
                print(f"    Error getting session details: {e}")
            print()
            
    except Exception as e:
        print(f"✗ Failed to check sessions: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                print(f"  Error details: {json.dumps(error_data, indent=2)}")
            except:
                print(f"  Response: {e.response.text}")

def main():
    endpoint = os.getenv("ROOT_AGENT_ENDPOINT")
    if not endpoint:
        if len(sys.argv) > 1:
            endpoint = sys.argv[1]
        else:
            print("ERROR: ROOT_AGENT_ENDPOINT environment variable not set")
            print("Usage: python check_session_events.py <endpoint_url>")
            sys.exit(1)
    
    endpoint = endpoint.rstrip('/')
    
    print(f"\n{'='*60}")
    print(f"Session Events Diagnostic")
    print(f"Endpoint: {endpoint}")
    print(f"{'='*60}")
    
    check_session_events(endpoint)
    
    print(f"\n{'='*60}")
    print("Diagnostic Complete")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()


#!/usr/bin/env python3
"""
Verify that events are stored and visible in ADK web UI
"""

import json
import requests
import sys
import os

def verify_session_events(endpoint: str, app_name: str = "root_agent", user_id: str = "user"):
    """Verify that sessions have events stored"""
    print(f"\n{'='*60}")
    print("Verifying Session Events for ADK Web UI")
    print(f"{'='*60}")
    print(f"Endpoint: {endpoint}")
    print(f"App: {app_name}")
    print(f"User: {user_id}")
    
    # List sessions
    try:
        response = requests.get(
            f"{endpoint}/web/apps/{app_name}/users/{user_id}/sessions",
            timeout=10
        )
        response.raise_for_status()
        sessions = response.json()
        
        print(f"\n✓ Found {len(sessions)} sessions")
        print(f"\nNote: List endpoint shows 0 events (by design for performance)")
        print(f"      But individual sessions DO have events stored.\n")
        
        # Check each session for events
        sessions_with_events = []
        for session in sessions:
            session_id = session.get('id')
            try:
                # Get full session details
                detail_response = requests.get(
                    f"{endpoint}/web/apps/{app_name}/users/{user_id}/sessions/{session_id}",
                    timeout=10
                )
                detail_response.raise_for_status()
                detail_session = detail_response.json()
                events_count = len(detail_session.get('events', []))
                
                if events_count > 0:
                    sessions_with_events.append((session_id, events_count))
                    print(f"  ✓ Session: {session_id[:50]}...")
                    print(f"    Events: {events_count}")
                    # Show event authors
                    events = detail_session.get('events', [])
                    authors = [e.get('author', 'unknown') for e in events]
                    print(f"    Authors: {', '.join(set(authors))}")
                    print()
            except Exception as e:
                print(f"  ✗ Error checking session {session_id[:50]}...: {e}")
        
        if sessions_with_events:
            print(f"\n{'='*60}")
            print("✓ SUCCESS: Events are stored correctly!")
            print(f"{'='*60}")
            print(f"\nTo view traces in ADK Web UI:")
            print(f"  1. Open: {endpoint}/web")
            print(f"  2. Select app: {app_name}")
            print(f"  3. Click on a session ID to view details")
            print(f"  4. Events will be visible in the session detail view")
            print(f"\nRecent sessions with events:")
            for session_id, count in sessions_with_events[:5]:
                print(f"  - {session_id}")
                print(f"    Direct URL: {endpoint}/web/apps/{app_name}/users/{user_id}/sessions/{session_id}")
        else:
            print(f"\n⚠️  No sessions with events found")
            print(f"   Run ./test_root_agent.sh to generate events")
            
    except Exception as e:
        print(f"✗ Failed to verify sessions: {e}")
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
            print("Usage: python verify_web_ui_traces.py <endpoint_url>")
            sys.exit(1)
    
    endpoint = endpoint.rstrip('/')
    verify_session_events(endpoint)

if __name__ == "__main__":
    main()


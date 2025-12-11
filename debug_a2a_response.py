#!/usr/bin/env python3
"""
Debug script to inspect A2A response structure from Threat Analysis Agent
"""

import os
import json
import logging
from dotenv import load_dotenv

load_dotenv(override=True)

from shared.communication.a2a_client import A2AClient

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT")

    # Read threat agent endpoint
    threat_agent_endpoint = os.getenv("THREAT_AGENT_ENDPOINT")

    # Also try reading from .env.agents
    if not threat_agent_endpoint:
        try:
            with open('.env.agents', 'r') as f:
                for line in f:
                    if line.strip().startswith('THREAT_AGENT_ENDPOINT='):
                        threat_agent_endpoint = line.split('=', 1)[1].strip().strip('"').strip("'")
                        break
        except Exception as e:
            logger.warning(f"Could not read .env.agents: {e}")

    if not threat_agent_endpoint:
        logger.error("THREAT_AGENT_ENDPOINT not found in environment or .env.agents")
        logger.info("Please set THREAT_AGENT_ENDPOINT or deploy the threat agent first")
        return

    logger.info(f"Testing A2A call to: {threat_agent_endpoint}")
    logger.info("=" * 80)

    # Create A2A client
    client = A2AClient(project_id)

    # Test with a known safe IP (Google DNS)
    test_indicator = "8.8.8.8"

    logger.info(f"Calling analyze_indicator with: {test_indicator}")
    logger.info("-" * 80)

    try:
        result = client.invoke_agent(
            agent_name="ThreatAnalysisAgent",
            method="analyze_indicator",
            params={
                "indicator": test_indicator,
                "indicator_type": "ip",
                "context": "Debug test"
            },
            endpoint=threat_agent_endpoint
        )

        # Print response structure
        logger.info("✓ A2A call succeeded!")
        logger.info("=" * 80)
        logger.info("RESPONSE STRUCTURE:")
        logger.info("=" * 80)

        print("\n" + "="*80)
        print("RESPONSE TYPE:", type(result))
        print("="*80)

        if isinstance(result, dict):
            print("\nTOP-LEVEL KEYS:", list(result.keys()))
            print("="*80)

            # Pretty print the full response
            print("\nFULL RESPONSE (formatted):")
            print(json.dumps(result, indent=2, default=str))
            print("="*80)

            # Inspect each top-level key
            for key, value in result.items():
                print(f"\n[KEY: '{key}']")
                print(f"  Type: {type(value)}")
                if isinstance(value, dict):
                    print(f"  Dict keys: {list(value.keys())}")
                    # If it's a nested dict, show first level
                    for k, v in value.items():
                        print(f"    - {k}: {type(v).__name__} = {str(v)[:100]}")
                elif isinstance(value, list):
                    print(f"  List length: {len(value)}")
                else:
                    print(f"  Value preview: {str(value)[:200]}")

            print("\n" + "="*80)
            print("EXPECTED STRUCTURE FOR ROOT AGENT:")
            print("="*80)
            print("""
The root agent expects this structure at root_agent.py:721-722:

    analysis = analysis_result.get('analysis', {})
    mode = analysis_result.get('mode', {})

So the response should have 'analysis' and 'mode' keys at the TOP LEVEL.

Current A2A server returns (a2a_server_fastapi.py:204-209):
{
  "success": true,
  "agent": "ThreatAnalysisAgent",
  "method": "analyze_indicator",
  "result": {                          ← Actual data nested here!
    "success": true,
    "analysis": {...},
    "mode": {...}
  }
}

If you see 'result' key above, the response needs to be unwrapped!
""")

        else:
            print(f"\nERROR: Response is not a dict, it's: {type(result)}")
            print(f"Value: {result}")

    except Exception as e:
        logger.error(f"A2A call failed: {e}", exc_info=True)
        print("\n" + "="*80)
        print("ERROR DETAILS:")
        print("="*80)
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

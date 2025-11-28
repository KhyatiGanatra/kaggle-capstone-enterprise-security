"""Incident Response Agent - Standalone service with A2A protocol support"""

import os
import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional

from dotenv import load_dotenv
load_dotenv(override=True)

from google import adk
from google.adk.agents.invocation_context import InvocationContext
from google.adk.agents.run_config import RunConfig
from google.adk.sessions import InMemorySessionService, Session
import uuid

from shared.memory import IncidentMemory
from shared.config import GoogleSecurityMCPConfig
from shared.a2a_server import A2AServer
from shared.vertex_registry import VertexAIAgentRegistry

logger = logging.getLogger(__name__)


# =============================================================================
# SOAR TOOLS - Simulated incident response actions
# =============================================================================

# In-memory case storage for demo
_cases = {}
_case_counter = [0]


def create_case(title: str, severity: str, description: str = "") -> str:
    """
    Create a new incident case in the SOAR system.
    
    Args:
        title: Title of the incident case
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        description: Description of the incident
    
    Returns:
        JSON string with case ID and details
    """
    _case_counter[0] += 1
    case_id = f"CASE-{datetime.now().strftime('%Y%m%d')}-{_case_counter[0]:04d}"
    
    case = {
        "case_id": case_id,
        "title": title,
        "severity": severity,
        "description": description,
        "status": "Open",
        "created_at": datetime.now().isoformat(),
        "actions_taken": []
    }
    _cases[case_id] = case
    
    logger.info(f"[TOOL] create_case: {case_id} - {title}")
    return json.dumps(case, indent=2)


def block_ip(ip_address: str, case_id: str = "") -> str:
    """
    Block an IP address at the firewall.
    
    Args:
        ip_address: The IP address to block
        case_id: Optional case ID to associate with this action
    
    Returns:
        JSON string with action result
    """
    logger.info(f"[TOOL] block_ip: {ip_address}")
    
    result = {
        "action": "block_ip",
        "ip_address": ip_address,
        "status": "SUCCESS",
        "message": f"IP {ip_address} blocked at perimeter firewall",
        "case_id": case_id,
        "timestamp": datetime.now().isoformat()
    }
    
    if case_id and case_id in _cases:
        _cases[case_id]["actions_taken"].append(f"Blocked IP: {ip_address}")
    
    return json.dumps(result, indent=2)


def isolate_endpoint(hostname: str, case_id: str = "") -> str:
    """
    Isolate an endpoint from the network.
    
    Args:
        hostname: The hostname or IP of the endpoint to isolate
        case_id: Optional case ID to associate with this action
    
    Returns:
        JSON string with action result
    """
    logger.info(f"[TOOL] isolate_endpoint: {hostname}")
    
    result = {
        "action": "isolate_endpoint",
        "hostname": hostname,
        "status": "SUCCESS",
        "message": f"Endpoint {hostname} isolated from network",
        "case_id": case_id,
        "timestamp": datetime.now().isoformat()
    }
    
    if case_id and case_id in _cases:
        _cases[case_id]["actions_taken"].append(f"Isolated endpoint: {hostname}")
    
    return json.dumps(result, indent=2)


def disable_user(username: str, case_id: str = "") -> str:
    """
    Disable a user account.
    
    Args:
        username: The username to disable
        case_id: Optional case ID to associate with this action
    
    Returns:
        JSON string with action result
    """
    logger.info(f"[TOOL] disable_user: {username}")
    
    result = {
        "action": "disable_user",
        "username": username,
        "status": "SUCCESS",
        "message": f"User account {username} disabled and sessions revoked",
        "case_id": case_id,
        "timestamp": datetime.now().isoformat()
    }
    
    if case_id and case_id in _cases:
        _cases[case_id]["actions_taken"].append(f"Disabled user: {username}")
    
    return json.dumps(result, indent=2)


def get_case_status(case_id: str) -> str:
    """
    Get the status of an incident case.
    
    Args:
        case_id: The case ID to look up
    
    Returns:
        JSON string with case details
    """
    logger.info(f"[TOOL] get_case_status: {case_id}")
    
    if case_id in _cases:
        return json.dumps(_cases[case_id], indent=2)
    else:
        return json.dumps({"error": f"Case {case_id} not found"}, indent=2)


def run_agent_sync(agent, message: str) -> str:
    """Helper function to run an ADK agent synchronously"""
    async def _run_async():
        session_service = InMemorySessionService()
        session = Session(
            id=str(uuid.uuid4()),
            appName="incident-response-agent",
            userId="system"
        )
        run_config = RunConfig()
        
        context = InvocationContext(
            session_service=session_service,
            invocation_id=str(uuid.uuid4()),
            agent=agent,
            session=session,
            user_content={"parts": [{"text": message}]},
            run_config=run_config
        )
        
        content_parts = []
        async for event in agent.run_async(context):
            if hasattr(event, 'content'):
                content_parts.append(event.content)
            elif hasattr(event, 'text'):
                content_parts.append(event.text)
            elif isinstance(event, str):
                content_parts.append(event)
            elif hasattr(event, 'parts'):
                for part in event.parts:
                    if hasattr(part, 'text'):
                        content_parts.append(part.text)
        
        return ''.join(str(part) for part in content_parts if part)
    
    try:
        return asyncio.run(_run_async())
    except Exception as e:
        logger.error(f"Error running agent: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return f"Error: {str(e)}"


class IncidentResponseAgent:
    """
    Incident Response Agent using Chronicle SecOps and SOAR MCP Servers
    Can run as standalone service with A2A protocol support
    """
    
    def __init__(self, project_id: str, endpoint: Optional[str] = None):
        self.project_id = project_id
        try:
            self.memory = IncidentMemory(project_id)
        except Exception as e:
            logger.warning(f"Failed to initialize memory: {e}")
            self.memory = None
        self.config = GoogleSecurityMCPConfig()
        self.endpoint = endpoint or os.getenv("INCIDENT_AGENT_ENDPOINT", "http://localhost:8082")
        
        # Initialize ADK agent with SOAR tools
        self.agent = adk.Agent(
            name="IncidentResponseAgent",
            model="gemini-2.0-flash",
            instruction="""You are an Incident Response specialist. Your job is to handle security incidents using the available tools.

WORKFLOW:
1. When given a threat analysis, first create a case using create_case
2. Based on severity, take appropriate actions:
   - CRITICAL/HIGH: Block IPs, isolate endpoints, disable users
   - MEDIUM: Create case and monitor
   - LOW: Document only

AVAILABLE TOOLS:
- create_case: Create an incident case
- block_ip: Block malicious IP at firewall
- isolate_endpoint: Isolate compromised endpoint
- disable_user: Disable compromised user account
- get_case_status: Check case status

RESPONSE FORMAT:
{
  "incident_id": "case ID",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "actions_taken": ["action1", "action2"],
  "status": "Open|In Progress|Resolved",
  "recommendations": ["next steps"]
}

Always create a case first, then take containment actions for HIGH/CRITICAL threats.""",
            tools=[create_case, block_ip, isolate_endpoint, disable_user, get_case_status]
        )
        
        logger.info("✓ Incident Response Agent initialized with SOAR tools")
    
    def handle_incident(self, threat_analysis: dict, context: str = "") -> dict:
        """Handle security incident using Chronicle SecOps and SOAR"""
        
        # Get active incidents for context
        active_incidents = self.memory.get_active_incidents()
        
        incident_prompt = f"""A security threat has been identified and requires incident response:

Threat Analysis:
{json.dumps(threat_analysis, indent=2, default=str)}

Additional Context:
{context}

Active Incidents (for correlation):
{len(active_incidents)} incidents currently in progress

Please execute the full incident response workflow:

1. INVESTIGATE using Chronicle SecOps:
   - Search for related security events
   - Look up the indicator entity
   - Check for IOC matches in environment
   - Identify affected assets

2. CREATE CASE in Chronicle SOAR:
   - Create incident case with appropriate severity
   - Include all findings from investigation
   - Tag with relevant threat information

3. EXECUTE CONTAINMENT:
   - Run appropriate SOAR playbooks based on threat type
   - Document all actions taken
   
4. PROVIDE RECOMMENDATIONS:
   - Next steps for investigation
   - Additional monitoring needed
   - Escalation if required

Return comprehensive response with:
- Investigation findings from Chronicle
- SOAR case ID and status
- Playbooks executed
- Affected assets list
- Recommended next actions"""

        # Execute incident response
        try:
            content = run_agent_sync(self.agent, incident_prompt)
        except Exception as e:
            logger.error(f"Error in incident response execution: {e}")
            return {"success": False, "error": str(e)}
        
        # Store incident in memory
        incident_data = {
            "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "threat_indicator": threat_analysis.get('indicator'),
            "indicator_type": threat_analysis.get('indicator_type'),
            "severity": threat_analysis.get('severity', 'MEDIUM'),
            "status": "IN_PROGRESS",
            "response_summary": content[:1000],
            "created_at": datetime.now().isoformat()
        }
        
        self.memory.store_incident(incident_data)
        
        return {
            "success": True,
            "incident_id": incident_data["incident_id"],
            "response": content,
            "timestamp": datetime.now().isoformat()
        }
    
    def start_a2a_server(self, port: int = 8082, register: bool = True):
        """
        Start A2A protocol server for this agent
        
        Args:
            port: Port to run the server on
            register: Whether to register with Vertex AI Agent Registry
        """
        server = A2AServer(agent_name="IncidentResponseAgent", port=port)
        
        # Register A2A methods
        server.register_method("handle_incident", self.handle_incident)
        
        # Register with Vertex AI if requested
        if register:
            registry = VertexAIAgentRegistry(self.project_id)
            registry.register_agent(
                agent_name="IncidentResponseAgent",
                endpoint=self.endpoint,
                capabilities=["handle_incident", "incident_response", "chronicle_integration"]
            )
            logger.info("Registered IncidentResponseAgent with Vertex AI Agent Registry")
        
        # Start server
        logger.info(f"Starting IncidentResponseAgent A2A server on port {port}")
        server.run(host='0.0.0.0', debug=False)


if __name__ == "__main__":
    # Run as standalone service
    import sys
    
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("ERROR: GOOGLE_CLOUD_PROJECT environment variable not set")
        sys.exit(1)
    
    # Cloud Run sets PORT environment variable, fallback to INCIDENT_AGENT_PORT for local dev
    port = int(os.getenv("PORT", os.getenv("INCIDENT_AGENT_PORT", "8082")))
    
    agent = IncidentResponseAgent(project_id)
    agent.start_a2a_server(port=port, register=True)


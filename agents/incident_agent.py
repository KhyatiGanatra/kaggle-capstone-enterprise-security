"""Incident Response Agent - Using simulated SOAR tools for demo"""

import os
import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List

from dotenv import load_dotenv
load_dotenv(override=True)

from google import adk
from google.adk.agents.invocation_context import InvocationContext
from google.adk.agents.run_config import RunConfig
from google.adk.sessions import InMemorySessionService, Session
import uuid

from shared.memory.incident_memory import IncidentMemory
from shared.config import GoogleSecurityMCPConfig
from shared.communication.a2a_server import A2AServer
from shared.communication.a2a_server_fastapi import A2AServerFastAPI
from shared.discovery.vertex_registry import VertexAIAgentRegistry
from shared.web_server.start_with_web_ui import start_agent_with_web_ui

logger = logging.getLogger(__name__)


# =============================================================================
# SOAR TOOLS - Simulated for Demo (Chronicle SOAR requires enterprise access)
# =============================================================================

# In-memory case storage for demo
_cases: Dict[str, Dict] = {}
_case_counter = [0]

# Check if real SOAR is configured
SOAR_API_KEY = os.getenv("SOAR_API_KEY", "")
IS_LIVE_SOAR = bool(SOAR_API_KEY and not SOAR_API_KEY.startswith("your-"))


def create_case(title: str, severity: str, description: str = "") -> str:
    """
    Create a new incident case in the SOAR system.
    
    NOTE: This is a SIMULATED action for demo purposes.
    In production, this would integrate with Chronicle SOAR.
    
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
        "actions_taken": [],
        "source": "Simulated SOAR"
    }
    _cases[case_id] = case
    
    logger.info(f"[SIMULATED] create_case: {case_id} - {title}")
    return json.dumps(case, indent=2)


def block_ip(ip_address: str, case_id: str = "") -> str:
    """
    Block an IP address at the firewall.
    
    NOTE: This is a SIMULATED action for demo purposes.
    In production, this would trigger a firewall rule change.
    
    Args:
        ip_address: The IP address to block
        case_id: Optional case ID to associate with this action
    
    Returns:
        JSON string with action result
    """
    logger.info(f"[SIMULATED] block_ip: {ip_address}")
    
    result = {
        "action": "block_ip",
        "ip_address": ip_address,
        "status": "SUCCESS",
        "message": f"[SIMULATED] IP {ip_address} blocked at perimeter firewall",
        "case_id": case_id,
        "timestamp": datetime.now().isoformat(),
        "source": "Simulated SOAR"
    }
    
    if case_id and case_id in _cases:
        _cases[case_id]["actions_taken"].append(f"[SIMULATED] Blocked IP: {ip_address}")
    
    return json.dumps(result, indent=2)


def isolate_endpoint(hostname: str, case_id: str = "") -> str:
    """
    Isolate an endpoint from the network.
    
    NOTE: This is a SIMULATED action for demo purposes.
    In production, this would trigger EDR isolation.
    
    Args:
        hostname: The hostname or IP of the endpoint to isolate
        case_id: Optional case ID to associate with this action
    
    Returns:
        JSON string with action result
    """
    logger.info(f"[SIMULATED] isolate_endpoint: {hostname}")
    
    result = {
        "action": "isolate_endpoint",
        "hostname": hostname,
        "status": "SUCCESS",
        "message": f"[SIMULATED] Endpoint {hostname} isolated from network",
        "case_id": case_id,
        "timestamp": datetime.now().isoformat(),
        "source": "Simulated SOAR"
    }
    
    if case_id and case_id in _cases:
        _cases[case_id]["actions_taken"].append(f"[SIMULATED] Isolated endpoint: {hostname}")
    
    return json.dumps(result, indent=2)


def disable_user(username: str, case_id: str = "") -> str:
    """
    Disable a user account.
    
    NOTE: This is a SIMULATED action for demo purposes.
    In production, this would disable the account in IAM/AD.
    
    Args:
        username: The username to disable
        case_id: Optional case ID to associate with this action
    
    Returns:
        JSON string with action result
    """
    logger.info(f"[SIMULATED] disable_user: {username}")
    
    result = {
        "action": "disable_user",
        "username": username,
        "status": "SUCCESS",
        "message": f"[SIMULATED] User account {username} disabled and sessions revoked",
        "case_id": case_id,
        "timestamp": datetime.now().isoformat(),
        "source": "Simulated SOAR"
    }
    
    if case_id and case_id in _cases:
        _cases[case_id]["actions_taken"].append(f"[SIMULATED] Disabled user: {username}")
    
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
        return json.dumps({"error": f"Case {case_id} not found", "source": "Simulated SOAR"}, indent=2)


def list_all_cases() -> str:
    """
    List all incident cases.
    
    Returns:
        JSON string with all cases
    """
    logger.info(f"[TOOL] list_all_cases: {len(_cases)} cases")
    return json.dumps({"cases": list(_cases.values()), "count": len(_cases), "source": "Simulated SOAR"}, indent=2)


# =============================================================================
# SYNC HELPER
# =============================================================================

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


# =============================================================================
# INCIDENT RESPONSE AGENT
# =============================================================================

class IncidentResponseAgent:
    """
    Incident Response Agent with simulated SOAR capabilities.
    
    In production, this would connect to Chronicle SOAR MCP server.
    For demo purposes, it uses simulated tools that mirror SOAR behavior.
    """
    
    def __init__(self, project_id: str, endpoint: Optional[str] = None):
        self.project_id = project_id
        self.is_live_mode = IS_LIVE_SOAR  # False for demo
        
        # Initialize memory (optional)
        try:
            self.memory = IncidentMemory(project_id)
            logger.info("Incident memory initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize memory: {e}")
            self.memory = None
        
        self.config = GoogleSecurityMCPConfig()
        self.endpoint = endpoint or os.getenv("INCIDENT_AGENT_ENDPOINT", "http://localhost:8082")
        
        # Define available tools
        self.tools = [create_case, block_ip, isolate_endpoint, disable_user, get_case_status, list_all_cases]
        
        # Initialize ADK agent
        self.agent = adk.Agent(
            name="IncidentResponseAgent",
            model="gemini-2.0-flash",
            instruction="""You are an Incident Response specialist. Your job is to handle security incidents using the available tools.

⚠️ NOTE: All actions are SIMULATED for demo purposes. In production, these would execute real SOAR playbooks.

AVAILABLE TOOLS (Simulated SOAR):
- create_case: Create an incident case
- block_ip: Block malicious IP at firewall [SIMULATED]
- isolate_endpoint: Isolate compromised endpoint [SIMULATED]
- disable_user: Disable compromised user account [SIMULATED]
- get_case_status: Check case status
- list_all_cases: List all incident cases

WORKFLOW:
1. When given a threat analysis, first create a case using create_case
2. Based on severity, take appropriate actions:
   - CRITICAL/HIGH: Block IPs, isolate endpoints, disable users
   - MEDIUM: Create case and monitor
   - LOW: Document only

3. Always create a case first, then take containment actions.

RESPONSE FORMAT:
{
  "incident_id": "case ID",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "actions_taken": ["action1", "action2"],
  "status": "Open|In Progress|Resolved",
  "source": "Simulated SOAR",
  "recommendations": ["next steps"]
}""",
            tools=self.tools
        )
        
        logger.info("✓ Incident Response Agent initialized with simulated SOAR tools")
    
    def get_mode_indicator(self) -> Dict[str, Any]:
        """Return mode indicator for UI display"""
        return {
            "is_live": self.is_live_mode,
            "mode": "Live" if self.is_live_mode else "Demo",
            "source": "Chronicle SOAR" if self.is_live_mode else "Simulated SOAR",
            "tools_count": len(self.tools),
            "icon": "🟢" if self.is_live_mode else "🟡"
        }
    
    def handle_incident(self, threat_analysis: dict, context: str = "") -> dict:
        """Handle security incident"""
        
        mode_info = self.get_mode_indicator()
        
        # Get active incidents for context
        active_incidents = []
        if self.memory:
            try:
                active_incidents = self.memory.get_active_incidents()
            except Exception as e:
                logger.warning(f"Failed to get active incidents: {e}")
        
        incident_prompt = f"""A security threat has been identified and requires incident response:

Threat Analysis:
{json.dumps(threat_analysis, indent=2, default=str)}

Additional Context:
{context}

Active Incidents: {len(active_incidents)} currently in progress

Please execute the incident response workflow:

1. CREATE CASE: Use create_case with appropriate severity
2. CONTAINMENT: Based on severity, take containment actions:
   - For IPs: use block_ip
   - For hosts: use isolate_endpoint  
   - For users: use disable_user
3. DOCUMENT: All actions in the case

Return your response in the JSON format specified in your instructions."""

        # Execute incident response
        try:
            content = run_agent_sync(self.agent, incident_prompt)
        except Exception as e:
            logger.error(f"Error in incident response: {e}")
            return {"success": False, "error": str(e), "mode": mode_info}
        
        # Store incident in memory
        incident_data = {
            "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "threat_indicator": threat_analysis.get('indicator'),
            "indicator_type": threat_analysis.get('indicator_type'),
            "severity": threat_analysis.get('severity', 'MEDIUM'),
            "status": "IN_PROGRESS",
            "response_summary": content[:1000],
            "created_at": datetime.now().isoformat(),
            "source": mode_info["source"]
        }
        
        if self.memory:
            try:
                self.memory.store_incident(incident_data)
            except Exception as e:
                logger.warning(f"Failed to store incident: {e}")
        
        return {
            "success": True,
            "incident_id": incident_data["incident_id"],
            "response": content,
            "timestamp": datetime.now().isoformat(),
            "mode": mode_info
        }
    
    def execute_action(self, action: str, target: str, case_id: str = "") -> dict:
        """Execute a single response action directly"""
        
        mode_info = self.get_mode_indicator()
        
        action_map = {
            "block_ip": lambda: block_ip(target, case_id),
            "isolate_endpoint": lambda: isolate_endpoint(target, case_id),
            "disable_user": lambda: disable_user(target, case_id),
        }
        
        if action not in action_map:
            return {
                "success": False,
                "error": f"Unknown action: {action}",
                "available_actions": list(action_map.keys()),
                "mode": mode_info
            }
        
        try:
            result = json.loads(action_map[action]())
            return {
                "success": True,
                "result": result,
                "mode": mode_info
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "mode": mode_info
            }
    
    def start_a2a_server(self, port: int = 8082, register: bool = True, enable_web_ui: bool = True):
        """
        Start A2A protocol server with optional ADK web UI for this agent
        
        Args:
            port: Port to run the server on
            register: Whether to register with Vertex AI Agent Registry
            enable_web_ui: Whether to enable ADK web UI for monitoring
        """
        # Prepare A2A methods - include all methods from both branches
        a2a_methods = {
            "handle_incident": self.handle_incident,
            "execute_action": self.execute_action,
            "get_mode": self.get_mode_indicator
        }
        
        # Determine agents directory for ADK web UI
        # In Cloud Run, the agent structure is created in the Dockerfile
        agents_dir = os.getenv("ADK_AGENTS_DIR", "/app/adk_web_ui")
        
        # Register with Vertex AI if requested
        if register:
            try:
                registry = VertexAIAgentRegistry(self.project_id)
                endpoint = os.getenv("INCIDENT_AGENT_ENDPOINT", f"http://localhost:{port}")
                registry.register_agent(
                    agent_name="IncidentResponseAgent",
                    endpoint=endpoint,
                    capabilities=["handle_incident", "execute_action", "incident_response", "chronicle_integration", "soar_simulated"]
                )
                logger.info("Registered IncidentResponseAgent with Vertex AI Agent Registry")
            except Exception as e:
                logger.warning(f"Failed to register with Vertex AI Agent Registry (continuing anyway): {e}")
        
        # Start unified server with A2A and web UI
        logger.info(f"Starting IncidentResponseAgent server on port {port}")
        if enable_web_ui:
            logger.info(f"ADK web UI enabled - access at http://<service-url>/web")
        
        start_agent_with_web_ui(
            agent_name="IncidentResponseAgent",
            agents_dir=agents_dir,
            a2a_methods=a2a_methods,
            port=port,
            enable_web_ui=enable_web_ui
        )


if __name__ == "__main__":
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        logger.error("ERROR: GOOGLE_CLOUD_PROJECT environment variable not set")
        print("ERROR: GOOGLE_CLOUD_PROJECT environment variable not set", file=sys.stderr)
        sys.exit(1)
    
    port = int(os.getenv("PORT", os.getenv("INCIDENT_AGENT_PORT", "8082")))
    
    logger.info(f"Starting Incident Response Agent for project: {project_id}")
    logger.info(f"Server will listen on port: {port}")
    
    try:
        agent = IncidentResponseAgent(project_id)
        
        # Show mode
        mode = agent.get_mode_indicator()
        logger.info(f"Agent Mode: {mode['icon']} {mode['mode']} - {mode['tools_count']} tools available")
        
        agent.start_a2a_server(port=port, register=True)
    except Exception as e:
        logger.error(f"Failed to start Incident Response Agent: {e}", exc_info=True)
        print(f"ERROR: Failed to start agent: {e}", file=sys.stderr)
        sys.exit(1)

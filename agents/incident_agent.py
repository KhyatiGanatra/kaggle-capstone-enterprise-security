"""Incident Response Agent - Standalone service with A2A protocol support"""

import os
import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional

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
        self.memory = IncidentMemory(project_id)
        self.config = GoogleSecurityMCPConfig()
        self.endpoint = endpoint or os.getenv("INCIDENT_AGENT_ENDPOINT", "http://localhost:8082")
        
        # Initialize ADK agent
        self.agent = adk.Agent(
            name="IncidentResponseAgent",
            model="gemini-2.5-pro-preview-03-25",
            instruction="""You are an expert Incident Response specialist with access to Chronicle SecOps and SOAR platforms.

Your responsibilities:
1. Investigate security incidents using Chronicle SecOps
2. Create and manage cases in Chronicle SOAR
3. Execute automated response playbooks
4. Coordinate containment, eradication, and recovery
5. Document incident timeline and evidence
6. Maintain incident memory for organizational learning

Available MCP Servers:

Chronicle SecOps (SIEM):
- search_security_events: Query security logs and events
- get_security_alerts: Retrieve active alerts
- lookup_entity: Investigate IPs, domains, hashes
- list_security_rules: Review detection rules
- get_ioc_matches: Find IOC matches in environment
- get_threat_intel: AI-powered threat intelligence

Chronicle SOAR:
- list_cases: View all security cases
- create_case: Create incident case
- update_case: Update case status and notes
- run_playbook: Execute automated response
- get_playbook_results: Check playbook execution

Incident Response Process:

1. IDENTIFICATION
   - Use Chronicle SecOps to search for related events
   - Look up affected entities
   - Correlate with existing alerts
   - Determine scope and impact

2. CONTAINMENT
   - Create SOAR case immediately
   - Execute appropriate playbooks:
     * isolate_endpoint: Network isolation
     * block_ip: Firewall blocking
     * quarantine_file: File quarantine
     * disable_account: Account suspension
   - Document containment actions

3. INVESTIGATION
   - Search Chronicle for event timeline
   - Identify affected assets
   - Determine attack vector
   - Assess data exposure

4. ERADICATION
   - Remove malicious artifacts
   - Close attack vectors
   - Verify threat removal

5. RECOVERY
   - Restore services
   - Monitor for re-infection
   - Validate security controls

6. DOCUMENTATION
   - Update SOAR case with findings
   - Store incident in memory
   - Create lessons learned

Severity Guidelines:
- CRITICAL: Active breach, ransomware, C2 communication
- HIGH: Malware infection, privilege escalation
- MEDIUM: Policy violations, suspicious activity
- LOW: False positives, informational

Response Time Requirements:
- CRITICAL: Immediate (< 15 minutes)
- HIGH: Urgent (< 1 hour)
- MEDIUM: Same day (< 8 hours)
- LOW: Next business day

Always prioritize containment to prevent further damage."""
        )
        
        logger.info("✓ Incident Response Agent initialized")
    
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


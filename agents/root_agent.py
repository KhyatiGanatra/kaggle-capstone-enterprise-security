"""Root Orchestrator Agent - Coordinates sub-agents via A2A protocol"""

import os
import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List

from google import adk
from google.adk.agents.invocation_context import InvocationContext
from google.adk.agents.run_config import RunConfig
from google.adk.sessions import InMemorySessionService, Session
import uuid

from shared.memory.threat_memory import ThreatIntelMemory
from shared.memory.incident_memory import IncidentMemory
from shared.communication.a2a_client import A2AClient
from shared.communication.a2a_server import A2AServer
from shared.discovery.vertex_registry import VertexAIAgentRegistry

logger = logging.getLogger(__name__)


def run_agent_sync(agent, message: str) -> str:
    """Helper function to run an ADK agent synchronously"""
    async def _run_async():
        session_service = InMemorySessionService()
        session = Session(
            id=str(uuid.uuid4()),
            appName="root-orchestrator-agent",
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


class RootOrchestratorAgent:
    """
    Root Orchestrator Agent coordinating all sub-agents via A2A protocol
    Discovers sub-agents from Vertex AI Agent Registry
    """
    
    def __init__(self, project_id: str, location: str = "us-central1"):
        self.project_id = project_id
        self.location = location
        
        # Initialize A2A client for communicating with sub-agents
        self.a2a_client = A2AClient(project_id, location)
        
        # Initialize Vertex AI Agent Registry for discovery
        self.registry = VertexAIAgentRegistry(project_id, location)
        
        # Discover sub-agents from registry
        logger.info("Discovering sub-agents from Vertex AI Agent Registry...")
        self._discover_sub_agents()
        
        # Session memory (active investigations in current session)
        self.session_memory = {
            "active_investigations": [],
            "processed_indicators": set(),
            "session_start": datetime.now().isoformat()
        }
        
        # Persistent memory access (optional - won't crash if BigQuery unavailable)
        try:
            self.threat_memory = ThreatIntelMemory(project_id)
            logger.info("Threat intelligence memory initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize BigQuery threat memory (will continue without persistence): {e}")
            self.threat_memory = None
        
        try:
            self.incident_memory = IncidentMemory(project_id)
            logger.info("Incident memory initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize BigQuery incident memory (will continue without persistence): {e}")
            self.incident_memory = None
        
        # Root orchestrator agent
        self.agent = adk.Agent(
            name="RootOrchestratorAgent",
            model="gemini-2.5-pro-preview-03-25",
            instruction="""You are the Root Security Orchestrator managing a team of specialized security agents using Google Cloud Security platforms.

Your Team (accessed via A2A protocol):
1. Threat Analysis Agent - Uses Google Threat Intelligence (GTI/VirusTotal) for IOC analysis
2. Incident Response Agent - Uses Chronicle SecOps (SIEM) and SOAR for investigation and response

Your Capabilities:
- Session Memory: Track all investigations in current session
- Persistent Memory: Access historical threat intelligence and incidents from BigQuery
- Agent Coordination: Delegate tasks via A2A (Agent-to-Agent) protocol over HTTPS
- Decision Making: Determine response priorities and escalation

Workflow for Security Events:

1. ASSESS
   - Evaluate the security event/alert
   - Check if indicator already processed in this session
   - Review relevant historical data from persistent memory

2. DELEGATE TO THREAT ANALYSIS (via A2A)
   - Use A2A protocol to call Threat Analysis Agent
   - Provide historical context from memory
   - Get threat assessment with severity and confidence

3. DECIDE ON RESPONSE
   - If CRITICAL/HIGH: Immediate incident response via Incident Response Agent
   - If MEDIUM: Investigate further, then respond if confirmed
   - If LOW: Log to memory, monitor, no immediate action

4. COORDINATE INCIDENT RESPONSE (via A2A)
   - Use A2A protocol to call Incident Response Agent with full context
   - Agent will use Chronicle SecOps for investigation
   - Agent will use Chronicle SOAR for case management and automation

5. SUPERVISE & TRACK
   - Monitor progress through session memory
   - Intervene if escalation needed
   - Update persistent memory with findings

6. REPORT
   - Provide executive summary
   - Include actions taken by all agents
   - Highlight any items requiring human decision

Decision Criteria:
- CRITICAL threats → Immediate IR workflow (< 15 min response)
- HIGH threats → Urgent IR workflow (< 1 hour)
- MEDIUM threats → Investigate first, IR if confirmed (< 8 hours)
- LOW threats → Log and monitor only

Memory Usage:
- Session Memory: Current investigation state, processed indicators
- Persistent Memory: Historical threat intel, past incidents, trends

Communication Protocol:
Use A2A protocol over HTTPS to delegate tasks to sub-agents. Sub-agents are discovered from Vertex AI Agent Registry.

Be decisive, coordinate effectively, and ensure no threat goes unaddressed."""
        )
        
        logger.info("✓ Root Orchestrator initialized")
    
    def _discover_sub_agents(self):
        """Discover sub-agents from Vertex AI Agent Registry, with fallback to environment variables"""
        try:
            # Discover Threat Analysis Agent
            threat_agent_info = self.registry.discover_agent("ThreatAnalysisAgent")
            if threat_agent_info:
                self.threat_agent_endpoint = threat_agent_info.get('endpoint')
                logger.info(f"✓ Discovered ThreatAnalysisAgent at {self.threat_agent_endpoint}")
            else:
                # Fallback to environment variable for local development
                self.threat_agent_endpoint = os.getenv("THREAT_AGENT_ENDPOINT")
                if self.threat_agent_endpoint:
                    logger.info(f"✓ Using ThreatAnalysisAgent from environment: {self.threat_agent_endpoint}")
                else:
                    logger.warning("⚠ ThreatAnalysisAgent not found in registry and no THREAT_AGENT_ENDPOINT set")
            
            # Discover Incident Response Agent
            incident_agent_info = self.registry.discover_agent("IncidentResponseAgent")
            if incident_agent_info:
                self.incident_agent_endpoint = incident_agent_info.get('endpoint')
                logger.info(f"✓ Discovered IncidentResponseAgent at {self.incident_agent_endpoint}")
            else:
                # Fallback to environment variable for local development
                self.incident_agent_endpoint = os.getenv("INCIDENT_AGENT_ENDPOINT")
                if self.incident_agent_endpoint:
                    logger.info(f"✓ Using IncidentResponseAgent from environment: {self.incident_agent_endpoint}")
                else:
                    logger.warning("⚠ IncidentResponseAgent not found in registry and no INCIDENT_AGENT_ENDPOINT set")
                
        except Exception as e:
            logger.error(f"Error discovering sub-agents: {e}")
            # Fallback to environment variables on error
            self.threat_agent_endpoint = os.getenv("THREAT_AGENT_ENDPOINT")
            self.incident_agent_endpoint = os.getenv("INCIDENT_AGENT_ENDPOINT")
    
    def _call_threat_agent(self, indicator: str, indicator_type: str, context: str = "") -> dict:
        """Call Threat Analysis Agent via A2A protocol"""
        if not self.threat_agent_endpoint:
            return {"success": False, "error": "ThreatAnalysisAgent endpoint not available"}
        
        try:
            result = self.a2a_client.invoke_agent(
                agent_name="ThreatAnalysisAgent",
                method="analyze_indicator",
                params={
                    "indicator": indicator,
                    "indicator_type": indicator_type,
                    "context": context
                },
                endpoint=self.threat_agent_endpoint
            )
            return result
        except Exception as e:
            logger.error(f"Error calling ThreatAnalysisAgent: {e}")
            return {"success": False, "error": str(e)}
    
    def _call_incident_agent(self, threat_analysis: dict, context: str = "") -> dict:
        """Call Incident Response Agent via A2A protocol"""
        if not self.incident_agent_endpoint:
            return {"success": False, "error": "IncidentResponseAgent endpoint not available"}
        
        try:
            result = self.a2a_client.invoke_agent(
                agent_name="IncidentResponseAgent",
                method="handle_incident",
                params={
                    "threat_analysis": threat_analysis,
                    "context": context
                },
                endpoint=self.incident_agent_endpoint
            )
            return result
        except Exception as e:
            logger.error(f"Error calling IncidentResponseAgent: {e}")
            return {"success": False, "error": str(e)}
    
    def process_security_event(self, event: dict) -> dict:
        """Process incoming security event through the multi-agent workflow"""
        
        indicator = event.get('indicator')
        indicator_type = event.get('indicator_type')
        
        # Check if already processed in this session
        if indicator in self.session_memory['processed_indicators']:
            logger.warning(f"⚠ Indicator {indicator} already processed in this session")
            return {
                "status": "DUPLICATE",
                "message": f"Indicator {indicator} already processed",
                "previous_investigation": [
                    inv for inv in self.session_memory['active_investigations']
                    if inv.get('indicator') == indicator
                ]
            }
        
        # Create investigation
        investigation_id = f"INV-{len(self.session_memory['active_investigations']) + 1:04d}"
        
        investigation = {
            "investigation_id": investigation_id,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "event": event,
            "started_at": datetime.now().isoformat(),
            "status": "IN_PROGRESS"
        }
        
        self.session_memory['active_investigations'].append(investigation)
        self.session_memory['processed_indicators'].add(indicator)
        
        # Get historical context from persistent memory
        # Retrieve historical data from memory (if available)
        threat_history = []
        if self.threat_memory:
            try:
                threat_history = self.threat_memory.retrieve_threat_history(indicator)
            except Exception as e:
                logger.warning(f"Failed to retrieve threat history: {e}")
        
        active_incidents = []
        if self.incident_memory:
            try:
                active_incidents = self.incident_memory.get_active_incidents()
            except Exception as e:
                logger.warning(f"Failed to retrieve active incidents: {e}")
        
        # Step 1: Delegate to Threat Analysis Agent via A2A
        logger.info(f"[ORCHESTRATOR] Delegating to ThreatAnalysisAgent via A2A...")
        threat_result = self._call_threat_agent(indicator, indicator_type)
        
        if not threat_result.get('success'):
            return {
                "success": False,
                "error": f"Threat analysis failed: {threat_result.get('error')}",
                "investigation_id": investigation_id
            }
        
        threat_analysis = threat_result.get('analysis', {})
        severity = threat_analysis.get('severity', 'LOW')
        
        # Step 2: Decide on response based on severity
        incident_result = None
        if severity in ['CRITICAL', 'HIGH']:
            logger.info(f"[ORCHESTRATOR] Escalating to IncidentResponseAgent via A2A...")
            incident_result = self._call_incident_agent(threat_analysis)
        
        # Step 3: Build orchestration response
        orchestration_prompt = f"""Security event processed through multi-agent workflow:

Investigation ID: {investigation_id}

Event Details:
{json.dumps(event, indent=2)}

Threat Analysis Result (from ThreatAnalysisAgent via A2A):
{json.dumps(threat_analysis, indent=2, default=str)}

Incident Response Result (from IncidentResponseAgent via A2A):
{json.dumps(incident_result, indent=2, default=str) if incident_result else 'Not triggered (low severity)'}

Please provide an executive summary of:
1. Threat assessment
2. Actions taken by sub-agents
3. Recommendations
4. Any items requiring human attention"""

        # Execute orchestration
        logger.info(f"[ORCHESTRATOR] Processing investigation {investigation_id}...")
        try:
            content = run_agent_sync(self.agent, orchestration_prompt)
        except Exception as e:
            logger.error(f"Orchestration failed: {e}")
            content = f"Error: {e}"
        
        # Update investigation status
        investigation['status'] = "COMPLETED"
        investigation['completed_at'] = datetime.now().isoformat()
        investigation['orchestrator_response'] = content
        
        return {
            "success": True,
            "investigation_id": investigation_id,
            "threat_analysis": threat_analysis,
            "incident_response": incident_result,
            "orchestrator_decision": content,
            "timestamp": datetime.now().isoformat()
        }
    
    def get_session_status(self) -> dict:
        """Get current session status"""
        return {
            "session_start": self.session_memory['session_start'],
            "total_investigations": len(self.session_memory['active_investigations']),
            "unique_indicators": len(self.session_memory['processed_indicators']),
            "investigations": self.session_memory['active_investigations']
        }
    
    def get_organizational_intelligence(self, days: int = 7) -> dict:
        """Get organizational threat intelligence summary from persistent memory"""
        # Retrieve data from memory (if available)
        recent_threats = []
        if self.threat_memory:
            try:
                recent_threats = self.threat_memory.get_recent_threats(hours=days*24)
            except Exception as e:
                logger.warning(f"Failed to retrieve recent threats: {e}")
        
        active_incidents = []
        if self.incident_memory:
            try:
                active_incidents = self.incident_memory.get_active_incidents()
            except Exception as e:
                logger.warning(f"Failed to retrieve active incidents: {e}")
        
        # Aggregate statistics
        severity_counts = {}
        threat_types = {}
        
        for threat in recent_threats:
            sev = threat.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            threat_type = threat.get('threat_type', 'UNKNOWN')
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        return {
            "period_days": days,
            "total_threats_detected": len(recent_threats),
            "threats_by_severity": severity_counts,
            "threats_by_type": threat_types,
            "active_incidents": len(active_incidents),
            "critical_incidents": len([i for i in active_incidents if i.get('severity') == 'CRITICAL']),
            "high_incidents": len([i for i in active_incidents if i.get('severity') == 'HIGH'])
        }
    
    def start_a2a_server(self, port: int = 8080, register: bool = True):
        """
        Start A2A protocol server for this agent
        
        Args:
            port: Port to run the server on
            register: Whether to register with Vertex AI Agent Registry
        """
        server = A2AServer(agent_name="RootOrchestratorAgent", port=port)
        
        # Register A2A methods
        server.register_method("process_security_event", self.process_security_event)
        server.register_method("get_session_status", self.get_session_status)
        
        # Start server FIRST (so Cloud Run health checks pass)
        logger.info(f"Starting RootOrchestratorAgent A2A server on port {port}")
        
        # Register with Vertex AI in background (non-blocking)
        if register:
            try:
                registry = VertexAIAgentRegistry(self.project_id, self.location)
                endpoint = os.getenv("ROOT_AGENT_ENDPOINT", f"http://localhost:{port}")
                registry.register_agent(
                    agent_name="RootOrchestratorAgent",
                    endpoint=endpoint,
                    capabilities=["process_security_event", "orchestration", "threat_coordination"]
                )
                logger.info("Registered RootOrchestratorAgent with Vertex AI Agent Registry")
            except Exception as e:
                logger.warning(f"Failed to register with Vertex AI Agent Registry (continuing anyway): {e}")
        
        # Start server (this blocks)
        server.run(host='0.0.0.0', debug=False)


if __name__ == "__main__":
    # Run as standalone service
    import sys
    
    # Configure logging for Cloud Run
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        logger.error("ERROR: GOOGLE_CLOUD_PROJECT environment variable not set")
        print("ERROR: GOOGLE_CLOUD_PROJECT environment variable not set", file=sys.stderr)
        sys.exit(1)
    
    location = os.getenv("VERTEX_AI_LOCATION", "us-central1")
    
    # Cloud Run sets PORT environment variable, fallback to ROOT_AGENT_PORT for local dev
    port = int(os.getenv("PORT", os.getenv("ROOT_AGENT_PORT", "8080")))
    
    logger.info(f"Starting Root Orchestrator Agent for project: {project_id}")
    logger.info(f"Server will listen on port: {port}")
    
    try:
        orchestrator = RootOrchestratorAgent(project_id, location)
        logger.info("Root Orchestrator Agent initialized successfully")
        orchestrator.start_a2a_server(port=port, register=True)
    except Exception as e:
        logger.error(f"Failed to start Root Orchestrator Agent: {e}", exc_info=True)
        print(f"ERROR: Failed to start agent: {e}", file=sys.stderr)
        sys.exit(1)



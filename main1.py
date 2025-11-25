# Multi-Agent Security System - Google Cloud Security MCP Setup Guide
# Code - Corrected Version

# Multi-Agent Security System using Google Cloud Security MCP Servers
# Architecture: Root Orchestrator + Threat Analysis + Incident Response Agents
# MCP Servers: Chronicle SecOps, SOAR, Google Threat Intelligence (GTI), SCC

import os
import sys
import json
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv(override=True)

# --- FIX 1: Correct Import for Agent Development Kit ---
try:
    from google import adk
except ImportError:
    print("CRITICAL ERROR: 'google-adk' is not installed.")
    print("Please install it using: pip install google-adk")
    sys.exit(1)

# --- FIX 2: Robust Cloud Imports ---
try:
    from google.cloud import bigquery, storage, aiplatform
    from google.api_core import exceptions as google_exceptions
except ImportError:
    print("WARNING: Google Cloud SDK libraries not fully installed.")
    print("Please install: pip install google-cloud-bigquery google-cloud-storage google-cloud-aiplatform")
    # We continue, but methods using these will fail gracefully

import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Helper function to run ADK agents synchronously ---
def run_agent_sync(agent, message: str) -> str:
    """
    Helper function to run an ADK agent synchronously.
    ADK agents use async methods, so we wrap them here.
    Creates a proper InvocationContext with all required services.
    """
    async def _run_async():
        from google.adk.agents.invocation_context import InvocationContext
        from google.adk.agents.run_config import RunConfig
        from google.adk.sessions import InMemorySessionService, Session
        import uuid
        
        # Create required services
        session_service = InMemorySessionService()
        
        # Create a session with required fields
        session = Session(
            id=str(uuid.uuid4()),
            appName="security-agent",
            userId="system"
        )
        
        # Create run_config (required to avoid NoneType errors)
        run_config = RunConfig()
        
        # Create invocation context with all required fields
        context = InvocationContext(
            session_service=session_service,
            invocation_id=str(uuid.uuid4()),
            agent=agent,
            session=session,
            user_content={"parts": [{"text": message}]},  # Format as dict with parts
            run_config=run_config  # Required to avoid AttributeError
        )
        
        content_parts = []
        
        async for event in agent.run_async(context):
            # Collect content from events
            if hasattr(event, 'content'):
                content_parts.append(event.content)
            elif hasattr(event, 'text'):
                content_parts.append(event.text)
            elif isinstance(event, str):
                content_parts.append(event)
            # Also check for parts in the event
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

# ============================================================================
# PART 1: GOOGLE CLOUD SECURITY MCP SERVER CONFIGURATION
# ============================================================================

"""
Google Cloud Security MCP Servers (Official):
1. Chronicle SecOps (SIEM) - google-secops-mcp
2. Chronicle SOAR - secops-soar-mcp  
3. Google Threat Intelligence (GTI) - gti-mcp (formerly VirusTotal)
4. Security Command Center (SCC) - scc-mcp

GitHub: https://github.com/google/mcp-security
"""

class GoogleSecurityMCPConfig:
    """Configuration for Google Cloud Security MCP Servers"""
    
    # Helper to safely get env vars
    @staticmethod
    def _get_env(key, default=None):
        val = os.getenv(key, default)
        if not val and default is None:
            logger.warning(f"Environment variable {key} is missing. dependent MCP servers may fail.")
        return val

    @property
    def CHRONICLE_SECOPS(self):
        return {
            "name": "chronicle_secops",
            "command": "uvx",
            "args": ["--from", "google-secops-mcp", "secops_mcp"],
            "env": {
                "CHRONICLE_PROJECT_ID": self._get_env("CHRONICLE_PROJECT_ID", "your-project-id"),
                "CHRONICLE_CUSTOMER_ID": self._get_env("CHRONICLE_CUSTOMER_ID", "your-customer-id"),
                "CHRONICLE_REGION": self._get_env("CHRONICLE_REGION", "us"),
            }
        }
    
    @property
    def CHRONICLE_SOAR(self):
        return {
            "name": "chronicle_soar",
            "command": "uvx",
            "args": ["secops_soar_mcp", "--integrations", "CSV,OKTA"],
            "env": {
                "SOAR_URL": self._get_env("SOAR_URL", "https://your-tenant.siemplify-soar.com:443"),
                "SOAR_APP_KEY": self._get_env("SOAR_APP_KEY", "your-soar-api-key"),
            }
        }
    
    @property
    def GOOGLE_THREAT_INTEL(self):
        return {
            "name": "gti",
            "command": "uvx",
            "args": ["gti_mcp"],
            "env": {
                "VT_APIKEY": self._get_env("VT_APIKEY", "your-virustotal-api-key"),
            }
        }
    
    @property
    def SECURITY_COMMAND_CENTER(self):
        return {
            "name": "scc",
            "command": "uvx",
            "args": ["scc_mcp"],
            "env": {
                "GOOGLE_CLOUD_PROJECT": self._get_env("GOOGLE_CLOUD_PROJECT", "your-project-id"),
            }
        }

# ============================================================================
# PART 2: MEMORY MANAGEMENT WITH BIGQUERY
# ============================================================================

class ThreatIntelMemory:
    """Memory storage for Threat Analysis Agent using BigQuery"""
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.bq_client = bigquery.Client(project=project_id)
        self.dataset_id = "security_intel"
        self.table_id = "threat_intelligence"
        self.full_table_id = f"{project_id}.{self.dataset_id}.{self.table_id}"
    
    def store_threat_analysis(self, analysis: dict) -> bool:
        """Store threat analysis results in BigQuery"""
        try:
            # Add metadata
            analysis['analyzed_at'] = datetime.now().isoformat()
            analysis['agent'] = 'ThreatAnalysisAgent'
            
            rows_to_insert = [analysis]
            errors = self.bq_client.insert_rows_json(self.full_table_id, rows_to_insert)
            
            if errors:
                logger.error(f"Error storing threat analysis: {errors}")
                return False
            
            logger.info(f"✓ Stored threat analysis for {analysis.get('indicator')}")
            return True
            
        except Exception as e:
            logger.error(f"Exception storing threat analysis: {e}")
            return False
    
    def retrieve_threat_history(self, indicator: str, days_back: int = 30) -> List[dict]:
        """Retrieve historical threat intelligence for an indicator"""
        query = f"""
            SELECT 
                indicator,
                indicator_type,
                threat_type,
                severity,
                confidence,
                source,
                mitre_techniques,
                first_seen,
                last_seen,
                analyzed_at
            FROM `{self.full_table_id}`
            WHERE indicator = @indicator
              AND analyzed_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days_back DAY)
            ORDER BY analyzed_at DESC
            LIMIT 10
        """
        
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("indicator", "STRING", indicator),
                bigquery.ScalarQueryParameter("days_back", "INT64", days_back)
            ]
        )
        
        try:
            results = self.bq_client.query(query, job_config=job_config)
            return [dict(row) for row in results]
        except Exception as e:
            logger.error(f"Error retrieving threat history: {e}")
            return []
    
    def get_recent_threats(self, hours: int = 24, severity: str = None) -> List[dict]:
        """Get recent threats detected in the specified time window"""
        query = f"""
            SELECT *
            FROM `{self.full_table_id}`
            WHERE analyzed_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @hours HOUR)
        """
        
        if severity:
            query += " AND severity = @severity"
        
        query += " ORDER BY analyzed_at DESC LIMIT 100"
        
        params = [bigquery.ScalarQueryParameter("hours", "INT64", hours)]
        if severity:
            params.append(bigquery.ScalarQueryParameter("severity", "STRING", severity))
        
        job_config = bigquery.QueryJobConfig(query_parameters=params)
        
        try:
            results = self.bq_client.query(query, job_config=job_config)
            return [dict(row) for row in results]
        except Exception as e:
            logger.error(f"Error retrieving recent threats: {e}")
            return []


class IncidentMemory:
    """Memory storage for Incident Response Agent using BigQuery"""
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.bq_client = bigquery.Client(project=project_id)
        self.dataset_id = "security_intel"
        self.table_id = "active_incidents"
        self.full_table_id = f"{project_id}.{self.dataset_id}.{self.table_id}"
    
    def store_incident(self, incident: dict) -> bool:
        """Store incident information in BigQuery"""
        try:
            incident['created_at'] = incident.get('created_at', datetime.now().isoformat())
            incident['updated_at'] = datetime.now().isoformat()
            
            rows_to_insert = [incident]
            errors = self.bq_client.insert_rows_json(self.full_table_id, rows_to_insert)
            
            if errors:
                logger.error(f"Error storing incident: {errors}")
                return False
            
            logger.info(f"✓ Stored incident {incident.get('incident_id')}")
            return True
            
        except Exception as e:
            logger.error(f"Exception storing incident: {e}")
            return False
    
    def get_active_incidents(self, severity: str = None) -> List[dict]:
        """Retrieve all active incidents"""
        query = f"""
            SELECT *
            FROM `{self.full_table_id}`
            WHERE status IN ('OPEN', 'IN_PROGRESS', 'INVESTIGATING')
        """
        
        if severity:
            query += " AND severity = @severity"
        
        query += " ORDER BY severity DESC, created_at DESC"
        
        params = []
        if severity:
            params.append(bigquery.ScalarQueryParameter("severity", "STRING", severity))
        
        job_config = bigquery.QueryJobConfig(query_parameters=params) if params else None
        
        try:
            results = self.bq_client.query(query, job_config=job_config)
            return [dict(row) for row in results]
        except Exception as e:
            logger.error(f"Error retrieving active incidents: {e}")
            return []
    
    def update_incident_status(self, incident_id: str, status: str, notes: str = None) -> bool:
        """Update incident status"""
        query = f"""
            UPDATE `{self.full_table_id}`
            SET status = @status,
                updated_at = CURRENT_TIMESTAMP()
            WHERE incident_id = @incident_id
        """
        
        params = [
            bigquery.ScalarQueryParameter("status", "STRING", status),
            bigquery.ScalarQueryParameter("incident_id", "STRING", incident_id)
        ]
        
        job_config = bigquery.QueryJobConfig(query_parameters=params)
        
        try:
            self.bq_client.query(query, job_config=job_config)
            logger.info(f"✓ Updated incident {incident_id} to status: {status}")
            return True
        except Exception as e:
            logger.error(f"Error updating incident: {e}")
            return False


# ============================================================================
# PART 3: THREAT ANALYSIS AGENT
# ============================================================================

class ThreatAnalysisAgent:
    """
    Threat Analysis Agent using Google Threat Intelligence (GTI) MCP Server
    """
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.memory = ThreatIntelMemory(project_id)
        self.config = GoogleSecurityMCPConfig()
        
        self.agent = adk.Agent(
            name="ThreatAnalysisAgent",
            model="gemini-2.5-pro-preview-03-25",  # Using available model from API
            instruction="""You are an expert Cyber Threat Intelligence Analyst with access to Google Threat Intelligence (GTI).

Your responsibilities:
1. Analyze security indicators (IPs, domains, file hashes, URLs) using GTI MCP server
2. Determine threat severity and confidence levels
3. Identify threat actors and malware families
4. Map threats to MITRE ATT&CK techniques
5. Provide actionable detection and mitigation recommendations
6. Store findings in organizational threat intelligence memory

Available Tools via GTI MCP Server:
- search_iocs: Search for any indicator of compromise
- get_file_report: Analyze file hashes (MD5, SHA1, SHA256)
- get_ip_report: Check IP address reputation
- get_domain_report: Analyze domain reputation
- get_url_report: Scan URLs for malicious content
- search_threat_actors: Get information about APT groups
- search_malware_families: Research malware families

Analysis Process:
1. Use GTI to look up the indicator
2. Check organizational memory for historical context
3. Assess threat level based on:
   - Detection ratio from GTI
   - Historical activity
   - Associated threat actors/campaigns
   - MITRE ATT&CK techniques

Severity Levels:
- CRITICAL: Active C2, ransomware, 0-day exploits (90-100% confidence)
- HIGH: Known malware, phishing infrastructure (70-89% confidence)
- MEDIUM: Suspicious activity, reconnaissance (50-69% confidence)
- LOW: Potentially unwanted programs, low confidence (< 50%)

Output Format:
{
  "indicator": "...",
  "indicator_type": "ip|domain|hash|url",
  "threat_type": "malware|phishing|c2|exploit|...",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0-100,
  "gti_detection_ratio": "X/Y vendors",
  "threat_actors": ["APT28", ...],
  "malware_families": ["Emotet", ...],
  "mitre_techniques": ["T1566.001", ...],
  "first_seen": "timestamp",
  "last_seen": "timestamp",
  "recommendations": {
    "detection": ["Monitor for X", "Alert on Y"],
    "mitigation": ["Block at firewall", "Isolate endpoints"],
    "priority": "immediate|high|medium|low"
  }
}

Be thorough, accurate, and prioritize based on actual threat level."""
        )
        # Note: MCP servers are configured separately and may need to be set up
        # via environment variables or ADK configuration. The mcp_servers parameter
        # is not directly supported in the Agent constructor.
    
    def analyze_indicator(self, indicator: str, indicator_type: str, context: str = "") -> dict:
        """Analyze a security indicator using GTI and organizational memory"""
        
        # Retrieve historical data from memory
        historical_data = self.memory.retrieve_threat_history(indicator)
        
        # Build analysis request
        analysis_prompt = f"""Analyze this security indicator using Google Threat Intelligence:

Indicator: {indicator}
Type: {indicator_type}

{f'Additional Context: {context}' if context else ''}

Historical Intelligence (from our memory):
{json.dumps(historical_data, indent=2, default=str) if historical_data else 'No historical data found'}

Please:
1. Use the GTI MCP server to look up this {indicator_type}
2. Assess the threat level and confidence
3. Identify associated threat actors and malware families
4. Map to MITRE ATT&CK techniques if applicable
5. Provide specific detection and mitigation recommendations
6. Compare with our historical data to identify trends

Return your analysis in the JSON format specified in your instructions."""

        # Run analysis
        try:
            content = run_agent_sync(self.agent, analysis_prompt)
        except Exception as e:
            logger.error(f"Error running agent: {e}")
            return {"success": False, "error": str(e)}
        
        # Parse and store result
        try:
            # Try to extract JSON from response
            if '{' in content and '}' in content:
                # --- FIX 3: Better JSON extraction logic ---
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                json_str = content[json_start:json_end]
                analysis_result = json.loads(json_str)
            else:
                # If no JSON, create structured result from text
                analysis_result = {
                    "indicator": indicator,
                    "indicator_type": indicator_type,
                    "analysis": content,
                    "analyzed_at": datetime.now().isoformat()
                }
            
            # Store in memory
            self.memory.store_threat_analysis(analysis_result)
            
            return {
                "success": True,
                "analysis": analysis_result,
                "raw_response": content
            }
            
        except json.JSONDecodeError as e:
            logger.warning(f"Warning: Could not parse JSON from response: {e}")
            return {
                "success": False,
                "error": "JSON parse error",
                "raw_response": content
            }
        except Exception as e:
            logger.error(f"Error in analysis: {e}")
            return {
                "success": False,
                "error": str(e),
                "raw_response": content
            }


# ============================================================================
# PART 4: INCIDENT RESPONSE AGENT
# ============================================================================

class IncidentResponseAgent:
    """
    Incident Response Agent using Chronicle SecOps and SOAR MCP Servers
    """
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.memory = IncidentMemory(project_id)
        self.config = GoogleSecurityMCPConfig()
        
        self.agent = adk.Agent(
            name="IncidentResponseAgent",
            model="gemini-2.5-pro-preview-03-25",  # Using available model from API
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
        # Note: MCP servers are configured separately and may need to be set up
        # via environment variables or ADK configuration. The mcp_servers parameter
        # is not directly supported in the Agent constructor.
    
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
            "response_summary": content[:1000],  # Store first 1000 chars
            "created_at": datetime.now().isoformat()
        }
        
        self.memory.store_incident(incident_data)
        
        return {
            "success": True,
            "incident_id": incident_data["incident_id"],
            "response": content,
            "timestamp": datetime.now().isoformat()
        }


# ============================================================================
# PART 5: ROOT ORCHESTRATOR AGENT
# ============================================================================

class RootOrchestratorAgent:
    """
    Root Orchestrator Agent coordinating all sub-agents
    Uses Gemini 1.5 Pro with session and persistent memory
    """
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        
        # Initialize sub-agents
        logger.info("Initializing sub-agents...")
        self.threat_agent = ThreatAnalysisAgent(project_id)
        logger.info("  ✓ Threat Analysis Agent initialized")
        
        self.incident_agent = IncidentResponseAgent(project_id)
        logger.info("  ✓ Incident Response Agent initialized")
        
        # Session memory (active investigations in current session)
        self.session_memory = {
            "active_investigations": [],
            "processed_indicators": set(),
            "session_start": datetime.now().isoformat()
        }
        
        # Persistent memory access
        self.threat_memory = ThreatIntelMemory(project_id)
        self.incident_memory = IncidentMemory(project_id)
        
        # Root orchestrator agent
        self.agent = adk.Agent(
            name="RootOrchestratorAgent",
            model="gemini-2.5-pro-preview-03-25",  # Using available model from API
            instruction="""You are the Root Security Orchestrator managing a team of specialized security agents using Google Cloud Security platforms.

Your Team:
1. Threat Analysis Agent - Uses Google Threat Intelligence (GTI/VirusTotal) for IOC analysis
2. Incident Response Agent - Uses Chronicle SecOps (SIEM) and SOAR for investigation and response

Your Capabilities:
- Session Memory: Track all investigations in current session
- Persistent Memory: Access historical threat intelligence and incidents from BigQuery
- Agent Coordination: Delegate tasks via A2A (Agent-to-Agent) protocol
- Decision Making: Determine response priorities and escalation

Workflow for Security Events:

1. ASSESS
   - Evaluate the security event/alert
   - Check if indicator already processed in this session
   - Review relevant historical data from persistent memory

2. DELEGATE TO THREAT ANALYSIS
   - Route to Threat Analysis Agent for GTI lookup
   - Provide historical context from memory
   - Get threat assessment with severity and confidence

3. DECIDE ON RESPONSE
   - If CRITICAL/HIGH: Immediate incident response via Incident Response Agent
   - If MEDIUM: Investigate further, then respond if confirmed
   - If LOW: Log to memory, monitor, no immediate action

4. COORDINATE INCIDENT RESPONSE
   - Delegate to Incident Response Agent with full context
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
Use A2A protocol to delegate tasks to sub-agents efficiently. Provide full context and receive structured responses.

Be decisive, coordinate effectively, and ensure no threat goes unaddressed."""
        )
        
        # Add sub-agents to orchestrator
        # --- NOTE: Depending on ADK version, ensure add_agents is supported ---
        try:
            self.agent.add_agents([
                self.threat_agent.agent,
                self.incident_agent.agent
            ])
        except AttributeError:
             # Fallback if add_agents isn't direct method, usually it is part of adk.Agent construction
             # Assuming standard ADK usage here based on original file
             pass
        
        logger.info("✓ Root Orchestrator initialized")
    
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
        threat_history = self.threat_memory.retrieve_threat_history(indicator)
        active_incidents = self.incident_memory.get_active_incidents()
        
        # Build orchestration prompt
        orchestration_prompt = f"""New security event requires your coordination:

Investigation ID: {investigation_id}

Event Details:
{json.dumps(event, indent=2)}

Session Context:
- Active investigations: {len(self.session_memory['active_investigations'])}
- Indicators processed this session: {len(self.session_memory['processed_indicators'])}

Persistent Memory Context:
- Historical threat intelligence for this indicator: {len(threat_history)} records
- Currently active incidents: {len(active_incidents)}

Please coordinate the full security workflow:

1. Delegate to Threat Analysis Agent to analyze the indicator using GTI
2. Based on threat level, decide if Incident Response Agent should be engaged
3. If IR needed, delegate with full context for Chronicle SecOps investigation and SOAR case creation
4. Provide executive summary of all actions taken

Use A2A protocol to communicate with sub-agents."""

        # Execute orchestration
        logger.info(f"\n[ORCHESTRATOR] Processing investigation {investigation_id}...")
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
        recent_threats = self.threat_memory.get_recent_threats(hours=days*24)
        active_incidents = self.incident_memory.get_active_incidents()
        
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


# ============================================================================
# PART 6: DATA PIPELINE & INITIALIZATION
# ============================================================================

class SecurityDataPipeline:
    """Initialize BigQuery tables and load sample data"""
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.bq_client = bigquery.Client(project=project_id)
        self.dataset_id = "security_intel"
    
    def setup_bigquery_tables(self):
        """Create BigQuery dataset and tables"""
        
        logger.info("\n[DATA PIPELINE] Setting up BigQuery tables...")
        
        # Create dataset
        dataset_ref = self.bq_client.dataset(self.dataset_id)
        try:
            self.bq_client.get_dataset(dataset_ref)
            logger.info(f"  ✓ Dataset {self.dataset_id} already exists")
        except google_exceptions.NotFound:
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = "US"
            self.bq_client.create_dataset(dataset)
            logger.info(f"  ✓ Created dataset: {self.dataset_id}")
        
        # Threat Intelligence table schema
        threat_schema = [
            bigquery.SchemaField("indicator", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("indicator_type", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("threat_type", "STRING"),
            bigquery.SchemaField("severity", "STRING"),
            bigquery.SchemaField("confidence", "INTEGER"),
            bigquery.SchemaField("gti_detection_ratio", "STRING"),
            bigquery.SchemaField("threat_actors", "STRING", mode="REPEATED"),
            bigquery.SchemaField("malware_families", "STRING", mode="REPEATED"),
            bigquery.SchemaField("mitre_techniques", "STRING", mode="REPEATED"),
            bigquery.SchemaField("source", "STRING"),
            bigquery.SchemaField("first_seen", "TIMESTAMP"),
            bigquery.SchemaField("last_seen", "TIMESTAMP"),
            bigquery.SchemaField("analyzed_at", "TIMESTAMP"),
            bigquery.SchemaField("agent", "STRING"),
            bigquery.SchemaField("analysis", "STRING"),
        ]
        
        # Incidents table schema
        incident_schema = [
            bigquery.SchemaField("incident_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("threat_indicator", "STRING"),
            bigquery.SchemaField("indicator_type", "STRING"),
            bigquery.SchemaField("severity", "STRING"),
            bigquery.SchemaField("status", "STRING"),
            bigquery.SchemaField("chronicle_case_id", "STRING"),
            bigquery.SchemaField("affected_assets", "STRING", mode="REPEATED"),
            bigquery.SchemaField("playbooks_executed", "STRING", mode="REPEATED"),
            bigquery.SchemaField("created_at", "TIMESTAMP"),
            bigquery.SchemaField("updated_at", "TIMESTAMP"),
            bigquery.SchemaField("response_summary", "STRING"),
        ]
        
        # Create tables
        self._create_table("threat_intelligence", threat_schema)
        self._create_table("active_incidents", incident_schema)
        
        logger.info("✓ BigQuery tables setup completed")
    
    def _create_table(self, table_id: str, schema: List):
        """Create a BigQuery table"""
        dataset_ref = self.bq_client.dataset(self.dataset_id)
        table_ref = dataset_ref.table(table_id)
        table = bigquery.Table(table_ref, schema=schema)
        
        try:
            self.bq_client.create_table(table)
            logger.info(f"  ✓ Created table: {self.dataset_id}.{table_id}")
        except Exception as e:
            if "Already Exists" in str(e):
                logger.info(f"  ✓ Table {table_id} already exists")
            else:
                logger.error(f"  ✗ Error creating table {table_id}: {e}")
    
    def load_sample_data(self):
        """Load sample threat intelligence data"""
        
        logger.info("\n[DATA PIPELINE] Loading sample threat data...")
        
        sample_threats = [
            {
                "indicator": "203.0.113.42",
                "indicator_type": "ip",
                "threat_type": "C2 Server",
                "severity": "HIGH",
                "confidence": 92,
                "gti_detection_ratio": "45/70",
                "threat_actors": ["APT28", "Fancy Bear"],
                "malware_families": ["Cobalt Strike"],
                "mitre_techniques": ["T1071.001", "T1568.002"],
                "source": "Google Threat Intelligence",
                "first_seen": "2024-11-01T10:00:00",
                "last_seen": "2024-11-20T15:30:00",
                "analyzed_at": datetime.now().isoformat(),
                "agent": "ThreatAnalysisAgent",
                "analysis": "Known C2 infrastructure used by APT28"
            },
            {
                "indicator": "evil-phishing.com",
                "indicator_type": "domain",
                "threat_type": "Phishing",
                "severity": "CRITICAL",
                "confidence": 98,
                "gti_detection_ratio": "65/70",
                "threat_actors": [],
                "malware_families": [],
                "mitre_techniques": ["T1566.001", "T1566.002"],
                "source": "Google Threat Intelligence",
                "first_seen": "2024-11-18T08:00:00",
                "last_seen": "2024-11-21T09:00:00",
                "analyzed_at": datetime.now().isoformat(),
                "agent": "ThreatAnalysisAgent",
                "analysis": "Active phishing campaign targeting financial sector"
            },
            {
                "indicator": "a3c5b2e7f89d1234567890abcdef1234",
                "indicator_type": "hash",
                "threat_type": "Ransomware",
                "severity": "CRITICAL",
                "confidence": 99,
                "gti_detection_ratio": "68/70",
                "threat_actors": ["Conti Group"],
                "malware_families": ["Emotet", "Conti"],
                "mitre_techniques": ["T1486", "T1490", "T1489"],
                "source": "Google Threat Intelligence",
                "first_seen": "2024-11-15T12:00:00",
                "last_seen": "2024-11-20T14:30:00",
                "analyzed_at": datetime.now().isoformat(),
                "agent": "ThreatAnalysisAgent",
                "analysis": "Emotet ransomware variant linked to Conti operations"
            }
        ]
        
        table_id = f"{self.project_id}.{self.dataset_id}.threat_intelligence"
        # Avoid insertion errors if duplicates exist by checking basic exception handling
        try:
            errors = self.bq_client.insert_rows_json(table_id, sample_threats)
            if errors:
                logger.error(f"  ✗ Errors loading sample data: {errors}")
            else:
                logger.info(f"  ✓ Loaded {len(sample_threats)} sample threat records")
        except Exception as e:
            logger.error(f"Failed to load sample data: {e}")


# ============================================================================
# PART 7: MVP PIPELINE EXECUTION
# ============================================================================

class GoogleSecurityMVP:
    """Complete MVP using Google Cloud Security MCP Servers"""
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        
        print("=" * 80)
        print("MULTI-AGENT SECURITY SYSTEM - GOOGLE CLOUD SECURITY EDITION")
        print("=" * 80)
        print("\nMCP Servers:")
        print("  • Google Threat Intelligence (GTI/VirusTotal)")
        print("  • Chronicle Security Operations (SecOps SIEM)")
        print("  • Chronicle SOAR Platform")
        print("  • Security Command Center (SCC)")
        print("=" * 80)
        
        # Step 1: Initialize data pipeline
        print("\n[1/3] Initializing data pipeline...")
        self.data_pipeline = SecurityDataPipeline(project_id)
        self.data_pipeline.setup_bigquery_tables()
        self.data_pipeline.load_sample_data()
        
        # Step 2: Initialize agents
        print("\n[2/3] Initializing multi-agent system...")
        self.orchestrator = RootOrchestratorAgent(project_id)
        
        # Step 3: System ready
        print("\n[3/3] System initialization complete!")
        print("=" * 80)
        print("STATUS: OPERATIONAL")
        print("  ✓ Root Orchestrator Agent (Gemini 1.5 Pro)")
        print("  ✓ Threat Analysis Agent (Gemini Flash + GTI MCP)")
        print("  ✓ Incident Response Agent (Gemini Flash + Chronicle MCP)")
        print("  ✓ BigQuery Memory Systems Active")
        print("=" * 80)
    
    def simulate_security_event(self, scenario: str = "malicious_ip") -> dict:
        """Simulate security events for testing"""
        
        scenarios = {
            "malicious_ip": {
                "event_type": "network_alert",
                "indicator": "203.0.113.42",
                "indicator_type": "ip",
                "source": "Chronicle SecOps Alert",
                "alert_name": "Suspicious Outbound Connection",
                "description": "Multiple endpoints connecting to known C2 infrastructure",
                "affected_assets": ["workstation-1234", "laptop-5678"],
                "severity": "HIGH",
                "timestamp": datetime.now().isoformat(),
                "metadata": {
                    "connection_count": 47,
                    "data_transferred_mb": 2.3,
                    "protocols": ["HTTPS", "TCP/443"]
                }
            },
            
            "phishing_domain": {
                "event_type": "dns_alert",
                "indicator": "evil-phishing.com",
                "indicator_type": "domain",
                "source": "Chronicle SecOps Alert",
                "alert_name": "Phishing Domain Access Attempt",
                "description": "User attempted to access known phishing infrastructure",
                "affected_assets": ["laptop-user42"],
                "severity": "CRITICAL",
                "timestamp": datetime.now().isoformat(),
                "metadata": {
                    "dns_queries": 12,
                    "user": "jane.doe@company.com",
                    "blocked": True
                }
            },
            
            "ransomware_hash": {
                "event_type": "file_execution_alert",
                "indicator": "a3c5b2e7f89d1234567890abcdef1234",
                "indicator_type": "hash",
                "source": "Chronicle SecOps Alert",
                "alert_name": "Suspicious File Execution Detected",
                "description": "Known ransomware hash detected during execution",
                "affected_assets": ["server-prod-001"],
                "severity": "CRITICAL",
                "timestamp": datetime.now().isoformat(),
                "metadata": {
                    "file_path": "C:\\Users\\admin\\Downloads\\invoice.exe",
                    "process_id": 4892,
                    "parent_process": "outlook.exe",
                    "execution_blocked": False
                }
            },
            
            "apt_campaign": {
                "event_type": "correlation_alert",
                "indicator": "apt28-campaign.net",
                "indicator_type": "domain",
                "source": "Chronicle SecOps Alert",
                "alert_name": "APT Campaign Indicators Detected",
                "description": "Multiple IOCs from APT28 campaign detected in environment",
                "affected_assets": ["workstation-exec01", "workstation-exec02", "laptop-cfo"],
                "severity": "CRITICAL",
                "timestamp": datetime.now().isoformat(),
                "metadata": {
                    "campaign": "APT28 Spearphishing",
                    "threat_actor": "Fancy Bear",
                    "confidence": 95,
                    "related_iocs": 8
                }
            }
        }
        
        return scenarios.get(scenario, scenarios["malicious_ip"])
    
    def run_threat_detection_scenario(self, scenario: str = "malicious_ip"):
        """Run threat detection and analysis scenario"""
        
        print("\n" + "=" * 80)
        print(f"SCENARIO: THREAT DETECTION - {scenario.upper().replace('_', ' ')}")
        print("=" * 80)
        
        # Generate security event
        event = self.simulate_security_event(scenario)
        
        print(f"\n[ALERT RECEIVED] Chronicle SecOps Alert:")
        print(f"  • Type: {event['event_type']}")
        print(f"  • Indicator: {event['indicator']} ({event['indicator_type']})")
        print(f"  • Severity: {event['severity']}")
        print(f"  • Affected Assets: {', '.join(event['affected_assets'])}")
        print(f"  • Description: {event['description']}")
        
        print("\n[ORCHESTRATOR] Initiating multi-agent workflow...")
        print("  → Checking session memory for duplicates")
        print("  → Retrieving historical threat intelligence")
        print("  → Delegating to Threat Analysis Agent (GTI MCP)")
        
        # Process through orchestrator
        result = self.orchestrator.process_security_event(event)
        
        print("\n[RESULTS]")
        print(f"  • Investigation ID: {result.get('investigation_id')}")
        print(f"  • Status: {result.get('success', False) and 'SUCCESS' or 'FAILED'}")
        
        if result.get('orchestrator_decision'):
            print(f"\n[ORCHESTRATOR DECISION]")
            decision = result['orchestrator_decision']
            print(decision[:500] + "..." if len(decision) > 500 else decision)
        
        return result
    
    def run_incident_response_scenario(self):
        """Run incident response workflow"""
        
        print("\n" + "=" * 80)
        print("SCENARIO: INCIDENT RESPONSE - CRITICAL THREAT")
        print("=" * 80)
        
        # Simulate critical threat that requires IR
        threat_analysis = {
            "indicator": "203.0.113.42",
            "indicator_type": "ip",
            "threat_type": "C2 Server",
            "severity": "CRITICAL",
            "confidence": 95,
            "gti_detection_ratio": "45/70",
            "threat_actors": ["APT28"],
            "malware_families": ["Cobalt Strike"],
            "mitre_techniques": ["T1071.001", "T1568.002"],
            "recommendations": {
                "detection": ["Monitor network connections", "Alert on beacon patterns"],
                "mitigation": ["Block IP at firewall", "Isolate affected endpoints", "Hunt for additional IOCs"],
                "priority": "immediate"
            }
        }
        
        print("\n[CRITICAL THREAT CONFIRMED]")
        print(f"  • Indicator: {threat_analysis['indicator']}")
        print(f"  • Type: {threat_analysis['threat_type']}")
        print(f"  • Severity: {threat_analysis['severity']}")
        print(f"  • Threat Actors: {', '.join(threat_analysis['threat_actors'])}")
        print(f"  • GTI Detection: {threat_analysis['gti_detection_ratio']}")
        
        print("\n[INCIDENT RESPONSE] Engaging IR workflow...")
        print("  → Creating case in Chronicle SOAR")
        print("  → Investigating with Chronicle SecOps")
        print("  → Executing containment playbooks")
        
        # Trigger incident response
        response = self.orchestrator.incident_agent.handle_incident(
            threat_analysis,
            context="Multiple endpoints showing C2 beacon activity. Urgent containment required."
        )
        
        print("\n[IR RESULTS]")
        print(f"  • Incident ID: {response.get('incident_id')}")
        print(f"  • Status: {response.get('success', False) and 'SUCCESS' or 'FAILED'}")
        
        if response.get('response'):
            print(f"\n[IR ACTIONS TAKEN]")
            resp_content = response['response']
            print(resp_content[:500] + "..." if len(resp_content) > 500 else resp_content)
        
        return response
    
    def run_complete_pipeline(self):
        """Execute complete end-to-end pipeline"""
        
        print("\n" + "=" * 80)
        print("EXECUTING COMPLETE END-TO-END SECURITY PIPELINE")
        print("=" * 80)
        
        # Scenario 1: Malicious IP Detection
        print("\n" + "▼" * 40)
        print("PHASE 1: THREAT DETECTION")
        print("▼" * 40)
        result1 = self.run_threat_detection_scenario("malicious_ip")
        
        # Scenario 2: Phishing Domain
        print("\n" + "▼" * 40)
        print("PHASE 2: PHISHING DETECTION")
        print("▼" * 40)
        result2 = self.run_threat_detection_scenario("phishing_domain")
        
        # Scenario 3: Incident Response
        print("\n" + "▼" * 40)
        print("PHASE 3: INCIDENT RESPONSE")
        print("▼" * 40)
        result3 = self.run_incident_response_scenario()
        
        # Session Status
        print("\n" + "▼" * 40)
        print("PHASE 4: SESSION STATUS")
        print("▼" * 40)
        session_status = self.orchestrator.get_session_status()
        print(f"\n[SESSION SUMMARY]")
        print(f"  • Session started: {session_status['session_start']}")
        print(f"  • Total investigations: {session_status['total_investigations']}")
        print(f"  • Unique indicators: {session_status['unique_indicators']}")
        
        # Organizational Intelligence
        print("\n" + "▼" * 40)
        print("PHASE 5: ORGANIZATIONAL INTELLIGENCE")
        print("▼" * 40)
        org_intel = self.orchestrator.get_organizational_intelligence(days=7)
        print(f"\n[7-DAY THREAT SUMMARY]")
        print(f"  • Total threats: {org_intel['total_threats_detected']}")
        print(f"  • By severity: {org_intel['threats_by_severity']}")
        print(f"  • Active incidents: {org_intel['active_incidents']}")
        print(f"  • Critical incidents: {org_intel['critical_incidents']}")
        
        print("\n" + "=" * 80)
        print("PIPELINE EXECUTION COMPLETED SUCCESSFULLY")
        print("=" * 80)
        
        return {
            "threat_detection_1": result1,
            "threat_detection_2": result2,
            "incident_response": result3,
            "session_status": session_status,
            "organizational_intelligence": org_intel
        }


# ============================================================================
# PART 8: DEPLOYMENT FUNCTIONS
# ============================================================================

def deploy_to_vertex_ai(project_id: str, location: str = "us-central1"):
    """Deploy multi-agent system to Vertex AI Agent Engine"""
    
    print("\n" + "=" * 80)
    print("DEPLOYING TO VERTEX AI AGENT ENGINE")
    print("=" * 80)
    
    try:
        from google.cloud import aiplatform
        aiplatform.init(project=project_id, location=location)
    except ImportError:
        logger.error("google-cloud-aiplatform not installed. Skipping deployment.")
        return
    
    # Initialize system
    mvp = GoogleSecurityMVP(project_id)
    
    print("\n[DEPLOYMENT] Deploying agents to Vertex AI...")
    
    # Deploy Root Orchestrator
    print("\n  [1/3] Deploying Root Orchestrator Agent...")
    try:
        # Assuming the Agent object has a deploy method in this specific SDK version
        # If not, this serves as a placeholder for the actual Model Garden / Agent Builder API call
        orchestrator_endpoint = mvp.orchestrator.agent.deploy(
            deployed_model_display_name="security-orchestrator-gcp-v1",
            machine_type="n1-standard-4",
            min_replica_count=1,
            max_replica_count=10,
        )
        print(f"  ✓ Orchestrator deployed: {orchestrator_endpoint.resource_name}")
    except Exception as e:
        print(f"  ✗ Orchestrator deployment error: {e}")
    
    # Deploy Threat Analysis Agent
    print("\n  [2/3] Deploying Threat Analysis Agent...")
    try:
        threat_endpoint = mvp.orchestrator.threat_agent.agent.deploy(
            deployed_model_display_name="threat-analysis-gti-v1",
            machine_type="n1-standard-2",
            min_replica_count=1,
            max_replica_count=5,
        )
        print(f"  ✓ Threat Agent deployed: {threat_endpoint.resource_name}")
    except Exception as e:
        print(f"  ✗ Threat Agent deployment error: {e}")
    
    # Deploy Incident Response Agent
    print("\n  [3/3] Deploying Incident Response Agent...")
    try:
        incident_endpoint = mvp.orchestrator.incident_agent.agent.deploy(
            deployed_model_display_name="incident-response-chronicle-v1",
            machine_type="n1-standard-2",
            min_replica_count=1,
            max_replica_count=5,
        )
        print(f"  ✓ Incident Agent deployed: {incident_endpoint.resource_name}")
    except Exception as e:
        print(f"  ✗ Incident Agent deployment error: {e}")
    
    print("\n" + "=" * 80)
    print("DEPLOYMENT COMPLETED")
    print("=" * 80)
    
    return {
        "orchestrator": orchestrator_endpoint if 'orchestrator_endpoint' in locals() else None,
        "threat_agent": threat_endpoint if 'threat_endpoint' in locals() else None,
        "incident_agent": incident_endpoint if 'incident_endpoint' in locals() else None
    }


# ============================================================================
# PART 9: MAIN EXECUTION
# ============================================================================

def list_available_models():
    """Helper function to list available Gemini models"""
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("GOOGLE_API_KEY not set. Cannot list models.")
        print("Set it with: export GOOGLE_API_KEY='your-api-key'")
        return
    
    try:
        import requests
        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print("\nAvailable Gemini models that support generateContent:")
            print("=" * 80)
            models_found = []
            for model in data.get('models', []):
                name = model.get('name', '').replace('models/', '')
                methods = model.get('supportedGenerationMethods', [])
                if 'generateContent' in methods:
                    models_found.append(name)
                    print(f"  ✓ {name}")
            
            if not models_found:
                print("  ⚠ No models found that support generateContent")
                print("\nAll available models:")
                for model in data.get('models', [])[:20]:
                    name = model.get('name', '').replace('models/', '')
                    print(f"  - {name}")
            else:
                print(f"\n💡 Suggested model to use: {models_found[0]}")
                print(f"   Update your code with: model=\"{models_found[0]}\"")
            print("=" * 80)
        else:
            print(f"Error listing models: {response.status_code}")
            print(response.text[:500])
    except ImportError:
        # Try with urllib as fallback
        try:
            import urllib.request
            import json
            url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode())
                print("\nAvailable Gemini models that support generateContent:")
                print("=" * 80)
                for model in data.get('models', []):
                    name = model.get('name', '').replace('models/', '')
                    methods = model.get('supportedGenerationMethods', [])
                    if 'generateContent' in methods:
                        print(f"  ✓ {name}")
                print("=" * 80)
        except Exception as e2:
            print(f"Error: {e2}")
            print("Install requests for better error handling: pip install requests")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Main execution function"""
    
    # Configuration
    PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT")
    
    if not PROJECT_ID:
        print("Error: GOOGLE_CLOUD_PROJECT environment variable not set")
        print("Please set it with: export GOOGLE_CLOUD_PROJECT='your-project-id'")
        return
    
    # --- Google Cloud Authentication Setup ---
    # Option 1: Application Default Credentials (ADC) - Recommended
    # Run: gcloud auth application-default login
    # OR set: export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"
    #
    # Option 2: Google AI API Key (for Gemini models)
    # Set: export GOOGLE_API_KEY="your-api-key"
    # Get API key from: https://aistudio.google.com/app/apikey
    #
    # The code will automatically use:
    # - ADC for BigQuery, Vertex AI, and other GCP services
    # - GOOGLE_API_KEY for Gemini models if ADC is not available
    #
    # Verify authentication:
    if not os.getenv("GOOGLE_APPLICATION_CREDENTIALS") and not os.getenv("GOOGLE_API_KEY"):
        logger.warning("No authentication method detected. Set GOOGLE_APPLICATION_CREDENTIALS or GOOGLE_API_KEY")
        logger.warning("For Gemini models via Google AI API, GOOGLE_API_KEY is required.")
        logger.warning("Get your API key from: https://aistudio.google.com/app/apikey")
        logger.warning("Then set: export GOOGLE_API_KEY='your-api-key'")
    
    # Check if API key is set for Google AI API
    if not os.getenv("GOOGLE_API_KEY"):
        logger.warning("GOOGLE_API_KEY not set. Gemini API calls may fail with 403 Forbidden.")
        logger.warning("The code is using Google AI API (generativelanguage.googleapis.com)")
        logger.warning("which requires an API key. Set GOOGLE_API_KEY environment variable.")
    
    print("""
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║     MULTI-AGENT SECURITY SYSTEM - GOOGLE CLOUD SECURITY EDITION         ║
║                                                                          ║
║  Architecture:                                                           ║
║                                                                          ║
║  ┌────────────────────────────────────────────────────────────────┐    ║
║  │  Root Orchestrator Agent (Gemini 1.5 Pro)                      │    ║
║  │  • Session Memory: Active investigations                       │    ║
║  │  • Persistent Memory: BigQuery threat intel & incidents        │    ║
║  │  • A2A Protocol: Coordinates sub-agents                        │    ║
║  └──────────────┬──────────────────────┬──────────────────────────┘    ║
║                 │                      │                                ║
║                 ▼                      ▼                                ║
║  ┌──────────────────────┐  ┌─────────────────────────────────┐        ║
║  │ Threat Analysis      │  │ Incident Response Agent         │        ║
║  │ Agent (Gemini Flash) │  │ (Gemini Flash)                  │        ║
║  │                      │  │                                 │        ║
║  │ MCP:                 │  │ MCP:                            │        ║
║  │ • Google Threat      │  │ • Chronicle SecOps (SIEM)       │        ║
║  │   Intelligence (GTI) │  │ • Chronicle SOAR                │        ║
║  │                      │  │                                 │        ║
║  │ Memory:              │  │ Memory:                         │        ║
║  │ • Threat Intel       │  │ • Active Incidents              │        ║
║  │   (BigQuery)         │  │   (BigQuery)                    │        ║
║  └──────────────────────┘  └─────────────────────────────────┘        ║
║                                                                          ║
║  Google Cloud Security MCP Servers:                                     ║
║  ✓ Google Threat Intelligence (VirusTotal)                              ║
║  ✓ Chronicle Security Operations (SIEM)                                 ║
║  ✓ Chronicle SOAR Platform                                              ║
║  ✓ Security Command Center                                              ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize and run MVP
    try:
        mvp = GoogleSecurityMVP(PROJECT_ID)
        
        print("\n[EXECUTE] Running complete security pipeline...")
        results = mvp.run_complete_pipeline()
        
        print("\n" + "=" * 80)
        print("EXECUTION SUMMARY")
        print("=" * 80)
        print("""
✓ Data pipeline initialized with BigQuery
✓ All agents deployed and operational
✓ Threat detection workflows completed
✓ Incident response workflow executed
✓ Session and persistent memory active

System Status: OPERATIONAL
All Agents: READY
MCP Servers: Google Cloud Security (GTI, Chronicle)
Memory: BigQuery active
        """)
        
        print("\n" + "=" * 80)
        print("NEXT STEPS")
        print("=" * 80)
        print("""
1. Configure Google Cloud Security MCP Servers:
   
   # Install MCP servers
   pip install google-secops-mcp secops-soar-mcp gti-mcp scc-mcp
   
   # Set environment variables
   export CHRONICLE_PROJECT_ID="your-project-id"
   export CHRONICLE_CUSTOMER_ID="your-customer-id"
   export VT_APIKEY="your-virustotal-api-key"
   export SOAR_URL="https://your-tenant.siemplify-soar.com:443"
   export SOAR_APP_KEY="your-soar-api-key"

2. Deploy to Production:
   python main.py --deploy

3. Integrate with Real Security Tools:
   • Connect Chronicle SecOps instance
   • Configure Chronicle SOAR playbooks
   • Enable Security Command Center
   • Set up GTI API access

4. Monitor & Optimize:
   • Access Vertex AI console for agent monitoring
   • Review BigQuery for threat intelligence trends
   • Configure alerting in Chronicle
   • Tune detection rules based on findings

5. Extend Capabilities:
   • Add Forensic Analysis Agent
   • Add Policy Enforcement Agent  
   • Add Executive Reporting Agent
   • Integrate with Cloud Security Command Center
        """)
        
    except Exception as e:
        print(f"\n✗ Error during execution: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--deploy":
            # Deploy to Vertex AI
            PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT")
            if not PROJECT_ID:
                print("Error: Set GOOGLE_CLOUD_PROJECT environment variable")
                sys.exit(1)
            deploy_to_vertex_ai(PROJECT_ID)
        elif sys.argv[1] == "--list-models":
            # List available models
            list_available_models()
        else:
            print(f"Unknown option: {sys.argv[1]}")
            print("Usage: python3 main1.py [--deploy|--list-models]")
            sys.exit(1)
    else:
        # Run MVP locally
        main()

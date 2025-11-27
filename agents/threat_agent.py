"""Threat Analysis Agent - Standalone service with A2A protocol support"""

import os
import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv(override=True)  # Loads from .env in current directory or parent directories

from google import adk
from google.adk.agents.invocation_context import InvocationContext
from google.adk.agents.run_config import RunConfig
from google.adk.sessions import InMemorySessionService, Session
import uuid

from shared.memory import ThreatIntelMemory
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
            appName="threat-analysis-agent",
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


class ThreatAnalysisAgent:
    """
    Threat Analysis Agent using Google Threat Intelligence (GTI) MCP Server
    Can run as standalone service with A2A protocol support
    """
    
    def __init__(self, project_id: str, endpoint: Optional[str] = None):
        self.project_id = project_id
        self.memory = ThreatIntelMemory(project_id)
        self.config = GoogleSecurityMCPConfig()
        self.endpoint = endpoint or os.getenv("THREAT_AGENT_ENDPOINT", "http://localhost:8081")
        
        # Initialize ADK agent
        self.agent = adk.Agent(
            name="ThreatAnalysisAgent",
            model="gemini-2.5-pro-preview-03-25",
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
        
        logger.info("✓ Threat Analysis Agent initialized")
    
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
            if '{' in content and '}' in content:
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                json_str = content[json_start:json_end]
                analysis_result = json.loads(json_str)
            else:
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
    
    def start_a2a_server(self, port: int = 8081, register: bool = True):
        """
        Start A2A protocol server for this agent
        
        Args:
            port: Port to run the server on
            register: Whether to register with Vertex AI Agent Registry
        """
        server = A2AServer(agent_name="ThreatAnalysisAgent", port=port)
        
        # Register A2A methods
        server.register_method("analyze_indicator", self.analyze_indicator)
        
        # Register with Vertex AI if requested
        if register:
            registry = VertexAIAgentRegistry(self.project_id)
            registry.register_agent(
                agent_name="ThreatAnalysisAgent",
                endpoint=self.endpoint,
                capabilities=["analyze_indicator", "threat_intelligence", "ioc_analysis"]
            )
            logger.info("Registered ThreatAnalysisAgent with Vertex AI Agent Registry")
        
        # Start server
        logger.info(f"Starting ThreatAnalysisAgent A2A server on port {port}")
        server.run(host='0.0.0.0', debug=False)


if __name__ == "__main__":
    # Run as standalone service
    import sys
    
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("ERROR: GOOGLE_CLOUD_PROJECT environment variable not set")
        sys.exit(1)
    
    port = int(os.getenv("THREAT_AGENT_PORT", "8081"))
    
    agent = ThreatAnalysisAgent(project_id)
    agent.start_a2a_server(port=port, register=True)

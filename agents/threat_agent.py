"""Threat Analysis Agent - Standalone service with A2A protocol support"""

import os
import json
import logging
import asyncio
import requests
from datetime import datetime
from typing import Dict, Any, Optional

from dotenv import load_dotenv
load_dotenv(override=True)

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


# =============================================================================
# VIRUSTOTAL TOOLS - These are the actual tools the agent can call
# =============================================================================

VT_API_KEY = os.getenv("VT_APIKEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _vt_request(endpoint: str) -> Dict:
    """Make a request to VirusTotal API"""
    if not VT_API_KEY or VT_API_KEY.startswith("your-"):
        # Return mock data for demo
        return {"mock": True, "data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}
    
    try:
        response = requests.get(
            f"{VT_BASE_URL}/{endpoint}",
            headers={"x-apikey": VT_API_KEY},
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"VirusTotal API error: {e}")
        return {"error": str(e)}


def _parse_vt_stats(data: Dict, indicator: str, indicator_type: str) -> Dict:
    """Parse VirusTotal response into standard format"""
    if data.get("mock"):
        # Generate mock data based on indicator patterns
        is_malicious = (
            indicator.startswith("203.0.113") or
            "evil" in indicator.lower() or
            "malware" in indicator.lower()
        )
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "severity": "CRITICAL" if is_malicious else "LOW",
            "confidence": 92 if is_malicious else 10,
            "malicious_count": 45 if is_malicious else 0,
            "total_scanners": 70,
            "detection_ratio": "45/70" if is_malicious else "0/70",
            "source": "VirusTotal (MOCK)",
        }
    
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    
    if total > 0:
        ratio = malicious / total
        severity = "CRITICAL" if ratio >= 0.5 else "HIGH" if ratio >= 0.3 else "MEDIUM" if ratio >= 0.1 else "LOW"
        confidence = min(95, int(ratio * 100 + 20))
    else:
        severity = "UNKNOWN"
        confidence = 0
    
    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "severity": severity,
        "confidence": confidence,
        "malicious_count": malicious,
        "total_scanners": total,
        "detection_ratio": f"{malicious}/{total}",
        "source": "VirusTotal",
    }


def get_ip_report(ip_address: str) -> str:
    """
    Check IP address reputation using VirusTotal.
    
    Args:
        ip_address: The IP address to analyze (e.g., "203.0.113.42")
    
    Returns:
        JSON string with severity, confidence, and detection ratio
    """
    logger.info(f"[TOOL] get_ip_report: {ip_address}")
    data = _vt_request(f"ip_addresses/{ip_address}")
    result = _parse_vt_stats(data, ip_address, "ip")
    return json.dumps(result, indent=2)


def get_domain_report(domain: str) -> str:
    """
    Check domain reputation using VirusTotal.
    
    Args:
        domain: The domain to analyze (e.g., "evil-site.com")
    
    Returns:
        JSON string with severity, confidence, and detection ratio
    """
    logger.info(f"[TOOL] get_domain_report: {domain}")
    data = _vt_request(f"domains/{domain}")
    result = _parse_vt_stats(data, domain, "domain")
    return json.dumps(result, indent=2)


def get_hash_report(file_hash: str) -> str:
    """
    Check file hash reputation using VirusTotal.
    
    Args:
        file_hash: The file hash to analyze (MD5, SHA1, or SHA256)
    
    Returns:
        JSON string with severity, confidence, and detection ratio
    """
    logger.info(f"[TOOL] get_hash_report: {file_hash}")
    data = _vt_request(f"files/{file_hash}")
    result = _parse_vt_stats(data, file_hash, "hash")
    return json.dumps(result, indent=2)


def get_url_report(url: str) -> str:
    """
    Check URL reputation using VirusTotal.
    
    Args:
        url: The URL to analyze
    
    Returns:
        JSON string with severity, confidence, and detection ratio
    """
    import base64
    logger.info(f"[TOOL] get_url_report: {url}")
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    data = _vt_request(f"urls/{url_id}")
    result = _parse_vt_stats(data, url, "url")
    return json.dumps(result, indent=2)


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
        try:
            self.memory = ThreatIntelMemory(project_id)
            logger.info("Threat intelligence memory initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize BigQuery memory (will continue without persistence): {e}")
            self.memory = None
        
        self.config = GoogleSecurityMCPConfig()
        self.endpoint = endpoint or os.getenv("THREAT_AGENT_ENDPOINT", "http://localhost:8081")
        
        # Initialize ADK agent with tools
        try:
            self.agent = adk.Agent(
                name="ThreatAnalysisAgent",
                model="gemini-2.0-flash",
                instruction="""You are a Cyber Threat Intelligence Analyst. Your job is to analyze security indicators using the available tools.

WORKFLOW:
1. When given an indicator, use the appropriate tool to check it:
   - IP address → use get_ip_report
   - Domain → use get_domain_report  
   - File hash → use get_hash_report
   - URL → use get_url_report

2. Interpret the results and provide:
   - Severity assessment (CRITICAL/HIGH/MEDIUM/LOW)
   - Confidence level (0-100)
   - Recommended actions

3. Always use the tools first, then analyze the results.

OUTPUT FORMAT:
{
  "indicator": "the indicator analyzed",
  "indicator_type": "ip|domain|hash|url",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0-100,
  "threat_type": "malware|phishing|c2|benign",
  "detection_ratio": "X/Y",
  "recommendations": ["action1", "action2"]
}""",
                tools=[get_ip_report, get_domain_report, get_hash_report, get_url_report]
            )
            logger.info("ADK agent initialized with VirusTotal tools")
        except Exception as e:
            logger.error(f"Failed to initialize ADK agent: {e}", exc_info=True)
            raise
        
        logger.info("✓ Threat Analysis Agent initialized")
    
    def analyze_indicator(self, indicator: str, indicator_type: str, context: str = "") -> dict:
        """Analyze a security indicator using GTI and organizational memory"""
        
        # Retrieve historical data from memory (if available)
        historical_data = []
        if self.memory:
            try:
                historical_data = self.memory.retrieve_threat_history(indicator)
            except Exception as e:
                logger.warning(f"Failed to retrieve historical data: {e}")
        
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
            
            # Store in memory (if available)
            if self.memory:
                try:
                    self.memory.store_threat_analysis(analysis_result)
                except Exception as e:
                    logger.warning(f"Failed to store analysis in memory: {e}")
            
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
        
        # Start server FIRST (so Cloud Run health checks pass)
        logger.info(f"Starting ThreatAnalysisAgent A2A server on port {port}")
        
        # Register with Vertex AI in background (non-blocking)
        if register:
            try:
                registry = VertexAIAgentRegistry(self.project_id)
                registry.register_agent(
                    agent_name="ThreatAnalysisAgent",
                    endpoint=self.endpoint,
                    capabilities=["analyze_indicator", "threat_intelligence", "ioc_analysis"]
                )
                logger.info("Registered ThreatAnalysisAgent with Vertex AI Agent Registry")
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
    
    # Cloud Run sets PORT environment variable, fallback to THREAT_AGENT_PORT for local dev
    port = int(os.getenv("PORT", os.getenv("THREAT_AGENT_PORT", "8081")))
    
    logger.info(f"Starting Threat Analysis Agent for project: {project_id}")
    logger.info(f"Server will listen on port: {port}")
    
    try:
        agent = ThreatAnalysisAgent(project_id)
        logger.info("Threat Analysis Agent initialized successfully")
        agent.start_a2a_server(port=port, register=True)
    except Exception as e:
        logger.error(f"Failed to start Threat Analysis Agent: {e}", exc_info=True)
        print(f"ERROR: Failed to start agent: {e}", file=sys.stderr)
        sys.exit(1)

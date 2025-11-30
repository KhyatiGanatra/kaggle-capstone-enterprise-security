"""Threat Analysis Agent - Using GTI MCP Server for dynamic tool discovery"""

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
from google.adk.tools.mcp_tool import McpToolset, StdioConnectionParams
from mcp.client.stdio import StdioServerParameters
import uuid

from shared.memory.threat_memory import ThreatIntelMemory
from shared.config import GoogleSecurityMCPConfig
from shared.communication.a2a_server import A2AServer
from shared.discovery.vertex_registry import VertexAIAgentRegistry

logger = logging.getLogger(__name__)


# =============================================================================
# MCP TOOLSET CONFIGURATION
# =============================================================================

def create_gti_mcp_toolset() -> Optional[McpToolset]:
    """
    Create an MCP Toolset connected to the GTI (VirusTotal) MCP Server.
    
    The GTI MCP server provides 35+ tools for threat intelligence:
    - File analysis (get_file_report, get_entities_related_to_a_file, etc.)
    - Domain analysis (get_domain_report, get_entities_related_to_a_domain)
    - IP analysis (get_ip_address_report, get_entities_related_to_an_ip_address)
    - URL analysis (get_url_report, get_entities_related_to_an_url)
    - Threat collections (search_threats, search_malware_families, etc.)
    - IoC search (search_iocs)
    - And many more...
    
    Returns:
        McpToolset if VT_APIKEY is available, None otherwise
    """
    vt_api_key = os.getenv("VT_APIKEY", "")
    
    if not vt_api_key or vt_api_key.startswith("your-"):
        logger.warning("VT_APIKEY not set - GTI MCP tools will not be available")
        return None
    
    try:
        connection_params = StdioConnectionParams(
            server_params=StdioServerParameters(
                command='gti_mcp',
                args=[],
                env={
                    'VT_APIKEY': vt_api_key,
                }
            ),
            timeout=30.0  # Allow time for complex queries
        )
        
        toolset = McpToolset(connection_params=connection_params)
        logger.info("✓ GTI MCP Toolset created successfully")
        return toolset
        
    except Exception as e:
        logger.error(f"Failed to create GTI MCP Toolset: {e}")
        return None


async def get_mcp_tools(toolset: McpToolset) -> List:
    """Get tools from MCP toolset asynchronously"""
    try:
        tools = await toolset.get_tools()
        logger.info(f"✓ Discovered {len(tools)} tools from GTI MCP server")
        return tools
    except Exception as e:
        logger.error(f"Failed to get tools from MCP: {e}")
        return []


# =============================================================================
# SYNC HELPER
# =============================================================================

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


# =============================================================================
# THREAT ANALYSIS AGENT
# =============================================================================

class ThreatAnalysisAgent:
    """
    Threat Analysis Agent using Google Threat Intelligence (GTI) MCP Server
    
    This agent dynamically discovers and uses tools from the GTI MCP server,
    which provides comprehensive threat intelligence capabilities via VirusTotal.
    """
    
    def __init__(self, project_id: str, endpoint: Optional[str] = None):
        self.project_id = project_id
        self.mcp_toolset: Optional[McpToolset] = None
        self.tools: List = []
        self.is_live_mode = False  # Track if using real API or demo mode
        
        # Initialize memory (optional)
        try:
            self.memory = ThreatIntelMemory(project_id)
            logger.info("Threat intelligence memory initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize memory (continuing without persistence): {e}")
            self.memory = None
        
        self.config = GoogleSecurityMCPConfig()
        self.endpoint = endpoint or os.getenv("THREAT_AGENT_ENDPOINT", "http://localhost:8081")
        
        # Initialize MCP toolset and agent
        self._initialize_agent()
        
        logger.info("✓ Threat Analysis Agent initialized")
    
    def _initialize_agent(self):
        """Initialize the ADK agent with MCP tools"""
        
        # Create MCP toolset
        self.mcp_toolset = create_gti_mcp_toolset()
        
        if self.mcp_toolset:
            # Get tools from MCP server
            try:
                self.tools = asyncio.run(get_mcp_tools(self.mcp_toolset))
                self.is_live_mode = len(self.tools) > 0
            except Exception as e:
                logger.error(f"Failed to get MCP tools: {e}")
                self.tools = []
                self.is_live_mode = False
        
        # Build tool list string for system prompt
        if self.tools:
            tool_names = [t.name for t in self.tools]
            tools_description = f"""You have access to {len(self.tools)} tools from the GTI MCP server:

KEY TOOLS:
- get_ip_address_report: Analyze IP addresses for threats
- get_domain_report: Analyze domains for threats
- get_file_report: Analyze file hashes (MD5, SHA1, SHA256)
- get_url_report: Analyze URLs for threats
- search_iocs: Search for indicators of compromise
- search_threats: Search threat intelligence database
- search_malware_families: Look up malware families
- search_threat_actors: Look up threat actors

FULL TOOL LIST: {', '.join(tool_names[:20])}{'...' if len(tool_names) > 20 else ''}

DATA SOURCE: VirusTotal (Live API) ✓"""
        else:
            tools_description = """NO TOOLS AVAILABLE - Running in DEMO MODE.
You cannot perform real threat analysis without the GTI MCP tools.
Please ensure VT_APIKEY is set correctly."""
        
        # Build agent instruction
        instruction = f"""You are a Cyber Threat Intelligence Analyst powered by Google Threat Intelligence (GTI).

{tools_description}

WORKFLOW:
1. When given an indicator, identify its type:
   - IP address → use get_ip_address_report
   - Domain → use get_domain_report  
   - File hash (MD5/SHA1/SHA256) → use get_file_report
   - URL → use get_url_report

2. Analyze the results and provide:
   - Severity assessment (CRITICAL/HIGH/MEDIUM/LOW)
   - Confidence level (0-100)
   - Threat type identification
   - Recommended actions

3. For deeper investigation, use related entity tools to find connections.

OUTPUT FORMAT:
{{
  "indicator": "the indicator analyzed",
  "indicator_type": "ip|domain|hash|url",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0-100,
  "threat_type": "malware|phishing|c2|benign|unknown",
  "detection_ratio": "X/Y",
  "source": "VirusTotal (Live)" or "Demo Mode",
  "recommendations": ["action1", "action2"],
  "related_threats": []
}}"""
        
        # Create the agent
        try:
            self.agent = adk.Agent(
                name="ThreatAnalysisAgent",
                model="gemini-2.0-flash",
                instruction=instruction,
                tools=self.tools  # Always pass list (even if empty)
            )
            
            mode = "LIVE (GTI MCP)" if self.is_live_mode else "DEMO (no tools)"
            logger.info(f"ADK agent initialized in {mode} mode with {len(self.tools)} tools")
            
        except Exception as e:
            logger.error(f"Failed to initialize ADK agent: {e}", exc_info=True)
            raise
    
    def get_mode_indicator(self) -> Dict[str, Any]:
        """Return mode indicator for UI display"""
        return {
            "is_live": self.is_live_mode,
            "mode": "Live" if self.is_live_mode else "Demo",
            "source": "VirusTotal GTI" if self.is_live_mode else "Demo Mode",
            "tools_count": len(self.tools),
            "icon": "🟢" if self.is_live_mode else "🟡"
        }
    
    def analyze_indicator(self, indicator: str, indicator_type: str, context: str = "") -> dict:
        """Analyze a security indicator using GTI MCP tools"""
        
        # Check mode
        mode_info = self.get_mode_indicator()
        
        # Retrieve historical data from memory (if available)
        historical_data = []
        if self.memory:
            try:
                historical_data = self.memory.retrieve_threat_history(indicator)
            except Exception as e:
                logger.warning(f"Failed to retrieve historical data: {e}")
        
        # Build analysis request
        analysis_prompt = f"""Analyze this security indicator:

Indicator: {indicator}
Type: {indicator_type}

{f'Additional Context: {context}' if context else ''}

Historical Intelligence:
{json.dumps(historical_data, indent=2, default=str) if historical_data else 'No historical data found'}

Please:
1. Use the appropriate GTI MCP tool to analyze this {indicator_type}
2. Assess the threat level and confidence
3. Identify any associated threats, malware families, or threat actors
4. Provide specific detection and mitigation recommendations

Return your analysis in the JSON format specified in your instructions."""

        # Run analysis
        try:
            content = run_agent_sync(self.agent, analysis_prompt)
        except Exception as e:
            logger.error(f"Error running agent: {e}")
            return {
                "success": False, 
                "error": str(e),
                "mode": mode_info
            }
        
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
            
            # Add mode info
            analysis_result["source"] = mode_info["source"]
            
            # Store in memory (if available)
            if self.memory:
                try:
                    self.memory.store_threat_analysis(analysis_result)
                except Exception as e:
                    logger.warning(f"Failed to store analysis in memory: {e}")
            
            return {
                "success": True,
                "analysis": analysis_result,
                "raw_response": content,
                "mode": mode_info
            }
            
        except json.JSONDecodeError as e:
            logger.warning(f"Warning: Could not parse JSON from response: {e}")
            return {
                "success": False,
                "error": "JSON parse error",
                "raw_response": content,
                "mode": mode_info
            }
        except Exception as e:
            logger.error(f"Error in analysis: {e}")
            return {
                "success": False,
                "error": str(e),
                "raw_response": content,
                "mode": mode_info
            }
    
    async def close(self):
        """Clean up MCP toolset connection"""
        if self.mcp_toolset:
            try:
                await self.mcp_toolset.close()
                logger.info("MCP toolset closed")
            except Exception as e:
                logger.warning(f"Error closing MCP toolset: {e}")
    
    def start_a2a_server(self, port: int = 8081, register: bool = True):
        """Start A2A protocol server for this agent"""
        server = A2AServer(agent_name="ThreatAnalysisAgent", port=port)
        
        # Register A2A methods
        server.register_method("analyze_indicator", self.analyze_indicator)
        server.register_method("get_mode", self.get_mode_indicator)
        
        logger.info(f"Starting ThreatAnalysisAgent A2A server on port {port}")
        
        # Register with Vertex AI in background (non-blocking)
        if register:
            try:
                registry = VertexAIAgentRegistry(self.project_id)
                registry.register_agent(
                    agent_name="ThreatAnalysisAgent",
                    endpoint=self.endpoint,
                    capabilities=["analyze_indicator", "threat_intelligence", "ioc_analysis", "gti_mcp"]
                )
                logger.info("Registered ThreatAnalysisAgent with Vertex AI Agent Registry")
            except Exception as e:
                logger.warning(f"Failed to register with Vertex AI Agent Registry: {e}")
        
        # Start server (this blocks)
        server.run(host='0.0.0.0', debug=False)


if __name__ == "__main__":
    import sys
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        logger.error("ERROR: GOOGLE_CLOUD_PROJECT environment variable not set")
        print("ERROR: GOOGLE_CLOUD_PROJECT environment variable not set", file=sys.stderr)
        sys.exit(1)
    
    port = int(os.getenv("PORT", os.getenv("THREAT_AGENT_PORT", "8081")))
    
    logger.info(f"Starting Threat Analysis Agent for project: {project_id}")
    logger.info(f"Server will listen on port: {port}")
    
    try:
        agent = ThreatAnalysisAgent(project_id)
        
        # Show mode
        mode = agent.get_mode_indicator()
        logger.info(f"Agent Mode: {mode['icon']} {mode['mode']} - {mode['tools_count']} tools available")
        
        agent.start_a2a_server(port=port, register=True)
    except Exception as e:
        logger.error(f"Failed to start Threat Analysis Agent: {e}", exc_info=True)
        print(f"ERROR: Failed to start agent: {e}", file=sys.stderr)
        sys.exit(1)

"""Threat Analysis Agent - Using GTI MCP Server for dynamic tool discovery"""

import os
import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List

from dotenv import load_dotenv
load_dotenv(override=True)

# Fix async event loop conflicts (Streamlit + MCP)
import nest_asyncio
nest_asyncio.apply()

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
    import shutil
    
    vt_api_key = os.getenv("VT_APIKEY", "")
    
    if not vt_api_key or vt_api_key.startswith("your-"):
        logger.warning("VT_APIKEY not set - GTI MCP tools will not be available")
        return None
    
    # Check if gti_mcp CLI is available
    gti_mcp_path = shutil.which('gti_mcp')
    
    # Fallback: check virtual environment bin directory
    if not gti_mcp_path:
        import sys
        venv_bin = os.path.join(os.path.dirname(sys.executable), 'gti_mcp')
        if os.path.exists(venv_bin):
            gti_mcp_path = venv_bin
    
    logger.info(f"gti_mcp binary path: {gti_mcp_path}")
    
    if not gti_mcp_path:
        logger.error("gti_mcp CLI not found in PATH or venv - cannot create MCP toolset")
        return None
    
    try:
        logger.info("Creating MCP connection params...")
        connection_params = StdioConnectionParams(
            server_params=StdioServerParameters(
                command=gti_mcp_path,  # Use full path
                args=[],
                env={
                    'VT_APIKEY': vt_api_key,
                    'PATH': os.environ.get('PATH', ''),
                }
            ),
            timeout=60.0  # Increased timeout for cloud environments
        )
        
        logger.info("Creating McpToolset...")
        toolset = McpToolset(connection_params=connection_params)
        logger.info("✓ GTI MCP Toolset created successfully")
        return toolset
        
    except Exception as e:
        logger.error(f"Failed to create GTI MCP Toolset: {e}", exc_info=True)
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
    """Helper function to run an ADK agent synchronously with tool calling support"""
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
        
        final_text = ""
        tool_results = []
        
        async for event in agent.run_async(context):
            # Log event type for debugging
            event_type = type(event).__name__
            logger.debug(f"Event type: {event_type}")
            
            # Extract text from various event formats
            if hasattr(event, 'content') and event.content:
                content = event.content
                if hasattr(content, 'parts'):
                    for part in content.parts:
                        if hasattr(part, 'text') and part.text:
                            final_text = part.text  # Keep last text response
                        if hasattr(part, 'function_response'):
                            tool_results.append(str(part.function_response))
                elif hasattr(content, 'text'):
                    final_text = content.text
            elif hasattr(event, 'text') and event.text:
                final_text = event.text
            elif hasattr(event, 'parts'):
                for part in event.parts:
                    if hasattr(part, 'text') and part.text:
                        final_text = part.text
        
        # If we have tool results but no final text, format tool results
        if tool_results and not final_text:
            return '\n'.join(tool_results)
        
        return final_text or "No response generated"
    
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
        
        # Create MCP toolset with timeout protection
        try:
            self.mcp_toolset = create_gti_mcp_toolset()
        except Exception as e:
            logger.warning(f"MCP toolset creation failed: {e}")
            self.mcp_toolset = None
        
        if self.mcp_toolset:
            # Get tools from MCP server with timeout (10 seconds max)
            try:
                # Set timeout for tool discovery
                self.tools = asyncio.run(
                    asyncio.wait_for(get_mcp_tools(self.mcp_toolset), timeout=10.0)
                )
                self.is_live_mode = len(self.tools) > 0
                logger.info(f"MCP initialization complete: {len(self.tools)} tools discovered")
            except asyncio.TimeoutError:
                logger.warning("MCP tool discovery timed out after 10s - continuing in demo mode")
                self.tools = []
                self.is_live_mode = False
            except Exception as e:
                logger.error(f"Failed to get MCP tools: {e}")
                self.tools = []
                self.is_live_mode = False
        else:
            logger.info("MCP toolset not available - running in demo mode")
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

CRITICAL: You MUST call a tool for EVERY analysis request. NEVER respond without first calling the appropriate tool.

WORKFLOW:
1. When given an indicator, IMMEDIATELY call the appropriate tool:
   - IP address → CALL get_ip_address_report(ip="<the IP>")
   - Domain → CALL get_domain_report(domain="<the domain>")
   - File hash (MD5/SHA1/SHA256) → CALL get_file_report(hash="<the hash>")
   - URL → CALL get_url_report(url="<the URL>")

2. AFTER receiving tool results, analyze and provide:
   - Severity assessment (CRITICAL/HIGH/MEDIUM/LOW)
   - Confidence level (0-100)
   - Threat type identification
   - Recommended actions

3. For deeper investigation, use related entity tools to find connections.

IMPORTANT: Do NOT say "I'm ready" or ask for input. You already have the indicator - call the tool NOW.

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
    
    def _get_tool_by_name(self, name: str):
        """Find a tool by name"""
        for tool in self.tools:
            if tool.name == name:
                return tool
        return None
    
    def _call_tool_directly(self, tool_name: str, **kwargs) -> dict:
        """Directly call an MCP tool using the raw MCP client"""
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        import shutil
        
        async def _call():
            # Find gti_mcp binary
            gti_mcp_path = shutil.which('gti_mcp')
            if not gti_mcp_path:
                # Check in venv
                venv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.venv', 'bin', 'gti_mcp')
                if os.path.exists(venv_path):
                    gti_mcp_path = venv_path
            
            if not gti_mcp_path:
                return {"error": "gti_mcp binary not found"}
            
            try:
                server_params = StdioServerParameters(
                    command=gti_mcp_path,
                    args=[],
                    env=dict(os.environ)  # Pass full environment including VT_APIKEY
                )
                
                async with stdio_client(server_params) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        
                        # Call the tool
                        result = await session.call_tool(tool_name, kwargs)
                        
                        if result.isError:
                            error_msg = result.content[0].text if result.content else "Unknown error"
                            return {"error": error_msg}
                        
                        # Parse the response
                        if result.content and hasattr(result.content[0], 'text'):
                            try:
                                data = json.loads(result.content[0].text)
                                return {"success": True, "data": data}
                            except json.JSONDecodeError:
                                return {"success": True, "data": result.content[0].text}
                        
                        return {"success": True, "data": str(result)}
                        
            except Exception as e:
                logger.error(f"Tool call failed: {e}")
                return {"error": str(e)}
        
        return asyncio.run(_call())
    
    def _parse_vt_response(self, indicator: str, indicator_type: str, raw_data: dict) -> dict:
        """Parse VirusTotal response into a structured analysis result"""
        
        # Handle nested structure - VT returns data in 'attributes' key
        attributes = raw_data.get('attributes', raw_data)
        
        # Get last analysis stats
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        malicious = last_analysis_stats.get('malicious', 0)
        suspicious = last_analysis_stats.get('suspicious', 0)
        harmless = last_analysis_stats.get('harmless', 0)
        undetected = last_analysis_stats.get('undetected', 0)
        total = malicious + suspicious + harmless + undetected
        
        # Calculate detection ratio
        if total > 0:
            detection_ratio = f"{malicious}/{total}"
            detection_pct = (malicious / total) * 100
        else:
            detection_ratio = "0/0"
            detection_pct = 0
        
        # Determine severity based on detection percentage and reputation
        reputation = attributes.get('reputation', 0)
        
        if malicious >= 10 or detection_pct >= 20:
            severity = "CRITICAL"
            confidence = 95
        elif malicious >= 5 or detection_pct >= 10:
            severity = "HIGH"
            confidence = 85
        elif malicious >= 2 or detection_pct >= 5 or reputation < -50:
            severity = "MEDIUM"
            confidence = 70
        elif malicious >= 1 or suspicious >= 3:
            severity = "LOW"
            confidence = 55
        else:
            severity = "INFO"
            confidence = 40
        
        # Build structured result
        result = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "severity": severity,
            "confidence": confidence,
            "detection_ratio": detection_ratio,
            "reputation": reputation,
            "source": "VirusTotal GTI",
            "analyzed_at": datetime.now().isoformat(),
        }
        
        # Add type-specific fields
        if indicator_type == "ip":
            result["asn"] = attributes.get('asn')
            result["asn_owner"] = attributes.get('as_owner')
            result["country"] = attributes.get('country')
            result["network"] = attributes.get('network')
            result["continent"] = attributes.get('continent')
            
            # Get crowdsourced context if available
            crowdsourced = attributes.get('crowdsourced_context', [])
            if crowdsourced:
                result["threat_context"] = [
                    {
                        "title": ctx.get('title', ''),
                        "severity": ctx.get('severity', ''),
                        "details": ctx.get('details', '')[:200]
                    }
                    for ctx in crowdsourced[:3]  # Top 3
                ]
        
        elif indicator_type == "domain":
            result["registrar"] = attributes.get('registrar')
            result["creation_date"] = attributes.get('creation_date')
            categories = attributes.get('categories', {})
            result["categories"] = list(categories.values()) if categories else []
        
        elif indicator_type == "hash":
            result["file_type"] = attributes.get('type_description')
            result["file_size"] = attributes.get('size')
            result["names"] = attributes.get('names', [])[:5]  # First 5 names
            result["threat_label"] = attributes.get('popular_threat_classification', {}).get('suggested_threat_label')
        
        elif indicator_type == "url":
            result["final_url"] = attributes.get('last_final_url')
            result["title"] = attributes.get('title')
            
        # Add recommendations
        if severity in ["CRITICAL", "HIGH"]:
            result["recommendations"] = [
                "🚨 Immediate block recommended",
                "Investigate all connections to/from this indicator",
                "Check for lateral movement",
                "Collect forensic evidence"
            ]
        elif severity == "MEDIUM":
            result["recommendations"] = [
                "⚠️ Monitor closely",
                "Add to watchlist",
                "Investigate if associated with suspicious activity"
            ]
        else:
            result["recommendations"] = [
                "✅ No immediate action required",
                "Continue monitoring"
            ]
        
        return result
    
    def analyze_indicator(self, indicator: str, indicator_type: str, context: str = "") -> dict:
        """Analyze a security indicator using GTI MCP tools - DIRECT TOOL CALLING"""
        
        mode_info = self.get_mode_indicator()
        
        # Map indicator types to tools (using correct MCP parameter names)
        tool_map = {
            "ip": ("get_ip_address_report", {"ip_address": indicator}),
            "domain": ("get_domain_report", {"domain": indicator}),
            "hash": ("get_file_report", {"hash": indicator}),
            "url": ("get_url_report", {"url": indicator}),
        }
        
        # Determine tool to use
        tool_info = tool_map.get(indicator_type.lower())
        
        if not tool_info and self.is_live_mode:
            # Try to auto-detect type
            if indicator.replace('.', '').isdigit() or ':' in indicator:
                tool_info = tool_map["ip"]
            elif '/' in indicator or indicator.startswith('http'):
                tool_info = tool_map["url"]
            elif len(indicator) in [32, 40, 64] and indicator.isalnum():
                tool_info = tool_map["hash"]
            else:
                tool_info = tool_map["domain"]
        
        # If live mode, call the tool directly
        if self.is_live_mode and tool_info and self.tools:
            tool_name, tool_args = tool_info
            logger.info(f"Calling {tool_name} with {tool_args}")
            
            tool_result = self._call_tool_directly(tool_name, **tool_args)
            
            if tool_result.get("success"):
                raw_data = tool_result.get("data", {})
                
                # Parse VT response
                analysis_result = self._parse_vt_response(indicator, indicator_type, raw_data)
                analysis_result["source"] = "VirusTotal GTI"
                
                return {
                    "success": True,
                    "analysis": analysis_result,
                    "raw_response": str(raw_data)[:1000],
                    "mode": mode_info
                }
            else:
                logger.warning(f"Tool call failed: {tool_result.get('error')}")
        
        # Fallback to demo mode response
        analysis_result = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "severity": "UNKNOWN",
            "confidence": 0,
            "threat_type": "unknown",
            "detection_ratio": "N/A",
            "source": mode_info["source"],
            "analyzed_at": datetime.now().isoformat(),
            "recommendations": ["Analysis unavailable - running in demo mode"]
        }
        
        return {
            "success": True,
            "analysis": analysis_result,
            "raw_response": "",
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

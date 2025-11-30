"""Argus Root Orchestrator Agent - Chat-first interface with sub-agent delegation"""

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

from shared.memory.threat_memory import ThreatIntelMemory
from shared.memory.incident_memory import IncidentMemory
from shared.communication.a2a_client import A2AClient
from shared.communication.a2a_server import A2AServer
from shared.discovery.vertex_registry import VertexAIAgentRegistry

logger = logging.getLogger(__name__)


# =============================================================================
# SYNC HELPER
# =============================================================================

def run_agent_sync(agent, message: str) -> Dict[str, Any]:
    """
    Helper function to run an ADK agent synchronously.
    Returns a dictionary with 'text' (final response) and 'trace' (tool calls).
    """
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
        
        text_parts = []
        trace = []
        
        async for event in agent.run_async(context):
            event_type = type(event).__name__
            
            # Track tool calls
            if hasattr(event, 'tool_code') or hasattr(event, 'function_call'):
                trace.append({
                    "type": "tool_call",
                    "event": event_type,
                    "timestamp": datetime.now().isoformat()
                })
            
            # Extract text from various event types
            # Handle Content objects with parts
            if hasattr(event, 'parts') and event.parts:
                for part in event.parts:
                    # Part has text attribute
                    if hasattr(part, 'text') and part.text:
                        text_parts.append(part.text)
            # Handle direct text attribute
            elif hasattr(event, 'text') and event.text:
                text_parts.append(event.text)
            # Handle string events
            elif isinstance(event, str):
                text_parts.append(event)
            # Handle content that might be a string
            elif hasattr(event, 'content'):
                content = event.content
                if isinstance(content, str):
                    text_parts.append(content)
                elif hasattr(content, 'parts'):
                    for part in content.parts:
                        if hasattr(part, 'text') and part.text:
                            text_parts.append(part.text)
        
        # Join only actual text strings
        final_text = ''.join(text_parts)
        return {"text": final_text, "trace": trace}
    
    try:
        return asyncio.run(_run_async())
    except Exception as e:
        logger.error(f"Error running agent: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {"text": f"Error: {str(e)}", "trace": []}


# =============================================================================
# ROOT ORCHESTRATOR AGENT
# =============================================================================

class RootOrchestratorAgent:
    """
    Root Orchestrator Agent - The central coordinator for security operations.
    
    This agent:
    1. Receives natural language requests via chat()
    2. Delegates to sub-agents (ThreatAnalysis, IncidentResponse) as needed
    3. Returns structured, professional responses
    """
    
    def __init__(self, project_id: str, location: str = "us-central1", 
                 threat_agent=None, incident_agent=None):
        self.project_id = project_id
        self.location = location
        
        # Store pre-initialized agents (if provided)
        self._threat_agent_instance = threat_agent
        self._incident_agent_instance = incident_agent
        
        # Initialize A2A client for communicating with sub-agents
        self.a2a_client = A2AClient(project_id, location)
        
        # Initialize Vertex AI Agent Registry for discovery
        self.registry = VertexAIAgentRegistry(project_id, location)
        
        # Discover sub-agents from registry
        logger.info("Discovering sub-agents...")
        self._discover_sub_agents()
        
        # Session memory
        self.session_memory = {
            "active_investigations": [],
            "processed_indicators": set(),
            "conversation_history": [],
            "session_start": datetime.now().isoformat()
        }
        
        # Persistent memory (optional)
        try:
            self.threat_memory = ThreatIntelMemory(project_id)
            logger.info("Threat intelligence memory initialized")
        except Exception as e:
            logger.warning(f"Memory not available: {e}")
            self.threat_memory = None
        
        try:
            self.incident_memory = IncidentMemory(project_id)
            logger.info("Incident memory initialized")
        except Exception as e:
            logger.warning(f"Memory not available: {e}")
            self.incident_memory = None
        
        # Create delegation tools for the LLM
        self._create_delegation_tools()
        
        # Initialize the root agent with tools
        self.agent = adk.Agent(
            name="RootOrchestratorAgent",
            model="gemini-2.0-flash",
            instruction=self._get_system_prompt(),
            tools=[self.analyze_threat_tool, self.respond_to_incident_tool, self.execute_quick_action_tool]
        )
        
        logger.info("✓ Root Orchestrator Agent initialized")
    
    def _get_system_prompt(self) -> str:
        """Generate the system prompt with mode indicators"""
        return """You are Argus, the Root Security Orchestrator. You MUST use your tools to analyze threats and respond to security requests.

CRITICAL: You MUST call tools to get real data. NEVER make up threat information.

YOUR TOOLS (use them!):
- `analyze_threat(indicator, indicator_type)` - Analyze IPs, domains, hashes, URLs via VirusTotal
- `respond_to_incident(threat_summary, severity, indicator)` - Create incident case and take action
- `execute_quick_action(action, target)` - Execute block_ip, isolate_endpoint, or disable_user

WHEN TO USE EACH TOOL:
- User mentions IP address (like 8.8.8.8) → IMMEDIATELY call `analyze_threat(indicator="8.8.8.8", indicator_type="ip")`
- User mentions domain (like evil.com) → IMMEDIATELY call `analyze_threat(indicator="evil.com", indicator_type="domain")`  
- User mentions file hash → IMMEDIATELY call `analyze_threat(indicator="<hash>", indicator_type="hash")`
- User mentions URL → IMMEDIATELY call `analyze_threat(indicator="<url>", indicator_type="url")`
- User says "block IP X" → call `execute_quick_action(action="block_ip", target="X")`
- User says "isolate host X" → call `execute_quick_action(action="isolate_endpoint", target="X")`

WORKFLOW:
1. IMMEDIATELY call the appropriate tool - don't ask for confirmation
2. Wait for the tool result
3. Format the result using the template below

RESPONSE FORMAT (use after getting tool results):

### 🛡️ Security Assessment

**Status:** [Analysis Complete / Action Taken / Monitoring]  
**Severity:** [CRITICAL/HIGH/MEDIUM/LOW] | **Confidence:** [0-100]%

---

### 📊 Analysis Details

[Detailed findings from threat analysis]

- **Indicator:** `value`
- **Type:** IP/Domain/Hash/URL
- **Detection Ratio:** X/Y engines
- **Threat Type:** malware/phishing/c2/benign

---

### 🛑 Actions Taken

[List of containment actions if any]

1. ✅ Action 1
2. ✅ Action 2

---

### 📋 Recommendations

[Next steps for the security team]

1. Recommendation 1
2. Recommendation 2

---

*Argus Security Platform*

IMPORTANT:
- Always use tools before responding - don't guess at threat data
- Be concise but thorough
- Include specific technical details from tool results
- Mark simulated actions clearly with [SIMULATED]"""
    
    def _create_delegation_tools(self):
        """Create the delegation tools that the LLM can call"""
        
        def analyze_threat(indicator: str, indicator_type: str = "auto") -> str:
            """
            Analyze a security indicator using the Threat Analysis Agent.
            
            Args:
                indicator: The indicator to analyze (IP, domain, hash, or URL)
                indicator_type: Type of indicator (ip, domain, hash, url) or 'auto' to detect
            
            Returns:
                JSON string with threat analysis results
            """
            # Auto-detect indicator type if not specified
            if indicator_type == "auto":
                indicator_type = self._detect_indicator_type(indicator)
            
            logger.info(f"[ROOT] Delegating threat analysis: {indicator} ({indicator_type})")
            result = self._call_threat_agent(indicator, indicator_type)
            return json.dumps(result, indent=2, default=str)
        
        def respond_to_incident(threat_summary: str, severity: str, indicator: str) -> str:
            """
            Create an incident case and execute response actions via the Incident Response Agent.
            
            Args:
                threat_summary: Summary of the threat to respond to
                severity: Threat severity (CRITICAL, HIGH, MEDIUM, LOW)
                indicator: The malicious indicator
            
            Returns:
                JSON string with incident response results
            """
            logger.info(f"[ROOT] Delegating incident response: {severity} threat")
            threat_analysis = {
                "indicator": indicator,
                "severity": severity,
                "summary": threat_summary
            }
            result = self._call_incident_agent(threat_analysis)
            return json.dumps(result, indent=2, default=str)
        
        def execute_quick_action(action: str, target: str) -> str:
            """
            Execute a quick response action immediately.
            
            Args:
                action: The action to execute (block_ip, isolate_endpoint, disable_user)
                target: The target of the action (IP address, hostname, or username)
            
            Returns:
                JSON string with action result
            """
            logger.info(f"[ROOT] Executing quick action: {action} on {target}")
            result = self._call_incident_action(action, target)
            return json.dumps(result, indent=2, default=str)
        
        # Store as instance methods
        self.analyze_threat_tool = analyze_threat
        self.respond_to_incident_tool = respond_to_incident
        self.execute_quick_action_tool = execute_quick_action
    
    def _detect_indicator_type(self, indicator: str) -> str:
        """Auto-detect the type of security indicator"""
        import re
        
        # IP address pattern
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
            return "ip"
        
        # Hash patterns
        if re.match(r'^[a-fA-F0-9]{32}$', indicator):  # MD5
            return "hash"
        if re.match(r'^[a-fA-F0-9]{40}$', indicator):  # SHA1
            return "hash"
        if re.match(r'^[a-fA-F0-9]{64}$', indicator):  # SHA256
            return "hash"
        
        # URL pattern
        if indicator.startswith(('http://', 'https://')):
            return "url"
        
        # Default to domain
        return "domain"
    
    def _discover_sub_agents(self):
        """Discover sub-agents from registry or environment variables"""
        try:
            # Threat Analysis Agent
            threat_agent_info = self.registry.discover_agent("ThreatAnalysisAgent")
            if threat_agent_info:
                self.threat_agent_endpoint = threat_agent_info.get('endpoint')
                logger.info(f"✓ Discovered ThreatAnalysisAgent at {self.threat_agent_endpoint}")
            else:
                self.threat_agent_endpoint = os.getenv("THREAT_AGENT_ENDPOINT")
                if self.threat_agent_endpoint:
                    logger.info(f"✓ Using ThreatAnalysisAgent from env: {self.threat_agent_endpoint}")
                else:
                    logger.warning("⚠ ThreatAnalysisAgent not configured - will use direct instantiation")
            
            # Incident Response Agent
            incident_agent_info = self.registry.discover_agent("IncidentResponseAgent")
            if incident_agent_info:
                self.incident_agent_endpoint = incident_agent_info.get('endpoint')
                logger.info(f"✓ Discovered IncidentResponseAgent at {self.incident_agent_endpoint}")
            else:
                self.incident_agent_endpoint = os.getenv("INCIDENT_AGENT_ENDPOINT")
                if self.incident_agent_endpoint:
                    logger.info(f"✓ Using IncidentResponseAgent from env: {self.incident_agent_endpoint}")
                else:
                    logger.warning("⚠ IncidentResponseAgent not configured - will use direct instantiation")
                
        except Exception as e:
            logger.error(f"Error discovering sub-agents: {e}")
            self.threat_agent_endpoint = os.getenv("THREAT_AGENT_ENDPOINT")
            self.incident_agent_endpoint = os.getenv("INCIDENT_AGENT_ENDPOINT")
    
    def _call_threat_agent(self, indicator: str, indicator_type: str, context: str = "") -> dict:
        """Call Threat Analysis Agent - via A2A, pre-initialized instance, or new instance"""
        
        # Try A2A first (for distributed deployment)
        if self.threat_agent_endpoint:
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
                logger.warning(f"A2A call failed, falling back to direct: {e}")
        
        # Use pre-initialized agent if available (avoids MCP re-initialization)
        if self._threat_agent_instance:
            logger.info("[ROOT] Using pre-initialized ThreatAnalysisAgent")
            try:
                return self._threat_agent_instance.analyze_indicator(indicator, indicator_type, context)
            except Exception as e:
                logger.error(f"Pre-initialized agent failed: {e}")
                return {"success": False, "error": str(e)}
        
        # Last resort: create new instance (not recommended for UI use)
        try:
            logger.warning("[ROOT] Creating new ThreatAnalysisAgent instance (not optimal)")
            from agents.threat_agent import ThreatAnalysisAgent
            agent = ThreatAnalysisAgent(self.project_id)
            return agent.analyze_indicator(indicator, indicator_type, context)
        except Exception as e:
            logger.error(f"Direct instantiation failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _call_incident_agent(self, threat_analysis: dict, context: str = "") -> dict:
        """Call Incident Response Agent - via A2A, pre-initialized instance, or new instance"""
        
        # Try A2A first (for distributed deployment)
        if self.incident_agent_endpoint:
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
                logger.warning(f"A2A call failed, falling back to direct: {e}")
        
        # Use pre-initialized agent if available
        if self._incident_agent_instance:
            logger.info("[ROOT] Using pre-initialized IncidentResponseAgent")
            try:
                return self._incident_agent_instance.handle_incident(threat_analysis, context)
            except Exception as e:
                logger.error(f"Pre-initialized agent failed: {e}")
                return {"success": False, "error": str(e)}
        
        # Last resort: create new instance
        try:
            logger.warning("[ROOT] Creating new IncidentResponseAgent instance")
            from agents.incident_agent import IncidentResponseAgent
            agent = IncidentResponseAgent(self.project_id)
            return agent.handle_incident(threat_analysis, context)
        except Exception as e:
            logger.error(f"Direct instantiation failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _call_incident_action(self, action: str, target: str) -> dict:
        """Execute a single incident response action"""
        
        # Try A2A first
        if self.incident_agent_endpoint:
            try:
                result = self.a2a_client.invoke_agent(
                    agent_name="IncidentResponseAgent",
                    method="execute_action",
                    params={
                        "action": action,
                        "target": target
                    },
                    endpoint=self.incident_agent_endpoint
                )
                return result
            except Exception as e:
                logger.warning(f"A2A call failed, falling back to direct: {e}")
        
        # Use pre-initialized agent if available
        if self._incident_agent_instance:
            try:
                return self._incident_agent_instance.execute_action(action, target)
            except Exception as e:
                logger.error(f"Pre-initialized agent failed: {e}")
                return {"success": False, "error": str(e)}
        
        # Fallback to direct instantiation
        try:
            from agents.incident_agent import IncidentResponseAgent
            agent = IncidentResponseAgent(self.project_id)
            return agent.execute_action(action, target)
        except Exception as e:
            logger.error(f"Direct instantiation failed: {e}")
            return {"success": False, "error": str(e)}
    
    def get_mode_indicator(self) -> Dict[str, Any]:
        """Get mode indicators for all agents"""
        threat_mode = {"is_live": False, "source": "Unknown", "icon": "⚪"}
        incident_mode = {"is_live": False, "source": "Simulated SOAR", "icon": "🟡"}
        
        # Try to get threat agent mode
        try:
            if self.threat_agent_endpoint:
                result = self.a2a_client.invoke_agent(
                    agent_name="ThreatAnalysisAgent",
                    method="get_mode",
                    params={},
                    endpoint=self.threat_agent_endpoint
                )
                if result:
                    threat_mode = result
            else:
                from agents.threat_agent import ThreatAnalysisAgent
                agent = ThreatAnalysisAgent(self.project_id)
                threat_mode = agent.get_mode_indicator()
        except Exception as e:
            logger.warning(f"Could not get threat agent mode: {e}")
        
            return {
            "threat_agent": threat_mode,
            "incident_agent": incident_mode,
            "overall": "🟢 Live" if threat_mode.get("is_live") else "🟡 Demo"
        }
    
    def chat(self, user_message: str) -> Dict[str, Any]:
        """
        Process a natural language message from the user.
        
        Uses explicit routing to delegate to sub-agents based on detected
        indicators and action keywords in the message.
        
        Args:
            user_message: Natural language message from the user
        
        Returns:
            Dictionary with 'text' (structured response) and 'trace' (execution trace)
        """
        import re
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        trace = []
        
        # Store in conversation history
        self.session_memory["conversation_history"].append({
            "role": "user",
            "content": user_message,
            "timestamp": timestamp
        })
        
        # --- STEP 1: Parse user message for indicators and actions ---
        message_lower = user_message.lower()
        
        # Detect action keywords
        is_block_action = any(word in message_lower for word in ['block', 'ban', 'blacklist'])
        is_isolate_action = any(word in message_lower for word in ['isolate', 'quarantine', 'disconnect'])
        is_disable_action = any(word in message_lower for word in ['disable', 'suspend', 'lock', 'revoke'])
        
        # Extract indicators from message
        indicators = self._extract_indicators(user_message)
        
        logger.info(f"[ARGUS] Parsed message: indicators={indicators}, block={is_block_action}, isolate={is_isolate_action}")
        
        # --- STEP 2: Route to appropriate sub-agent ---
        analysis_result = None
        action_result = None
        
        # Handle quick actions first
        if is_block_action and indicators.get('ip'):
            trace.append({"action": "execute_quick_action", "type": "block_ip", "target": indicators['ip']})
            action_result = self._call_incident_action("block_ip", indicators['ip'])
            
        elif is_isolate_action and indicators.get('hostname'):
            trace.append({"action": "execute_quick_action", "type": "isolate_endpoint", "target": indicators['hostname']})
            action_result = self._call_incident_action("isolate_endpoint", indicators['hostname'])
            
        elif is_disable_action and indicators.get('username'):
            trace.append({"action": "execute_quick_action", "type": "disable_user", "target": indicators['username']})
            action_result = self._call_incident_action("disable_user", indicators['username'])
        
        # Analyze indicators if found
        elif indicators:
            # Pick the first indicator found
            if indicators.get('ip'):
                trace.append({"action": "analyze_threat", "type": "ip", "indicator": indicators['ip']})
                analysis_result = self._call_threat_agent(indicators['ip'], 'ip')
            elif indicators.get('domain'):
                trace.append({"action": "analyze_threat", "type": "domain", "indicator": indicators['domain']})
                analysis_result = self._call_threat_agent(indicators['domain'], 'domain')
            elif indicators.get('hash'):
                trace.append({"action": "analyze_threat", "type": "hash", "indicator": indicators['hash']})
                analysis_result = self._call_threat_agent(indicators['hash'], 'hash')
            elif indicators.get('url'):
                trace.append({"action": "analyze_threat", "type": "url", "indicator": indicators['url']})
                analysis_result = self._call_threat_agent(indicators['url'], 'url')
        
        # --- STEP 3: Format response ---
        response_text = self._format_response(user_message, analysis_result, action_result, timestamp)
        
        # Store response
        self.session_memory["conversation_history"].append({
            "role": "assistant",
            "content": response_text,
            "timestamp": datetime.now().isoformat()
        })
        
        return {"text": response_text, "trace": trace}
    
    def _extract_indicators(self, text: str) -> Dict[str, Optional[str]]:
        """Extract security indicators from text"""
        import re
        
        indicators = {
            'ip': None,
            'domain': None,
            'hash': None,
            'url': None,
            'hostname': None,
            'username': None
        }
        
        # IP address pattern
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
        if ip_match:
            indicators['ip'] = ip_match.group(1)
        
        # URL pattern (must check before domain)
        url_match = re.search(r'(https?://[^\s]+)', text)
        if url_match:
            indicators['url'] = url_match.group(1)
        
        # Hash patterns (MD5, SHA1, SHA256)
        hash_match = re.search(r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b', text)
        if hash_match:
            indicators['hash'] = hash_match.group(1)
        
        # Domain pattern (if no URL found)
        if not indicators['url']:
            domain_match = re.search(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b', text)
            if domain_match:
                # Avoid matching common words
                domain = domain_match.group(0)
                if domain.lower() not in ['e.g.', 'i.e.', 'etc.']:
                    indicators['domain'] = domain
        
        # Hostname pattern (for isolate actions)
        hostname_match = re.search(r'\b([A-Z0-9][-A-Z0-9]*[A-Z0-9])\b', text, re.IGNORECASE)
        if hostname_match and not indicators['ip']:
            indicators['hostname'] = hostname_match.group(1)
        
        # Username pattern (for disable actions)
        username_match = re.search(r'\buser[:\s]+([a-zA-Z0-9._-]+)', text, re.IGNORECASE)
        if username_match:
            indicators['username'] = username_match.group(1)
        
        return indicators
    
    def _format_response(self, user_message: str, analysis_result: Optional[dict], 
                         action_result: Optional[dict], timestamp: str) -> str:
        """Format the response based on analysis/action results"""
        
        # If no results, provide a helpful response
        if not analysis_result and not action_result:
            return """### 🛡️ Argus Security Assistant

I couldn't identify a specific security indicator in your message. 

**I can help you with:**
- **Threat Analysis**: "Analyze 8.8.8.8" or "Check evil-domain.com"
- **Quick Actions**: "Block IP 10.0.0.1" or "Isolate host WORKSTATION-01"
- **Incident Response**: "Disable user john.doe"

Please provide an IP address, domain, URL, or file hash to analyze."""
        
        # Format analysis result
        if analysis_result:
            success = analysis_result.get('success', False)
            
            if success:
                analysis = analysis_result.get('analysis', {})
                mode = analysis_result.get('mode', {})
                
                indicator = analysis.get('indicator', 'Unknown')
                indicator_type = analysis.get('indicator_type', 'unknown')
                severity = analysis.get('severity', 'UNKNOWN')
                confidence = analysis.get('confidence', 'N/A')
                detection_ratio = analysis.get('detection_ratio', 'N/A')
                threat_type = analysis.get('threat_type', 'unknown')
                source = mode.get('source', analysis.get('source', 'Unknown'))
                
                # Severity emoji
                sev_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
                
                return f"""### 🛡️ Threat Assessment

**Status:** Analysis Complete  
**Severity:** {sev_emoji} {severity} | **Confidence:** {confidence}%

---

### 📊 Analysis Details

- **Indicator:** `{indicator}`
- **Type:** {indicator_type.upper()}
- **Detection Ratio:** {detection_ratio}
- **Threat Type:** {threat_type}
- **Source:** {source}

---

### 📋 Recommendations

{"⚠️ **Immediate Action Required** - Consider blocking this indicator and investigating affected systems." if severity in ['CRITICAL', 'HIGH'] else "✅ No immediate action required. Continue monitoring."}

---

*Argus Security Platform | {timestamp}*"""
            else:
                error = analysis_result.get('error', 'Unknown error')
                return f"""### ⚠️ Analysis Error

Unable to complete threat analysis.

**Error:** {error}

Please try again or check your API configuration.

*Argus Security Platform | {timestamp}*"""
        
        # Format action result
        if action_result:
            success = action_result.get('success', False)
            
            if success:
                result = action_result.get('result', {})
                action = result.get('action', 'unknown')
                message = result.get('message', 'Action completed')
                mode = action_result.get('mode', {})
                source = mode.get('source', 'Unknown')
                
                return f"""### 🛡️ Action Executed

**Status:** ✅ Success  
**Action:** {action}

---

### 🛑 Result

{message}

**Source:** {source}

---

*Argus Security Platform | {timestamp}*"""
            else:
                error = action_result.get('error', 'Unknown error')
                return f"""### ⚠️ Action Failed

**Error:** {error}

*Argus Security Platform | {timestamp}*"""
        
        return "An unexpected error occurred."
    
    def process_security_event(self, event: dict) -> dict:
        """Legacy method: Process structured security event"""
        indicator = event.get('indicator', '')
        indicator_type = event.get('indicator_type', 'auto')
        
        message = f"Analyze this security indicator: {indicator} (type: {indicator_type})"
        result = self.chat(message)
        
        return {
            "success": True,
            "response": result.get("text", ""),
            "trace": result.get("trace", []),
            "timestamp": datetime.now().isoformat()
        }
    
    def get_session_status(self) -> dict:
        """Get current session status"""
        return {
            "session_start": self.session_memory['session_start'],
            "total_investigations": len(self.session_memory['active_investigations']),
            "conversation_turns": len(self.session_memory['conversation_history']),
            "unique_indicators": len(self.session_memory['processed_indicators'])
        }
    
    def start_a2a_server(self, port: int = 8080, register: bool = True):
        """Start A2A protocol server for this agent"""
        server = A2AServer(agent_name="RootOrchestratorAgent", port=port)
        
        # Register A2A methods
        server.register_method("chat", self.chat)
        server.register_method("process_security_event", self.process_security_event)
        server.register_method("get_session_status", self.get_session_status)
        server.register_method("get_mode", self.get_mode_indicator)
        
        logger.info(f"Starting RootOrchestratorAgent A2A server on port {port}")
        
        # Register with Vertex AI
        if register:
            try:
                endpoint = os.getenv("ROOT_AGENT_ENDPOINT", f"http://localhost:{port}")
                self.registry.register_agent(
                    agent_name="RootOrchestratorAgent",
                    endpoint=endpoint,
                    capabilities=["chat", "process_security_event", "orchestration", "threat_coordination"]
                )
                logger.info("Registered RootOrchestratorAgent with Vertex AI Agent Registry")
            except Exception as e:
                logger.warning(f"Failed to register with Vertex AI Agent Registry: {e}")
        
        # Start server (this blocks)
        server.run(host='0.0.0.0', debug=False)


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
    
    location = os.getenv("VERTEX_AI_LOCATION", "us-central1")
    port = int(os.getenv("PORT", os.getenv("ROOT_AGENT_PORT", "8080")))
    
    logger.info(f"Starting Root Orchestrator Agent for project: {project_id}")
    logger.info(f"Server will listen on port: {port}")
    
    try:
        orchestrator = RootOrchestratorAgent(project_id, location)
        
        # Show mode
        mode = orchestrator.get_mode_indicator()
        logger.info(f"Agent Mode: {mode['overall']}")
        
        orchestrator.start_a2a_server(port=port, register=True)
    except Exception as e:
        logger.error(f"Failed to start Root Orchestrator Agent: {e}", exc_info=True)
        print(f"ERROR: Failed to start agent: {e}", file=sys.stderr)
        sys.exit(1)

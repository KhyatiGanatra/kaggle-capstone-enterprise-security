import os
import logging
from typing import Dict, Any

from shared.communication.a2a_client import A2AClient

logger = logging.getLogger(__name__)

class ADKRootAgentClient:
    """
    A client for the Root Orchestrator Agent when it's deployed as an ADK service.
    This class wraps the A2AClient to provide a 'chat' interface compatible with ui.py.
    """
    def __init__(self, service_url: str, project_id: str):
        self.service_url = service_url
        self.project_id = project_id
        # The agent_name for the root agent is typically 'root_agent'
        # This will be used in the invoke_agent call.
        self.agent_name = os.getenv("ROOT_AGENT_NAME", "root_agent")
        self.a2a_client = A2AClient(project_id=self.project_id)
        logger.info(f"Initialized ADKRootAgentClient for service URL: {self.service_url}, agent name: {self.agent_name}")

    def chat(self, prompt: str) -> Dict[str, Any]:
        """
        Sends a chat prompt to the remote ADK root agent and returns its response.
        """
        logger.debug(f"Sending chat prompt to ADK Root Agent: {prompt}")
        try:
            response = self.a2a_client.invoke_agent(
                agent_name=self.agent_name,
                method="chat",  # Assuming the remote agent has a 'chat' method
                params={"prompt": prompt},
                endpoint=self.service_url
            )
            logger.debug(f"Received response from ADK Root Agent: {response}")
            return response
        except Exception as e:
            logger.error(f"Error invoking remote ADK Root Agent chat method: {e}", exc_info=True)
            # Return an error structure compatible with what ui.py expects
            return {"text": f"Error communicating with deployed root agent: {str(e)}", "error": True}

    def _detect_indicator_type(self, indicator: str) -> str:
        """
        Placeholder for detecting indicator type.
        In a real scenario, this might involve another remote call or local logic.
        For now, it's a simple placeholder that delegates to a local implementation
        or can be expanded later.
        """
        # This method is called by the threat analysis tab if the root agent is local.
        # If the root agent is remote, this method might not be directly called
        # or the remote agent itself handles the detection.
        # For compatibility, we can add a very basic implementation or raise an error.
        # For now, let's delegate to a simple local check or a more robust future remote call.
        if isinstance(indicator, str):
            if '.' in indicator and not indicator.replace('.', '').isdigit():
                return "domain"
            elif indicator.replace('.', '').isdigit() and indicator.count('.') == 3:
                return "ip"
            elif len(indicator) == 32 or len(indicator) == 40 or len(indicator) == 64:
                return "hash"
            elif indicator.startswith("http"):
                return "url"
        return "unknown"

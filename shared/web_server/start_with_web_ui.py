"""Start agent with both A2A server and ADK web UI"""

import os
import logging
import threading
import json
from typing import Optional
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from google.adk.cli.fast_api import get_fast_api_app
from shared.communication.a2a_server_fastapi import A2AServerFastAPI

logger = logging.getLogger(__name__)


def start_agent_with_web_ui(
    agent_name: str,
    agents_dir: str,
    a2a_methods: dict,
    port: int = 8080,
    enable_web_ui: bool = True
):
    """
    Start agent with both A2A server and ADK web UI
    
    Args:
        agent_name: Name of the agent (e.g., "root_agent")
        agents_dir: Directory containing agent code for ADK web UI
        a2a_methods: Dict of method_name -> handler for A2A protocol
        port: Port for A2A server (Cloud Run PORT)
        enable_web_ui: Whether to enable ADK web UI
    """
    # Create A2A server
    a2a_server = A2AServerFastAPI(agent_name)
    for method_name, handler in a2a_methods.items():
        a2a_server.register_method(method_name, handler)
    
    # Get A2A FastAPI app
    a2a_app = a2a_server.get_app()
    
    # Store reference to web UI server for A2A to use Runner
    adk_web_server_instance = None
    
    # Always add web-status endpoint (even if web UI fails)
    web_ui_enabled = False
    web_ui_error = None
    
    # Get ADK web UI app
    if enable_web_ui:
        logger.info(f"Initializing ADK web UI from {agents_dir}")
        
        # Check if agents_dir exists
        import os
        if not os.path.exists(agents_dir):
            logger.error(f"ADK agents directory does not exist: {agents_dir}")
            logger.warning("Continuing without web UI - A2A server will still work")
            enable_web_ui = False
        else:
            # List what's in the directory for debugging
            try:
                dir_contents = os.listdir(agents_dir)
                logger.info(f"ADK agents directory contents: {dir_contents}")
            except Exception as e:
                logger.warning(f"Could not list agents directory: {e}")
        
        if enable_web_ui:
            try:
                # Get the AdkWebServer instance from the web UI app
                # We need to access it to get the Runner for trace generation
                from google.adk.cli.fast_api import get_fast_api_app
                from google.adk.cli.adk_web_server import AdkWebServer
                from google.adk.cli.utils.agent_loader import AgentLoader
                from google.adk.sessions.in_memory_session_service import InMemorySessionService
                from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService
                from google.adk.memory.in_memory_memory_service import InMemoryMemoryService
                from google.adk.auth.credential_service.in_memory_credential_service import InMemoryCredentialService
                from google.adk.evaluation.local_eval_sets_manager import LocalEvalSetsManager
                from google.adk.evaluation.local_eval_set_results_manager import LocalEvalSetResultsManager
                
                # Create AdkWebServer instance to access Runner
                agent_loader = AgentLoader(agents_dir)
                adk_web_server_instance = AdkWebServer(
                    agent_loader=agent_loader,
                    session_service=InMemorySessionService(),
                    artifact_service=InMemoryArtifactService(),
                    memory_service=InMemoryMemoryService(),
                    credential_service=InMemoryCredentialService(),
                    eval_sets_manager=LocalEvalSetsManager(agents_dir=agents_dir),
                    eval_set_results_manager=LocalEvalSetResultsManager(agents_dir=agents_dir),
                    agents_dir=agents_dir,
                    url_prefix="/web",
                )
                
                # Get FastAPI app from the AdkWebServer instance we created
                # This ensures they share the same session service and Runner
                import sys
                from pathlib import Path
                
                # Find the browser directory for web assets
                browser_path = None
                for path in sys.path:
                    potential_path = Path(path) / "google" / "adk" / "cli" / "browser"
                    if potential_path.exists():
                        browser_path = str(potential_path)
                        logger.info(f"Found browser assets at: {browser_path}")
                        break
                
                if not browser_path:
                    logger.warning("Browser assets directory not found - web UI may not display correctly")
                
                web_ui_app = adk_web_server_instance.get_fast_api_app(
                    web_assets_dir=browser_path,
                    otel_to_cloud=False,
                )
                
                # Mount web UI app on /web path in A2A app
                a2a_app.mount("/web", web_ui_app)
                
                # Determine app name from agents_dir (directory name)
                # For root_agent, threat_agent, incident_agent
                app_name = os.path.basename(agents_dir.rstrip('/'))
                if app_name == "adk_web_ui":
                    # If agents_dir is /app/adk_web_ui, we need to get the actual agent name
                    # Check what's in the directory
                    try:
                        agent_dirs = [d for d in os.listdir(agents_dir) 
                                    if os.path.isdir(os.path.join(agents_dir, d)) and not d.startswith('.')]
                        if agent_dirs:
                            app_name = agent_dirs[0]  # Use first agent directory
                    except:
                        # Fallback: derive from agent_name
                        app_name = agent_name.lower().replace("orchestratoragent", "root_agent").replace("threatanalysisagent", "threat_agent").replace("incidentresponseagent", "incident_agent")
                
                # Store reference in A2A server so it can use Runner for traces
                a2a_server.set_adk_web_server(adk_web_server_instance, app_name)
                logger.info(f"A2A calls will generate traces via Runner for app: {app_name}")
                
                # Also handle /web/ with trailing slash
                @a2a_app.get("/web/")
                async def web_root():
                    """Redirect /web/ to /web"""
                    from fastapi.responses import RedirectResponse
                    return RedirectResponse(url="/web", status_code=301)
                
                logger.info(f"✓ ADK web UI successfully mounted at /web")
                web_ui_enabled = True
                
                # Also add redirect from root to web UI
                @a2a_app.get("/web-ui")
                async def web_ui_redirect():
                    """Redirect to web UI"""
                    from fastapi.responses import RedirectResponse
                    return RedirectResponse(url="/web")
                    
            except Exception as e:
                logger.error(f"Failed to initialize ADK web UI: {e}", exc_info=True)
                logger.warning("Continuing without web UI - A2A server will still work")
                web_ui_error = str(e)
                import traceback
                web_ui_error_trace = traceback.format_exc()
                logger.debug(f"Web UI error traceback: {web_ui_error_trace}")
    
    # Always add web-status endpoint (regardless of web UI success/failure)
    @a2a_app.get("/web-status")
    async def web_ui_status():
        """Check if web UI is enabled and get status"""
        status = {
            "web_ui_enabled": web_ui_enabled,
            "agents_dir": agents_dir,
            "web_ui_path": "/web" if web_ui_enabled else None
        }
        if web_ui_error:
            status["error"] = web_ui_error
        return status
    
    # Add CORS middleware for web UI
    a2a_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, restrict this
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Start server
    logger.info(f"Starting {agent_name} server on port {port}")
    logger.info(f"A2A endpoint: http://0.0.0.0:{port}/a2a/invoke")
    logger.info(f"Web status: http://0.0.0.0:{port}/web-status")
    if web_ui_enabled:
        logger.info(f"✓ Web UI: http://0.0.0.0:{port}/web")
    else:
        logger.warning("⚠ Web UI is DISABLED - check /web-status endpoint for details")
    
    config = uvicorn.Config(
        a2a_app,
        host="0.0.0.0",
        port=port,
        reload=False,
    )
    server = uvicorn.Server(config)
    server.run()


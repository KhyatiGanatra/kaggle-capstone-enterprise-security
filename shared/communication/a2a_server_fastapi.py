"""A2A (Agent-to-Agent) Protocol Server using FastAPI - for integration with ADK web UI"""

import json
import logging
import inspect
import asyncio
from typing import Dict, Any, Callable, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class A2AInvokeRequest(BaseModel):
    """Request model for A2A protocol invocation"""
    agent: str
    method: str
    params: Dict[str, Any] = {}
    protocol_version: Optional[str] = "1.0"


class A2AServerFastAPI:
    """FastAPI-based A2A protocol server that can be integrated with ADK web UI"""
    
    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.app = FastAPI(title=f"{agent_name} A2A Server")
        self.methods: Dict[str, Callable] = {}
        self.adk_web_server = None  # Reference to AdkWebServer for trace generation
        self.app_name = None  # Agent app name for Runner
        self._setup_routes()
    
    def set_adk_web_server(self, adk_web_server, app_name: str):
        """Set reference to AdkWebServer so A2A calls can generate traces"""
        self.adk_web_server = adk_web_server
        self.app_name = app_name
        logger.info(f"A2A server configured to generate traces via AdkWebServer for {app_name}")
    
    def _setup_routes(self):
        """Setup FastAPI routes for A2A protocol"""
        
        @self.app.get('/health')
        async def health():
            """Health check endpoint - responds immediately"""
            return {"status": "healthy", "agent": self.agent_name}
        
        @self.app.get('/')
        async def root():
            """Root endpoint for Cloud Run health checks"""
            return {
                "status": "ok",
                "agent": self.agent_name,
                "service": "a2a",
                "web_ui": "Available at /web",
                "endpoints": {
                    "health": "/health",
                    "a2a": "/a2a/invoke",
                    "web_ui": "/web",
                    "web_status": "/web-status"
                }
            }
        
        @self.app.post('/a2a/invoke')
        async def invoke(request_data: A2AInvokeRequest):
            """Handle A2A protocol invocation - optionally through Runner for traces"""
            try:
                if request_data.agent != self.agent_name:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Agent mismatch: expected {self.agent_name}, got {request_data.agent}"
                    )
                
                if request_data.method not in self.methods:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Method {request_data.method} not found"
                    )
                
                # If AdkWebServer is available, execute through Runner to generate traces
                if self.adk_web_server and self.app_name:
                    try:
                        # Create a session for this A2A call
                        import uuid
                        from google.genai import types
                        from google.adk.utils.context_utils import Aclosing
                        
                        # Use "user" as the user ID - this is what ADK web UI uses by default
                        # The web UI defaults to userId=user, so we must match that
                        user_id = "user"
                        # Use a predictable session ID based on method and params for easier tracking
                        import hashlib
                        params_hash = hashlib.md5(json.dumps(request_data.params, sort_keys=True).encode()).hexdigest()[:8]
                        session_id = f"a2a-{request_data.method}-{params_hash}"
                        
                        # Check if session already exists, if not create it
                        try:
                            session = await self.adk_web_server.session_service.get_session(
                                app_name=self.app_name,
                                user_id=user_id,
                                session_id=session_id
                            )
                            if not session:
                                session = await self.adk_web_server.session_service.create_session(
                                    app_name=self.app_name,
                                    user_id=user_id,
                                    session_id=session_id
                                )
                        except Exception:
                            # Create new session if get fails
                            session = await self.adk_web_server.session_service.create_session(
                                app_name=self.app_name,
                                user_id=user_id,
                                session_id=session_id
                            )
                        
                        # Convert A2A method call to a message for the agent
                        method_summary = json.dumps(request_data.params, indent=2) if isinstance(request_data.params, dict) else str(request_data.params)
                        message_text = f"Execute {request_data.method} with parameters:\n{method_summary}"
                        
                        # Get Runner and execute to generate traces
                        runner = await self.adk_web_server.get_runner_async(self.app_name)
                        content = types.Content(role="user", parts=[types.Part(text=message_text)])
                        
                        # Execute Runner and collect events
                        async with Aclosing(
                            runner.run_async(
                                user_id=user_id,
                                session_id=session_id,
                                new_message=content,
                            )
                        ) as agen:
                            # Consume events from Runner
                            events = []
                            async for event in agen:
                                events.append(event)
                        
                        # Manually append all events to the session
                        # The Runner generates events but doesn't automatically store them in the session
                        for event in events:
                            try:
                                # Get fresh session reference for each append
                                current_session = await self.adk_web_server.session_service.get_session(
                                    app_name=self.app_name,
                                    user_id=user_id,
                                    session_id=session_id
                                )
                                if current_session:
                                    await self.adk_web_server.session_service.append_event(
                                        session=current_session,
                                        event=event
                                    )
                            except Exception as append_error:
                                logger.warning(f"Failed to append event to session: {append_error}", exc_info=True)
                        
                        # Verify events were stored in session
                        updated_session = await self.adk_web_server.session_service.get_session(
                            app_name=self.app_name,
                            user_id=user_id,
                            session_id=session_id
                        )
                        stored_events_count = len(updated_session.events) if updated_session else 0
                        
                        logger.info(f"Generated {len(events)} events through Runner for A2A call - session: {session_id}")
                        logger.info(f"Stored {stored_events_count} events in session (should match {len(events)} generated events)")
                        if stored_events_count != len(events):
                            logger.warning(f"Event count mismatch: generated {len(events)} but stored {stored_events_count}")
                        logger.info(f"View traces at: /web (look for session {session_id} with user 'user')")
                    except Exception as trace_error:
                        # If trace generation fails, log but continue with direct execution
                        logger.warning(f"Failed to generate traces for A2A call: {trace_error}")
                
                # Execute method directly (this is the actual work)
                handler = self.methods[request_data.method]
                sig = inspect.signature(handler)
                params_list = list(sig.parameters.keys())

                # If method has exactly one parameter (bound methods don't include 'self'),
                # check if it expects a dict and pass params as that single parameter
                # Otherwise, unpack params as keyword arguments
                if len(params_list) == 1:
                    param_name = params_list[0]
                    param = sig.parameters[param_name]
                    # Check if parameter annotation suggests it's a dict
                    # or if param name suggests it should be a dict (event, data, payload)
                    param_annotation = param.annotation
                    is_dict_param = (
                        param_annotation == dict or
                        (hasattr(param_annotation, '__origin__') and
                         param_annotation.__origin__ is dict) or
                        param_name in ['event', 'data', 'payload', 'threat_analysis']
                    )

                    if is_dict_param and isinstance(request_data.params, dict):
                        # Single dict parameter - pass params dict directly
                        result = handler(request_data.params)
                    else:
                        # Single parameter but not a dict - unpack as keyword arguments
                        result = handler(**request_data.params)
                else:
                    # Multiple parameters - unpack as keyword arguments
                    result = handler(**request_data.params)

                # DEBUG: Log what the handler returned vs. what we're sending
                logger.info(f"[A2A-DEBUG] Handler returned type: {type(result)}")
                if isinstance(result, dict):
                    logger.info(f"[A2A-DEBUG] Handler result keys: {list(result.keys())}")
                logger.info(f"[A2A-DEBUG] Handler result preview: {json.dumps(result, indent=2, default=str)[:500]}")

                wrapped_response = {
                    "success": True,
                    "agent": self.agent_name,
                    "method": request_data.method,
                    "result": result
                }

                logger.info(f"[A2A-DEBUG] Wrapped response keys: {list(wrapped_response.keys())}")
                logger.info(f"[A2A-DEBUG] Returning wrapped response to client")

                return wrapped_response
                
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"A2A invocation error: {e}", exc_info=True)
                raise HTTPException(
                    status_code=500,
                    detail=f"Internal server error: {str(e)}"
                )
    
    def register_method(self, method_name: str, handler: Callable):
        """Register a method that can be called via A2A protocol"""
        self.methods[method_name] = handler
        logger.info(f"Registered A2A method: {method_name}")
    
    def get_app(self) -> FastAPI:
        """Get the FastAPI app instance"""
        return self.app


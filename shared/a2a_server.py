"""A2A (Agent-to-Agent) Protocol Server for HTTPS endpoints"""

import json
import logging
import inspect
from typing import Dict, Any, Callable
from flask import Flask, request, jsonify
from google.auth import default
from google.auth.transport.requests import Request

logger = logging.getLogger(__name__)


class A2AServer:
    """Server for A2A protocol communication over HTTPS"""
    
    def __init__(self, agent_name: str, port: int = 8080):
        self.agent_name = agent_name
        self.port = port
        self.app = Flask(__name__)
        self.methods: Dict[str, Callable] = {}
        self._setup_routes()
        self.credentials, _ = default()
    
    def _setup_routes(self):
        """Setup Flask routes for A2A protocol"""
        
        @self.app.route('/health', methods=['GET'])
        def health():
            """Health check endpoint - responds immediately"""
            return jsonify({"status": "healthy", "agent": self.agent_name}), 200
        
        @self.app.route('/', methods=['GET'])
        def root():
            """Root endpoint for Cloud Run health checks"""
            return jsonify({"status": "ok", "agent": self.agent_name, "service": "a2a"}), 200
        
        @self.app.route('/a2a/invoke', methods=['POST'])
        def invoke():
            """Handle A2A protocol invocation"""
            try:
                data = request.json
                agent = data.get('agent')
                method = data.get('method')
                params = data.get('params', {})
                
                if agent != self.agent_name:
                    return jsonify({
                        "error": f"Agent mismatch: expected {self.agent_name}, got {agent}"
                    }), 400
                
                if method not in self.methods:
                    return jsonify({
                        "error": f"Method {method} not found"
                    }), 404
                
                # Execute method
                # Check if method expects a single dict parameter (like process_security_event)
                handler = self.methods[method]
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
                    
                    if is_dict_param and isinstance(params, dict):
                        # Single dict parameter - pass params dict directly
                        result = handler(params)
                    else:
                        # Single parameter but not a dict - unpack as keyword arguments
                        result = handler(**params)
                else:
                    # Multiple parameters - unpack as keyword arguments
                    result = handler(**params)
                
                return jsonify({
                    "success": True,
                    "agent": self.agent_name,
                    "method": method,
                    "result": result
                }), 200
                
            except Exception as e:
                logger.error(f"A2A invocation error: {e}")
                return jsonify({
                    "success": False,
                    "error": str(e)
                }), 500
    
    def register_method(self, method_name: str, handler: Callable):
        """Register a method that can be called via A2A protocol"""
        self.methods[method_name] = handler
        logger.info(f"Registered A2A method: {method_name}")
    
    def run(self, host: str = '0.0.0.0', debug: bool = False):
        """Run the A2A server"""
        logger.info(f"Starting A2A server for {self.agent_name} on {host}:{self.port}")
        try:
            # Use threaded mode for better concurrency
            self.app.run(host=host, port=self.port, debug=debug, threaded=True)
        except Exception as e:
            logger.error(f"Failed to start A2A server: {e}", exc_info=True)
            raise




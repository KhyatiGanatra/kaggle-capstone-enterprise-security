"""A2A (Agent-to-Agent) Protocol Server for HTTPS endpoints"""

import json
import logging
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
            return jsonify({"status": "healthy", "agent": self.agent_name}), 200
        
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
                result = self.methods[method](**params)
                
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
        logger.info(f"Starting A2A server for {self.agent_name} on port {self.port}")
        self.app.run(host=host, port=self.port, debug=debug)



"""Tests for A2A protocol communication"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.communication.a2a_client import A2AClient
from shared.communication.a2a_server import A2AServer


class TestA2AClient(unittest.TestCase):
    """Test cases for A2A Client"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.project_id = "test-project"
        self.client = A2AClient(self.project_id)
    
    @patch('shared.communication.a2a_client.requests.post')
    def test_invoke_agent_success(self, mock_post):
        """Test successful agent invocation"""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "success": True,
            "result": {"status": "completed"}
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        result = self.client.invoke_agent(
            agent_name="TestAgent",
            method="test_method",
            params={"param1": "value1"},
            endpoint="http://localhost:8080"
        )
        
        self.assertTrue(result['success'])
        mock_post.assert_called_once()
    
    @patch('shared.communication.a2a_client.requests.post')
    def test_invoke_agent_failure(self, mock_post):
        """Test agent invocation failure"""
        mock_post.side_effect = Exception("Connection error")
        
        with self.assertRaises(Exception):
            self.client.invoke_agent(
                agent_name="TestAgent",
                method="test_method",
                params={},
                endpoint="http://localhost:8080"
            )


class TestA2AServer(unittest.TestCase):
    """Test cases for A2A Server"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.server = A2AServer(agent_name="TestAgent", port=8080)
    
    def test_register_method(self):
        """Test method registration"""
        def test_handler(param1):
            return {"result": param1}
        
        self.server.register_method("test_method", test_handler)
        
        self.assertIn("test_method", self.server.methods)
        self.assertEqual(self.server.methods["test_method"], test_handler)


if __name__ == '__main__':
    unittest.main()







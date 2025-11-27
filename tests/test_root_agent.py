"""Tests for Root Orchestrator Agent"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.root_agent import RootOrchestratorAgent


class TestRootOrchestratorAgent(unittest.TestCase):
    """Test cases for RootOrchestratorAgent"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.project_id = "test-project"
        with patch('agents.root_agent.VertexAIAgentRegistry') as mock_registry:
            mock_registry.return_value.discover_agent.return_value = {
                'endpoint': 'http://localhost:8081'
            }
            self.orchestrator = RootOrchestratorAgent(self.project_id)
    
    def test_agent_initialization(self):
        """Test that orchestrator initializes correctly"""
        self.assertIsNotNone(self.orchestrator.agent)
        self.assertEqual(self.orchestrator.agent.name, "RootOrchestratorAgent")
        self.assertIsNotNone(self.orchestrator.a2a_client)
        self.assertIsNotNone(self.orchestrator.registry)
    
    @patch('agents.root_agent.A2AClient')
    def test_process_security_event(self, mock_a2a_client):
        """Test processing a security event"""
        # Mock A2A client
        mock_client = MagicMock()
        mock_client.invoke_agent.return_value = {
            'success': True,
            'analysis': {
                'indicator': '203.0.113.42',
                'severity': 'CRITICAL',
                'confidence': 95
            }
        }
        self.orchestrator.a2a_client = mock_client
        
        # Mock threat and incident memory
        with patch.object(self.orchestrator.threat_memory, 'retrieve_threat_history') as mock_threat:
            mock_threat.return_value = []
            with patch.object(self.orchestrator.incident_memory, 'get_active_incidents') as mock_incident:
                mock_incident.return_value = []
                with patch('agents.root_agent.run_agent_sync') as mock_run:
                    mock_run.return_value = "Orchestration complete"
                    
                    event = {
                        "indicator": "203.0.113.42",
                        "indicator_type": "ip",
                        "source": "SIEM"
                    }
                    
                    result = self.orchestrator.process_security_event(event)
                    
                    self.assertTrue(result['success'])
                    self.assertIn('investigation_id', result)
                    self.assertIn('threat_analysis', result)
    
    def test_get_session_status(self):
        """Test getting session status"""
        status = self.orchestrator.get_session_status()
        
        self.assertIn('session_start', status)
        self.assertIn('total_investigations', status)
        self.assertIn('unique_indicators', status)
    
    def test_duplicate_indicator_handling(self):
        """Test that duplicate indicators are handled correctly"""
        event = {
            "indicator": "203.0.113.42",
            "indicator_type": "ip"
        }
        
        # Process first time
        with patch.object(self.orchestrator, '_call_threat_agent') as mock_call:
            mock_call.return_value = {'success': True, 'analysis': {}}
            with patch('agents.root_agent.run_agent_sync'):
                self.orchestrator.process_security_event(event)
        
        # Process second time (should be duplicate)
        result = self.orchestrator.process_security_event(event)
        
        self.assertEqual(result['status'], 'DUPLICATE')


if __name__ == '__main__':
    unittest.main()






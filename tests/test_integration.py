"""Integration tests for multi-agent system"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestMultiAgentIntegration(unittest.TestCase):
    """Integration tests for the complete multi-agent workflow"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.project_id = "test-project"
    
    @patch('agents.root_agent.VertexAIAgentRegistry')
    @patch('agents.root_agent.A2AClient')
    def test_end_to_end_workflow(self, mock_a2a_client, mock_registry):
        """Test complete end-to-end workflow"""
        # Mock registry discovery
        mock_registry_instance = MagicMock()
        mock_registry_instance.discover_agent.return_value = {
            'endpoint': 'http://localhost:8081'
        }
        mock_registry.return_value = mock_registry_instance
        
        # Mock A2A client
        mock_client_instance = MagicMock()
        mock_client_instance.invoke_agent.side_effect = [
            # Threat analysis response
            {
                'success': True,
                'analysis': {
                    'indicator': '203.0.113.42',
                    'severity': 'CRITICAL',
                    'confidence': 95
                }
            },
            # Incident response response
            {
                'success': True,
                'incident_id': 'INC-001',
                'response': 'Incident handled'
            }
        ]
        mock_a2a_client.return_value = mock_client_instance
        
        from agents.root_agent import RootOrchestratorAgent
        
        orchestrator = RootOrchestratorAgent(self.project_id)
        orchestrator.a2a_client = mock_client_instance
        
        # Mock memory
        with patch.object(orchestrator.threat_memory, 'retrieve_threat_history'):
            with patch.object(orchestrator.incident_memory, 'get_active_incidents'):
                with patch('agents.root_agent.run_agent_sync') as mock_run:
                    mock_run.return_value = "Workflow complete"
                    
                    event = {
                        "indicator": "203.0.113.42",
                        "indicator_type": "ip",
                        "source": "SIEM"
                    }
                    
                    result = orchestrator.process_security_event(event)
                    
                    # Verify workflow completed
                    self.assertTrue(result['success'])
                    self.assertIn('threat_analysis', result)
                    self.assertIn('incident_response', result)
                    
                    # Verify A2A calls were made
                    self.assertEqual(mock_client_instance.invoke_agent.call_count, 2)


if __name__ == '__main__':
    unittest.main()



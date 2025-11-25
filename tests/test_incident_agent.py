"""Tests for Incident Response Agent"""

import unittest
from unittest.mock import Mock, patch
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.incident_agent import IncidentResponseAgent


class TestIncidentResponseAgent(unittest.TestCase):
    """Test cases for IncidentResponseAgent"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.project_id = "test-project"
        self.agent = IncidentResponseAgent(self.project_id)
    
    def test_agent_initialization(self):
        """Test that agent initializes correctly"""
        self.assertIsNotNone(self.agent.agent)
        self.assertEqual(self.agent.agent.name, "IncidentResponseAgent")
        self.assertIsNotNone(self.agent.memory)
        self.assertIsNotNone(self.agent.config)
    
    @patch('agents.incident_agent.run_agent_sync')
    def test_handle_incident_success(self, mock_run):
        """Test successful incident handling"""
        mock_response = "Incident handled successfully. Case ID: INC-001"
        mock_run.return_value = mock_response
        
        threat_analysis = {
            "indicator": "203.0.113.42",
            "indicator_type": "ip",
            "severity": "CRITICAL",
            "confidence": 95
        }
        
        with patch.object(self.agent.memory, 'store_incident') as mock_store:
            result = self.agent.handle_incident(threat_analysis)
            
            self.assertTrue(result['success'])
            self.assertIn('incident_id', result)
            mock_store.assert_called_once()
    
    @patch('agents.incident_agent.run_agent_sync')
    def test_handle_incident_failure(self, mock_run):
        """Test incident handling failure"""
        mock_run.side_effect = Exception("Agent error")
        
        threat_analysis = {"indicator": "test", "severity": "HIGH"}
        result = self.agent.handle_incident(threat_analysis)
        
        self.assertFalse(result['success'])
        self.assertIn('error', result)


if __name__ == '__main__':
    unittest.main()



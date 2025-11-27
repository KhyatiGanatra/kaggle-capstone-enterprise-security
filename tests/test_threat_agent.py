"""Tests for Threat Analysis Agent"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.threat_agent import ThreatAnalysisAgent


class TestThreatAnalysisAgent(unittest.TestCase):
    """Test cases for ThreatAnalysisAgent"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.project_id = "test-project"
        self.agent = ThreatAnalysisAgent(self.project_id)
    
    def test_agent_initialization(self):
        """Test that agent initializes correctly"""
        self.assertIsNotNone(self.agent.agent)
        self.assertEqual(self.agent.agent.name, "ThreatAnalysisAgent")
        self.assertIsNotNone(self.agent.memory)
        self.assertIsNotNone(self.agent.config)
    
    @patch('agents.threat_agent.run_agent_sync')
    def test_analyze_indicator_success(self, mock_run):
        """Test successful indicator analysis"""
        # Mock agent response
        mock_response = """{
            "indicator": "203.0.113.42",
            "indicator_type": "ip",
            "severity": "CRITICAL",
            "confidence": 95,
            "threat_type": "c2",
            "threat_actors": ["APT28"],
            "malware_families": ["Cobalt Strike"]
        }"""
        mock_run.return_value = mock_response
        
        # Mock memory storage
        with patch.object(self.agent.memory, 'store_threat_analysis') as mock_store:
            result = self.agent.analyze_indicator("203.0.113.42", "ip")
            
            self.assertTrue(result['success'])
            self.assertIn('analysis', result)
            mock_store.assert_called_once()
    
    @patch('agents.threat_agent.run_agent_sync')
    def test_analyze_indicator_failure(self, mock_run):
        """Test indicator analysis failure"""
        mock_run.side_effect = Exception("Agent error")
        
        result = self.agent.analyze_indicator("203.0.113.42", "ip")
        
        self.assertFalse(result['success'])
        self.assertIn('error', result)
    
    def test_analyze_indicator_with_context(self):
        """Test indicator analysis with additional context"""
        with patch('agents.threat_agent.run_agent_sync') as mock_run:
            mock_run.return_value = '{"indicator": "test", "severity": "LOW"}'
            with patch.object(self.agent.memory, 'store_threat_analysis'):
                result = self.agent.analyze_indicator(
                    "203.0.113.42",
                    "ip",
                    context="Suspicious activity detected"
                )
                self.assertTrue(result['success'])
                # Verify context was included in prompt
                call_args = mock_run.call_args[0]
                self.assertIn("Suspicious activity detected", call_args[1])


if __name__ == '__main__':
    unittest.main()






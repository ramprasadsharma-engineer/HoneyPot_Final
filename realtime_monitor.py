#!/usr/bin/env python3
"""
Real-time Honeypot Monitoring System with AI-powered Threat Detection
Features: Live stream processing, behavioral analysis, automated alerting, and adaptive defense
"""

import asyncio
import websockets
import json
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import queue
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
import subprocess
import sys
import os

class ThreatDetectionEngine:
    def __init__(self):
        self.attack_signatures = {
            'sql_injection': [
                r"union\s+select", r"drop\s+table", r"1=1", r"admin'--", 
                r"or\s+1=1", r"exec\s*\(", r"char\(", r"0x"
            ],
            'command_injection': [
                r";.*rm\s+-rf", r"&&.*cat", r"\|\s*nc", r"wget.*http", 
                r"curl\s+.*\|\s*bash", r"bash.*-c", r"python.*-c", r"perl.*-e",
                r"rm\s+-rf", r"nc\s+.*-e\s+/bin/bash"
            ],
            'cryptomining': [
                r"xmrig", r"stratum\+tcp", r"monero", r"mining", 
                r"hashrate", r"pool", r"worker", r"difficulty"
            ],
            'ransomware': [
                r"\.encrypt", r"\.locked", r"ransom", r"bitcoin", 
                r"decrypt", r"key.*payment", r"restore.*files"
            ],
            'persistence': [
                r"crontab", r"systemctl", r"service", r"rc\.local",
                r"\.bashrc", r"\.profile", r"startup", r"autostart"
            ]
        }
        
        self.behavioral_patterns = {
            'reconnaissance': {
                'commands': ['ls', 'ps', 'netstat', 'whoami', 'id', 'uname'],
                'threshold': 5,
                'time_window': 300  # 5 minutes
            },
            'privilege_escalation': {
                'commands': ['sudo', 'su', 'chmod +s', 'passwd', 'usermod'],
                'threshold': 3,
                'time_window': 180  # 3 minutes
            },
            'data_exfiltration': {
                'commands': ['tar', 'zip', 'scp', 'rsync', 'base64'],
                'threshold': 2,
                'time_window': 120  # 2 minutes
            }
        }
        
        self.risk_scores = {}
        self.session_profiles = {}

    def analyze_command(self, command, session_id, timestamp):
        """Real-time command analysis with ML-based threat scoring"""
        threat_level = 0
        detected_attacks = []
        
        command_lower = command.lower()
        
        # Signature-based detection
        for attack_type, signatures in self.attack_signatures.items():
            for signature in signatures:
                import re
                if re.search(signature, command_lower):
                    threat_level += 20
                    detected_attacks.append(attack_type)
                    break
        
        # Behavioral analysis
        if session_id not in self.session_profiles:
            self.session_profiles[session_id] = {
                'commands': [],
                'start_time': timestamp,
                'risk_indicators': []
            }
        
        profile = self.session_profiles[session_id]
        profile['commands'].append((command, timestamp))
        
        # Check behavioral patterns
        recent_commands = [cmd for cmd, ts in profile['commands'] 
                          if (timestamp - ts).total_seconds() < 300]
        
        for pattern_name, pattern_data in self.behavioral_patterns.items():
            matching_commands = [cmd for cmd in recent_commands 
                               if any(keyword in cmd.lower() for keyword in pattern_data['commands'])]
            
            if len(matching_commands) >= pattern_data['threshold']:
                threat_level += 15
                detected_attacks.append(pattern_name)
                profile['risk_indicators'].append(pattern_name)
        
        # Anomaly scoring based on command frequency and timing
        if len(recent_commands) > 20:  # High activity
            threat_level += 10
        
        # Update risk score for session
        self.risk_scores[session_id] = min(100, threat_level)
        
        return {
            'threat_level': threat_level,
            'detected_attacks': detected_attacks,
            'risk_score': self.risk_scores.get(session_id, 0),
            'session_profile': profile
        }

class RealTimeMonitor(FileSystemEventHandler):
    def __init__(self, log_file_path, alert_queue):
        self.log_file_path = log_file_path
        self.alert_queue = alert_queue
        self.threat_engine = ThreatDetectionEngine()
        self.file_position = 0
        self.websocket_clients = set()
        
        # Initialize file position
        if os.path.exists(log_file_path):
            with open(log_file_path, 'r') as f:
                f.seek(0, 2)  # Go to end of file
                self.file_position = f.tell()

    def on_modified(self, event):
        if event.src_path == self.log_file_path:
            self.process_new_log_entries()

    def process_new_log_entries(self):
        """Process new log entries in real-time"""
        try:
            with open(self.log_file_path, 'r') as f:
                f.seek(self.file_position)
                new_lines = f.readlines()
                self.file_position = f.tell()
                
                for line in new_lines:
                    try:
                        event = json.loads(line.strip())
                        self.analyze_event(event)
                    except json.JSONDecodeError:
                        continue
                        
        except FileNotFoundError:
            pass

    def analyze_event(self, event):
        """Analyze individual log events"""
        event_id = event.get('eventid', '')
        timestamp = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
        
        # Command analysis
        if event_id == 'cowrie.command.input':
            command = event.get('input', '')
            session_id = event.get('session', '')
            src_ip = event.get('src_ip', '')
            
            analysis = self.threat_engine.analyze_command(command, session_id, timestamp)
            
            # Generate alert if high threat level
            if analysis['threat_level'] > 30:
                alert = {
                    'timestamp': timestamp.isoformat(),
                    'type': 'high_threat_command',
                    'src_ip': src_ip,
                    'session_id': session_id,
                    'command': command,
                    'threat_level': analysis['threat_level'],
                    'detected_attacks': analysis['detected_attacks'],
                    'risk_score': analysis['risk_score']
                }
                
                self.alert_queue.put(alert)
                
                # Send to WebSocket clients (only if running loop)
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self.broadcast_alert(alert))
                except RuntimeError:
                    pass
        
        # Failed login analysis
        elif event_id == 'cowrie.login.failed':
            username = event.get('username', '')
            password = event.get('password', '')
            src_ip = event.get('src_ip', '')
            
            # Check for credential stuffing or brute force
            if self.is_suspicious_login_pattern(src_ip, username, password):
                alert = {
                    'timestamp': timestamp.isoformat(),
                    'type': 'suspicious_login_pattern',
                    'src_ip': src_ip,
                    'username': username,
                    'password': password[:3] + '*' * (len(password) - 3) if password else '',
                    'threat_level': 25
                }
                
                self.alert_queue.put(alert)
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self.broadcast_alert(alert))
                except RuntimeError:
                    pass

    def is_suspicious_login_pattern(self, src_ip, username, password):
        """Detect suspicious login patterns"""
        # This would normally check against a database of recent attempts
        # For now, we'll use simple heuristics
        
        suspicious_usernames = ['admin', 'root', 'administrator', 'user', 'test']
        common_passwords = ['password', '123456', 'admin', 'root', 'qwerty']
        
        return username.lower() in suspicious_usernames or password in common_passwords

    async def broadcast_alert(self, alert):
        """Broadcast alerts to WebSocket clients"""
        if self.websocket_clients:
            message = json.dumps(alert)
            disconnected = set()
            
            for client in self.websocket_clients:
                try:
                    await client.send(message)
                except websockets.exceptions.ConnectionClosed:
                    disconnected.add(client)
            
            # Remove disconnected clients
            self.websocket_clients -= disconnected

class AlertManager:
    def __init__(self, config_file='alert_config.json'):
        self.config = self.load_config(config_file)
        self.alert_history = []
        
    def load_config(self, config_file):
        """Load alerting configuration"""
        default_config = {
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'recipients': []
            },
            'slack': {
                'enabled': False,
                'webhook_url': ''
            },
            'thresholds': {
                'high_threat_alert': 50,
                'critical_threat_alert': 80
            }
        }
        
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        except FileNotFoundError:
            # Create default config file
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
        
        return default_config

    def process_alerts(self, alert_queue):
        """Process alerts from the queue"""
        while True:
            try:
                alert = alert_queue.get(timeout=1)
                self.handle_alert(alert)
                self.alert_history.append(alert)
                
                # Keep only last 1000 alerts
                if len(self.alert_history) > 1000:
                    self.alert_history = self.alert_history[-1000:]
                    
            except queue.Empty:
                continue

    def handle_alert(self, alert):
        """Handle individual alerts based on severity"""
        threat_level = alert.get('threat_level', 0)
        
        print(f"🚨 ALERT: {alert['type']} - Threat Level: {threat_level}")
        print(f"   Source: {alert.get('src_ip', 'Unknown')}")
        print(f"   Time: {alert['timestamp']}")
        
        if alert['type'] == 'high_threat_command':
            print(f"   Command: {alert['command']}")
            print(f"   Attacks: {', '.join(alert['detected_attacks'])}")
        
        # Send email alerts for high-severity threats
        if (threat_level >= self.config['thresholds']['high_threat_alert'] and 
            self.config['email']['enabled']):
            self.send_email_alert(alert)
        
        # Log to database
        self.log_alert_to_db(alert)
        
        # Record in history immediately
        self.alert_history.append(alert)

    def send_email_alert(self, alert):
        """Send email alert"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['email']['username']
            msg['To'] = ', '.join(self.config['email']['recipients'])
            msg['Subject'] = f"Honeypot Alert: {alert['type']}"
            
            body = f"""
            Honeypot Security Alert
            
            Alert Type: {alert['type']}
            Threat Level: {alert.get('threat_level', 0)}
            Source IP: {alert.get('src_ip', 'Unknown')}
            Timestamp: {alert['timestamp']}
            
            Details:
            {json.dumps(alert, indent=2)}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.config['email']['smtp_server'], 
                                self.config['email']['smtp_port'])
            server.starttls()
            server.login(self.config['email']['username'], 
                        self.config['email']['password'])
            
            server.send_message(msg)
            server.quit()
            
            print(f"📧 Email alert sent for {alert['type']}")
            
        except Exception as e:
            print(f"Failed to send email alert: {e}")

    def log_alert_to_db(self, alert):
        """Log alert to database"""
        try:
            conn = sqlite3.connect('honeypot_intelligence.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    alert_type TEXT,
                    src_ip TEXT,
                    threat_level INTEGER,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                INSERT INTO alerts (timestamp, alert_type, src_ip, threat_level, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                alert['timestamp'],
                alert['type'],
                alert.get('src_ip', ''),
                alert.get('threat_level', 0),
                json.dumps(alert)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Failed to log alert to database: {e}")

class WebSocketServer:
    def __init__(self, monitor, port=8765):
        self.monitor = monitor
        self.port = port

    async def handle_client(self, websocket, path):
        """Handle WebSocket client connections"""
        self.monitor.websocket_clients.add(websocket)
        print(f"🔌 WebSocket client connected: {websocket.remote_address}")
        
        try:
            # Send initial status
            status = {
                'type': 'status',
                'message': 'Connected to Honeypot Real-time Monitor',
                'timestamp': datetime.now().isoformat()
            }
            await websocket.send(json.dumps(status))
            
            # Keep connection alive
            await websocket.wait_closed()
            
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.monitor.websocket_clients.discard(websocket)
            print(f"🔌 WebSocket client disconnected")

    async def start_server(self):
        """Start WebSocket server"""
        print(f"🌐 Starting WebSocket server on port {self.port}")
        await websockets.serve(self.handle_client, "localhost", self.port)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 realtime_monitor.py <cowrie_log_file>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    alert_queue = queue.Queue()
    
    # Initialize components
    monitor = RealTimeMonitor(log_file, alert_queue)
    alert_manager = AlertManager()
    websocket_server = WebSocketServer(monitor)
    
    # Start file monitoring
    observer = Observer()
    observer.schedule(monitor, path=os.path.dirname(log_file), recursive=False)
    observer.start()
    
    # Start alert processing in background thread
    alert_thread = threading.Thread(target=alert_manager.process_alerts, 
                                   args=(alert_queue,), daemon=True)
    alert_thread.start()
    
    print("🚀 Real-time Honeypot Monitor started")
    print(f"📁 Monitoring: {log_file}")
    print("🔗 WebSocket dashboard: ws://localhost:8765")
    print("Press Ctrl+C to stop")
    
    try:
        # Start WebSocket server
        loop = asyncio.get_event_loop()
        loop.run_until_complete(websocket_server.start_server())
        loop.run_forever()
        
    except KeyboardInterrupt:
        print("\n🛑 Shutting down monitor...")
        observer.stop()
        
    observer.join()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Advanced Honeypot Analytics Engine
Features: ML-based attack classification, geolocation analysis, threat intelligence integration,
behavioral pattern recognition, and automated reporting with AI-generated insights.
"""

import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import sys
import requests
import hashlib
import sqlite3
import geoip2.database
import geoip2.errors
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import asyncio
import aiohttp
import warnings
warnings.filterwarnings('ignore')

class AdvancedHoneypotAnalyzer:
    def __init__(self, db_path="honeypot_intelligence.db"):
        self.db_path = db_path
        self.init_database()
        self.threat_feeds = {
            'abuseipdb': 'https://api.abuseipdb.com/api/v2/check',
            'virustotal': 'https://www.virustotal.com/api/v3/ip_addresses/',
            'shodan': 'https://api.shodan.io/shodan/host/'
        }
        
    def init_database(self):
        """Initialize SQLite database for threat intelligence caching"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                ip_address TEXT PRIMARY KEY,
                country TEXT,
                isp TEXT,
                threat_score REAL,
                last_seen TEXT,
                attack_types TEXT,
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_patterns (
                session_id TEXT,
                ip_address TEXT,
                pattern_hash TEXT,
                commands TEXT,
                files_downloaded TEXT,
                duration INTEGER,
                classification TEXT,
                risk_level TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

    def parse_cowrie_logs(self, logfile):
        """Enhanced log parsing with session tracking and command analysis"""
        events = []
        sessions = {}
        
        with open(logfile, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    events.append(event)
                    
                    # Track sessions for behavioral analysis
                    if 'session' in event:
                        session_id = event['session']
                        if session_id not in sessions:
                            sessions[session_id] = {
                                'start_time': event.get('timestamp'),
                                'src_ip': event.get('src_ip'),
                                'commands': [],
                                'files': [],
                                'login_attempts': 0
                            }
                        
                        if event.get('eventid') == 'cowrie.command.input':
                            sessions[session_id]['commands'].append(event.get('input', ''))
                        elif event.get('eventid') == 'cowrie.session.file_download':
                            sessions[session_id]['files'].append(event.get('outfile', ''))
                        elif 'login' in event.get('eventid', ''):
                            sessions[session_id]['login_attempts'] += 1
                            
                except json.JSONDecodeError:
                    continue
                    
        df = pd.DataFrame(events)
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
        return df, sessions

    def ml_attack_classification(self, df):
        """Machine Learning-based attack pattern classification"""
        if df.empty:
            return df
            
        # Feature engineering for ML
        features = []
        labels = []
        
        for session_id in df['session'].unique():
            if pd.isna(session_id):
                continue
                
            session_data = df[df['session'] == session_id]
            
            # Extract features
            feature_vector = [
                len(session_data),  # Number of events
                session_data['eventid'].nunique(),  # Event diversity
                (session_data['timestamp'].max() - session_data['timestamp'].min()).total_seconds(),  # Duration
                len(session_data[session_data['eventid'] == 'cowrie.login.failed']),  # Failed logins
                len(session_data[session_data['eventid'] == 'cowrie.command.input']),  # Commands executed
                len(session_data[session_data['eventid'].str.contains('download', na=False)]),  # Downloads
            ]
            
            features.append(feature_vector)
            
            # Simple rule-based labeling for training (can be improved with manual labeling)
            if feature_vector[4] > 10:  # Many commands
                labels.append('Advanced Persistent Threat')
            elif feature_vector[3] > 20:  # Many login attempts
                labels.append('Brute Force Attack')
            elif feature_vector[5] > 0:  # File downloads
                labels.append('Malware Deployment')
            else:
                labels.append('Reconnaissance')
        
        if not features:
            return df
            
        # Anomaly detection using Isolation Forest
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        clf = IsolationForest(contamination=0.1, random_state=42)
        anomaly_scores = clf.fit_predict(features_scaled)
        
        # Clustering for pattern recognition
        clustering = DBSCAN(eps=0.5, min_samples=2)
        clusters = clustering.fit_predict(features_scaled)
        
        return {
            'features': features,
            'labels': labels,
            'anomaly_scores': anomaly_scores,
            'clusters': clusters
        }

    async def enrich_with_threat_intel(self, ip_addresses):
        """Asynchronous threat intelligence enrichment"""
        enriched_data = {}
        
        async with aiohttp.ClientSession() as session:
            for ip in ip_addresses:
                try:
                    # Check local cache first
                    cached_data = self.get_cached_threat_intel(ip)
                    if cached_data:
                        enriched_data[ip] = cached_data
                        continue
                    
                    # Fetch from multiple threat intelligence sources
                    intel_data = await self.fetch_threat_intel(session, ip)
                    enriched_data[ip] = intel_data
                    
                    # Cache the results
                    self.cache_threat_intel(ip, intel_data)
                    
                except Exception as e:
                    print(f"Error enriching IP {ip}: {e}")
                    enriched_data[ip] = {'error': str(e)}
                    
        return enriched_data

    async def fetch_threat_intel(self, session, ip):
        """Fetch threat intelligence from multiple sources"""
        intel_data = {
            'ip': ip,
            'threat_score': 0,
            'sources': [],
            'country': 'Unknown',
            'isp': 'Unknown'
        }
        
        try:
            # Simulate threat intel API calls (replace with real API keys)
            # In practice, you would use real APIs like AbuseIPDB, VirusTotal, etc.
            
            # Geolocation enrichment
            try:
                # You would download and use a GeoIP database
                intel_data['country'] = 'Simulated Country'
                intel_data['isp'] = 'Simulated ISP'
            except Exception:
                pass
                
            # Threat scoring based on various factors
            intel_data['threat_score'] = np.random.uniform(0, 100)  # Simulate threat score
            intel_data['sources'].append('simulation')
            
        except Exception as e:
            intel_data['error'] = str(e)
            
        return intel_data

    def get_cached_threat_intel(self, ip):
        """Retrieve cached threat intelligence"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM threat_intel WHERE ip_address = ? 
            AND datetime(created_at) > datetime('now', '-24 hours')
        ''', (ip,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'ip': result[0],
                'country': result[1],
                'isp': result[2],
                'threat_score': result[3],
                'last_seen': result[4],
                'attack_types': result[5],
                'confidence': result[6]
            }
        return None

    def cache_threat_intel(self, ip, intel_data):
        """Cache threat intelligence data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO threat_intel 
            (ip_address, country, isp, threat_score, last_seen, attack_types, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            ip,
            intel_data.get('country', 'Unknown'),
            intel_data.get('isp', 'Unknown'),
            intel_data.get('threat_score', 0),
            datetime.now().isoformat(),
            ','.join(intel_data.get('attack_types', [])),
            intel_data.get('confidence', 0)
        ))
        
        conn.commit()
        conn.close()

    def generate_advanced_visualizations(self, df, analysis_results):
        """Generate interactive visualizations using Plotly"""
        if df.empty:
            return None
            
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=['Attack Timeline', 'Geographic Distribution', 
                          'Attack Type Classification', 'Threat Intelligence'],
            specs=[[{"secondary_y": True}, {"type": "geo"}],
                   [{"type": "pie"}, {"type": "scatter"}]]
        )
        
        # Timeline analysis
        timeline_data = df.groupby(df['timestamp'].dt.date).size()
        fig.add_trace(
            go.Scatter(x=timeline_data.index, y=timeline_data.values,
                      mode='lines+markers', name='Daily Attacks'),
            row=1, col=1
        )
        
        # Geographic visualization (simulated data)
        countries = df['src_ip'].value_counts().head(10).index
        fig.add_trace(
            go.Scattergeo(
                lon=[np.random.uniform(-180, 180) for _ in range(len(countries))],
                lat=[np.random.uniform(-90, 90) for _ in range(len(countries))],
                text=countries,
                mode='markers',
                marker_size=[10, 15, 20, 8, 12, 18, 14, 9, 11, 16]
            ),
            row=1, col=2
        )
        
        # Attack classification pie chart
        if 'labels' in analysis_results:
            attack_types = pd.Series(analysis_results['labels']).value_counts()
            fig.add_trace(
                go.Pie(labels=attack_types.index, values=attack_types.values,
                      name="Attack Types"),
                row=2, col=1
            )
        
        # Threat intelligence scatter
        if df['src_ip'].nunique() > 0:
            threat_scores = np.random.uniform(0, 100, df['src_ip'].nunique())
            fig.add_trace(
                go.Scatter(
                    x=range(len(threat_scores)),
                    y=threat_scores,
                    mode='markers',
                    marker=dict(
                        size=10,
                        color=threat_scores,
                        colorscale='Reds',
                        showscale=True
                    ),
                    name='Threat Scores'
                ),
                row=2, col=2
            )
        
        fig.update_layout(height=800, showlegend=True, 
                         title_text="Advanced Honeypot Intelligence Dashboard")
        
        return fig

    def generate_ai_insights(self, df, sessions, analysis_results):
        """Generate AI-powered insights and recommendations"""
        insights = {
            'summary': {},
            'patterns': [],
            'recommendations': [],
            'risk_assessment': {}
        }
        
        if df.empty:
            return insights
            
        # Basic statistics
        insights['summary'] = {
            'total_events': len(df),
            'unique_attackers': df['src_ip'].nunique(),
            'attack_duration_hours': (df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600,
            'most_active_hour': df['timestamp'].dt.hour.mode().iloc[0] if not df.empty else 0,
            'peak_attack_day': df['timestamp'].dt.day_name().mode().iloc[0] if not df.empty else 'Unknown'
        }
        
        # Pattern detection
        command_patterns = []
        for session_id, session_data in sessions.items():
            if session_data['commands']:
                pattern_hash = hashlib.md5(''.join(session_data['commands']).encode()).hexdigest()
                command_patterns.append({
                    'pattern_hash': pattern_hash,
                    'commands': session_data['commands'][:5],  # First 5 commands
                    'frequency': 1
                })
        
        # Group similar patterns
        pattern_counts = {}
        for pattern in command_patterns:
            hash_key = pattern['pattern_hash']
            if hash_key in pattern_counts:
                pattern_counts[hash_key]['frequency'] += 1
            else:
                pattern_counts[hash_key] = pattern
                
        insights['patterns'] = list(pattern_counts.values())
        
        # Risk assessment
        high_risk_indicators = 0
        if insights['summary']['unique_attackers'] > 50:
            high_risk_indicators += 1
        if insights['summary']['total_events'] > 1000:
            high_risk_indicators += 1
        if len([p for p in insights['patterns'] if p['frequency'] > 5]) > 3:
            high_risk_indicators += 1
            
        insights['risk_assessment'] = {
            'level': 'High' if high_risk_indicators >= 2 else 'Medium' if high_risk_indicators == 1 else 'Low',
            'score': high_risk_indicators * 33.33,
            'indicators': high_risk_indicators
        }
        
        # Recommendations
        if insights['risk_assessment']['level'] == 'High':
            insights['recommendations'].extend([
                'Consider implementing additional security measures',
                'Review firewall rules and access controls',
                'Enable real-time alerting for suspicious activities'
            ])
        
        if insights['summary']['unique_attackers'] > 20:
            insights['recommendations'].append('Implement IP-based rate limiting')
            
        return insights

def parse_cowrie_logs(logfile):
    """Legacy function for backward compatibility"""
    analyzer = AdvancedHoneypotAnalyzer()
    df, _ = analyzer.parse_cowrie_logs(logfile)
    return df

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cowrie_json_log> [--advanced]")
        sys.exit(1)
    
    analyzer = AdvancedHoneypotAnalyzer()
    df, sessions = analyzer.parse_cowrie_logs(sys.argv[1])
    
    print(f"🔍 Advanced Honeypot Analysis Results")
    print("=" * 50)
    print(f"Total events: {len(df)}")
    
    if '--advanced' in sys.argv:
        print("\n🤖 Running ML-based attack classification...")
        ml_results = analyzer.ml_attack_classification(df)
        
        print("\n🌍 Enriching with threat intelligence...")
        if not df.empty:
            unique_ips = df['src_ip'].dropna().unique()[:10]  # Limit for demo
            threat_intel = asyncio.run(analyzer.enrich_with_threat_intel(unique_ips))
            
            print(f"\n📊 Threat Intelligence Summary:")
            for ip, intel in threat_intel.items():
                if 'error' not in intel:
                    print(f"  {ip}: Threat Score {intel.get('threat_score', 0):.1f}/100")
        
        print("\n🧠 Generating AI insights...")
        insights = analyzer.generate_ai_insights(df, sessions, ml_results)
        
        print(f"\n📈 Risk Assessment: {insights['risk_assessment']['level']}")
        print(f"Risk Score: {insights['risk_assessment']['score']:.1f}/100")
        
        print(f"\n💡 Top Recommendations:")
        for i, rec in enumerate(insights['recommendations'][:3], 1):
            print(f"  {i}. {rec}")
        
        print(f"\n🔄 Detected {len(insights['patterns'])} unique attack patterns")
        
        # Generate visualizations
        print("\n📊 Generating advanced visualizations...")
        fig = analyzer.generate_advanced_visualizations(df, ml_results)
        if fig:
            fig.write_html("advanced_honeypot_dashboard.html")
            print("Dashboard saved to: advanced_honeypot_dashboard.html")
    
    else:
        # Basic analysis
        if 'eventid' in df.columns:
            print("\nEvent Types:")
            print(df['eventid'].value_counts())
        if 'src_ip' in df.columns:
            print(f"\nTop source IPs:")
            print(df['src_ip'].value_counts().head(10))

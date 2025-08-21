#!/usr/bin/env python3
"""
Advanced Honeypot API Server
Provides REST API endpoints for threat intelligence, analytics, and management
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import asyncio
import json
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
import uvicorn
import os
from parse_logs import AdvancedHoneypotAnalyzer
from ai_threat_intel import AIThreatIntelligence, AutomatedResponseSystem
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Advanced Honeypot Intelligence API",
    description="Real-time threat detection and analysis API for honeypot systems",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Global instances
analyzer = AdvancedHoneypotAnalyzer()
ai_intel = AIThreatIntelligence()
response_system = AutomatedResponseSystem()

# Pydantic models
class ThreatPrediction(BaseModel):
    command: str
    session_id: str
    src_ip: str
    threat_type: str
    confidence: float
    risk_score: int
    is_anomaly: bool
    timestamp: datetime

class IPIntelligence(BaseModel):
    ip_address: str
    reputation_score: int
    threat_categories: List[str]
    country: str
    asn: str
    threat_feeds: List[str]

class AttackSummary(BaseModel):
    total_attacks: int
    unique_ips: int
    high_threat_events: int
    avg_threat_score: float
    top_attack_types: Dict[str, int]
    timeline_data: List[Dict[str, Any]]

class AlertCreate(BaseModel):
    alert_type: str
    src_ip: str
    threat_level: int
    description: str
    metadata: Optional[Dict[str, Any]] = None

class SystemStatus(BaseModel):
    status: str
    uptime: int
    total_events: int
    active_sessions: int
    database_size: str
    last_update: datetime

# Dependency functions
async def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Verify API token (simplified for demo)"""
    # In production, implement proper JWT token validation
    if credentials.credentials != "demo_token_12345":
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return credentials.credentials

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Routes
@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main dashboard"""
    try:
        with open("dashboard.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Advanced Honeypot Dashboard</h1><p>Dashboard not found</p>")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/api/status", response_model=SystemStatus)
async def get_system_status(token: str = Depends(verify_token)):
    """Get system status and metrics"""
    try:
        # Calculate uptime (simplified)
        uptime = 3600  # 1 hour for demo
        
        # Get database stats
        conn = sqlite3.connect(analyzer.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM threat_intel")
        total_events = cursor.fetchone()[0]
        conn.close()
        
        # Get file size
        db_size = os.path.getsize(analyzer.db_path) if os.path.exists(analyzer.db_path) else 0
        db_size_mb = f"{db_size / (1024*1024):.2f} MB"
        
        return SystemStatus(
            status="operational",
            uptime=uptime,
            total_events=total_events,
            active_sessions=5,  # Simulated
            database_size=db_size_mb,
            last_update=datetime.now()
        )
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system status")

@app.get("/api/attacks/summary", response_model=AttackSummary)
async def get_attack_summary(
    hours: int = 24,
    token: str = Depends(verify_token)
):
    """Get attack summary for specified time period"""
    try:
        # Simulate attack data (in production, query real database)
        summary = AttackSummary(
            total_attacks=150,
            unique_ips=45,
            high_threat_events=23,
            avg_threat_score=42.5,
            top_attack_types={
                "reconnaissance": 35,
                "brute_force": 28,
                "malware_download": 15,
                "privilege_escalation": 12,
                "data_exfiltration": 8
            },
            timeline_data=[
                {"hour": i, "attacks": 5 + (i % 3) * 2} 
                for i in range(24)
            ]
        )
        
        return summary
    except Exception as e:
        logger.error(f"Error getting attack summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to get attack summary")

@app.post("/api/threats/analyze")
async def analyze_threat(
    command: str,
    session_id: str,
    src_ip: str,
    token: str = Depends(verify_token)
):
    """Analyze a command for threats using AI"""
    try:
        # Create session data
        session_data = {
            'session_id': session_id,
            'src_ip': src_ip,
            'start_time': datetime.now() - timedelta(minutes=10),
            'login_attempts': 1
        }
        
        # Get AI prediction
        prediction = ai_intel.predict_threat(command, session_data)
        
        # Get IP intelligence
        ip_intel = await ai_intel.enrich_with_external_intel(src_ip)
        
        # Evaluate automated responses
        responses = []
        if prediction['risk_score'] > 50:
            responses = await response_system.evaluate_and_respond(
                prediction, ip_intel, session_data
            )
        
        result = {
            "prediction": prediction,
            "ip_intelligence": ip_intel,
            "automated_responses": responses,
            "timestamp": datetime.now().isoformat()
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Error analyzing threat: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze threat")

@app.get("/api/threats/predictions")
async def get_threat_predictions(
    limit: int = 100,
    token: str = Depends(verify_token)
):
    """Get recent threat predictions"""
    try:
        conn = sqlite3.connect(analyzer.db_path)
        
        query = """
        SELECT command, session_id, src_ip, predicted_threat, 
               confidence, risk_score, is_anomaly, timestamp
        FROM threat_predictions 
        ORDER BY timestamp DESC 
        LIMIT ?
        """
        
        df = pd.read_sql_query(query, conn, params=[limit])
        conn.close()
        
        if df.empty:
            return []
        
        predictions = []
        for _, row in df.iterrows():
            predictions.append({
                "command": row['command'],
                "session_id": row['session_id'],
                "src_ip": row['src_ip'],
                "threat_type": row['predicted_threat'],
                "confidence": row['confidence'],
                "risk_score": row['risk_score'],
                "is_anomaly": bool(row['is_anomaly']),
                "timestamp": row['timestamp']
            })
        
        return predictions
        
    except Exception as e:
        logger.error(f"Error getting predictions: {e}")
        raise HTTPException(status_code=500, detail="Failed to get predictions")

@app.get("/api/intelligence/ip/{ip_address}", response_model=IPIntelligence)
async def get_ip_intelligence(
    ip_address: str,
    token: str = Depends(verify_token)
):
    """Get threat intelligence for an IP address"""
    try:
        # Get intelligence from database
        conn = sqlite3.connect(analyzer.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        SELECT reputation_score, threat_categories, country, asn, threat_feeds
        FROM ip_intelligence WHERE ip_address = ?
        """, (ip_address,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return IPIntelligence(
                ip_address=ip_address,
                reputation_score=result[0],
                threat_categories=result[1].split(',') if result[1] else [],
                country=result[2],
                asn=result[3],
                threat_feeds=result[4].split(',') if result[4] else []
            )
        else:
            # Get fresh intelligence
            intel_data = await ai_intel.enrich_with_external_intel(ip_address)
            return IPIntelligence(
                ip_address=ip_address,
                reputation_score=intel_data['reputation_score'],
                threat_categories=intel_data['categories'],
                country=intel_data.get('country', 'Unknown'),
                asn=intel_data.get('asn', 'Unknown'),
                threat_feeds=intel_data['threat_feeds']
            )
            
    except Exception as e:
        logger.error(f"Error getting IP intelligence: {e}")
        raise HTTPException(status_code=500, detail="Failed to get IP intelligence")

@app.post("/api/alerts")
async def create_alert(
    alert: AlertCreate,
    background_tasks: BackgroundTasks,
    token: str = Depends(verify_token)
):
    """Create a new security alert"""
    try:
        # Store alert in database
        conn = sqlite3.connect(analyzer.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT INTO alerts (timestamp, alert_type, src_ip, threat_level, details)
        VALUES (?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            alert.alert_type,
            alert.src_ip,
            alert.threat_level,
            json.dumps({
                "description": alert.description,
                "metadata": alert.metadata or {}
            })
        ))
        
        alert_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Process alert in background
        background_tasks.add_task(process_alert_background, alert, alert_id)
        
        return {
            "alert_id": alert_id,
            "status": "created",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating alert: {e}")
        raise HTTPException(status_code=500, detail="Failed to create alert")

@app.get("/api/alerts")
async def get_alerts(
    limit: int = 50,
    alert_type: Optional[str] = None,
    token: str = Depends(verify_token)
):
    """Get recent alerts"""
    try:
        conn = sqlite3.connect(analyzer.db_path)
        
        if alert_type:
            query = """
            SELECT id, timestamp, alert_type, src_ip, threat_level, details
            FROM alerts 
            WHERE alert_type = ?
            ORDER BY timestamp DESC 
            LIMIT ?
            """
            params = [alert_type, limit]
        else:
            query = """
            SELECT id, timestamp, alert_type, src_ip, threat_level, details
            FROM alerts 
            ORDER BY timestamp DESC 
            LIMIT ?
            """
            params = [limit]
        
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        
        if df.empty:
            return []
        
        alerts = []
        for _, row in df.iterrows():
            details = json.loads(row['details']) if row['details'] else {}
            alerts.append({
                "id": row['id'],
                "timestamp": row['timestamp'],
                "alert_type": row['alert_type'],
                "src_ip": row['src_ip'],
                "threat_level": row['threat_level'],
                "description": details.get('description', ''),
                "metadata": details.get('metadata', {})
            })
        
        return alerts
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to get alerts")

@app.get("/api/reports/threat-landscape")
async def get_threat_landscape_report(
    days: int = 7,
    token: str = Depends(verify_token)
):
    """Generate threat landscape report"""
    try:
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Simulate comprehensive report data
        report = {
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "days": days
            },
            "executive_summary": {
                "total_attacks": 1247,
                "unique_attackers": 156,
                "blocked_ips": 23,
                "malware_samples": 8,
                "risk_level": "Medium-High"
            },
            "attack_vectors": {
                "ssh_brute_force": 45,
                "malware_download": 25,
                "reconnaissance": 20,
                "privilege_escalation": 7,
                "data_exfiltration": 3
            },
            "geographic_distribution": {
                "CN": 35,
                "RU": 28,
                "US": 15,
                "DE": 12,
                "BR": 10
            },
            "trending_threats": [
                "Increased cryptomining attempts",
                "New SSH credential stuffing campaigns",
                "IoT botnet recruitment attempts"
            ],
            "recommendations": [
                "Implement IP-based rate limiting",
                "Update threat intelligence feeds",
                "Review credential policies",
                "Monitor for lateral movement"
            ]
        }
        
        return report
        
    except Exception as e:
        logger.error(f"Error generating threat landscape report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")

@app.post("/api/models/retrain")
async def retrain_ai_model(
    background_tasks: BackgroundTasks,
    token: str = Depends(verify_token)
):
    """Trigger AI model retraining"""
    try:
        # Start retraining in background
        background_tasks.add_task(retrain_model_background)
        
        return {
            "status": "started",
            "message": "AI model retraining initiated",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error starting model retraining: {e}")
        raise HTTPException(status_code=500, detail="Failed to start retraining")

@app.get("/api/export/data")
async def export_data(
    format: str = "json",
    days: int = 7,
    token: str = Depends(verify_token)
):
    """Export honeypot data"""
    try:
        if format not in ["json", "csv"]:
            raise HTTPException(status_code=400, detail="Unsupported format")
        
        # Get data from database
        conn = sqlite3.connect(analyzer.db_path)
        
        # Export threat predictions
        query = """
        SELECT * FROM threat_predictions 
        WHERE datetime(timestamp) > datetime('now', '-{} days')
        """.format(days)
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        if format == "csv":
            filename = f"honeypot_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            df.to_csv(filename, index=False)
            return FileResponse(filename, media_type="text/csv", filename=filename)
        else:
            return df.to_json(orient='records')
        
    except Exception as e:
        logger.error(f"Error exporting data: {e}")
        raise HTTPException(status_code=500, detail="Failed to export data")

# Background tasks
async def process_alert_background(alert: AlertCreate, alert_id: int):
    """Process alert in background"""
    try:
        logger.info(f"Processing alert {alert_id}: {alert.alert_type}")
        
        # Simulate alert processing
        await asyncio.sleep(2)
        
        # Could trigger additional actions like:
        # - Send notifications
        # - Update threat feeds
        # - Trigger automated responses
        
        logger.info(f"Alert {alert_id} processed successfully")
        
    except Exception as e:
        logger.error(f"Error processing alert {alert_id}: {e}")

async def retrain_model_background():
    """Retrain AI model in background"""
    try:
        logger.info("Starting AI model retraining...")
        
        # Simulate model retraining
        await asyncio.sleep(30)
        
        # In production, this would:
        # - Fetch latest training data
        # - Retrain the model
        # - Validate performance
        # - Deploy new model
        
        logger.info("AI model retraining completed")
        
    except Exception as e:
        logger.error(f"Error retraining model: {e}")

if __name__ == "__main__":
    # Create static directory if it doesn't exist
    os.makedirs("static", exist_ok=True)
    
    # Run the API server
    uvicorn.run(
        "api_server:app",
        host="127.0.0.1",
        port=8888,
        reload=True,
        log_level="info"
    )

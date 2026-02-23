
# modules/threat.py

from models.db import Database
from sklearn.ensemble import IsolationForest
import numpy as np

# Thresholds
BRUTE_FORCE_THRESHOLD = 5      # 5 failed logins = alert
TIME_WINDOW_SECONDS = 300      # within 5 minutes

def check_brute_force(username: str, db: Database):
    """
    Check if a user is under brute force attack
    Returns alert if threshold exceeded
    """
    attempts = db.get_recent_failed_attempts(username, TIME_WINDOW_SECONDS)
    
    if len(attempts) >= BRUTE_FORCE_THRESHOLD:
        alert = {
            "type": "BRUTE_FORCE",
            "target": username,
            "severity": "HIGH",
            "message": f"{len(attempts)} failed login attempts in 5 minutes for user '{username}'",
        }
        db.save_incident(alert)
        print(f"[THREAT] Brute force detected on user '{username}'")
        return alert
    
    return None


def run_anomaly_detection(db: Database):
    """
    Use machine learning to detect unusual login patterns
    Uses Isolation Forest algorithm
    """
    logs = db.get_all_login_logs()
    
    if len(logs) < 10:
        return {
            "message": "Not enough data for anomaly detection (need at least 10 login records)",
            "anomalies_detected": 0
        }

    # Convert to feature matrix
    X = np.array([[log['hour'], log['failed_count']] for log in logs])
    
    # Train Isolation Forest model
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)
    predictions = model.predict(X)

    # Find anomalies (predictions = -1 means anomaly)
    anomalies = [logs[i] for i, p in enumerate(predictions) if p == -1]
    
    if anomalies:
        for anomaly in anomalies:
            incident = {
                "type": "ANOMALY",
                "severity": "MEDIUM",
                "message": f"Unusual login pattern detected at hour {anomaly['hour']} — {anomaly['failed_count']} failed attempts"
            }
            db.save_incident(incident)
        print(f"[THREAT] {len(anomalies)} anomalies detected")
    
    return {
        "anomalies_detected": len(anomalies),
        "details": anomalies,
        "total_patterns_analyzed": len(logs)
    }


def get_threat_summary(db: Database):
    """
    Get overall threat status
    """
    incidents = db.get_all_incidents()
    
    # Count by severity
    high = len([i for i in incidents if i['severity'] == 'HIGH' and i['status'] == 'OPEN'])
    medium = len([i for i in incidents if i['severity'] == 'MEDIUM' and i['status'] == 'OPEN'])
    low = len([i for i in incidents if i['severity'] == 'LOW' and i['status'] == 'OPEN'])
    
    # Determine threat level
    if high > 0:
        threat_level = "CRITICAL"
    elif medium > 2:
        threat_level = "ELEVATED"
    elif medium > 0 or low > 0:
        threat_level = "GUARDED"
    else:
        threat_level = "LOW"
    
    return {
        "threat_level": threat_level,
        "open_incidents": {
            "high": high,
            "medium": medium,
            "low": low
        },
        "total_incidents": len(incidents)
    }
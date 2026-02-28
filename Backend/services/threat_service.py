# Backend/services/threat_service.py

from models.db import Database
from sklearn.ensemble import IsolationForest
import numpy as np

class ThreatService:
    def __init__(self, db: Database):
        self.db = db

    def get_summary(self):
        incidents = self.db.get_all_incidents()
        high = len([i for i in incidents if i['severity'] == 'HIGH' and i['status'] == 'OPEN'])
        medium = len([i for i in incidents if i['severity'] == 'MEDIUM' and i['status'] == 'OPEN'])
        low = len([i for i in incidents if i['severity'] == 'LOW' and i['status'] == 'OPEN'])
        
        if high > 0: level = "CRITICAL"
        elif medium > 2: level = "ELEVATED"
        elif medium > 0 or low > 0: level = "GUARDED"
        else: level = "LOW"
        
        return {
            "threat_level": level,
            "open_incidents": {"high": high, "medium": medium, "low": low},
            "total_incidents": len(incidents)
        }

    def run_scan(self):
        logs = self.db.get_all_login_logs()
        if len(logs) < 10:
            return {"message": "Insufficient data", "anomalies_detected": 0}

        X = np.array([[log['hour'], log['failed_count']] for log in logs])
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X)
        predictions = model.predict(X)
        anomalies = [logs[i] for i, p in enumerate(predictions) if p == -1]
        
        for anomaly in anomalies:
            self.db.save_incident({
                "type": "ANOMALY",
                "severity": "MEDIUM",
                "message": f"Login anomaly at hour {anomaly['hour']}"
            })
        return {"anomalies_detected": len(anomalies), "details": anomalies}
    def check_brute_force(self, username):
        recent_fails = self.db.get_recent_failed_attempts(username, 3600) # Past 1 hour
        count = len(recent_fails)
        
        status = "NORMAL"
        if count >= 10: status = "CRITICAL_ATTACK"
        elif count >= 5: status = "SUSPICIOUS_ACTIVITY"
        
        return {
            "username": username,
            "failed_attempts_1h": count,
            "threat_status": status
        }

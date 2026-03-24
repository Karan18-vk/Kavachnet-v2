from database import db
from models.user import ThreatLog, Incident, ActivityLog, User
from datetime import datetime, timedelta
import sqlalchemy as sa

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

class ThreatService:
    def __init__(self):
        pass

    def get_summary(self, institution_id=None):
        query = Incident.query
        if institution_id:
            query = query.filter_by(institution_id=institution_id)
        
        incidents = query.all()
        high = len([i for i in incidents if i.severity == 'HIGH' and i.status == 'OPEN'])
        medium = len([i for i in incidents if i.severity == 'MEDIUM' and i.status == 'OPEN'])
        low = len([i for i in incidents if i.severity == 'LOW' and i.status == 'OPEN'])
        
        if high > 0: level = "CRITICAL"
        elif medium > 2: level = "ELEVATED"
        elif medium > 0 or low > 0: level = "GUARDED"
        else: level = "LOW"
        
        return {
            "threat_level": level,
            "open_incidents": {"high": high, "medium": medium, "low": low},
            "total_incidents": len(incidents)
        }

    def log_threat(self, threat_type, status, risk_level, user_email=None, details=None):
        user = User.query.filter_by(email=user_email).first() if user_email else None
        
        new_log = ThreatLog(
            type=threat_type,
            status=status,
            risk_level=risk_level,
            user_id=user.id if user else None,
            institution_id=user.institution_id if user else None,
            details=details
        )
        
        try:
            db.session.add(new_log)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            print(f"Failed to log threat: {e}")
            return False

    def get_threat_logs(self, institution_id=None, limit=100):
        query = ThreatLog.query
        if institution_id:
            query = query.filter_by(institution_id=institution_id)
        
        logs = query.order_by(ThreatLog.created_at.desc()).limit(limit).all()
        return [log.to_dict() for log in logs]

    def get_dashboard_stats(self, institution_id=None):
        # Aggregate stats for dashboard
        now = datetime.utcnow()
        today_start = datetime(now.year, now.month, now.day)
        
        threats_query = ThreatLog.query
        incidents_query = Incident.query
        
        if institution_id:
            threats_query = threats_query.filter_by(institution_id=institution_id)
            incidents_query = incidents_query.filter_by(institution_id=institution_id)
            
        total_threats = threats_query.count()
        blocked_threats = threats_query.filter_by(status='blocked').count()
        active_incidents = incidents_query.filter_by(status='OPEN').count()
        today_threats = threats_query.filter(ThreatLog.created_at >= today_start).count()
        
        return {
            "total_threats": total_threats,
            "blocked_threats": blocked_threats,
            "active_incidents": active_incidents,
            "today_threats": today_threats,
            "threat_level": self.get_summary(institution_id)["threat_level"]
        }

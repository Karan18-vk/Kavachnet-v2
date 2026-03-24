from database import db
from models.user import Incident, User, Institution
from flask_jwt_extended import get_jwt
from datetime import datetime
import sqlalchemy as sa

class IncidentService:
    def __init__(self):
        pass

    def get_incidents_list(self):
        claims = get_jwt()
        inst_id = claims.get("institution_id")
        role = claims.get("role")

        query = Incident.query
        if role != "superadmin":
            if not inst_id:
                return {"incidents": [], "count": 0}
            query = query.filter_by(institution_id=inst_id)
        
        incidents = query.order_by(Incident.created_at.desc()).all()
        return {"incidents": [inc.to_dict() for inc in incidents], "count": len(incidents)}

    def get_incident(self, incident_id):
        inc = Incident.query.get(incident_id)
        if not inc: return {"error": "Incident not found."}, 404
        return inc.to_dict(), 200

    def update_status(self, incident_id, status):
        inc = Incident.query.get(incident_id)
        if not inc: return {"error": "Incident not found."}, 404
        
        try:
            inc.status = status
            db.session.commit()
            return {"message": "Incident status updated."}, 200
        except Exception as e:
            db.session.rollback()
            return {"error": f"Failed to update incident: {str(e)}"}, 500

    def generate_report(self):
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        import io

        claims = get_jwt()
        inst_id = claims.get("institution_id")
        role = claims.get("role")

        query = Incident.query
        if role != "superadmin":
            query = query.filter_by(institution_id=inst_id)
        
        incidents = query.order_by(Incident.created_at.desc()).all()
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        
        # Header
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, height - 50, "KavachNet — Security Incident Report")
        
        c.setFont("Helvetica", 10)
        c.drawString(50, height - 70, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(50, height - 85, f"Total incidents scoped: {len(incidents)}")
        
        # Draw line
        c.line(50, height - 110, width - 50, height - 110)
        
        # Incidents list
        y = height - 140
        for i, inc in enumerate(incidents):
            if y < 100:
                c.showPage()
                y = height - 50
            
            c.setFont("Helvetica-Bold", 11)
            c.drawString(50, y, f"#{i+1} — [{inc.severity}] {inc.threat_type or 'Unknown'}")
            c.setFont("Helvetica", 9)
            c.drawString(70, y - 15, f"Status: {inc.status} | Date: {inc.created_at.isoformat() if inc.created_at else 'N/A'}")
            
            message = inc.description or "No description provided."
            if len(message) > 80: message = message[:77] + "..."
            c.drawString(70, y - 30, f"Detail: {message}")
            c.line(50, y - 45, width - 50, y - 45)
            y -= 60
        
        c.save()
        buffer.seek(0)
        return buffer

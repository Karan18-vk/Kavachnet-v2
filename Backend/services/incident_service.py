# Backend/services/incident_service.py

from models.db import Database
from flask_jwt_extended import get_jwt

class IncidentService:
    def __init__(self, db: Database):
        self.db = db

    def get_incidents_list(self):
        claims = get_jwt()
        inst_code = claims.get("institution_code") if claims.get("role") != "superadmin" else None
        incidents = self.db.get_all_incidents(institution_code=inst_code)
        return {"incidents": incidents, "count": len(incidents)}

    def get_incident(self, incident_id):
        inc = self.db.get_incident_by_id(incident_id) # Need to ensure this exists in db.py
        if not inc: return {"error": "Incident not found."}, 404
        return inc, 200

    def update_status(self, incident_id, status):
        self.db.update_incident_status(incident_id, status)
        return {"message": "Incident updated."}, 200
    def generate_report(self):
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        import datetime
        import io

        claims = get_jwt()
        inst_code = claims.get("institution_code") if claims.get("role") != "superadmin" else None
        incidents = self.db.get_all_incidents(institution_code=inst_code)
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        
        # Header
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, height - 50, "KavachNet — Security Incident Report")
        
        c.setFont("Helvetica", 10)
        c.drawString(50, height - 70, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
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
            c.drawString(50, y, f"#{i+1} — [{inc['severity']}] {inc['type']}")
            c.setFont("Helvetica", 9)
            c.drawString(70, y - 15, f"Status: {inc['status']} | Date: {inc['timestamp'][:19]}")
            
            message = inc['message']
            if len(message) > 80: message = message[:77] + "..."
            c.drawString(70, y - 30, f"Detail: {message}")
            c.line(50, y - 45, width - 50, y - 45)
            y -= 60
        
        c.save()
        buffer.seek(0)
        return buffer

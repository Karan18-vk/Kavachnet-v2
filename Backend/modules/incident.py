
# modules/incident.py

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from models.db import Database
import datetime
import io

def get_incidents(db: Database, institution_code=None):
    """Get incidents, optionally scoped to an institution"""
    return db.get_all_incidents(institution_code=institution_code)


def get_incident_by_id(incident_id: str, db: Database):
    """Get a specific incident by ID"""
    incidents = db.get_all_incidents()
    for inc in incidents:
        if inc['id'] == incident_id:
            return inc
    return None


def update_status(incident_id: str, new_status: str, db: Database):
    """Update incident status"""
    valid_statuses = ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"]
    
    if new_status not in valid_statuses:
        return {"error": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"}, 400
    
    db.update_incident_status(incident_id, new_status)
    return {"message": f"Incident {incident_id} marked as {new_status}"}, 200


def generate_pdf_report(db: Database):
    """
    Generate a PDF incident report
    Returns a BytesIO buffer containing the PDF
    """
    incidents = db.get_all_incidents()
    buffer = io.BytesIO()
    
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    
    # Header
    c.setFont("Helvetica-Bold", 20)
    c.drawString(50, height - 50, "KavachNet — Security Incident Report")
    
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 70, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(50, height - 85, f"Total Incidents: {len(incidents)}")
    
    # Count by status
    open_count = len([i for i in incidents if i['status'] == 'OPEN'])
    investigating = len([i for i in incidents if i['status'] == 'INVESTIGATING'])
    resolved = len([i for i in incidents if i['status'] == 'RESOLVED'])
    
    c.drawString(50, height - 100, f"Open: {open_count} | Investigating: {investigating} | Resolved: {resolved}")
    
    # Draw line
    c.line(50, height - 110, width - 50, height - 110)
    
    # Incidents list
    y = height - 140
    
    if not incidents:
        c.setFont("Helvetica-Oblique", 12)
        c.drawString(50, y, "No incidents recorded yet.")
    else:
        for i, inc in enumerate(incidents):
            # Check if we need a new page
            if y < 100:
                c.showPage()
                y = height - 50
            
            # Incident header
            c.setFont("Helvetica-Bold", 11)
            severity_color = {
                "HIGH": "red",
                "MEDIUM": "orange", 
                "LOW": "green"
            }.get(inc['severity'], "black")
            
            c.drawString(50, y, f"#{i+1} — [{inc['severity']}] {inc['type']}")
            
            # Incident details
            c.setFont("Helvetica", 9)
            c.drawString(70, y - 15, f"Status: {inc['status']}")
            c.drawString(70, y - 28, f"Time: {inc['timestamp'][:19]}")
            
            # Message (wrap if too long)
            message = inc['message']
            if len(message) > 80:
                message = message[:77] + "..."
            c.drawString(70, y - 41, f"Message: {message}")
            
            # Draw separator line
            c.line(50, y - 50, width - 50, y - 50)
            
            y -= 70
    
    # Footer
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(50, 30, "KavachNet Cyber Security System — Municipal Corporation of Delhi")
    c.drawString(50, 20, f"Report ID: {datetime.datetime.now().strftime('%Y%m%d%H%M%S')}")
    
    c.save()
    buffer.seek(0)
    
    return buffer


def get_incident_statistics(db: Database):
    """Get statistics about incidents"""
    incidents = db.get_all_incidents()
    
    stats = {
        "total": len(incidents),
        "by_severity": {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        },
        "by_status": {
            "OPEN": 0,
            "INVESTIGATING": 0,
            "RESOLVED": 0,
            "CLOSED": 0
        },
        "by_type": {}
    }
    
    for inc in incidents:
        # Count by severity
        if inc['severity'] in stats['by_severity']:
            stats['by_severity'][inc['severity']] += 1
        
        # Count by status
        if inc['status'] in stats['by_status']:
            stats['by_status'][inc['status']] += 1
        
        # Count by type
        inc_type = inc['type']
        if inc_type not in stats['by_type']:
            stats['by_type'][inc_type] = 0
        stats['by_type'][inc_type] += 1
    
    return stats
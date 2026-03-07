from flask import Blueprint, request
from utils.security import superadmin_required
from utils.response import api_response, api_error
from models.db import Database

admin_bp = Blueprint('admin', __name__)
db = Database()

@admin_bp.route("/email-logs", methods=["GET"])
@superadmin_required
def get_email_logs():
    """
    SuperAdmin observability endpoint for viewing masked email delivery 
    states and anomaly block events.
    """
    try:
        limit = request.args.get("limit", 100, type=int)
        log_type = request.args.get("type", None)
        status = request.args.get("status", None)
        
        logs = db.get_email_logs(limit=limit, log_type=log_type, status=status)
        return api_response(data=logs)
    except Exception as e:
        return api_error("An internal error occurred", code=500)

@admin_bp.route("/debug", methods=["GET"])
def debug_queue():
    try:
        conn = db._connect()
        q = conn.execute("SELECT * FROM email_queue ORDER BY created_at DESC LIMIT 5").fetchall()
        l = conn.execute("SELECT * FROM email_logs ORDER BY created_at DESC LIMIT 5").fetchall()
        i = conn.execute("SELECT id, name, status FROM institutions").fetchall()
        u = conn.execute("SELECT id, username FROM users").fetchall()
        return api_response(data={"queue": q, "logs": l, "institutions": i, "users": u})
    except Exception as e:
        return api_error(str(e))

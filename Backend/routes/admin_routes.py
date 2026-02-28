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

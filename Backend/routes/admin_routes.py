from flask import Blueprint, request
from utils.security import superadmin_required
from utils.response import api_response, api_error
from models.user import EmailQueue, Institution, User
from database import db

admin_bp = Blueprint('admin', __name__)

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
        
        query = EmailQueue.query
        if log_type:
            query = query.filter_by(type=log_type)
        if status:
            query = query.filter_by(status=status)
            
        logs = query.order_by(EmailQueue.created_at.desc()).limit(limit).all()
        return api_response(data=[log.to_dict() for log in logs])
    except Exception as e:
        return api_error(f"An internal error occurred: {str(e)}", code=500)

@admin_bp.route("/debug", methods=["GET"])
@superadmin_required
def debug_queue():
    try:
        q = EmailQueue.query.order_by(EmailQueue.created_at.desc()).limit(5).all()
        i = Institution.query.limit(5).all()
        u = User.query.limit(5).all()
        return api_response(data={
            "queue": [email.to_dict() for email in q],
            "institutions": [inst.to_dict() for inst in i],
            "users": [user.to_dict() for user in u]
        })
    except Exception as e:
        return api_error(str(e))

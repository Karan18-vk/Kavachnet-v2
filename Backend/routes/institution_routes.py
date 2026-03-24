from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt
from services.institution_service import InstitutionService
from utils.validation import validate_payload, sanitize_input
from utils.response import api_response, api_error
from utils.security import superadmin_required, admin_or_above_required
from models.user import User, Institution, ActivityLog
from database import db

institution_bp = Blueprint('institutions', __name__)
inst_service = InstitutionService()

@institution_bp.route("/request", methods=["POST"])
@validate_payload({"name": str, "email": str})
def request_institution():
    data = {k: sanitize_input(v) for k, v in request.json.items()}
    return inst_service.request_institution(data)

@institution_bp.route("/validate/<code>", methods=["GET"])
def validate_institution_code(code):
    return inst_service.validate_code(sanitize_input(code))

@institution_bp.route("/all", methods=["GET"])
@superadmin_required
def get_all_institutions():
    return api_response(data=inst_service.get_all_institutions())

@institution_bp.route("/<institution_id>/approve", methods=["POST"])
@superadmin_required
def approve_institution(institution_id):
    return inst_service.approve_institution(sanitize_input(institution_id))

@institution_bp.route("/<institution_id>/reject", methods=["POST"])
@superadmin_required
@validate_payload({"reason": str})
def reject_institution(institution_id):
    data = request.json
    reason = sanitize_input(data.get("reason", "No reason provided"))
    return inst_service.reject_institution(sanitize_input(institution_id), reason)

# ── Member Management (Admin Dashboard) ──────────────────
@institution_bp.route("/members", methods=["GET"])
@admin_or_above_required
def get_members():
    """Returns users belonging to the admin's institution."""
    claims = get_jwt()
    role = claims.get("role")
    inst_id = claims.get("institution_id")
    
    if role == "superadmin":
        members = User.query.all()
        return api_response(data=[m.to_dict() for m in members])
    
    if not inst_id:
        return api_error("No institution associated with your account.", code=400)
    
    members = User.query.filter_by(institution_id=inst_id).all()
    return api_response(data=[m.to_dict() for m in members])

@institution_bp.route("/members/<user_id>/<action>", methods=["POST"])
@admin_or_above_required
def update_member_status(user_id, action):
    """Approve or reject a staff member."""
    action = sanitize_input(action).lower()
    user_id = sanitize_input(user_id)
    
    if action not in ("approve", "reject"):
        return api_error("Invalid action. Must be 'approve' or 'reject'.", code=400)
    
    new_status = "approved" if action == "approve" else "rejected"
    
    try:
        user = User.query.get(user_id)
        if not user:
            return api_error("User not found.", code=404)
        user.status = new_status
        
        # Log activity
        activity = ActivityLog(user_id=user.id, action=f"MEMBER_{action.upper()}")
        db.session.add(activity)
        db.session.commit()
        
        return api_response(message=f"User {action}d successfully.")
    except Exception as e:
        db.session.rollback()
        return api_error(f"Failed to {action} user: {str(e)}", code=500)

@institution_bp.route("/pending-staff", methods=["GET"])
@admin_or_above_required
def get_pending_staff():
    """Returns pending staff for admin's institution."""
    claims = get_jwt()
    inst_id = claims.get("institution_id")
    
    if not inst_id:
        return api_error("No institution associated.", code=400)
    
    pending = User.query.filter_by(institution_id=inst_id, status='pending').all()
    return api_response(data=[p.to_dict() for p in pending])

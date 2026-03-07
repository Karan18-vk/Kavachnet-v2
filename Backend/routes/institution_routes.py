from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt
from models.db import Database
from services.institution_service import InstitutionService
from utils.validation import validate_payload, sanitize_input
from utils.response import api_response, api_error
from utils.security import superadmin_required, admin_or_above_required

institution_bp = Blueprint('institutions', __name__)
db = Database()
inst_service = InstitutionService(db)

@institution_bp.route("/request", methods=["POST"])
@validate_payload({"name": str, "email": str, "contact_person": str})
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

@institution_bp.route("/<institution_id>/rotate", methods=["POST"])
@superadmin_required
def rotate_institution_code(institution_id):
    return inst_service.rotate_institution_code(sanitize_input(institution_id))

# ── Member Management (Admin Dashboard) ──────────────────
@institution_bp.route("/members", methods=["GET"])
@admin_or_above_required
def get_members():
    """Returns users belonging to the admin's institution."""
    claims = get_jwt()
    role = claims.get("role")
    inst_code = claims.get("institution_code")
    
    # SuperAdmin can view all users; admins only see their institution
    if role == "superadmin":
        # Return all users across institutions (limited view)
        all_institutions = db.get_all_institutions()
        members = []
        for inst in all_institutions:
            code = inst.get("institution_code")
            if code:
                users = db.get_users_by_institution(code)
                members.extend(users)
        return api_response(data=members)
    
    if not inst_code:
        return api_error("No institution associated with your account.", code=400)
    
    members = db.get_users_by_institution(inst_code)
    return api_response(data=members)

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
        db.update_user_status(user_id, new_status)
        db.save_audit_log("admin", f"MEMBER_{action.upper()}", "user", user_id)
        return api_response(message=f"User {action}d successfully.")
    except Exception as e:
        return api_error(f"Failed to {action} user.", code=500)

@institution_bp.route("/pending-staff", methods=["GET"])
@admin_or_above_required
def get_pending_staff():
    """Returns pending staff for admin's institution."""
    claims = get_jwt()
    inst_code = claims.get("institution_code")
    
    if not inst_code:
        return api_error("No institution associated.", code=400)
    
    pending = db.get_pending_staff(inst_code)
    return api_response(data=pending)

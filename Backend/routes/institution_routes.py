from flask import Blueprint, request
from models.db import Database
from services.institution_service import InstitutionService
from utils.validation import validate_payload, sanitize_input
from utils.response import api_response, api_error
from utils.security import superadmin_required

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


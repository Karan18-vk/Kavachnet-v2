from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from services.auth_service import AuthService
from utils.validation import validate_payload, sanitize_input
from utils.response import api_response, api_error
from models.user import User

auth_bp = Blueprint('auth', __name__)
auth_service = AuthService()

@auth_bp.route("/register", methods=["POST"])
@validate_payload({
    "name": str, "email": str, "password": str, "institution_code": str
})
def register():
    data = {k: sanitize_input(v) for k, v in request.json.items()}
    return auth_service.register_user(data)

@auth_bp.route("/login", methods=["POST"])
@validate_payload({"email": str, "password": str})
def login():
    data = {k: sanitize_input(v) for k, v in request.json.items()}
    return auth_service.login(data)

@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    
    if not user:
        return api_error("User not found", code=404)
    
    new_access_token = create_access_token(
        identity=current_user_email,
        additional_claims={
            "role": user.role,
            "institution_id": user.institution_id,
            "name": user.name
        }
    )
    return api_response(data={"access_token": new_access_token})

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_me():
    current_user_email = get_jwt_identity()
    return auth_service.get_current_user_info(current_user_email)

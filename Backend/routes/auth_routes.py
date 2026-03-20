# Backend/routes/auth_routes.py

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, create_refresh_token
from services.auth_service import AuthService
from models.db import Database
from utils.validation import validate_payload, sanitize_input
from utils.response import api_response, api_error
from utils.logger import security_logger
from config import Config
import os

auth_bp = Blueprint('auth', __name__)

# Lazy loader for services to prevent import-time DB connection attempts
def get_auth_service():
    from models.db import Database
    from services.auth_service import AuthService
    return AuthService(Database())

@auth_bp.route("/register/admin", methods=["POST"])
@validate_payload({
    "username": str, "password": str, "email": str, "institution_code": str
})
def register_admin():
    data = {k: sanitize_input(v) for k, v in request.json.items()}
    return get_auth_service().register_admin(data)

@auth_bp.route("/register/staff", methods=["POST"])
@validate_payload({
    "username": str, "password": str, "email": str, "institution_code": str
})
def register_staff():
    data = {k: sanitize_input(v) for k, v in request.json.items()}
    return get_auth_service().register_staff(data)

@auth_bp.route("/login/step1", methods=["POST"])
@validate_payload({"username": str, "password": str})
def login_step1():
    data = {k: sanitize_input(v) for k, v in request.json.items()}
    return get_auth_service().login_step1(data)

@auth_bp.route("/login/step2", methods=["POST"])
@validate_payload({"username": str, "otp": str})
def login_step2():
    data = {k: sanitize_input(v) for k, v in request.json.items()}
    return get_auth_service().login_step2(data)

@auth_bp.route("/superadmin/login", methods=["POST"])
@validate_payload({"username": str, "password": str})
def superadmin_login():
    data = {k: sanitize_input(v) for k, v in request.json.items()}
    username = data.get("username")
    password = data.get("password")
    
    # Inline check — no circular import from app.py
    sa_username = Config.SUPERADMIN_USERNAME
    sa_password = os.getenv("SUPERADMIN_PASSWORD")
    
    if username == sa_username and sa_password and password == sa_password:
        access = create_access_token(identity=username, additional_claims={"role": "superadmin"})
        refresh = create_refresh_token(identity=username)
        security_logger.info(f"SuperAdmin session initialized for {username}")
        return api_response(message="SuperAdmin login successful", data={
            "access_token": access,
            "refresh_token": refresh,
            "role": "superadmin"
        })
    
    security_logger.warning(f"Failed SuperAdmin login attempt for {username}")
    return api_error("Invalid administrative credentials", code=401)

@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    from models.db import Database
    db = Database()
    user = db.get_user(current_user)
    
    if not user:
        return api_error("User not found", code=404)
    
    new_access_token = create_access_token(
        identity=current_user,
        additional_claims={
            "role": user['role'],
            "institution_code": user.get('institution_code')
        }
    )
    return api_response(data={"access_token": new_access_token})

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_me():
    current_user = get_jwt_identity()
    return get_auth_service().get_current_user_info(current_user)

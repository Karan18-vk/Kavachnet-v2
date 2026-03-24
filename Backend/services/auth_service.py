import bcrypt
import secrets
import datetime
from flask import request
from flask_jwt_extended import create_access_token, create_refresh_token
from database import db
from models.user import User, Institution, ActivityLog
from config import Config
from utils.logger import security_logger, app_logger
from utils.state import state_store
from utils.response import api_response, api_error

# ── Constants ────────────────────────────────────────────
MIN_PASSWORD_LENGTH = 8
MAX_ADMIN_PER_INSTITUTION = 1

class AuthService:
    def __init__(self):
        pass # We use db.session directly

    def _generate_otp(self):
        return "".join(secrets.choice("0123456789") for _ in range(6))

    def _store_otp(self, email, otp):
        key = f"otp:{email}"
        state_store.setex(key, 300, otp) # 5 minute expiry

    def _verify_otp(self, email, otp_input):
        key = f"otp:{email}"
        stored_otp = state_store.get(key)
        if not stored_otp:
            return False, "OTP invalid or expired."
        if str(stored_otp).strip() != str(otp_input).strip():
            return False, "Wrong OTP."
        state_store.delete(key)
        return True, None

    def validate_password_complexity(self, password: str):
        if len(password) < MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter."
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter."
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number."
        if not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/" for c in password):
            return False, "Password must contain at least one special character."
        return True, None

    def register_user(self, data, role='staff'):
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        institution_code = data.get('institution_code')

        if not all([name, email, password]):
            return api_error("Name, email, and password are required.", code=400)

        ok, error = self.validate_password_complexity(password)
        if not ok:
            return api_error(error, code=400)

        if User.query.filter_by(email=email).first():
            return api_error("Email already registered.", code=409)

        inst = None
        if institution_code:
            inst = Institution.query.filter_by(institution_code=institution_code).first()
            if not inst:
                return api_error("Invalid institution code.", code=400)
            if inst.status != 'approved':
                return api_error("Institution not approved.", code=403)

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        
        new_user = User(
            name=name,
            email=email,
            password_hash=password_hash,
            role=role,
            institution_id=inst.id if inst else None,
            status='approved' if role == 'admin' else 'pending'
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Log activity
            activity = ActivityLog(user_id=new_user.id, action=f"USER_REGISTERED_{role.upper()}")
            db.session.add(activity)
            db.session.commit()
            
            return api_response(message=f"{role.capitalize()} registered successfully.", data=new_user.to_dict(), code=201)
        except Exception as e:
            db.session.rollback()
            return api_error(f"Registration failed: {str(e)}", code=500)

    def login(self, data):
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return api_error("Email and password are required.", code=400)

        user = User.query.filter_by(email=email).first()
        if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            security_logger.warning(f"Failed login attempt for email: {email}")
            return api_error("Invalid credentials.", code=401)

        if user.status != 'approved':
            return api_error(f"Account is {user.status}.", code=403)

        # JWT Tokens
        access_token = create_access_token(
            identity=user.email,
            additional_claims={
                "role": user.role,
                "institution_id": user.institution_id,
                "name": user.name
            }
        )
        refresh_token = create_refresh_token(identity=user.email)

        # Log activity
        activity = ActivityLog(user_id=user.id, action="USER_LOGIN")
        db.session.add(activity)
        db.session.commit()

        return api_response(message="Login successful", data={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.to_dict()
        }, code=200)

    def get_current_user_info(self, email):
        user = User.query.filter_by(email=email).first()
        if not user:
            return api_error("User not found.", code=404)
        return api_response(data=user.to_dict(), code=200)


# Backend/services/auth_service.py

import bcrypt
import secrets
import datetime
from flask import request
from flask_jwt_extended import create_access_token, create_refresh_token
from utils.email_tasks import send_otp_task
from models.db import Database
from config import Config
from utils.logger import security_logger, app_logger
from utils.state import state_store
from utils.response import api_response, api_error

# ── Constants ────────────────────────────────────────────
MIN_PASSWORD_LENGTH = 8
MAX_ADMIN_PER_INSTITUTION = 1

class AuthService:
    def __init__(self, db: Database):
        self.db = db

    def _generate_otp(self):
        return "".join(secrets.choice("0123456789") for _ in range(6))

    def _store_otp(self, username, otp):
        key = f"otp:{username}"
        state_store.setex(key, 300, otp) # 5 minute expiry

    def _verify_otp(self, username, otp_input):
        key = f"otp:{username}"
        stored_otp = state_store.get(key)
        print(f"[DEBUG OTP] Username: {username} | Stored: {repr(stored_otp)} | Input: {repr(otp_input)}", flush=True)
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

    def register_admin(self, data):
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        institution_code = data.get('institution_code')

        if not all([username, password, email, institution_code]):
            return api_error("All fields are required.", code=400)

        ok, error = self.validate_password_complexity(password)
        if not ok:
            return api_error(error, code=400)

        inst = self.db.get_institution_by_code(institution_code)
        if not inst:
            return api_error("Invalid institution code.", code=400)
        
        if inst['status'] != 'approved':
            return api_error("Institution not yet approved.", code=403)

        if inst.get('code_expires_at'):
            expiry = datetime.datetime.fromisoformat(inst['code_expires_at'])
            if datetime.datetime.now() > expiry:
                return api_error("Code expired.", code=403)

        admin_count, _ = self.db.get_member_count(institution_code)
        if admin_count >= MAX_ADMIN_PER_INSTITUTION:
            return api_error("Admin already exists.", code=409)

        if self.db.get_user(username):
            return api_error("Username taken.", code=409)

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        ok, err = self.db.save_user(username, hashed, email, role='admin', institution_code=institution_code, status='approved')
        if ok:
            self.db.save_audit_log(username, "REGISTER_ADMIN_SUCCESS", "institution", institution_code)
            app_logger.info(f"New administrator registered: {username}")
            return api_response(message="Admin registered successfully.", code=201)
        return api_error(err or "Registration failed.", code=500)

    def login_step1(self, data):
        username = data.get('username')
        password = data.get('password')

        user = self.db.get_user(username)
        if not user:
            self.db.log_failed_attempt(username)
            self.db.log_login(username, "FAILED")
            return api_error("Invalid credentials.", code=401)

        # Check lockout
        if user.get('lockout_until'):
            try:
                lockout_time = datetime.datetime.fromisoformat(user['lockout_until'])
                if datetime.datetime.now() < lockout_time:
                    security_logger.warning(f"Login attempt on locked account: {username}")
                    return api_error("Account locked. Try again later.", code=403)
                self.db.clear_lockout(username)
            except (ValueError, TypeError):
                pass

        # schema.sql uses 'password'
        db_pwd = user.get('password') or user.get('password_hash')
        if not db_pwd:
             return api_error("User record missing password field.", code=500)

        if not bcrypt.checkpw(password.encode(), db_pwd.encode()):
            self.db.log_failed_attempt(username)
            self.db.log_login(username, "FAILED")
            
            # Brute force lockout logic
            recent_fails = self.db.get_recent_failed_attempts(username, 300)
            if len(recent_fails) >= 5:
                lock_until = (datetime.datetime.now() + datetime.timedelta(hours=1)).isoformat()
                self.db.lock_user(username, lock_until)
                security_logger.critical(f"Account locked due to brute force: {username}")
                return api_error("Too many attempts. Locked for 1 hour.", code=403)
            return api_error("Invalid credentials.", code=401)

        if user['status'] != 'approved':
            return api_error(f"Account {user['status']}.", code=403)

        # Token generation
        ua = request.headers.get('User-Agent', 'unknown')[:100]
        access_token = create_access_token(
            identity=username,
            additional_claims={
                "role": user['role'],
                "institution_code": user.get('institution_code'),
                "fingerprint": ua
            }
        )
        refresh_token = create_refresh_token(identity=username)

        self.db.save_audit_log(username, "LOGIN_SUCCESS", "user", username)
        self.db.log_login(username, "SUCCESS")
        self.db.clear_lockout(username)
        security_logger.info(f"User login successful: {username}")

        return api_response(message="Login successful", data={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "role": user['role'],
            "institution_code": user.get('institution_code')
        }, code=200)

    def login_step2(self, data):
        username = data.get('username')
        otp_input = data.get('otp')

        ok, err = self._verify_otp(username, otp_input)
        if not ok:
            return api_error(err, code=401 if "Wrong" in err else 400)

        user = self.db.get_user(username)
        ua = request.headers.get('User-Agent', 'unknown')[:100]
        
        access_token = create_access_token(
            identity=username,
            additional_claims={
                "role": user['role'],
                "institution_code": user.get('institution_code'),
                "fingerprint": ua
            }
        )
        refresh_token = create_refresh_token(identity=username)

        self.db.save_audit_log(username, "LOGIN_STEP2_SUCCESS", "user", username)
        self.db.log_login(username, "SUCCESS")
        self.db.clear_lockout(username)
        security_logger.info(f"User login verified: {username}")

        return api_response(message="Login successful", data={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "role": user['role'],
            "institution_code": user.get('institution_code')
        }, code=200)

    def register_staff(self, data):
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        institution_code = data.get('institution_code')

        if not all([username, password, email, institution_code]):
            return api_error("All fields are required.", code=400)

        ok, error = self.validate_password_complexity(password)
        if not ok:
            return api_error(error, code=400)

        if self.db.get_user(username):
            return api_error("Username taken.", code=409)

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        # Staff always starts as 'pending'
        ok, err = self.db.save_user(username, hashed, email, role='staff', institution_code=institution_code, status='pending')
        if ok:
            self.db.save_audit_log(username, "REGISTER_STAFF_REQUEST", "user", username)
            app_logger.info(f"New staff registration request: {username}")
            return api_response(message="Staff registration request submitted successfully. Awaiting approval.", code=201)
        return api_error(err or "Registration failed.", code=500)

    def get_current_user_info(self, username, db):
        user = db.get_user(username)
        if not user:
            return api_error("User not found.", code=404)
        return api_response(data={
            "username": user['username'],
            "email": user['email'],
            "role": user['role'],
            "institution_code": user.get('institution_code'),
            "status": user.get('status')
        }, code=200)


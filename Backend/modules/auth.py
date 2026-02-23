# modules/auth.py

import bcrypt
import random
import time
from flask_jwt_extended import create_access_token
from utils.email_sender import send_otp
from models.db import Database

# In-memory OTP store
otp_store = {}

MAX_ADMIN_PER_INSTITUTION = 1
MAX_STAFF_PER_INSTITUTION = 2


def register_institution_admin(username: str, password: str, email: str, institution_code: str, db: Database):
    """Register the admin for an approved institution. Only one admin allowed."""
    inst = db.get_institution_by_code(institution_code)
    if not inst:
        return {"error": "Invalid institution code. Contact Kavach Net support."}, 400
    if inst['status'] != 'approved':
        return {"error": "Your institution has not been approved yet."}, 403

    admin_count, _ = db.get_member_count(institution_code)
    # Also check pending admins
    pending = db.get_pending_staff(institution_code)
    pending_admins = [u for u in pending if u['role'] == 'admin']
    if admin_count + len(pending_admins) >= MAX_ADMIN_PER_INSTITUTION:
        return {"error": "This institution already has an admin registered."}, 409

    if db.get_user(username):
        return {"error": "Username already taken."}, 409

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    saved = db.save_user(username, hashed.decode(), email, role='admin',
                         institution_code=institution_code, status='approved')
    if saved:
        return {"message": f"Admin account created for institution '{inst['name']}'."}, 201
    return {"error": "Registration failed. Please try again."}, 500


def register_staff(username: str, password: str, email: str, institution_code: str, db: Database):
    """Register a staff member. Requires admin to exist and approve. Max 2 staff."""
    inst = db.get_institution_by_code(institution_code)
    if not inst:
        return {"error": "Invalid institution code."}, 400
    if inst['status'] != 'approved':
        return {"error": "Your institution has not been approved yet."}, 403

    admin_count, staff_count = db.get_member_count(institution_code)
    if admin_count == 0:
        return {"error": "No admin has been set up for this institution yet. Ask your admin to register first."}, 403

    # Count pending staff too
    pending = db.get_pending_staff(institution_code)
    pending_staff = [u for u in pending if u['role'] == 'staff']
    if staff_count + len(pending_staff) >= MAX_STAFF_PER_INSTITUTION:
        return {"error": f"This institution has reached its maximum of {MAX_STAFF_PER_INSTITUTION} staff members."}, 409

    if db.get_user(username):
        return {"error": "Username already taken."}, 409

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    saved = db.save_user(username, hashed.decode(), email, role='staff',
                         institution_code=institution_code, status='pending')
    if saved:
        return {"message": "Registration submitted. Your admin must approve your account before you can log in."}, 201
    return {"error": "Registration failed. Please try again."}, 500


def login_step1(username: str, password: str, db: Database):
    user = db.get_user(username)
    if not user:
        db.log_failed_attempt(username)
        db.log_login(username, "FAILED")
        return {"error": "User not found."}, 404

    if not bcrypt.checkpw(password.encode(), user['password'].encode()):
        db.log_failed_attempt(username)
        db.log_login(username, "FAILED")
        return {"error": "Wrong password."}, 401

    if user['status'] == 'pending':
        return {"error": "Your account is pending approval by your institution admin."}, 403
    if user['status'] == 'rejected':
        return {"error": "Your account has been rejected. Contact your institution admin."}, 403

    otp = str(random.randint(100000, 999999))
    otp_store[username] = {"otp": otp, "time": time.time()}

    sent = send_otp(user['email'], otp)
    if not sent:
        return {"error": "Failed to send OTP email."}, 500

    print(f"[AUTH] OTP for {username}: {otp}")
    return {"message": "OTP sent to your registered email."}, 200


def login_step2(username: str, otp_input: str, db: Database):
    record = otp_store.get(username)
    if not record:
        return {"error": "Please complete step 1 first."}, 400
    if time.time() - record['time'] > 300:
        del otp_store[username]
        return {"error": "OTP expired. Please log in again."}, 400
    if record['otp'] != otp_input:
        return {"error": "Wrong OTP."}, 401

    user = db.get_user(username)
    # Include role and institution_code in token identity
    token = create_access_token(identity={
        "username": username,
        "role": user['role'],
        "institution_code": user.get('institution_code')
    })
    del otp_store[username]
    db.log_login(username, "SUCCESS")

    return {
        "message": "Login successful.",
        "access_token": token,
        "role": user['role'],
        "institution_code": user.get('institution_code')
    }, 200


def get_current_user_info(username: str, db: Database):
    user = db.get_user(username)
    if not user:
        return {"error": "User not found."}, 404
    return {
        "username": user['username'],
        "email": user['email'],
        "role": user['role'],
        "institution_code": user.get('institution_code'),
        "status": user.get('status')
    }, 200


def get_otp_debug(username: str):
    record = otp_store.get(username)
    if record:
        return {"otp": record['otp']}, 200
    return {"error": "No OTP found for this user."}, 404

from flask import Blueprint, request, jsonify
from models.user import User, AuditLog
from utils.jwt_helper import create_token, token_required, hash_password
from utils.email_service import generate_otp, send_otp_email, store_otp, verify_otp
from database import db

auth_bp = Blueprint("auth", __name__)

def _log(action, user=None, detail="", severity="info"):
    db.session.add(AuditLog(user_id=user.id if user else None,
        institution_id=user.institution_id if user else None,
        action=action, detail=detail, ip_address=request.remote_addr, severity=severity))
    db.session.commit()

@auth_bp.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json() or {}
    email, password = data.get("email","").strip().lower(), data.get("password","")
    if not email or not password: return jsonify({"error":"Email and password required"}), 400
    user = User.query.filter_by(email=email, role="admin").first()
    if not user or user.password_hash != hash_password(password):
        _log("ADMIN_LOGIN_FAILED", detail=f"Failed for {email}", severity="warning")
        return jsonify({"error":"Invalid credentials"}), 401
    if user.status != "active": return jsonify({"error":"Account not active"}), 403
    otp = generate_otp(); store_otp(email, otp); email_sent = send_otp_email(email, otp, user.first_name)
    _log("ADMIN_OTP_SENT", user, f"OTP sent to {email}")
    return jsonify({"message":"OTP sent to your email","email":email,"email_sent":email_sent,
                    "dev_hint":"Check Render logs for OTP if email not configured"}), 200

@auth_bp.route("/admin/verify-otp", methods=["POST"])
def admin_verify_otp():
    data = request.get_json() or {}
    email, otp = data.get("email","").strip().lower(), data.get("otp","").strip()
    if not email or not otp: return jsonify({"error":"Email and OTP required"}), 400
    if not verify_otp(email, otp):
        _log("OTP_FAILED", detail=f"Wrong OTP for {email}", severity="warning")
        return jsonify({"error":"Invalid or expired OTP"}), 401
    user = User.query.filter_by(email=email, role="admin").first()
    if not user: return jsonify({"error":"User not found"}), 404
    token = create_token(user.id, user.role, user.institution_id)
    _log("ADMIN_LOGIN_SUCCESS", user)
    return jsonify({"token":token,"user":user.to_dict(),"message":"Login successful"}), 200

@auth_bp.route("/staff/login", methods=["POST"])
def staff_login():
    data = request.get_json() or {}
    staff_id, password = data.get("staff_id","").strip(), data.get("password","")
    if not staff_id or not password: return jsonify({"error":"Staff ID and password required"}), 400
    user = (User.query.filter_by(staff_id=staff_id).first() or
            User.query.filter_by(email=staff_id, role="staff").first())
    if not user or user.password_hash != hash_password(password):
        _log("STAFF_LOGIN_FAILED", detail=f"Failed for {staff_id}", severity="warning")
        return jsonify({"error":"Invalid Staff ID or password"}), 401
    if user.status != "active": return jsonify({"error":"Account pending approval"}), 403
    token = create_token(user.id, user.role, user.institution_id)
    _log("STAFF_LOGIN_SUCCESS", user)
    return jsonify({"token":token,"user":user.to_dict(),"message":"Login successful"}), 200

@auth_bp.route("/me", methods=["GET"])
@token_required
def me():
    return jsonify({"user":request.current_user.to_dict()}), 200

@auth_bp.route("/logout", methods=["POST"])
@token_required
def logout():
    _log("LOGOUT", request.current_user)
    return jsonify({"message":"Logged out"}), 200

import jwt, hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
from models.user import User

def create_token(user_id, role, institution_id):
    expiry = datetime.utcnow() + timedelta(hours=current_app.config["JWT_EXPIRY_HOURS"])
    return jwt.encode({"user_id":user_id,"role":role,"institution_id":institution_id,"exp":expiry},
                      current_app.config["SECRET_KEY"], algorithm="HS256")

def decode_token(token):
    return jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization","")
        if not auth.startswith("Bearer "):
            return jsonify({"error":"Authorization token missing"}), 401
        try:
            payload = decode_token(auth.split(" ")[1])
        except jwt.ExpiredSignatureError:
            return jsonify({"error":"Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error":"Invalid token"}), 401
        user = User.query.get(payload["user_id"])
        if not user or user.status != "active":
            return jsonify({"error":"User not found or inactive"}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if request.current_user.role != "admin":
            return jsonify({"error":"Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

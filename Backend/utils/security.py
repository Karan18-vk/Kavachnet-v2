# Backend/utils/security.py

from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import get_jwt, verify_jwt_in_request
from utils.response import api_error

def superadmin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS": return jsonify({"status":"ok"}), 200
        verify_jwt_in_request()
        claims = get_jwt()
        if claims.get("role") == "superadmin":
            return fn(*args, **kwargs)
        return api_error("Administrative privileges required", code=403)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS": return jsonify({"status":"ok"}), 200
        verify_jwt_in_request()
        claims = get_jwt()
        if claims.get("role") == "admin":
            return fn(*args, **kwargs)
        return api_error("Institutional administrator privileges required", code=403)
    return wrapper

def admin_or_above_required(fn):
    """Allows both admin and superadmin roles."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS": return jsonify({"status":"ok"}), 200
        verify_jwt_in_request()
        claims = get_jwt()
        if claims.get("role") in ("admin", "superadmin"):
            return fn(*args, **kwargs)
        return api_error("Administrator privileges required", code=403)
    return wrapper

def authenticated_required(fn):
    """Allows any authenticated user (staff, admin, superadmin)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS": return jsonify({"status":"ok"}), 200
        verify_jwt_in_request()
        return fn(*args, **kwargs)
    return wrapper

import secrets, string
from flask import Blueprint, request, jsonify
from models.user import Institution, User
from utils.jwt_helper import token_required, hash_password
from database import db

institution_bp = Blueprint("institution", __name__)

def _gen_code(n=8):
    return "".join(secrets.choice(string.ascii_uppercase+string.digits) for _ in range(n))

@institution_bp.route("/register", methods=["POST"])
def register_institution():
    data = request.get_json() or {}
    name, contact = data.get("institution_name","").strip(), data.get("contact_person","").strip()
    email, phone  = data.get("email","").strip().lower(), data.get("phone","").strip()
    if not name or not contact or not email:
        return jsonify({"error":"Name, contact, and email required"}), 400
    if Institution.query.filter_by(email=email).first():
        return jsonify({"error":"Institution with this email exists"}), 409
    code = _gen_code()
    inst = Institution(name=name,code=code,contact_person=contact,email=email,phone=phone,status="approved")
    db.session.add(inst); db.session.commit()
    return jsonify({"message":"Institution registered","institution_code":code,"institution_name":name}), 201

@institution_bp.route("/validate-code", methods=["POST"])
def validate_code():
    data = request.get_json() or {}
    code = data.get("code","").strip().upper()
    if not code: return jsonify({"error":"Code required"}), 400
    inst = Institution.query.filter_by(code=code, status="approved").first()
    if not inst: return jsonify({"error":"Invalid or unapproved code"}), 404
    admin_count = User.query.filter_by(institution_id=inst.id, role="admin").count()
    staff_count = User.query.filter_by(institution_id=inst.id, role="staff").count()
    return jsonify({"valid":True,"institution":inst.to_dict(),
        "slots":{"admin_available":admin_count==0,"staff_available":staff_count<2,
                 "admin_count":admin_count,"staff_count":staff_count}}), 200

@institution_bp.route("/create-account", methods=["POST"])
def create_account():
    data = request.get_json() or {}
    code  = data.get("institution_code","").strip().upper()
    email = data.get("email","").strip().lower()
    role  = data.get("role","staff")
    password = data.get("password","")
    if not all([code, data.get("first_name"), data.get("last_name"), email, password]):
        return jsonify({"error":"All fields required"}), 400
    if len(password) < 8: return jsonify({"error":"Password min 8 chars"}), 400
    inst = Institution.query.filter_by(code=code, status="approved").first()
    if not inst: return jsonify({"error":"Invalid institution code"}), 404
    if User.query.filter_by(email=email).first(): return jsonify({"error":"Email already registered"}), 409
    if role=="admin" and User.query.filter_by(institution_id=inst.id,role="admin").count()>=1:
        return jsonify({"error":"Institution already has an admin"}), 409
    if role=="staff" and User.query.filter_by(institution_id=inst.id,role="staff").count()>=2:
        return jsonify({"error":"Max 2 staff per institution"}), 409
    staff_id = f"KV-{inst.id:03d}-{User.query.count()+1:04d}"
    user = User(first_name=data.get("first_name",""), last_name=data.get("last_name",""),
        email=email, staff_id=staff_id, password_hash=hash_password(password), role=role,
        department=data.get("department","SOC"), institution_id=inst.id,
        status="active" if role=="admin" else "pending")
    db.session.add(user); db.session.commit()
    return jsonify({"message":"Account created","staff_id":staff_id,"user":user.to_dict()}), 201

@institution_bp.route("/users", methods=["GET"])
@token_required
def list_users():
    users = User.query.filter_by(institution_id=request.current_user.institution_id).all()
    return jsonify({"users":[u.to_dict() for u in users]}), 200

@institution_bp.route("/users/<int:user_id>/status", methods=["PUT"])
@token_required
def update_user_status(user_id):
    if request.current_user.role != "admin": return jsonify({"error":"Admin only"}), 403
    data   = request.get_json() or {}
    status = data.get("status")
    if status not in ("active","suspended","pending"): return jsonify({"error":"Invalid status"}), 400
    user = User.query.filter_by(id=user_id,institution_id=request.current_user.institution_id).first()
    if not user: return jsonify({"error":"User not found"}), 404
    user.status = status; db.session.commit()
    return jsonify({"message":f"Status set to {status}","user":user.to_dict()}), 200

# app.py

import os
from flask import Flask, request, jsonify, send_file
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from flask_cors import CORS
from config import Config
from models.db import Database
from modules import auth, encryption, phishing, threat, incident

app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY
app.config["JWT_SECRET_KEY"] = Config.JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = Config.JWT_ACCESS_TOKEN_EXPIRES

jwt = JWTManager(app)

# CORS enabled for all routes
CORS(app)
db = Database()

# ── DATABASE MIGRATION & SEEDING ──────────────────
def migrate_db():
    import sqlite3
    import uuid
    import datetime
    import bcrypt
    
    conn = sqlite3.connect(Config.DB_NAME)
    conn.row_factory = sqlite3.Row
    
    # 1. Migration: Add columns if missing
    try:
        conn.execute("ALTER TABLE institutions ADD COLUMN code_expires_at TEXT")
        print("[DB] Added code_expires_at column.")
    except sqlite3.OperationalError:
        pass 

    # 2. Seeding: Ensure at least one approved institution exists
    # This prevents the dashboard from being empty after Render wipes the disk.
    count = conn.execute("SELECT COUNT(*) FROM institutions").fetchone()[0]
    if count == 0:
        inst_id = str(uuid.uuid4())
        code = "KAVACH2026"
        now = datetime.datetime.now()
        expiry = (now + datetime.timedelta(days=365)).isoformat() # Long expiry for seed
        
        # Create Demo Institution
        conn.execute(
            "INSERT INTO institutions (id, name, email, contact_person, institution_code, status, created_at, approved_at, code_expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (inst_id, "Kavach Net Sentinel HQ", "sentinel@kavachnet.com", "Operations Lead", code, "approved", now.isoformat(), now.isoformat(), expiry)
        )
        
        # Create Demo Admin User (Password: DemoAdmin123!)
        hashed = bcrypt.hashpw("DemoAdmin123!".encode(), bcrypt.gensalt()).decode()
        conn.execute(
            "INSERT INTO users (id, username, password, email, role, institution_code, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), "sentinel_admin", hashed, "admin@kavachnet.com", "admin", code, "approved", now.isoformat())
        )
        print("[DB] Seeded Demo Institution and Admin User.")

    conn.commit()
    conn.close()

migrate_db()

# ── Super Admin credentials (only for Kavach Net team) ──────────
SUPERADMIN_USERNAME = os.getenv("SUPERADMIN_USERNAME", "kavachnet_root")
SUPERADMIN_PASSWORD = os.getenv("SUPERADMIN_PASSWORD", "KN@SuperAdmin2026!")

# ══════════════════════════════════════════
# HEALTH
# ══════════════════════════════════════════
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "KavachNet API running", "version": "2.0", "status": "active"}), 200

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy"}), 200


# ══════════════════════════════════════════
# SUPER ADMIN — only for Kavach Net team
# ══════════════════════════════════════════
@app.route("/api/superadmin/login", methods=["POST"])
def superadmin_login():
    data = request.json
    print(f"[AUTH] SuperAdmin login: {data.get('username')}")
    
    if data.get("username") != SUPERADMIN_USERNAME or data.get("password") != SUPERADMIN_PASSWORD:
        return jsonify({"error": "Invalid credentials."}), 401
    
    from flask_jwt_extended import create_access_token
    # BE EXPLICIT: string only
    token = create_access_token(
        identity="kavachnet_root",
        additional_claims={"role": "superadmin"}
    )
    return jsonify({"access_token": token, "role": "superadmin"}), 200


# ── JWT IDENTITY HELPER ────────────────────────────
from flask_jwt_extended import get_jwt

def is_superadmin(identity):
    claims = get_jwt()
    return claims.get("role") == "superadmin"

@app.route("/api/superadmin/institutions", methods=["GET"])
@jwt_required()
def sa_get_institutions():
    if not is_superadmin(get_jwt_identity()):
        return jsonify({"error": "Forbidden. Super Admin required."}), 403
    
    try:
        institutions = db.get_all_institutions()
        import datetime
        now = datetime.datetime.now()
        
        # Auto-rotate expired codes
        for inst in institutions:
            if inst.get('status') == 'approved' and inst.get('code_expires_at'):
                try:
                    expiry = datetime.datetime.fromisoformat(inst['code_expires_at'])
                    if now > expiry:
                        new_code, new_expiry = db.rotate_institution_code(inst['id'])
                        inst['institution_code'] = new_code
                        inst['code_expires_at'] = new_expiry
                        print(f"[SYSTEM] Auto-rotated code for {inst['name']}")
                except:
                    pass # Ignore bad date formats
            
            # Attach member counts
            if inst.get('institution_code'):
                a, s = db.get_member_count(inst['institution_code'])
                inst['admin_count'] = a
                inst['staff_count'] = s
            else:
                inst['admin_count'] = 0
                inst['staff_count'] = 0
                
        return jsonify({"institutions": institutions}), 200
    except Exception as e:
        print(f"[ERROR] sa_get_institutions: {e}")
        return jsonify({"error": f"Internal Error: {str(e)}"}), 500


@app.route("/api/superadmin/institutions/<inst_id>/approve", methods=["POST"])
@jwt_required()
def sa_approve_institution(inst_id):
    identity = get_jwt_identity()
    if not is_superadmin(identity):
        return jsonify({"error": "Forbidden."}), 403
    # ... rest of the code is unchanged but I'll update the whole route for safety
    inst = db.get_institution_by_id(inst_id)
    if not inst: return jsonify({"error": "Institution not found."}), 404
    if inst['status'] == 'approved':
        return jsonify({"error": "Already approved.", "institution_code": inst['institution_code']}), 400
    
    code, expiry = db.approve_institution(inst_id)
    from utils.email_sender import send_institution_approval
    send_institution_approval(inst['email'], inst['contact_person'], code, expiry)
    return jsonify({"message": "Institution approved. Code sent via email.", "institution_code": code, "expires_at": expiry}), 200


@app.route("/api/superadmin/institutions/<inst_id>/reject", methods=["POST"])
@jwt_required()
def sa_reject_institution(inst_id):
    if not is_superadmin(get_jwt_identity()):
        return jsonify({"error": "Forbidden."}), 403
    data = request.json or {}
    db.reject_institution(inst_id, data.get("reason", ""))
    return jsonify({"message": "Institution rejected."}), 200


# ══════════════════════════════════════════
# MAKER PORTAL (restricted to Super Admin)
# ══════════════════════════════════════════
@app.route("/api/maker/stats", methods=["GET"])
@jwt_required()
def maker_get_stats():
    if not is_superadmin(get_jwt_identity()):
        return jsonify({"error": "Forbidden. Maker access required."}), 403
    
    # Internal system metrics
    logs = db.get_all_login_logs()
    total_patterns = sum(log['failed_count'] + log['success_count'] for log in logs)
    
    from modules.threat import run_anomaly_detection
    # Preview anomalies without saving to incidents for "Stats"
    # We'll just return the count from the last logs analysis for now
    analysis = run_anomaly_detection(db)
    
    return jsonify({
        "system_status": "operational",
        "database": "connected",
        "ml_model": "Isolation Forest (scikit-learn)",
        "patterns_analyzed": total_patterns,
        "anomalies_detected": analysis.get("anomalies_detected", 0),
        "db_size_rough": len(logs) + len(db.get_all_incidents())
    }), 200


@app.route("/api/maker/scan", methods=["POST"])
@jwt_required()
def maker_trigger_scan():
    if not is_superadmin(get_jwt_identity()):
        return jsonify({"error": "Forbidden. Maker access required."}), 403
    
    from modules.threat import run_anomaly_detection
    result = run_anomaly_detection(db)
    return jsonify({
        "message": "Manual threat scan completed.",
        "details": result
    }), 200


# ══════════════════════════════════════════
# INSTITUTION REGISTRATION (public)
# ══════════════════════════════════════════
@app.route("/api/institutions/request", methods=["POST"])
def request_institution():
    data = request.json
    if not all(k in data for k in ["name", "email", "contact_person"]):
        return jsonify({"error": "name, email, and contact_person are required."}), 400
    ok, err = db.register_institution(
        data['name'], data['email'], data['contact_person'], data.get('phone', '')
    )
    if ok:
        return jsonify({"message": "Your institution request has been submitted. Kavach Net team will review and send you the institution code."}), 201
    return jsonify({"error": err}), 409


@app.route("/api/institutions/validate/<code>", methods=["GET"])
def validate_institution_code(code):
    inst = db.get_institution_by_code(code)
    if not inst:
        return jsonify({"valid": False, "error": "Invalid institution code."}), 404
    if inst['status'] != 'approved':
        return jsonify({"valid": False, "error": "Institution not approved."}), 403
    admin_count, staff_count = db.get_member_count(code)
    return jsonify({
        "valid": True,
        "institution_name": inst['name'],
        "admin_count": admin_count,
        "staff_count": staff_count,
        "admin_slots_available": max(0, 1 - admin_count),
        "staff_slots_available": max(0, 2 - staff_count)
    }), 200


# ══════════════════════════════════════════
# USER REGISTRATION
# ══════════════════════════════════════════
@app.route("/api/register/admin", methods=["POST"])
def register_admin():
    data = request.json
    if not all(k in data for k in ["username", "password", "email", "institution_code"]):
        return jsonify({"error": "username, password, email, institution_code are required."}), 400
    result, status = auth.register_institution_admin(
        data['username'], data['password'], data['email'], data['institution_code'], db
    )
    return jsonify(result), status


@app.route("/api/register/staff", methods=["POST"])
def register_staff():
    data = request.json
    if not all(k in data for k in ["username", "password", "email", "institution_code"]):
        return jsonify({"error": "username, password, email, institution_code are required."}), 400
    result, status = auth.register_staff(
        data['username'], data['password'], data['email'], data['institution_code'], db
    )
    return jsonify(result), status


# ══════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════
@app.route("/api/login/step1", methods=["POST"])
def login_step1():
    data = request.json
    if not all(k in data for k in ["username", "password"]):
        return jsonify({"error": "username and password required."}), 400
    result, status = auth.login_step1(data['username'], data['password'], db)
    return jsonify(result), status


@app.route("/api/login/step2", methods=["POST"])
def login_step2():
    data = request.json
    if not all(k in data for k in ["username", "otp"]):
        return jsonify({"error": "username and otp required."}), 400
    result, status = auth.login_step2(data['username'], data['otp'], db)
    return jsonify(result), status


@app.route("/api/debug/otp/<username>", methods=["GET"])
def get_debug_otp(username):
    result, status = auth.get_otp_debug(username)
    return jsonify(result), status


@app.route("/api/me", methods=["GET"])
@jwt_required()
def get_me():
    username = get_jwt_identity()
    result, status = auth.get_current_user_info(username, db)
    return jsonify(result), status


# ══════════════════════════════════════════
# ADMIN — manage their institution's staff
# ══════════════════════════════════════════
@app.route("/api/admin/members", methods=["GET"])
@jwt_required()
def admin_get_members():
    claims = get_jwt()
    if claims.get("role") not in ("admin", "superadmin"):
        return jsonify({"error": "Forbidden."}), 403
    inst_code = claims.get("institution_code")
    members = db.get_users_by_institution(inst_code)
    admin_count, staff_count = db.get_member_count(inst_code)
    return jsonify({
        "members": members,
        "admin_count": admin_count,
        "staff_count": staff_count,
        "slots_remaining": max(0, 2 - staff_count)
    }), 200


@app.route("/api/admin/members/<user_id>/approve", methods=["POST"])
@jwt_required()
def admin_approve_member(user_id):
    claims = get_jwt()
    if claims.get("role") not in ("admin", "superadmin"):
        return jsonify({"error": "Forbidden."}), 403
    db.update_user_status(user_id, 'approved')
    return jsonify({"message": "Member approved."}), 200


@app.route("/api/admin/members/<user_id>/reject", methods=["POST"])
@jwt_required()
def admin_reject_member(user_id):
    claims = get_jwt()
    if claims.get("role") not in ("admin", "superadmin"):
        return jsonify({"error": "Forbidden."}), 403
    db.update_user_status(user_id, 'rejected')
    return jsonify({"message": "Member rejected."}), 200


# ══════════════════════════════════════════
# ENCRYPTION
# ══════════════════════════════════════════
@app.route("/api/encryption/newkey", methods=["GET"])
@jwt_required()
def generate_new_key():
    key = encryption.generate_key()
    return jsonify({"key": key}), 200


@app.route("/api/encryption/encrypt", methods=["POST"])
@jwt_required()
def encrypt():
    data = request.json
    if not all(k in data for k in ["text", "key"]):
        return jsonify({"error": "text and key required."}), 400
    result = encryption.encrypt_data(data['text'], data['key'])
    if isinstance(result, dict) and "error" in result:
        return jsonify(result), 400
    return jsonify({"encrypted_text": result}), 200


@app.route("/api/encryption/decrypt", methods=["POST"])
@jwt_required()
def decrypt():
    data = request.json
    if not all(k in data for k in ["encrypted_text", "key"]):
        return jsonify({"error": "encrypted_text and key required."}), 400
    result = encryption.decrypt_data(data['encrypted_text'], data['key'])
    if isinstance(result, dict) and "error" in result:
        return jsonify(result), 400
    return jsonify({"decrypted_text": result}), 200


# ══════════════════════════════════════════
# PHISHING
# ══════════════════════════════════════════
@app.route("/api/phishing/check", methods=["POST"])
@jwt_required()
def check_phishing_url():
    data = request.json
    if "url" not in data:
        return jsonify({"error": "url required."}), 400
    result = phishing.check_phishing(data['url'])
    return jsonify(result), 200


# ══════════════════════════════════════════
# THREATS
# ══════════════════════════════════════════
@app.route("/api/threat/status", methods=["GET"])
@jwt_required()
def threat_status():
    summary = threat.get_threat_summary(db)
    return jsonify(summary), 200


@app.route("/api/threat/scan", methods=["POST"])
@jwt_required()
def threat_scan():
    result = threat.run_anomaly_detection(db)
    return jsonify(result), 200


@app.route("/api/threat/check-brute-force/<username>", methods=["GET"])
@jwt_required()
def check_brute_force_attack(username):
    result = threat.check_brute_force(username, db)
    if result:
        return jsonify(result), 200
    return jsonify({"message": "No brute force detected."}), 200


# ══════════════════════════════════════════
# INCIDENTS (scoped to institution)
# ══════════════════════════════════════════
@app.route("/api/incidents", methods=["GET"])
@jwt_required()
def get_incidents():
    claims = get_jwt()
    inst_code = claims.get("institution_code") if claims.get("role") != "superadmin" else None
    incidents = incident.get_incidents(db, institution_code=inst_code)
    return jsonify({"incidents": incidents, "count": len(incidents)}), 200


@app.route("/api/incidents/<incident_id>", methods=["GET"])
@jwt_required()
def get_incident(incident_id):
    inc = incident.get_incident_by_id(incident_id, db)
    if not inc:
        return jsonify({"error": "Incident not found."}), 404
    return jsonify(inc), 200


@app.route("/api/incidents/<incident_id>", methods=["PATCH"])
@jwt_required()
def update_incident_status(incident_id):
    data = request.json
    if "status" not in data:
        return jsonify({"error": "status required."}), 400
    result, status = incident.update_status(incident_id, data['status'], db)
    return jsonify(result), status


@app.route("/api/incidents/report/pdf", methods=["GET"])
@jwt_required()
def download_incident_report():
    buffer = incident.generate_pdf_report(db)
    return send_file(buffer, as_attachment=True, download_name="kavachnet_incident_report.pdf", mimetype='application/pdf')


@app.route("/api/incidents/statistics", methods=["GET"])
@jwt_required()
def get_incident_stats():
    stats = incident.get_incident_statistics(db)
    return jsonify(stats), 200


# ══════════════════════════════════════════
# ERROR HANDLERS
# ══════════════════════════════════════════
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found."}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error."}), 500


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  KavachNet Backend v2.0 Starting...")
    print("="*55)
    print("  API:          http://localhost:5000")
    print("  Health:       http://localhost:5000/api/health")
    print(f"  SuperAdmin:   POST /api/superadmin/login")
    print("="*55 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)

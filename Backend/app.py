"""
KavachNet v2 - Flask Backend
Run locally: python app.py
Deploy: push to GitHub, then connect to Render.com
"""

import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS
from config import Config
from routes.auth_routes import auth_bp
from routes.institution_routes import institution_bp
from routes.scanner import scanner_bp
from routes.dashboard import dashboard_bp
from routes.logs import logs_bp
from database import db

# Configure root logger for startup messages
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_boot_log = logging.getLogger("kavachnet.boot")


def _build_cors_origins():
    """
    Dynamically accept any origin to prevent CORS blocking
    across different frontend deployments.
    """
    return "*"


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    _boot_log.info("Starting KavachNet Backend (Stable v4.2)...")
    
    # ── Error Handlers (Early Registration) ──────────────────
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Endpoint not found", "status": 404}), 404

    @app.errorhandler(500)
    def server_error(e):
        _boot_log.error("Unhandled Runtime Exception: %s", e, exc_info=True)
        return jsonify({
            "error": "Internal server error",
            "detail": str(e) or "Check server logs for traceback",
            "status": 500
        }), 500

    _boot_log.info("Database URL: %s", Config.DATABASE_URL)

    # ── Validate email config at startup ────────────────────
    try:
        Config.validate_email_config()
        _boot_log.info("Email config validated.")
    except RuntimeError as e:
        _boot_log.warning("Email config issue: %s", e)

    # ── 1. JWT ───────────────────────────────────────────────
    from flask_jwt_extended import JWTManager
    JWTManager(app)
    _boot_log.info("JWT Manager initialized.")

    CORS(app, resources={r"/api/v1/.*": {
        "origins": "*",  # Allow all origins safely
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "Accept"],
        "supports_credentials": False, # Required for '*'
        "max_age": 600,
    }})
    _boot_log.info("Extensive CORS configured dynamically.")

    # ── 3. Rate Limiting ─────────────────────────────────────
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        Limiter(
            get_remote_address,
            app=app,
            default_limits=["2000 per day", "200 per hour"],
            storage_uri=app.config.get("REDIS_URL") or "memory://",
        )
        _boot_log.info("Rate Limiter initialized.")
    except ImportError:
        _boot_log.warning("Flask-Limiter not installed, skipping rate limiting.")

    # ── 4. Blueprints ────────────────────────────────────────
    app.register_blueprint(auth_bp,        url_prefix='/api/v1/auth')
    app.register_blueprint(institution_bp, url_prefix='/api/v1/institutions')

    try:
        app.register_blueprint(scanner_bp,   url_prefix='/api/v1/scan')
        app.register_blueprint(dashboard_bp, url_prefix='/api/v1/dashboard')
        app.register_blueprint(logs_bp,      url_prefix='/api/v1/logs')
        _boot_log.info("Standard blueprints registered.")
    except NameError as e:
        _boot_log.error("Blueprint registration error: %s", e)

    try:
        from routes.threat_routes import threat_bp
        from routes.incident_routes import incident_bp
        from routes.admin_routes import admin_bp
        from routes.chat_routes import chat_bp
        app.register_blueprint(threat_bp,   url_prefix='/api/v1/threats')
        app.register_blueprint(incident_bp, url_prefix='/api/v1/incidents')
        app.register_blueprint(admin_bp,    url_prefix='/api/v1/admin')
        app.register_blueprint(chat_bp,     url_prefix='/api/v1/chat')
        _boot_log.info("Advanced blueprints registered.")
    except ImportError as e:
        _boot_log.warning("Advanced blueprints skipped or misnamed: %s", e)

    # ── 4.5 Static Files (Development) ──────────────────────
    @app.route("/<path:filename>")
    def serve_frontend(filename):
        # Look in the sibling 'Frontend' directory
        frontend_dir = os.path.abspath(os.path.join(app.root_path, "..", "Frontend"))
        from flask import send_from_directory
        return send_from_directory(frontend_dir, filename)

    # ── 5. Health Check ──────────────────────────────────────
    @app.route("/")
    def root_health():
        return jsonify({
            "status": "online",
            "message": "KavachNet Backend API is running",
            "documentation": "/api/v1/health"
        }), 200

    @app.route("/api/v1/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": "KavachNet Backend",
            "version": "v4.1.0",
            "env": app.config.get("NODE_ENV", "development"),
        }), 200


    # ── 6. Database Init ─────────────────────────────────────
    # FIX (Bug 2): Removed duplicate 'return app' that was placed BEFORE
    # db.init_app(), causing the database to NEVER be initialized.
    _boot_log.info("Initializing Database...")
    db.init_app(app)
    with app.app_context():
        try:
            db.create_all()
            _boot_log.info("SQLAlchemy tables created/verified.")
            
            # Initialize custom Database tables
            from models.db import Database
            custom_db = Database()
            custom_db._create_tables()
            _boot_log.info("Custom Database tables ready.")
            
            _seed_demo_data()
            _boot_log.info("Demo data seeded.")
        except Exception as e:
            _boot_log.error("Database initialization error: %s", e, exc_info=True)

    _boot_log.info("Application Ready. All systems operational.")
    
    # Initialize background email dispatcher
    try:
        from utils.email_queue import email_worker
        email_worker.start()
    except Exception as e:
        _boot_log.warning(f"Email worker failed to start: {e}")
        
    return app


def _seed_demo_data():
    """Creates one demo institution + admin so you can test login immediately."""
    from models.user import Institution, User
    import uuid
    import datetime
    import bcrypt

    # Check if demo admin already exists
    if User.query.filter_by(username="admin_kavach").first():
        return

    now_iso = datetime.datetime.now().isoformat()
    
    inst_id = str(uuid.uuid4())
    inst = Institution(
        id=inst_id,
        name="KavachNet Demo Institution",
        institution_code="KAVACH2026",
        contact_person="System Administrator",
        email="admin@kavach.net",
        phone="555-0199",
        status="approved",
        created_at=now_iso
    )
    db.session.add(inst)
    
    # Password: Admin@123
    pwd_hash = bcrypt.hashpw("Admin@123".encode(), bcrypt.gensalt()).decode()
    admin = User(
        id=str(uuid.uuid4()),
        username="admin_kavach",
        password=pwd_hash,
        email="admin@kavach.net",
        role="superadmin",
        institution_code="KAVACH2026",
        status="approved",
        created_at=now_iso
    )
    db.session.add(admin)
    db.session.commit()
    _boot_log.info("Demo seeded — login: admin_kavach | password: Admin@123")


if __name__ == "__main__":
    app = create_app()
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    _boot_log.info("Running on http://0.0.0.0:%d (debug=%s)", port, debug)
    app.run(debug=debug, host="0.0.0.0", port=port)

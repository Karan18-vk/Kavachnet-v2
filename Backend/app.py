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
    Construct the list of allowed CORS origins.
    - Reads ALLOWED_ORIGINS env var (comma-separated).
    - Appends hardcoded production origins.
    - Falls back to localhost origins in non-production environments.
    NOTE: We NEVER mix wildcard '*' with supports_credentials=True
          because browsers reject that combination per the CORS spec.
    """
    base_origins = [
        "https://kavachnet-frontend.onrender.com",
        "https://kavach-front.s3.us-east-1.amazonaws.com",
        "http://kavachnet-bucket.s3-website.amazonaws.com",
    ]

    env_origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]

    # In development, also allow localhost ports commonly used
    is_production = os.getenv("NODE_ENV", "development") == "production"
    dev_origins = [] if is_production else [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        # VS Code Live Server / file:// origin
        "null",
    ]

    # Deduplicate while preserving order
    seen = set()
    merged = []
    for o in (base_origins + env_origins + dev_origins):
        if o not in seen:
            seen.add(o)
            merged.append(o)

    _boot_log.info("CORS allowed origins: %s", merged)
    return merged


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    _boot_log.info("Starting KavachNet Backend...")

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

    # ── 2. CORS  ─────────────────────────────────────────────
    # FIX (Bug 1, 4 & 7): Corrected origin list and resource regex.
    # Pattern r"/api/*" matches /api followed by slashes ONLY. 
    # Use r"/api/v1/.*" to correctly cover all versioned endpoints.
    CORS(app, resources={r"/api/v1/.*": {
        "origins": _build_cors_origins(),
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
        "supports_credentials": True,
        "max_age": 600,
    }})
    _boot_log.info("CORS configured.")

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

    # ── 5. Health Check ──────────────────────────────────────
    @app.route("/api/v1/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": "KavachNet Backend",
            "version": "v4.1.0",
            "env": app.config.get("NODE_ENV", "development"),
        }), 200

    # Generic 404 handler (returns JSON instead of HTML)
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Endpoint not found", "status": 404}), 404

    # Generic 500 handler
    @app.errorhandler(500)
    def server_error(e):
        _boot_log.error("Unhandled 500: %s", e, exc_info=True)
        return jsonify({"error": "Internal server error", "status": 500}), 500

    # ── 6. Database Init ─────────────────────────────────────
    # FIX (Bug 2): Removed duplicate 'return app' that was placed BEFORE
    # db.init_app(), causing the database to NEVER be initialized.
    _boot_log.info("Initializing Database...")
    db.init_app(app)
    with app.app_context():
        try:
            db.create_all()
            _boot_log.info("Database tables created/verified.")
            _seed_demo_data()
            _boot_log.info("Demo data seeded.")
        except Exception as e:
            _boot_log.error("Database initialization error: %s", e, exc_info=True)

    _boot_log.info("Application Ready. All systems operational.")
    return app


def _seed_demo_data():
    """Creates one demo institution + admin so you can test login immediately."""
    from models.user import Institution, User
    import hashlib

    if Institution.query.first():
        return  # already seeded

    inst = Institution(
        name="Demo University",
        code="DEMO2025",
        contact_person="Admin User",
        email="admin@demo.edu",
        phone="",
        status="approved"
    )
    db.session.add(inst)
    db.session.flush()

    # Password: Admin@123
    pwd_hash = hashlib.sha256("Admin@123".encode()).hexdigest()
    admin = User(
        first_name="Admin",
        last_name="User",
        email="admin@demo.edu",
        password_hash=pwd_hash,
        role="admin",
        department="SOC — Security Operations",
        institution_id=inst.id,
        status="active"
    )
    db.session.add(admin)
    db.session.commit()
    _boot_log.info("Demo seeded — login: admin@demo.edu | password: Admin@123")


if __name__ == "__main__":
    app = create_app()
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    _boot_log.info("Running on http://0.0.0.0:%d (debug=%s)", port, debug)
    app.run(debug=debug, host="0.0.0.0", port=port)

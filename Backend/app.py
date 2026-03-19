"""
KavachNet v2 - Flask Backend
Run locally: python app.py
Deploy: push to GitHub, then connect to Render.com
"""

from flask import Flask
from flask_cors import CORS
from config import Config
from routes.auth_routes import auth_bp
from routes.institution_routes import institution_bp
from routes.scanner import scanner_bp
from routes.dashboard import dashboard_bp
from routes.logs import logs_bp
from database import db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    print("[BOOT] Starting KavachNet Backend...")
    # Validate email config at startup
    try:
        Config.validate_email_config()
        print("[BOOT] Email config validated.")
    except Exception as e:
        print(f"[BOOT] Email config validation: {e}")

    # 1. CORE PLUGINS
    from flask_jwt_extended import JWTManager
    jwt = JWTManager(app)
    print("[BOOT] JWT Manager initialized.")
    
    # CORS Configuration - Merged
    CORS(app, resources={r"/api/*": {
        "origins": [
            "https://kavach-front.s3.us-east-1.amazonaws.com",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "*" # Development fallback
        ],
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
        "supports_credentials": True
    }})
    print("[BOOT] CORS configured.")

    # 2. RATE LIMITING (from local v4.1)
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        limiter = Limiter(
            get_remote_address,
            app=app,
            default_limits=["2000 per day", "100 per hour"],
            storage_uri=app.config.get("REDIS_URL") or "memory://",
        )
        print("[BOOT] Rate Limiter initialized.")
    except ImportError:
        print("[BOOT] Flask-Limiter not installed, skipping rate limiting.")

    # 3. BLUEPRINTS - Merged (Supporting both v1 and legacy prefixes if needed)
    # v1 Standard
    app.register_blueprint(auth_bp,        url_prefix='/api/v1/auth')
    app.register_blueprint(institution_bp, url_prefix='/api/v1/institutions')
    
    # Remote features
    try:
        app.register_blueprint(scanner_bp,     url_prefix='/api/v1/scan')
        app.register_blueprint(dashboard_bp,   url_prefix='/api/v1/dashboard')
        app.register_blueprint(logs_bp,        url_prefix='/api/v1/logs')
        print("[BOOT] Standard blueprints registered.")
    except NameError as e:
        print(f"[BOOT] Blueprint registration error: {e}")

    # Local advanced features
    try:
        from routes.threat import threat_bp
        from routes.incident import incident_bp
        from routes.admin import admin_bp
        from routes.chat import chat_bp
        app.register_blueprint(threat_bp,      url_prefix='/api/v1/threats')
        app.register_blueprint(incident_bp,    url_prefix='/api/v1/incidents')
        app.register_blueprint(admin_bp,       url_prefix='/api/v1/admin')
        app.register_blueprint(chat_bp,        url_prefix='/api/v1/chat')
        print("[BOOT] Advanced blueprints registered.")
    except ImportError as e:
        print(f"[BOOT] Advanced blueprints skipped: {e}")

    # 4. HEALTH CHECK
    @app.route("/api/v1/health")
    def health():
        return {
            "status": "KavachNet backend is running",
            "version": "v4.1.0-merged",
            "mode": app.config.get("NODE_ENV", "development")
        }, 200

    print("[BOOT] Initializing Database...")
    db.init_app(app)
    with app.app_context():
        try:
            db.create_all()
            print("[BOOT] Database tables created/verified.")
            _seed_demo_data()
            print("[BOOT] Demo data seeded.")
        except Exception as e:
            print(f"[BOOT] Database initialization error: {e}")

    print("[BOOT] Application Ready.")
    return app

    return app


def _seed_demo_data():
    """Creates one demo institution + admin so you can test login immediately."""
    from database import db
    from models.user import Institution, User
    import hashlib, os

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
    print("[KavachNet] Demo seeded — email: admin@demo.edu | password: Admin@123")


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host="0.0.0.0", port=5000)

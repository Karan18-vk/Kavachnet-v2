"""
KavachNet v2 - Flask Backend
Run locally: python app.py
Deploy: push to GitHub, then connect to Render.com
"""

from flask import Flask
from flask_cors import CORS
from config import Config
from routes.auth import auth_bp
from routes.institution import institution_bp
from routes.scanner import scanner_bp
from routes.dashboard import dashboard_bp
from routes.logs import logs_bp
from database import db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Allow requests from your S3 frontend
    CORS(app, resources={
        r"/api/*": {
            "origins": [
                "https://kavach-front.s3.us-east-1.amazonaws.com",
                "http://localhost:*",
                "*"  # Remove this in production, keep only your S3 origin
            ],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })

    db.init_app(app)

    # Register all route blueprints
    app.register_blueprint(auth_bp,        url_prefix="/api/auth")
    app.register_blueprint(institution_bp, url_prefix="/api/institution")
    app.register_blueprint(scanner_bp,     url_prefix="/api/scan")
    app.register_blueprint(dashboard_bp,   url_prefix="/api/dashboard")
    app.register_blueprint(logs_bp,        url_prefix="/api/logs")

    # Create DB tables on first run
    with app.app_context():
        db.create_all()
        _seed_demo_data()

    @app.route("/api/health")
    def health():
        return {"status": "KavachNet backend is running", "version": "2.0"}, 200

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

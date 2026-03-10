# app.py
# Refactored for Clean Architecture & Production-Grade Security

import os
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config
from models.db import Database
from utils.logger import app_logger, security_logger
from routes.auth_routes import auth_bp
from routes.institution_routes import institution_bp
from routes.threat_routes import threat_bp
from routes.incident_routes import incident_bp
from routes.admin_routes import admin_bp
from routes.chat_routes import chat_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Validate email config at startup (not at import time)
    try:
        Config.validate_email_config()
    except RuntimeError as e:
        app_logger.error(f"Email config validation failed: {e}")
        if Config.NODE_ENV == "production":
            raise

    # 1. CORE PLUGINS
    jwt = JWTManager(app)
    
    # Permissive CORS for Debugging/Local Access
    allowed_origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")
    app_logger.info(f"[BOOT] Allowed Origins: {allowed_origins}")
    app_logger.info(f"[BOOT] Node Env: {Config.NODE_ENV}")
    
    CORS(app, resources={r"/api/*": {
        "origins": allowed_origins,
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
        "supports_credentials": True
    }})
    
    # Global Rate Limiting (Redis-backed for production multi-worker sets)
    redis_available = False
    try:
        import redis
        rc = redis.from_url(app.config.get("REDIS_URL"), socket_timeout=1)
        rc.ping()
        redis_available = True
    except Exception:
        pass
    
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["2000 per day", "100 per hour"],
        storage_uri=app.config.get("REDIS_URL") if redis_available else "memory://",
    )

    # 2. MODELS & MIGRATIONS
    db = Database()
    
    # Legacy Migration (Simplified)
    from app_legacy_migration import run_migration
    run_migration(db)

    # 3. BLUEPRINTS (v1 Namespacing)
    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(institution_bp, url_prefix='/api/v1/institutions')
    app.register_blueprint(threat_bp, url_prefix='/api/v1/threats')
    app.register_blueprint(incident_bp, url_prefix='/api/v1/incidents')
    app.register_blueprint(admin_bp, url_prefix='/api/v1/admin')
    app.register_blueprint(chat_bp, url_prefix='/api/v1/chat')

    # 4. HEALTH CHECK & MONITORING
    from utils.response import api_response
    @app.route("/health", methods=["GET"])
    def health_check():
        try:
            queue_status = "Active" if email_worker.thread and email_worker.thread.is_alive() else "Offline"
        except Exception:
            queue_status = "Unknown"
        
        status_data = {
            "version": "v4.0.0-production",
            "redis": "Connected" if redis_available else "Memory Fallback",
            "email_queue_worker": queue_status
        }
        return api_response(message="KavachNet Operational", data=status_data)

    # 5. ERROR HANDLING (Standardized & Non-leaking)
    from utils.response import api_error
    @app.errorhandler(400)
    def bad_request(e):
        return api_error("Bad request", code=400)

    @app.errorhandler(401)
    def unauthorized(e):
        return api_error("Unauthorized access", code=401)

    @app.errorhandler(403)
    def forbidden(e):
        return api_error("Forbidden activity detected", code=403)

    @app.errorhandler(404)
    def not_found(e):
        return api_error("Resource not found", code=404)

    @app.errorhandler(405)
    def method_not_allowed(e):
        return api_error("Method not allowed", code=405)

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return api_error("Rate limit exceeded. Try again later.", code=429)

    @app.errorhandler(500)
    def internal_error(e):
        app_logger.error(f"Internal Error: {str(e)}")
        # Production safe: Do not leak stack trace
        return api_error("Internal system failure.", code=500)

    @app.after_request
    def apply_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        # Relaxed CSP for debugging connection issues
        # connect-src allows 'self' and * to bypass mysterious S3 overrides
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net fonts.googleapis.com; "
            "font-src 'self' fonts.gstatic.com cdn.jsdelivr.net; "
            "img-src 'self' data: images.unsplash.com; "
            "connect-src 'self' *;"
        )
        return response

    # 6. ENTERPRISE DAEMONS
    from utils.email_queue import email_worker
    email_worker.start()
    
    return app

app = create_app()

if __name__ == "__main__":
    app_logger.info("KavachNet v4 Production initialization started.")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))

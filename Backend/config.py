# Backend/config.py

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

def get_env_or_fail(var_name):
    val = os.getenv(var_name)
    if not val and os.getenv("NODE_ENV") == "production":
        raise ValueError(f"CRITICAL: Environment variable {var_name} is missing in production scope.")
    return val

class Config:
    # ── CORE ──────────────────────────────────
    SECRET_KEY = get_env_or_fail("SECRET_KEY") or "ultra-secret-dev-key"
    DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    PORT = int(os.getenv("PORT", 5000))
    NODE_ENV = os.getenv("NODE_ENV", "development")

    # ── DATABASE ──────────────────────────────
    _raw_db = os.getenv("DB_NAME", "kavachnet.db")
    DB_NAME = os.path.abspath(os.path.join(os.path.dirname(__file__), _raw_db)) if not os.path.isabs(_raw_db) else _raw_db
    # Priority: 1. ENV, 2. SQLite (for local/Render dev)
    DATABASE_URL = os.getenv("DATABASE_URL") or f"sqlite:///{DB_NAME}"
    # Flask-SQLAlchemy requires SQLALCHEMY_DATABASE_URI
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── REDIS (Production State) ──────────────
    REDIS_URL = os.getenv("REDIS_URL") or "memory://"

    # ── JWT SECURITY ──────────────────────────

    JWT_SECRET_KEY = get_env_or_fail("JWT_SECRET_KEY") or "jwt-super-secret-production-key"
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=int(os.getenv("JWT_ACCESS_EXPIRES_MIN", 15)))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(os.getenv("JWT_REFRESH_EXPIRES_DAYS", 7)))
    JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", 24))  # For jwt_helper.py
    
    JWT_TOKEN_LOCATION = ["headers", "cookies"]
    JWT_COOKIE_SECURE = NODE_ENV == "production"
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_ACCESS_COOKIE_PATH = "/"
    JWT_REFRESH_COOKIE_PATH = "/api/auth/refresh"
    JWT_COOKIE_SAMESITE = "Strict"

    # ── EMAIL & SMTP SETTINGS ─────────────────
    EMAIL_PROVIDER = os.getenv("EMAIL_PROVIDER", "smtp").lower() # smtp, ses, mock
    EMAIL_DRY_RUN = os.getenv("EMAIL_DRY_RUN", "False").lower() == "true"
    
    EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
    SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    
    @classmethod
    def validate_email_config(cls):
        """Zero-Trust verification of critical email capabilities at startup."""
        if cls.EMAIL_PROVIDER == 'smtp' and not cls.EMAIL_DRY_RUN:
            if not cls.EMAIL_ADDRESS or not cls.EMAIL_PASSWORD:
                raise RuntimeError(
                    "[CRITICAL] EMAIL_PROVIDER is 'smtp' but EMAIL_ADDRESS or EMAIL_PASSWORD "
                    "are missing from environment variables. Refusing to boot in insecure state."
                )


    # ── SECURITY HEADERS ──────────────────────
    # In production, this should be set to your S3 bucket URL via environment variables
    _raw_origins = os.getenv("ALLOWED_ORIGINS", "")
    ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]





    # ── THREAT DETECTION ──────────────────────
    ANOMALY_CONTAMINATION = float(os.getenv("ANOMALY_CONTAMINATION", 0.1))
    
    # SuperAdmin Credentials
    SUPERADMIN_USERNAME = os.getenv("SUPERADMIN_USERNAME", "admin_kavach")
    SUPERADMIN_PASSWORD = get_env_or_fail("SUPERADMIN_PASSWORD") or "DevSuperAdmin123!"

# NOTE: validate_email_config() is called inside create_app(), not at import time


 Secure Access — Multi-Factor Authentication (MFA)
✅ Encryption — AES-256 file/text encryption
✅ Phishing Prevention — URL risk analyzer
✅ Threat Detection — ML-based anomaly detection + brute force protection
✅ Incident Response — Auto PDF reports + incident tracking

Module 1: Secure Access (auth.py)
What it does:

User registration with password hashing (bcrypt)
Two-step login: password → OTP sent to email → JWT token issued
Role-based access control (Admin/Staff)
Tracks all login attempts (success/failed)

Tech: bcrypt, flask-jwt-extended, smtplib

Module 2: Encryption (encryption.py)
What it does:

Generate secure encryption keys
Encrypt text/files using AES-256
Decrypt with correct key only
Demo-ready: show encryption → gibberish → decrypt

Tech: cryptography (Fernet)

Module 3: Phishing Prevention (phishing.py)
What it does:

Checks URLs against 5 security tests:

Google Safe Browsing API (checks malware database)
HTTPS presence check
Suspicious keywords (login, verify, banking, etc.)
IP-as-domain detection
URL length analysis


Returns risk score + verdict (SAFE / SUSPICIOUS / PHISHING)

Tech: requests, Google Safe Browsing API

Module 4: Threat Detection (threat.py)
What it does:

Brute Force Detection: Alerts if 5+ failed logins in 5 minutes
ML Anomaly Detection: Uses Isolation Forest algorithm to detect unusual login patterns
Threat level assessment (LOW / GUARDED / ELEVATED / CRITICAL)
Auto-logs incidents when threats detected

Tech: scikit-learn, numpy (Isolation Forest ML model)

Module 5: Incident Response (incident.py)
What it does:

Logs all security incidents with severity (HIGH/MEDIUM/LOW)
Status tracking (OPEN → INVESTIGATING → RESOLVED)
Auto-generates PDF reports with incident details
Statistics dashboard (count by severity, type, status)

Tech: reportlab (PDF generation)


Database (db.py)
4 Tables:

users — username, hashed password, email, role
failed_attempts — tracks failed login attempts with timestamp
login_logs — all login activity (for ML analysis)
incidents — security alerts with severity and status.

Tech: SQLite3 (built-in Python)

Backend Framework:    Flask
Authentication:       JWT + bcrypt + OTP (email)
Database:            SQLite3
Machine Learning:    scikit-learn (Isolation Forest)
Encryption:          AES-256 (cryptography library)
External API:        Google Safe Browsing
PDF Generation:      ReportLab
Email Service:       Gmail SMTP




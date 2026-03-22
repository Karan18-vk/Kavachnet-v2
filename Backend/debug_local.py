import sys
import os
import importlib

print("=== KAVACHNET BACKEND DIAGNOSTIC ===")
print(f"Python Version: {sys.version}")
print(f"Current Directory: {os.getcwd()}")

packages = [
    "flask", "flask_cors", "flask_sqlalchemy", "sqlalchemy", 
    "flask_jwt_extended", "flask_limiter", "dotenv", "pymysql", "bcrypt"
]

print("\n--- Checking Dependencies ---")
missing = []
for pkg in packages:
    try:
        importlib.import_module(pkg.replace("-", "_"))
        print(f"[OK] {pkg}")
    except ImportError:
        print(f"[MISSING] {pkg}")
        missing.append(pkg)

if missing:
    print(f"\nERROR: Missing packages: {', '.join(missing)}")
    print("Run: pip install -r requirements.txt")
else:
    print("\n[OK] All core packages installed.")

print("\n--- Checking MySQL Connection ---")
try:
    import pymysql
    conn = pymysql.connect(host='localhost', user='root', password='', database='kavachnet')
    print("[OK] Connected to 'kavachnet' database.")
    conn.close()
except Exception as e:
    print(f"[ERROR] MySQL Connection Failed: {e}")
    print("Make sure XAMPP MySQL is started and 'kavachnet' database is created.")

print("\n--- Checking App Imports ---")
try:
    sys.path.append(os.getcwd())
    from app import create_app
    print("[OK] app.py imports successfully.")
except Exception as e:
    print(f"[ERROR] app.py failed to import: {e}")
    import traceback
    traceback.print_exc()

print("\n=== DIAGNOSTIC COMPLETE ===")

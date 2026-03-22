@echo off
echo === KavachNet Backend Auto-Setup ===
cd Backend

echo --- Installing missing dependencies ---
python -m pip install pymysql cryptography flask flask-cors flask-sqlalchemy sqlalchemy flask-jwt-extended flask-limiter python-dotenv requests bcrypt scikit-learn numpy

echo --- Starting Backend ---
python app.py

pause

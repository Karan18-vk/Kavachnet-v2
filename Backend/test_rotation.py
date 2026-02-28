from models.db import Database
from config import Config
from utils.logger import app_logger

def verify_integration():
    db = Database()
    
    # 1. Register a test institution
    name = "Test Security Inst"
    email = "test.admin" + str(id({}))[-4:] + "@kavachnet.test"
    db.register_institution(name, email, "Admin Bob", "+123456789")
    
    # Get institution id
    conn = db._connect()
    inst = conn.execute("SELECT id FROM institutions WHERE email=?", (email,)).fetchone()
    inst_id = inst['id']
    conn.close()

    # 2. Approve institution (generates first code and inserts into history)
    code, expiry = db.approve_institution(inst_id)
    print(f"[*] Initial Code: {code}, Expiry: {expiry}")
    
    # 3. Rotate and trigger email flow
    from services.institution_service import InstitutionService
    service = InstitutionService(db)
    
    res, status = service.rotate_institution_code(inst_id)
    print(f"[*] Rotation Result: {status} - {res}")

    # Check DB for history
    conn = db._connect()
    codes = conn.execute("SELECT code_value, status FROM institution_codes WHERE institution_id=?", (inst_id,)).fetchall()
    print("[*] History Table:")
    for c in codes:
        print(f"  - {c['code_value']} : {c['status']}")
    conn.close()

if __name__ == "__main__":
    verify_integration()

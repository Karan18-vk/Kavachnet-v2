
# modules/encryption.py

from cryptography.fernet import Fernet

def generate_key():
    """Generate a new encryption key"""
    return Fernet.generate_key().decode()

def encrypt_data(data: str, key: str):
    """Encrypt text data using the provided key"""
    try:
        f = Fernet(key.encode())
        encrypted = f.encrypt(data.encode())
        return encrypted.decode()
    except Exception as e:
        return {"error": f"Encryption failed: {str(e)}"}

def decrypt_data(encrypted_data: str, key: str):
    """Decrypt encrypted data using the provided key"""
    try:
        f = Fernet(key.encode())
        decrypted = f.decrypt(encrypted_data.encode())
        return decrypted.decode()
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}
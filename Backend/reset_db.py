import pymysql
import os
from config import Config

def reset_db():
    print("=== KAVACHNET DATABASE RESET ===")
    url = getattr(Config, 'DATABASE_URL', '')
    if not url.startswith('mysql'):
        print("ERROR: This script is only for MySQL.")
        return

    import urllib.parse
    result = urllib.parse.urlparse(url)
    db_name = result.path.lstrip('/')
    user = result.username or 'root'
    password = result.password or ''
    host = result.hostname or 'localhost'

    try:
        conn = pymysql.connect(host=host, user=user, password=password)
        cursor = conn.cursor()
        
        print(f"--- Recreating database '{db_name}' ---")
        cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")
        cursor.execute(f"CREATE DATABASE {db_name}")
        cursor.execute(f"USE {db_name}")
        
        # Read schema.sql
        schema_path = os.path.join(os.getcwd(), 'schema.sql')
        if os.path.exists(schema_path):
            print("--- Importing schema.sql ---")
            with open(schema_path, 'r') as f:
                sql_script = f.read()
                # Split by semicolon but ignore inside quotes (simple split for now)
                # For better reliability, we execute individual statements
                for statement in sql_script.split(';'):
                    if statement.strip():
                        cursor.execute(statement)
            print("[OK] Schema imported successfully.")
        else:
            print("[WARNING] schema.sql not found. Tables will be created by the app.")

        conn.commit()
        conn.close()
        print("\nSUCCESS: Database has been reset and is now clean.")
        print("Now run 'python app.py' to start the server.")

    except Exception as e:
        print(f"\nERROR: {e}")

if __name__ == "__main__":
    reset_db()

import sqlite3
import os

db_path = "kavachnet.db"
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    users = conn.execute("SELECT * FROM users").fetchall()
    print(f"Total users: {len(users)}")
    for u in users:
        print(dict(u))
    conn.close()
else:
    print("Database not found")

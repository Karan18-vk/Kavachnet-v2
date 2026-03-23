from models.db import Database
db = Database()
conn = db._connect()
rows = conn.execute("SELECT recipient, status, attempts, last_error FROM email_queue").fetchall()
for r in rows:
    print(dict(r))

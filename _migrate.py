import sqlite3
conn = sqlite3.connect(r'E:\cyber\PenteIA-V4.0\penteia_lab.db')
c = conn.cursor()

ops = [
    ("users.role", "ALTER TABLE users ADD COLUMN role VARCHAR DEFAULT 'user'"),
]
for name, sql in ops:
    try:
        c.execute(sql)
        print(f"OK: {name}")
    except Exception as e:
        print(f"SKIP {name}: {e}")

c.execute("UPDATE users SET role='admin' WHERE is_admin=1")
c.execute("UPDATE users SET role='user' WHERE (role IS NULL OR role='') AND is_admin=0")
print("Updated user roles")

# Ensure campaigns table exists (create_all may not have run for this table)
c.execute("""
    CREATE TABLE IF NOT EXISTS campaigns (
        id VARCHAR PRIMARY KEY,
        user_id VARCHAR NOT NULL,
        status VARCHAR DEFAULT 'pending',
        config JSON DEFAULT '{}',
        results JSON DEFAULT '{}',
        report JSON DEFAULT '{}',
        started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed_at DATETIME
    )
""")
print("Ensured campaigns table exists")

conn.commit()
conn.close()
print("Migration complete")

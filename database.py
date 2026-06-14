from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from models import Base
import os

DATABASE_URL = "sqlite:///./penteia_lab.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate_add_columns()
    print("[OK] Database initialized")

def _migrate_add_columns():
    from sqlalchemy import text
    migrations = [
        "ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0",
        "ALTER TABLE users ADD COLUMN credits INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN status VARCHAR(20) DEFAULT 'active'",
    ]
    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(text(sql))
                conn.commit()
            except Exception:
                pass  # column already exists

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

init_db()

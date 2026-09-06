"""
Database integration for the Password Strength Analyzer.

Uses SQLite to store a history of previously used passwords so the tool can
detect (and warn against) password reuse.

Security note on hashing:
  We store only a salted SHA-256 hash of each password - never the plaintext.
  This keeps the core behavioural feature (preventing reuse) without ever
  persisting passwords in a recoverable form. For production systems you would
  use a dedicated password KDF (bcrypt/argon2/scrypt/PBKDF2) with a random,
  per-user salt.
"""

import hashlib
import os
import sqlite3
from typing import List, Optional


DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "passwords.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    return conn


def _hash_password(password: str, salt: Optional[str] = None) -> tuple:
    salt = salt or secrets_hex()
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return digest, salt


def secrets_hex() -> str:
    return os.urandom(16).hex()


def record_password(password: str) -> None:
    """Persist a hashed copy of a newly accepted password."""
    digest, salt = _hash_password(password)
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO password_history (hash, salt) VALUES (?, ?)",
            (digest, salt),
        )
        conn.commit()
    finally:
        conn.close()


def is_reused(password: str) -> bool:
    """Return True if `password` matches any previously stored password."""
    conn = _connect()
    try:
        rows = conn.execute("SELECT hash, salt FROM password_history").fetchall()
    finally:
        conn.close()
    for digest, salt in rows:
        candidate, _ = _hash_password(password, salt)
        if candidate == digest:
            return True
    return False


def history_count() -> int:
    conn = _connect()
    try:
        return conn.execute("SELECT COUNT(*) FROM password_history").fetchone()[0]
    finally:
        conn.close()

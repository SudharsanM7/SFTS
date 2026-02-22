from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
import sqlite3
from typing import Optional, Tuple

from .config import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    PASSWORD_HASH_ITERATIONS,
    PASSWORD_MIN_LENGTH,
    PASSWORD_REQUIRE_DIGIT,
    PASSWORD_REQUIRE_LOWER,
    PASSWORD_REQUIRE_SYMBOL,
    PASSWORD_REQUIRE_UPPER,
    SESSION_SLIDING_TTL,
    SESSION_TTL,
)
from .db import get_connection


def _iterative_sha256(password: str, salt: bytes, iterations: int) -> bytes:
    data = password.encode("utf-8") + salt
    digest = hashlib.sha256(data).digest()
    for _ in range(iterations - 1):
        digest = hashlib.sha256(digest).digest()
    return digest


def _check_password_policy(password: str) -> Tuple[bool, str]:
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, "Password too short"
    if PASSWORD_REQUIRE_UPPER and not re.search(r"[A-Z]", password):
        return False, "Password requires uppercase"
    if PASSWORD_REQUIRE_LOWER and not re.search(r"[a-z]", password):
        return False, "Password requires lowercase"
    if PASSWORD_REQUIRE_DIGIT and not re.search(r"\d", password):
        return False, "Password requires digit"
    if PASSWORD_REQUIRE_SYMBOL and not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password requires symbol"
    return True, "OK"


def register_user(username: str, password: str, email: str | None = None) -> Tuple[bool, str]:
    ok, msg = _check_password_policy(password)
    if not ok:
        return False, msg

    salt = os.urandom(16)
    password_hash = _iterative_sha256(password, salt, PASSWORD_HASH_ITERATIONS).hex()

    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, salt, password_hash, role, email) VALUES (?, ?, ?, 'user', ?)",
                (username, salt.hex(), password_hash, email),
            )
        return True, "Registered"
    except Exception as exc:  # pragma: no cover - sqlite error mapping is environment specific
        return False, f"Registration failed: {exc}"


def _set_lockout(conn, user_id: int, failed_attempts: int) -> None:
    locked_until = None
    if failed_attempts >= 5:
        locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
    conn.execute(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
        (failed_attempts, locked_until.isoformat() if locked_until else None, user_id),
    )


def login_user(
    username: str,
    password: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Tuple[bool, str]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, salt, password_hash, failed_attempts, locked_until FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if not row:
            return False, "Invalid credentials"

        if row["locked_until"]:
            locked_until = datetime.fromisoformat(row["locked_until"])
            if locked_until > datetime.now(timezone.utc):
                return False, "Account locked"

        salt = bytes.fromhex(row["salt"])
        candidate = _iterative_sha256(password, salt, PASSWORD_HASH_ITERATIONS).hex()

        if not hmac.compare_digest(candidate, row["password_hash"]):
            failed_attempts = int(row["failed_attempts"]) + 1
            _set_lockout(conn, row["id"], failed_attempts)
            return False, "Invalid credentials"

        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), row["id"]),
        )

        token = secrets.token_hex(32)
        now = datetime.now(timezone.utc)
        expires_at = now + SESSION_TTL

        conn.execute(
            "INSERT INTO sessions (user_id, session_token, created_at, expires_at, ip_address, user_agent) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                row["id"],
                token,
                now.isoformat(),
                expires_at.isoformat(),
                ip_address,
                user_agent,
            ),
        )

        return True, token


def validate_session(token: str) -> Tuple[bool, str | int]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, user_id, expires_at FROM sessions WHERE session_token = ?",
            (token,),
        ).fetchone()
        if not row:
            return False, "Invalid session"

        expires_at = datetime.fromisoformat(row["expires_at"])
        now = datetime.now(timezone.utc)
        if expires_at < now:
            conn.execute("DELETE FROM sessions WHERE id = ?", (row["id"],))
            return False, "Session expired"

        new_expiry = now + SESSION_SLIDING_TTL
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE id = ?",
            (new_expiry.isoformat(), row["id"]),
        )
        return True, row["user_id"]


def get_user_salt(username: str) -> bytes:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT salt FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row:
            raise ValueError("User not found")
        return bytes.fromhex(row["salt"])


def get_user_by_username(username: str) -> Optional[dict]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, username, role, locked_until FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row:
            return None
        return dict(row)


def is_admin(user_id: int) -> bool:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not row:
            return False
        return row["role"] == "admin"


def ensure_admin_user(conn: sqlite3.Connection | None = None) -> None:
    ok, msg = _check_password_policy(ADMIN_PASSWORD)
    if not ok:
        return

    if conn is not None:
        row = conn.execute(
            "SELECT id FROM users WHERE role = 'admin' LIMIT 1",
        ).fetchone()
        if row:
            return

        salt = os.urandom(16)
        password_hash = _iterative_sha256(
            ADMIN_PASSWORD, salt, PASSWORD_HASH_ITERATIONS
        ).hex()
        conn.execute(
            "INSERT INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, 'admin')",
            (ADMIN_USERNAME, salt.hex(), password_hash),
        )
        return

    with get_connection() as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE role = 'admin' LIMIT 1",
        ).fetchone()
        if row:
            return

        salt = os.urandom(16)
        password_hash = _iterative_sha256(
            ADMIN_PASSWORD, salt, PASSWORD_HASH_ITERATIONS
        ).hex()
        conn.execute(
            "INSERT INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, 'admin')",
            (ADMIN_USERNAME, salt.hex(), password_hash),
        )

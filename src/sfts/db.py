from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from .config import DB_PATH


def get_db_path() -> str:
    return os.getenv("SFTS_DB_PATH", DB_PATH)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def init_db() -> None:
    Path(get_db_path()).touch(exist_ok=True)
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS transfer_logs (
                id INTEGER PRIMARY KEY,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                original_hash TEXT NOT NULL,
                transfer_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL,
                attack_detected BOOLEAN DEFAULT 0,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                encrypted_size INTEGER,
                original_hash TEXT NOT NULL,
                iv TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                encrypted_path TEXT NOT NULL,
                sender_salt TEXT,
                status TEXT NOT NULL DEFAULT 'queued',
                transfer_expires_at TIMESTAMP,
                downloaded_at TIMESTAMP,
                download_count INTEGER NOT NULL DEFAULT 0,
                max_downloads INTEGER NOT NULL DEFAULT 1,
                share_enabled INTEGER NOT NULL DEFAULT 0,
                note_ciphertext TEXT,
                note_iv TEXT,
                note_is_encrypted INTEGER NOT NULL DEFAULT 0,
                compressed INTEGER NOT NULL DEFAULT 0,
                original_path TEXT,
                folder_upload INTEGER NOT NULL DEFAULT 0,
                expiry_notified INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY,
                ip_address TEXT NOT NULL,
                window_start TIMESTAMP NOT NULL,
                request_count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                blocked_until TIMESTAMP NOT NULL,
                reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS mfa_factors (
                id INTEGER PRIMARY KEY,
                user_id INTEGER UNIQUE NOT NULL,
                secret TEXT NOT NULL,
                backup_codes_json TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS user_keys (
                id INTEGER PRIMARY KEY,
                user_id INTEGER UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS multipart_transfers (
                id INTEGER PRIMARY KEY,
                transfer_id TEXT UNIQUE NOT NULL,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                total_chunks INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'uploading',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS multipart_chunks (
                id INTEGER PRIMARY KEY,
                transfer_id TEXT NOT NULL,
                chunk_no INTEGER NOT NULL,
                chunk_hash TEXT NOT NULL,
                chunk_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(transfer_id, chunk_no),
                FOREIGN KEY(transfer_id) REFERENCES multipart_transfers(transfer_id)
            );

            CREATE TABLE IF NOT EXISTS transfer_jobs (
                id INTEGER PRIMARY KEY,
                transfer_id INTEGER,
                status TEXT NOT NULL DEFAULT 'queued',
                error TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(transfer_id) REFERENCES transfers(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY,
                actor_id INTEGER,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                meta_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(actor_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS nonce_cache (
                id INTEGER PRIMARY KEY,
                nonce TEXT UNIQUE NOT NULL,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                session_id INTEGER NOT NULL,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            );

            CREATE TABLE IF NOT EXISTS share_links (
                id INTEGER PRIMARY KEY,
                transfer_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                max_uses INTEGER NOT NULL DEFAULT 1,
                used_count INTEGER NOT NULL DEFAULT 0,
                expires_at TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(transfer_id) REFERENCES transfers(id)
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS email_templates (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                body_html TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS backup_jobs (
                id INTEGER PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'queued',
                output_path TEXT,
                error TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            );
            """
        )

        _ensure_column(conn, "users", "role", "TEXT NOT NULL DEFAULT 'user'")
        _ensure_column(conn, "users", "email", "TEXT")
        _ensure_column(conn, "users", "daily_quota_bytes", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "users", "monthly_quota_bytes", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "users", "storage_quota_bytes", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "transfers", "sender_salt", "TEXT")
        _ensure_column(conn, "transfers", "encrypted_size", "INTEGER")
        _ensure_column(conn, "transfers", "transfer_expires_at", "TIMESTAMP")
        _ensure_column(conn, "transfers", "downloaded_at", "TIMESTAMP")
        _ensure_column(conn, "transfers", "download_count", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "transfers", "max_downloads", "INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "transfers", "share_enabled", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "transfers", "note_ciphertext", "TEXT")
        _ensure_column(conn, "transfers", "note_iv", "TEXT")
        _ensure_column(conn, "transfers", "note_is_encrypted", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "transfers", "compressed", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "transfers", "original_path", "TEXT")
        _ensure_column(conn, "transfers", "folder_upload", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "transfers", "expiry_notified", "INTEGER NOT NULL DEFAULT 0")

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_transfers_receiver_created ON transfers(receiver_id, created_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_transfers_sender_created ON transfers(sender_id, created_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_transfers_expiry ON transfers(transfer_expires_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_notifications_user_created ON notifications(user_id, created_at DESC)"
        )

        conn.execute(
            "INSERT INTO email_templates (name, subject, body_html, enabled) "
            "VALUES ('file_arrived', 'New file received in SFTS', '<p>You received a new file: <strong>{{ filename }}</strong></p>', 1) "
            "ON CONFLICT(name) DO NOTHING"
        )
        conn.execute(
            "INSERT INTO email_templates (name, subject, body_html, enabled) "
            "VALUES ('transfer_expiring', 'SFTS transfer expiring soon', '<p>Your transfer <strong>{{ filename }}</strong> expires at {{ expires_at }}</p>', 1) "
            "ON CONFLICT(name) DO NOTHING"
        )
        conn.execute(
            "INSERT INTO email_templates (name, subject, body_html, enabled) "
            "VALUES ('security_alert', 'SFTS security alert', '<p>Security event: <strong>{{ event }}</strong></p><p>{{ details }}</p>', 1) "
            "ON CONFLICT(name) DO NOTHING"
        )

        from .auth import ensure_admin_user

        ensure_admin_user(conn)


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

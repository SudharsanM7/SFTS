from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from pathlib import Path
import smtplib

from .config import (
    ALLOWED_TRANSFER_TTL_HOURS,
    BACKUP_DIR,
    DEFAULT_DAILY_QUOTA_BYTES,
    DEFAULT_MONTHLY_QUOTA_BYTES,
    DEFAULT_STORAGE_QUOTA_BYTES,
    MAX_SHARE_LINK_DOWNLOADS,
    SMTP_FROM,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USE_TLS,
    SMTP_USERNAME,
)
from .crypto import decrypt_bytes, derive_key, encrypt_bytes

WORK_DIR = Path(os.getenv("SFTS_WORK_DIR", tempfile.gettempdir())) / "sfts_feature_files"
WORK_DIR.mkdir(parents=True, exist_ok=True)


def _allowed_ttls() -> list[int]:
    values = []
    for value in ALLOWED_TRANSFER_TTL_HOURS.split(","):
        value = value.strip()
        if value.isdigit():
            values.append(int(value))
    return values or [1, 24, 168, 720]


def parse_ttl_hours(value: str | None) -> int:
    allowed = _allowed_ttls()
    if not value:
        return 24
    try:
        ttl = int(value)
    except ValueError as exc:
        raise ValueError("Invalid TTL") from exc
    if ttl not in allowed:
        raise ValueError("Unsupported TTL")
    return ttl


def expires_at_from_ttl(hours: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=hours)


def _month_start(now: datetime) -> datetime:
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def ensure_user_quotas(conn: sqlite3.Connection, user_id: int) -> dict:
    row = conn.execute(
        "SELECT daily_quota_bytes, monthly_quota_bytes, storage_quota_bytes FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not row:
        raise ValueError("User not found")

    daily = int(row["daily_quota_bytes"] or 0)
    monthly = int(row["monthly_quota_bytes"] or 0)
    storage = int(row["storage_quota_bytes"] or 0)

    if daily <= 0 or monthly <= 0 or storage <= 0:
        conn.execute(
            "UPDATE users SET daily_quota_bytes = CASE WHEN daily_quota_bytes <= 0 THEN ? ELSE daily_quota_bytes END, "
            "monthly_quota_bytes = CASE WHEN monthly_quota_bytes <= 0 THEN ? ELSE monthly_quota_bytes END, "
            "storage_quota_bytes = CASE WHEN storage_quota_bytes <= 0 THEN ? ELSE storage_quota_bytes END "
            "WHERE id = ?",
            (DEFAULT_DAILY_QUOTA_BYTES, DEFAULT_MONTHLY_QUOTA_BYTES, DEFAULT_STORAGE_QUOTA_BYTES, user_id),
        )
        daily = daily if daily > 0 else DEFAULT_DAILY_QUOTA_BYTES
        monthly = monthly if monthly > 0 else DEFAULT_MONTHLY_QUOTA_BYTES
        storage = storage if storage > 0 else DEFAULT_STORAGE_QUOTA_BYTES

    return {
        "daily_quota_bytes": daily,
        "monthly_quota_bytes": monthly,
        "storage_quota_bytes": storage,
    }


def quota_usage(conn: sqlite3.Connection, user_id: int) -> dict:
    now = datetime.now(timezone.utc)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    month_start = _month_start(now).isoformat()

    daily_used = conn.execute(
        "SELECT COALESCE(SUM(file_size), 0) AS total FROM transfers WHERE sender_id = ? AND created_at >= ?",
        (user_id, day_start),
    ).fetchone()["total"]

    monthly_used = conn.execute(
        "SELECT COALESCE(SUM(file_size), 0) AS total FROM transfers WHERE sender_id = ? AND created_at >= ?",
        (user_id, month_start),
    ).fetchone()["total"]

    storage_used = conn.execute(
        "SELECT COALESCE(SUM(COALESCE(encrypted_size, file_size)), 0) AS total FROM transfers WHERE sender_id = ? AND status != 'deleted'",
        (user_id,),
    ).fetchone()["total"]

    return {
        "daily_used": int(daily_used or 0),
        "monthly_used": int(monthly_used or 0),
        "storage_used": int(storage_used or 0),
    }


def check_quota_allowance(conn: sqlite3.Connection, user_id: int, incoming_size: int) -> tuple[bool, str, dict]:
    limits = ensure_user_quotas(conn, user_id)
    usage = quota_usage(conn, user_id)

    if usage["daily_used"] + incoming_size > limits["daily_quota_bytes"]:
        return False, "Daily upload quota exceeded", {**limits, **usage}
    if usage["monthly_used"] + incoming_size > limits["monthly_quota_bytes"]:
        return False, "Monthly upload quota exceeded", {**limits, **usage}
    if usage["storage_used"] + incoming_size > limits["storage_quota_bytes"]:
        return False, "Storage quota exceeded", {**limits, **usage}

    return True, "ok", {**limits, **usage}


def maybe_compress_file(input_path: Path, enabled: bool) -> tuple[Path, bool, int]:
    if not enabled:
        return input_path, False, input_path.stat().st_size

    compressed_path = WORK_DIR / f"{input_path.name}.gz"
    with open(input_path, "rb") as src, gzip.open(compressed_path, "wb", compresslevel=6) as dst:
        shutil.copyfileobj(src, dst)

    if compressed_path.stat().st_size >= input_path.stat().st_size:
        compressed_path.unlink(missing_ok=True)
        return input_path, False, input_path.stat().st_size

    return compressed_path, True, input_path.stat().st_size


def maybe_decompress_file(input_path: Path, enabled: bool, output_path: Path) -> Path:
    if not enabled:
        return output_path

    temp_out = output_path.with_suffix(output_path.suffix + ".tmp")
    with gzip.open(input_path, "rb") as src, open(temp_out, "wb") as dst:
        shutil.copyfileobj(src, dst)
    temp_out.replace(output_path)
    return output_path


def encrypt_note(note: str, transfer_secret: str, salt_hex: str) -> tuple[str, str]:
    if not note.strip():
        return "", ""
    key = derive_key(transfer_secret, bytes.fromhex(salt_hex))
    iv = os.urandom(16)
    encrypted = encrypt_bytes(key, iv, note.encode("utf-8"))
    return base64.b64encode(encrypted).decode("ascii"), iv.hex()


def decrypt_note(note_ciphertext: str | None, note_iv: str | None, transfer_secret: str, salt_hex: str) -> str:
    if not note_ciphertext or not note_iv:
        return ""
    key = derive_key(transfer_secret, bytes.fromhex(salt_hex))
    plain = decrypt_bytes(
        key,
        bytes.fromhex(note_iv),
        base64.b64decode(note_ciphertext.encode("ascii")),
    )
    return plain.decode("utf-8", errors="replace")


def create_share_link(
    conn: sqlite3.Connection,
    transfer_id: int,
    expires_at: datetime | None,
    max_uses: int,
    password: str | None,
) -> dict:
    token = secrets.token_urlsafe(24)
    max_uses = max(1, min(max_uses, MAX_SHARE_LINK_DOWNLOADS))
    password_hash = None
    if password:
        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

    conn.execute(
        "INSERT INTO share_links (transfer_id, token, password_hash, max_uses, expires_at) VALUES (?, ?, ?, ?, ?)",
        (transfer_id, token, password_hash, max_uses, expires_at.isoformat() if expires_at else None),
    )
    conn.execute("UPDATE transfers SET share_enabled = 1 WHERE id = ?", (transfer_id,))
    return {"token": token, "max_uses": max_uses, "expires_at": expires_at.isoformat() if expires_at else None}


def validate_share_link(conn: sqlite3.Connection, token: str, password: str | None) -> tuple[bool, str, sqlite3.Row | None]:
    row = conn.execute(
        "SELECT sl.id, sl.transfer_id, sl.password_hash, sl.max_uses, sl.used_count, sl.expires_at, sl.status "
        "FROM share_links sl WHERE sl.token = ?",
        (token,),
    ).fetchone()
    if not row:
        return False, "Invalid link", None
    if row["status"] != "active":
        return False, "Link is inactive", None
    if row["expires_at"]:
        expires = datetime.fromisoformat(row["expires_at"])
        if expires < datetime.now(timezone.utc):
            return False, "Link expired", None
    if int(row["used_count"] or 0) >= int(row["max_uses"] or 1):
        return False, "Link usage limit reached", None
    if row["password_hash"]:
        candidate = hashlib.sha256((password or "").encode("utf-8")).hexdigest()
        if candidate != row["password_hash"]:
            return False, "Invalid link password", None
    return True, "ok", row


def consume_share_link(conn: sqlite3.Connection, share_link_id: int) -> None:
    conn.execute(
        "UPDATE share_links SET used_count = used_count + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (share_link_id,),
    )


def add_notification(conn: sqlite3.Connection, user_id: int, category: str, title: str, message: str) -> None:
    conn.execute(
        "INSERT INTO notifications (user_id, category, title, message) VALUES (?, ?, ?, ?)",
        (user_id, category, title, message),
    )


def unread_notifications(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, category, title, message, created_at FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC LIMIT 10",
        (user_id,),
    ).fetchall()


def mark_notifications_read(conn: sqlite3.Connection, user_id: int) -> int:
    cur = conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0", (user_id,))
    return int(cur.rowcount or 0)


def cleanup_expired_transfers(conn: sqlite3.Connection) -> dict:
    now_iso = datetime.now(timezone.utc).isoformat()
    rows = conn.execute(
        "SELECT id, encrypted_path, original_path FROM transfers WHERE status != 'deleted' AND transfer_expires_at IS NOT NULL AND transfer_expires_at < ?",
        (now_iso,),
    ).fetchall()

    deleted = 0
    for row in rows:
        Path(row["encrypted_path"]).unlink(missing_ok=True)
        if row["original_path"]:
            Path(row["original_path"]).unlink(missing_ok=True)
        conn.execute(
            "UPDATE transfers SET status = 'deleted', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (row["id"],),
        )
        deleted += 1

    conn.execute(
        "UPDATE share_links SET status = 'expired', updated_at = CURRENT_TIMESTAMP WHERE expires_at IS NOT NULL AND expires_at < ? AND status = 'active'",
        (now_iso,),
    )

    return {"deleted_transfers": deleted}


def session_details(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, session_token, ip_address, user_agent, created_at, expires_at FROM sessions WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()


def revoke_session(conn: sqlite3.Connection, user_id: int, session_id: int) -> int:
    cur = conn.execute("DELETE FROM sessions WHERE user_id = ? AND id = ?", (user_id, session_id))
    return int(cur.rowcount or 0)


def revoke_other_sessions(conn: sqlite3.Connection, user_id: int, current_token: str) -> int:
    cur = conn.execute(
        "DELETE FROM sessions WHERE user_id = ? AND session_token != ?",
        (user_id, current_token),
    )
    return int(cur.rowcount or 0)


def render_email_template(subject: str, body_html: str, values: dict) -> tuple[str, str]:
    rendered_subject = subject
    rendered_body = body_html
    for key, value in values.items():
        rendered_subject = rendered_subject.replace("{{ " + key + " }}", str(value))
        rendered_body = rendered_body.replace("{{ " + key + " }}", str(value))
    return rendered_subject, rendered_body


def send_email_if_configured(to_email: str, subject: str, body_html: str) -> tuple[bool, str]:
    if not SMTP_HOST or not to_email:
        return False, "smtp_not_configured"

    msg = MIMEText(body_html, "html", "utf-8")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        if SMTP_USE_TLS:
            server.starttls()
        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_FROM, [to_email], msg.as_string())
    return True, "sent"


def send_security_email(conn: sqlite3.Connection, user_id: int, event: str, details: str) -> tuple[bool, str]:
    user = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or not user["email"]:
        return False, "email_missing"
    template = conn.execute(
        "SELECT subject, body_html, enabled FROM email_templates WHERE name = 'security_alert'"
    ).fetchone()
    if not template or int(template["enabled"] or 0) != 1:
        return False, "template_disabled"
    subject, body = render_email_template(template["subject"], template["body_html"], {"event": event, "details": details})
    return send_email_if_configured(user["email"], subject, body)


def send_transfer_expiry_reminders(conn: sqlite3.Connection) -> int:
    now = datetime.now(timezone.utc)
    soon = (now + timedelta(hours=1)).isoformat()
    rows = conn.execute(
        "SELECT t.id, t.filename, t.transfer_expires_at, u.email, u.id AS sender_id "
        "FROM transfers t JOIN users u ON u.id = t.sender_id "
        "WHERE t.status = 'queued' AND t.transfer_expires_at IS NOT NULL AND t.transfer_expires_at <= ? AND t.transfer_expires_at >= ? AND t.expiry_notified = 0",
        (soon, now.isoformat()),
    ).fetchall()

    sent = 0
    template = conn.execute(
        "SELECT subject, body_html, enabled FROM email_templates WHERE name = 'transfer_expiring'"
    ).fetchone()
    if not template or int(template["enabled"] or 0) != 1:
        return 0

    for row in rows:
        if row["email"]:
            subject, body = render_email_template(
                template["subject"],
                template["body_html"],
                {"filename": row["filename"], "expires_at": row["transfer_expires_at"]},
            )
            send_email_if_configured(row["email"], subject, body)
        add_notification(
            conn,
            row["sender_id"],
            "transfer_expiring",
            "Transfer expiring soon",
            f"{row['filename']} expires at {row['transfer_expires_at']}",
        )
        conn.execute("UPDATE transfers SET expiry_notified = 1 WHERE id = ?", (row["id"],))
        sent += 1
    return sent


def create_backup_file(db_path: str) -> Path:
    backup_root = Path(BACKUP_DIR)
    backup_root.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output = backup_root / f"sfts_backup_{ts}.db"
    shutil.copy2(db_path, output)
    return output


def zip_files_for_upload(base_dir: Path, files: list) -> Path:
    out_zip = WORK_DIR / f"folder_upload_{secrets.token_hex(8)}.zip"
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for storage in files:
            rel = storage.filename or "unknown"
            safe_rel = rel.replace("..", "").replace("\\", "/").lstrip("/")
            temp_file = base_dir / (secrets.token_hex(8) + "_" + Path(safe_rel).name)
            storage.save(temp_file)
            zf.write(temp_file, arcname=safe_rel)
            temp_file.unlink(missing_ok=True)
    return out_zip


def summarize_metrics(conn: sqlite3.Connection) -> dict:
    totals = conn.execute(
        "SELECT COUNT(*) AS transfers, COALESCE(SUM(file_size), 0) AS bytes_in, COALESCE(SUM(COALESCE(encrypted_size, file_size)), 0) AS bytes_stored FROM transfers"
    ).fetchone()
    completed = conn.execute(
        "SELECT COUNT(*) AS total FROM transfers WHERE status = 'received'"
    ).fetchone()["total"]
    avg_size = conn.execute(
        "SELECT COALESCE(AVG(file_size), 0) AS avg_size FROM transfers"
    ).fetchone()["avg_size"]

    heatmap = conn.execute(
        "SELECT substr(created_at, 12, 2) AS hour, COUNT(*) AS total FROM transfers GROUP BY hour ORDER BY hour"
    ).fetchall()

    return {
        "transfers": int(totals["transfers"] or 0),
        "bytes_in": int(totals["bytes_in"] or 0),
        "bytes_stored": int(totals["bytes_stored"] or 0),
        "success_rate": 0 if int(totals["transfers"] or 0) == 0 else round((int(completed) / int(totals["transfers"])) * 100, 2),
        "avg_size": int(float(avg_size or 0)),
        "heatmap": [{"hour": row["hour"], "total": row["total"]} for row in heatmap],
    }


def openapi_spec(base_url: str) -> dict:
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "SFTS API",
            "version": "1.0.0",
            "description": "API docs for multipart upload and operational endpoints.",
        },
        "servers": [{"url": base_url}],
        "paths": {
            "/api/transfers/init": {
                "post": {
                    "summary": "Initialize multipart transfer",
                    "requestBody": {"required": True},
                    "responses": {"200": {"description": "Transfer initialized"}},
                }
            },
            "/api/transfers/{transfer_id}/chunk/{chunk_no}": {
                "post": {
                    "summary": "Upload chunk",
                    "responses": {"200": {"description": "Chunk accepted"}},
                }
            },
            "/api/transfers/{transfer_id}/finalize": {
                "post": {
                    "summary": "Finalize multipart transfer",
                    "responses": {"200": {"description": "Transfer assembled"}},
                }
            },
            "/health": {"get": {"summary": "Health check", "responses": {"200": {"description": "OK"}}}},
        },
    }

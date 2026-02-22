from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import secrets
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .config import BACKUP_INTERVAL_HOURS, DB_PATH, MULTIPART_MAX_CHUNKS, PROGRESSIVE_BLOCK_WINDOWS_MINUTES, WORKER_BATCH_SIZE
from .db import get_connection
from .features import cleanup_expired_transfers, create_backup_file, send_transfer_expiry_reminders

CHUNK_DIR = Path(os.getenv("SFTS_CHUNK_DIR", tempfile.gettempdir())) / "sfts_chunks"
CHUNK_DIR.mkdir(parents=True, exist_ok=True)


def generate_user_keypair(user_id: int) -> dict:
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO user_keys (user_id, public_key, private_key, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(user_id) DO UPDATE SET public_key = excluded.public_key, private_key = excluded.private_key, updated_at = CURRENT_TIMESTAMP",
            (user_id, public_raw, private_raw),
        )

    return {"user_id": user_id, "public_key": public_raw}


def encrypt_file_key_for_recipient(file_key: bytes, recipient_pubkey: bytes) -> bytes:
    eph_private = x25519.X25519PrivateKey.generate()
    eph_public = eph_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    recipient_key = x25519.X25519PublicKey.from_public_bytes(recipient_pubkey)
    shared = eph_private.exchange(recipient_key)
    keystream = hashlib.sha256(shared).digest()
    wrapped = bytes(byte ^ keystream[idx % len(keystream)] for idx, byte in enumerate(file_key))
    return eph_public + wrapped


def decrypt_file_key_for_user(wrapped_key: bytes, user_privkey: bytes) -> bytes:
    eph_public = wrapped_key[:32]
    ciphertext = wrapped_key[32:]

    private_key = x25519.X25519PrivateKey.from_private_bytes(user_privkey)
    peer_key = x25519.X25519PublicKey.from_public_bytes(eph_public)
    shared = private_key.exchange(peer_key)
    keystream = hashlib.sha256(shared).digest()
    return bytes(byte ^ keystream[idx % len(keystream)] for idx, byte in enumerate(ciphertext))


def init_multipart_transfer(sender_id: int, receiver_id: int, filename: str, total_chunks: int) -> str:
    if total_chunks <= 0 or total_chunks > MULTIPART_MAX_CHUNKS:
        raise ValueError("Invalid chunk count")

    transfer_id = secrets.token_hex(16)
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO multipart_transfers (transfer_id, sender_id, receiver_id, filename, total_chunks, status) "
            "VALUES (?, ?, ?, ?, ?, 'uploading')",
            (transfer_id, sender_id, receiver_id, filename, total_chunks),
        )
    return transfer_id


def upload_chunk(transfer_id: str, chunk_no: int, data: bytes, chunk_hash: str) -> bool:
    if chunk_no < 1:
        raise ValueError("chunk_no must be >= 1")

    digest = hashlib.sha256(data).hexdigest()
    if digest != chunk_hash:
        return False

    chunk_path = CHUNK_DIR / f"{transfer_id}_{chunk_no:06d}.part"
    chunk_path.write_bytes(data)

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO multipart_chunks (transfer_id, chunk_no, chunk_hash, chunk_path) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(transfer_id, chunk_no) DO UPDATE SET chunk_hash = excluded.chunk_hash, chunk_path = excluded.chunk_path",
            (transfer_id, chunk_no, chunk_hash, str(chunk_path)),
        )
    return True


def finalize_transfer(transfer_id: str) -> dict:
    with get_connection() as conn:
        transfer = conn.execute(
            "SELECT filename, total_chunks FROM multipart_transfers WHERE transfer_id = ?",
            (transfer_id,),
        ).fetchone()
        if not transfer:
            raise ValueError("Transfer not found")

        chunks = conn.execute(
            "SELECT chunk_no, chunk_path FROM multipart_chunks WHERE transfer_id = ? ORDER BY chunk_no ASC",
            (transfer_id,),
        ).fetchall()

        total_chunks = int(transfer["total_chunks"])
        if len(chunks) != total_chunks:
            raise ValueError("Transfer incomplete")

        output_path = CHUNK_DIR / f"{transfer_id}_{Path(transfer['filename']).name}"
        with open(output_path, "wb") as out:
            for chunk in chunks:
                out.write(Path(chunk["chunk_path"]).read_bytes())

        conn.execute(
            "UPDATE multipart_transfers SET status = 'completed', updated_at = CURRENT_TIMESTAMP WHERE transfer_id = ?",
            (transfer_id,),
        )

    return {"transfer_id": transfer_id, "output_path": str(output_path), "chunks": total_chunks}


def apply_progressive_block(ip: str, conn: sqlite3.Connection | None = None) -> datetime:
    windows = [int(part.strip()) for part in PROGRESSIVE_BLOCK_WINDOWS_MINUTES.split(",") if part.strip()]
    now = datetime.now(timezone.utc)

    if conn is None:
        with get_connection() as own_conn:
            return apply_progressive_block(ip, conn=own_conn)

    prior_blocks = conn.execute(
            "SELECT COUNT(*) AS total FROM security_events WHERE event_type = 'ip_blocked' AND details LIKE ? AND created_at >= ?",
            (f"%ip={ip}%", (now - timedelta(hours=24)).isoformat()),
        ).fetchone()

    level = min(int(prior_blocks["total"]), max(len(windows) - 1, 0))
    minutes = windows[level] if windows else 5
    blocked_until = now + timedelta(minutes=minutes)

    existing = conn.execute("SELECT id FROM blocked_ips WHERE ip_address = ?", (ip,)).fetchone()
    if existing:
        conn.execute(
            "UPDATE blocked_ips SET blocked_until = ?, reason = ?, updated_at = CURRENT_TIMESTAMP WHERE ip_address = ?",
            (blocked_until.isoformat(), f"progressive_block_level={level+1}", ip),
        )
    else:
        conn.execute(
            "INSERT INTO blocked_ips (ip_address, blocked_until, reason) VALUES (?, ?, ?)",
            (ip, blocked_until.isoformat(), f"progressive_block_level={level+1}"),
        )

    conn.execute(
        "INSERT INTO security_events (user_id, event_type, details) VALUES (?, ?, ?)",
        (None, "ip_blocked", f"ip={ip}, until={blocked_until.isoformat()}, level={level+1}"),
    )

    return blocked_until


def is_request_allowed(ip: str, user_id: int | None) -> tuple[bool, str]:
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT blocked_until FROM blocked_ips WHERE ip_address = ? AND blocked_until >= ?",
            (ip, now_iso),
        ).fetchone()

    if not row:
        return True, "allowed"

    return False, f"blocked_until={row['blocked_until']}"


def create_security_alert(
    event_type: str,
    severity: str,
    details: str,
    conn: sqlite3.Connection | None = None,
) -> None:
    if conn is not None:
        conn.execute(
            "INSERT INTO security_alerts (event_type, severity, details, status) VALUES (?, ?, ?, 'open')",
            (event_type, severity, details),
        )
        return

    with get_connection() as own_conn:
        create_security_alert(event_type, severity, details, conn=own_conn)


def append_audit_log(
    actor_id: int | None,
    action: str,
    target: str,
    meta: dict,
    conn: sqlite3.Connection | None = None,
) -> None:
    if conn is not None:
        conn.execute(
            "INSERT INTO audit_logs (actor_id, action, target, meta_json) VALUES (?, ?, ?, ?)",
            (actor_id, action, target, json.dumps(meta)),
        )
        return

    with get_connection() as own_conn:
        append_audit_log(actor_id, action, target, meta, conn=own_conn)


def export_audit_report(start: datetime, end: datetime, fmt: str = "csv") -> str:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT actor_id, action, target, meta_json, created_at FROM audit_logs WHERE created_at >= ? AND created_at <= ? ORDER BY created_at ASC",
            (start.isoformat(), end.isoformat()),
        ).fetchall()

    if fmt.lower() != "csv":
        raise ValueError("Only csv export is supported")

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["actor_id", "action", "target", "meta_json", "created_at"])
    for row in rows:
        writer.writerow([row["actor_id"], row["action"], row["target"], row["meta_json"], row["created_at"]])
    return buffer.getvalue()


def queue_transfer_job(transfer_id: int, conn: sqlite3.Connection | None = None) -> str:
    if conn is not None:
        conn.execute(
            "INSERT INTO transfer_jobs (transfer_id, status) VALUES (?, 'queued')",
            (transfer_id,),
        )
        return "queued"

    with get_connection() as own_conn:
        queue_transfer_job(transfer_id, conn=own_conn)
    return "queued"


def run_transfer_worker() -> None:
    with get_connection() as conn:
        jobs = conn.execute(
            "SELECT id FROM transfer_jobs WHERE status = 'queued' ORDER BY created_at ASC LIMIT ?",
            (WORKER_BATCH_SIZE,),
        ).fetchall()

        for job in jobs:
            conn.execute(
                "UPDATE transfer_jobs SET status = 'completed', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (job["id"],),
            )

        cleanup_expired_transfers(conn)
        send_transfer_expiry_reminders(conn)

        last_backup = conn.execute(
            "SELECT completed_at FROM backup_jobs WHERE status = 'completed' ORDER BY completed_at DESC LIMIT 1"
        ).fetchone()
        should_backup = True
        if last_backup and last_backup["completed_at"]:
            last = datetime.fromisoformat(last_backup["completed_at"])
            should_backup = (datetime.now(timezone.utc) - last) >= timedelta(hours=BACKUP_INTERVAL_HOURS)
        if should_backup:
            job_id = conn.execute("INSERT INTO backup_jobs (status) VALUES ('queued')").lastrowid
            try:
                output = create_backup_file(DB_PATH)
                conn.execute(
                    "UPDATE backup_jobs SET status = 'completed', output_path = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (str(output), job_id),
                )
            except Exception as exc:
                conn.execute(
                    "UPDATE backup_jobs SET status = 'failed', error = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (str(exc), job_id),
                )


def health_check() -> dict:
    now = datetime.now(timezone.utc)
    with get_connection() as conn:
        users = conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
        active_sessions = conn.execute(
            "SELECT COUNT(*) AS total FROM sessions WHERE expires_at >= ?",
            (now.isoformat(),),
        ).fetchone()["total"]
        queued_jobs = conn.execute(
            "SELECT COUNT(*) AS total FROM transfer_jobs WHERE status = 'queued'",
        ).fetchone()["total"]
        open_alerts = conn.execute(
            "SELECT COUNT(*) AS total FROM security_alerts WHERE status = 'open'",
        ).fetchone()["total"]

    return {
        "status": "ok",
        "time": now.isoformat(),
        "users": int(users),
        "active_sessions": int(active_sessions),
        "queued_jobs": int(queued_jobs),
        "open_alerts": int(open_alerts),
    }

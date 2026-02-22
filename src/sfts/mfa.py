from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from io import BytesIO
from typing import Optional

import qrcode

from .config import (
    MFA_ALLOWED_DRIFT_STEPS,
    MFA_BACKUP_CODES_COUNT,
    MFA_ISSUER,
    MFA_TIME_STEP_SECONDS,
)
from .db import get_connection


def _hotp(secret: str, counter: int, digits: int = 6) -> str:
    normalized = secret.strip().replace(" ", "").upper()
    pad_len = (-len(normalized)) % 8
    normalized += "=" * pad_len
    key = base64.b32decode(normalized, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def _totp_at(secret: str, ts: int) -> str:
    return _hotp(secret, ts // MFA_TIME_STEP_SECONDS)


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_uri(username: str, secret: str) -> str:
    issuer = MFA_ISSUER.replace(" ", "%20")
    account = username.replace(" ", "%20")
    return f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&period={MFA_TIME_STEP_SECONDS}"


def qr_code_data_uri(payload: str) -> str:
    image = qrcode.make(payload)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def verify_totp(secret: str, code: str) -> bool:
    now = int(time.time())
    candidate = (code or "").strip()
    if not candidate.isdigit() or len(candidate) != 6:
        return False
    for drift in range(-MFA_ALLOWED_DRIFT_STEPS, MFA_ALLOWED_DRIFT_STEPS + 1):
        step_time = now + (drift * MFA_TIME_STEP_SECONDS)
        if hmac.compare_digest(_totp_at(secret, step_time), candidate):
            return True
    return False


def _hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def generate_backup_codes() -> tuple[list[str], list[str]]:
    plain_codes = [secrets.token_hex(4) for _ in range(MFA_BACKUP_CODES_COUNT)]
    hashed_codes = [_hash_backup_code(code) for code in plain_codes]
    return plain_codes, hashed_codes


def setup_mfa_for_user(user_id: int) -> tuple[str, list[str]]:
    secret = generate_totp_secret()
    plain_codes, hashed_codes = generate_backup_codes()
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO mfa_factors (user_id, secret, backup_codes_json, enabled, updated_at) "
            "VALUES (?, ?, ?, 0, CURRENT_TIMESTAMP) "
            "ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, backup_codes_json = excluded.backup_codes_json, enabled = 0, updated_at = CURRENT_TIMESTAMP",
            (user_id, secret, json.dumps(hashed_codes)),
        )
    return secret, plain_codes


def _get_factor(user_id: int) -> Optional[dict]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT secret, backup_codes_json, enabled FROM mfa_factors WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    return dict(row) if row else None


def is_mfa_enabled(user_id: int) -> bool:
    factor = _get_factor(user_id)
    return bool(factor and int(factor.get("enabled", 0)) == 1)


def enable_mfa(user_id: int) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE mfa_factors SET enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (user_id,),
        )


def verify_mfa_code(user_id: int, code: str) -> bool:
    factor = _get_factor(user_id)
    if not factor:
        return False

    secret = factor["secret"]
    if verify_totp(secret, code):
        return True

    hashed = _hash_backup_code((code or "").strip())
    backup_codes = json.loads(factor["backup_codes_json"])
    if hashed not in backup_codes:
        return False

    updated_codes = [item for item in backup_codes if item != hashed]
    with get_connection() as conn:
        conn.execute(
            "UPDATE mfa_factors SET backup_codes_json = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (json.dumps(updated_codes), user_id),
        )
    return True

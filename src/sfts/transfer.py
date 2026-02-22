from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import MAX_FILE_SIZE_BYTES, TIMESTAMP_SKEW_SECONDS
from .integrity import hmac_sha256
from .replay import NonceCache


@dataclass
class TransferMetadata:
    session_token: str
    filename: str
    file_size: int
    original_hash: str
    iv: str
    timestamp: str
    nonce: str
    sequence: int
    hmac: Optional[str] = None


def sanitize_filename(name: str) -> str:
    return Path(name).name


def create_metadata(
    session_token: str,
    filename: str,
    file_size: int,
    original_hash: str,
    iv: bytes,
    nonce: str,
    sequence: int,
    hmac_key: Optional[bytes] = None,
) -> TransferMetadata:
    safe_name = sanitize_filename(filename)
    if file_size > MAX_FILE_SIZE_BYTES:
        raise ValueError("File size exceeds limit")
    timestamp = datetime.now(timezone.utc).isoformat()
    metadata = TransferMetadata(
        session_token=session_token,
        filename=safe_name,
        file_size=file_size,
        original_hash=original_hash,
        iv=iv.hex(),
        timestamp=timestamp,
        nonce=nonce,
        sequence=sequence,
    )
    if hmac_key:
        metadata.hmac = hmac_sha256(
            hmac_key, json.dumps(_hmac_payload(metadata), sort_keys=True).encode("utf-8")
        ).hex()
    return metadata


def validate_metadata(
    metadata: TransferMetadata,
    nonce_cache: NonceCache,
    hmac_key: Optional[bytes] = None,
) -> bool:
    if metadata.file_size > MAX_FILE_SIZE_BYTES:
        return False

    if sanitize_filename(metadata.filename) != metadata.filename:
        return False

    try:
        ts = datetime.fromisoformat(metadata.timestamp)
    except ValueError:
        return False

    now = datetime.now(timezone.utc)
    if abs((now - ts).total_seconds()) > TIMESTAMP_SKEW_SECONDS:
        return False

    if nonce_cache.seen(metadata.nonce):
        return False

    if metadata.hmac and hmac_key:
        recalculated = hmac_sha256(
            hmac_key, json.dumps(_hmac_payload(metadata), sort_keys=True).encode("utf-8")
        ).hex()
        if recalculated != metadata.hmac:
            return False

    nonce_cache.add(metadata.nonce)
    return True


def serialize_metadata(metadata: TransferMetadata) -> bytes:
    return json.dumps(asdict(metadata)).encode("utf-8")


def deserialize_metadata(raw: bytes) -> TransferMetadata:
    payload = json.loads(raw.decode("utf-8"))
    return TransferMetadata(**payload)


def _hmac_payload(metadata: TransferMetadata) -> dict:
    payload = asdict(metadata)
    payload["hmac"] = None
    return payload

from __future__ import annotations

import secrets
from pathlib import Path

from .auth import login_user
from .crypto import derive_key, encrypt_file
from .transfer import create_metadata


def prepare_transfer(
    username: str,
    transfer_secret: str,
    file_path: str,
    session_token: str,
) -> dict:
    if not transfer_secret:
        raise ValueError("Transfer secret is required")

    salt = secrets.token_bytes(16)
    key = derive_key(transfer_secret, salt)
    encrypted_path = f"{file_path}.enc"
    iv, file_hash, file_size = encrypt_file(file_path, encrypted_path, key)

    metadata = create_metadata(
        session_token=session_token,
        filename=Path(file_path).name,
        file_size=file_size,
        original_hash=file_hash,
        iv=iv,
        nonce=secrets.token_hex(16),
        sequence=1,
    )

    return {
        "metadata": metadata,
        "encrypted_path": encrypted_path,
        "salt": salt.hex(),
    }


def login_and_prepare(username: str, password: str, file_path: str) -> dict:
    ok, token_or_msg = login_user(username, password)
    if not ok:
        raise ValueError(token_or_msg)
    return prepare_transfer(username, password, file_path, token_or_msg)

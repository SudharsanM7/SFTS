from __future__ import annotations

import os
import hashlib
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .config import CHUNK_SIZE, PBKDF2_ITERATIONS
from .integrity import constant_time_compare


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(128).padder()
    encryptor = cipher.encryptor()
    padded = padder.update(data) + padder.finalize()
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_bytes(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    padded = decryptor.update(data) + decryptor.finalize()
    return unpadder.update(padded) + unpadder.finalize()


def encrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
) -> Tuple[bytes, str, int]:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    file_hash = hashlib.sha256()
    file_size = 0

    with open(input_path, "rb") as inp, open(output_path, "wb") as out:
        while True:
            chunk = inp.read(CHUNK_SIZE)
            if not chunk:
                break
            file_size += len(chunk)
            file_hash.update(chunk)
            padded = padder.update(chunk)
            if padded:
                out.write(encryptor.update(padded))
        final_padded = padder.finalize()
        out.write(encryptor.update(final_padded) + encryptor.finalize())

    return iv, file_hash.hexdigest(), file_size


def decrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
    iv: bytes,
    expected_hash: str,
) -> bool:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    file_hash = hashlib.sha256()

    try:
        with open(input_path, "rb") as inp, open(output_path, "wb") as out:
            while True:
                chunk = inp.read(CHUNK_SIZE)
                if not chunk:
                    break
                padded = decryptor.update(chunk)
                data = unpadder.update(padded)
                if data:
                    file_hash.update(data)
                    out.write(data)
            final_data = unpadder.update(decryptor.finalize()) + unpadder.finalize()
            if final_data:
                file_hash.update(final_data)
                out.write(final_data)
    except ValueError:
        Path(output_path).unlink(missing_ok=True)
        return False

    if not constant_time_compare(file_hash.hexdigest(), expected_hash):
        Path(output_path).unlink(missing_ok=True)
        return False
    return True

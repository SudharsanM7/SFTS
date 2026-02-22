import os
import tempfile

from sfts.crypto import derive_key, encrypt_file, decrypt_file


def test_encrypt_decrypt_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "plain.txt")
        enc = os.path.join(tmp, "plain.txt.enc")
        out = os.path.join(tmp, "plain.txt.out")

        with open(src, "wb") as handle:
            handle.write(b"hello secure world")

        key = derive_key("Password!12345", b"saltsalt12345678")
        iv, file_hash, _ = encrypt_file(src, enc, key)
        ok = decrypt_file(enc, out, key, iv, file_hash)
        assert ok is True

        with open(out, "rb") as handle:
            assert handle.read() == b"hello secure world"

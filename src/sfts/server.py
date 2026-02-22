from __future__ import annotations

from .crypto import derive_key, decrypt_file
from .replay import NonceCache
from .transfer import TransferMetadata, validate_metadata


class TransferReceiver:
    def __init__(self) -> None:
        self.nonce_cache = NonceCache()

    def receive(
        self,
        metadata: TransferMetadata,
        encrypted_path: str,
        output_path: str,
        transfer_secret: str,
        salt_hex: str,
    ) -> bool:
        if not validate_metadata(metadata, self.nonce_cache):
            return False

        key = derive_key(transfer_secret, bytes.fromhex(salt_hex))
        iv = bytes.fromhex(metadata.iv)
        return decrypt_file(encrypted_path, output_path, key, iv, metadata.original_hash)

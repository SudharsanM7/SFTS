from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass

from .config import NONCE_CACHE_SIZE, NONCE_TTL


@dataclass
class NonceEntry:
    nonce: str
    timestamp: float


class NonceCache:
    def __init__(self) -> None:
        self._entries: deque[NonceEntry] = deque(maxlen=NONCE_CACHE_SIZE)
        self._set: set[str] = set()

    def add(self, nonce: str) -> None:
        now = time.time()
        if nonce in self._set:
            return
        if len(self._entries) == self._entries.maxlen:
            oldest = self._entries[0]
            self._set.discard(oldest.nonce)
        self._entries.append(NonceEntry(nonce=nonce, timestamp=now))
        self._set.add(nonce)
        self._cleanup(now)

    def seen(self, nonce: str) -> bool:
        self._cleanup(time.time())
        return nonce in self._set

    def _cleanup(self, now: float) -> None:
        ttl_seconds = NONCE_TTL.total_seconds()
        while self._entries and (now - self._entries[0].timestamp) > ttl_seconds:
            entry = self._entries.popleft()
            self._set.discard(entry.nonce)

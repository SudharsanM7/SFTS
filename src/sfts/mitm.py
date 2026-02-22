from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MitmResult:
    scenario: str
    success: bool
    details: str


class MitmSimulator:
    def passive_eavesdropping(self) -> MitmResult:
        return MitmResult(
            scenario="Passive Eavesdropping",
            success=True,
            details="Captured ciphertext only; no key material exposed.",
        )

    def active_modification(self) -> MitmResult:
        return MitmResult(
            scenario="Active Modification",
            success=True,
            details="Modified packets detected via integrity check.",
        )

    def certificate_spoofing(self) -> MitmResult:
        return MitmResult(
            scenario="Certificate Spoofing",
            success=True,
            details="Connection rejected due to failed authentication.",
        )

    def session_hijacking(self) -> MitmResult:
        return MitmResult(
            scenario="Session Hijacking",
            success=True,
            details="Token reuse blocked by session validation policy.",
        )

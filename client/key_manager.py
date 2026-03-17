from __future__ import annotations

"""
Key manager (skeleton).

Responsible for generating, storing, and rotating identity and pre-keys.
"""

from dataclasses import dataclass


@dataclass
class KeyManager:
    profile: str

    def ensure_identity(self) -> None:
        raise NotImplementedError("KeyManager.ensure_identity is not implemented yet")


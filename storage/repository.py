from __future__ import annotations

"""
Repository layer (skeleton).

Provides a higher-level API over the encrypted database for storing and
retrieving identities, sessions, and group states.
"""

from dataclasses import dataclass
from typing import Optional

from .encrypted_db import EncryptedDB
from .models import IdentityRecord, SessionRecord


@dataclass
class StorageRepository:
    db: EncryptedDB

    def get_identity(self) -> Optional[IdentityRecord]:
        raise NotImplementedError("StorageRepository.get_identity is not implemented yet")

    def save_identity(self, record: IdentityRecord) -> None:
        raise NotImplementedError("StorageRepository.save_identity is not implemented yet")


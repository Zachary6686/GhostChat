from __future__ import annotations

"""
Encrypted database abstraction (skeleton).

In a full implementation, this would manage opening an encrypted SQLite
database, key derivation, and CRUD operations over logical models.
"""

from dataclasses import dataclass
from typing import Any


@dataclass
class EncryptedDB:
    path: str

    def execute(self, query: str, *params: Any) -> None:
        raise NotImplementedError("EncryptedDB.execute is not implemented yet")


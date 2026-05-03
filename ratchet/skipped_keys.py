from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple

from .errors import SkippedKeyNotFoundError, SkippedKeyStorageLimitError


HeaderKey = Tuple[bytes, int]  # (ratchet public key bytes, message number)


@dataclass
class SkippedKeyStore:
    """
    Bounded store for skipped message keys.
    """

    max_keys: int = 1000
    _store: Dict[HeaderKey, bytes] = field(default_factory=dict)

    def add(self, ratchet_pub: bytes, msg_num: int, key: bytes) -> None:
        if len(self._store) >= self.max_keys:
            raise SkippedKeyStorageLimitError("Skipped message key store capacity exceeded")
        self._store[(ratchet_pub, msg_num)] = key

    def pop(self, ratchet_pub: bytes, msg_num: int) -> bytes:
        try:
            return self._store.pop((ratchet_pub, msg_num))
        except KeyError as exc:
            raise SkippedKeyNotFoundError("No skipped key for header") from exc

    def has(self, ratchet_pub: bytes, msg_num: int) -> bool:
        return (ratchet_pub, msg_num) in self._store

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._store)

    def copy(self) -> "SkippedKeyStore":
        return SkippedKeyStore(max_keys=self.max_keys, _store=dict(self._store))


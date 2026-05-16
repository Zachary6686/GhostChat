from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Set, Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from crypto.serialization import b64u_decode, b64u_encode

from .group_state import GroupState, INITIAL_EPOCH
from .errors import EpochMismatchError, ReplayedGroupMessageError, MembershipError


@dataclass
class GroupMessageHeader:
    group_id: bytes
    epoch: int
    sender_leaf_index: int
    counter: int


@dataclass
class GroupMessage:
    header: GroupMessageHeader
    ciphertext: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gid": b64u_encode(self.header.group_id),
            "e": self.header.epoch,
            "s": self.header.sender_leaf_index,
            "c": self.header.counter,
            "ct": b64u_encode(self.ciphertext),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GroupMessage":
        try:
            gid = b64u_decode(data["gid"])
            e = int(data["e"])
            s = int(data["s"])
            c = int(data["c"])
            ct = b64u_decode(data["ct"])
        except (KeyError, TypeError, ValueError) as err:
            raise ValueError("Malformed group message") from err
        if e < INITIAL_EPOCH or s < 0 or c < 0:
            raise ValueError("Invalid group message fields")
        return cls(
            header=GroupMessageHeader(group_id=gid, epoch=e, sender_leaf_index=s, counter=c),
            ciphertext=ct,
        )


@dataclass
class ReplayCache:
    """
    Bounded per-sender replay cache keyed by (sender_leaf_index, counter).
    """

    max_entries: int = 2048
    seen: Set[Tuple[int, int]] = field(default_factory=set)

    def check(self, sender_leaf: int, counter: int) -> bool:
        key = (sender_leaf, counter)
        if key in self.seen:
            return False
        if len(self.seen) >= self.max_entries:
            return False
        return True

    def mark(self, sender_leaf: int, counter: int) -> None:
        self.seen.add((sender_leaf, counter))

    def check_and_mark(self, sender_leaf: int, counter: int) -> bool:
        if not self.check(sender_leaf, counter):
            return False
        self.mark(sender_leaf, counter)
        return True


class GroupMessenger:
    """
    MLS-inspired group messaging using the current application_key from
    GroupState. Intended for small, trusted groups.
    """

    def __init__(self, state: GroupState, sender_leaf_index: int, max_replay_entries: int = 2048) -> None:
        if state.application_key is None:
            raise ValueError("GroupState is missing application_key")
        self.state = state
        self.sender_leaf_index = sender_leaf_index
        self._counter = 0
        self._replay_cache = ReplayCache(max_entries=max_replay_entries)

    def _nonce_from_counter(self, counter: int) -> bytes:
        key = self.state.application_key or b""
        base = bytearray(key[:12])
        for i in range(4):
            base[-1 - i] ^= (counter >> (8 * i)) & 0xFF
        return bytes(base)

    def encrypt(self, plaintext: bytes, ad: bytes = b"") -> GroupMessage:
        app_key = self.state.application_key
        if app_key is None:
            raise ValueError("Missing application key")

        counter = self._counter
        nonce = self._nonce_from_counter(counter)
        aead = ChaCha20Poly1305(app_key)
        header = GroupMessageHeader(
            group_id=self.state.group_id,
            epoch=self.state.epoch,
            sender_leaf_index=self.sender_leaf_index,
            counter=counter,
        )
        ad_bytes = (
            header.group_id
            + header.epoch.to_bytes(8, "big")
            + header.sender_leaf_index.to_bytes(4, "big")
            + header.counter.to_bytes(8, "big")
            + ad
        )
        ct = aead.encrypt(nonce, plaintext, ad_bytes)
        self._counter += 1
        return GroupMessage(header=header, ciphertext=ct)

    def decrypt(self, message: GroupMessage, ad: bytes = b"") -> bytes:
        header = message.header

        if header.group_id != self.state.group_id:
            raise ValueError("Group ID mismatch")

        if header.epoch != self.state.epoch:
            raise EpochMismatchError("Stale or future epoch")

        if not any(
            m.leaf_index == header.sender_leaf_index for m in self.state.members.values()
        ):
            raise MembershipError("Unknown sender leaf index")

        if not self._replay_cache.check(
            header.sender_leaf_index, header.counter
        ):
            raise ReplayedGroupMessageError("Duplicate group message counter")

        app_key = self.state.application_key
        if app_key is None:
            raise ValueError("Missing application key")

        nonce = self._nonce_from_counter(header.counter)
        aead = ChaCha20Poly1305(app_key)
        ad_bytes = (
            header.group_id
            + header.epoch.to_bytes(8, "big")
            + header.sender_leaf_index.to_bytes(4, "big")
            + header.counter.to_bytes(8, "big")
            + ad
        )
        plaintext = aead.decrypt(nonce, message.ciphertext, ad_bytes)
        self._replay_cache.mark(header.sender_leaf_index, header.counter)
        return plaintext


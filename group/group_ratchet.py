from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from crypto.hkdf import hkdf_derive
from .group_state import GroupState


def _derive_message_key(group_secret: bytes, epoch: int, msg_index: int) -> bytes:
    return hkdf_derive(
        ikm=group_secret,
        salt=b"ghostchat-group-msg-salt",
        info=b"ghostchat-group-msg:"
        + epoch.to_bytes(8, "big")
        + b":"
        + msg_index.to_bytes(8, "big"),
        length=32,
    )


def _mk_to_nonce(mk: bytes, msg_index: int) -> bytes:
    base = bytearray(mk[:12])
    for i in range(4):
        base[-1 - i] ^= (msg_index >> (8 * i)) & 0xFF
    return bytes(base)


@dataclass
class GroupMessageHeader:
    group_id: bytes
    epoch: int
    index: int


@dataclass
class GroupCiphertext:
    header: GroupMessageHeader
    ciphertext: bytes


class GroupRatchet:
    """
    Simple epoch-based group message ratchet.

    All members in a given epoch share the same group_secret; per-message
    keys are derived from (group_secret, epoch, index) and used with
    ChaCha20-Poly1305.
    """

    def __init__(self, state: GroupState) -> None:
        if state.group_secret is None:
            raise ValueError("GroupState must have a group_secret")
        self.state = state
        self._send_index = 0

    def encrypt(self, plaintext: bytes, ad: bytes = b"") -> GroupCiphertext:
        if self.state.group_secret is None:
            raise ValueError("Missing group secret")

        mk = _derive_message_key(self.state.group_secret, self.state.epoch, self._send_index)
        nonce = _mk_to_nonce(mk, self._send_index)
        aead = ChaCha20Poly1305(mk)
        ct = aead.encrypt(nonce, plaintext, ad)

        header = GroupMessageHeader(
            group_id=self.state.group_id,
            epoch=self.state.epoch,
            index=self._send_index,
        )
        self._send_index += 1
        return GroupCiphertext(header=header, ciphertext=ct)

    def decrypt(self, message: GroupCiphertext, ad: bytes = b"") -> bytes:
        if self.state.group_secret is None:
            raise ValueError("Missing group secret")
        if message.header.group_id != self.state.group_id:
            raise ValueError("Group ID mismatch")
        if message.header.epoch != self.state.epoch:
            raise ValueError("Epoch mismatch")

        mk = _derive_message_key(
            self.state.group_secret,
            message.header.epoch,
            message.header.index,
        )
        nonce = _mk_to_nonce(mk, message.header.index)
        aead = ChaCha20Poly1305(mk)
        return aead.decrypt(nonce, message.ciphertext, ad)


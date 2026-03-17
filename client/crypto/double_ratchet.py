"""
Double Ratchet state machine for GhostChat client.

Research-grade hardening:
- Full AAD binding for all header fields (dh, n, pn).
- Anti-replay via persisted received message ids (bounded, FIFO eviction).
- Session versioning and anti-rollback on save.
- Skipped keys: upper bound and FIFO eviction when at capacity.
- Duplicate header detection via received_ids before any key derivation.
"""

from __future__ import annotations

import base64
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from nacl.public import Box, PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey

from client.crypto.kdf import kdf_chain, kdf_initial_chain, kdf_root
from client.crypto.message import RatchetMessageHeader, RatchetWireMessage
from client.crypto.ratchet_errors import (
    DecryptionError,
    DuplicateMessageError,
    SkippedKeyNotFoundError,
    SkippedKeyStorageLimitError,
)
from client.crypto.symmetric import aead_decrypt, aead_encrypt

# AAD length: dh(32) + n(4) + pn(4) = 40 bytes, big-endian for n and pn
AAD_NONCE_LEN = 12
DH_PUB_LEN = 32


def _dh(priv: X25519PrivateKey, pub: X25519PublicKey) -> bytes:
    """X25519 shared secret for KDF. Must not be used as a key directly."""
    return Box(priv, pub)._shared_key


def _header_aad(header: RatchetMessageHeader) -> bytes:
    """Build authenticated data from header so tampering fails at decrypt."""
    return (
        header.dh
        + bytes(
            [
                (header.n >> 24) & 0xFF,
                (header.n >> 16) & 0xFF,
                (header.n >> 8) & 0xFF,
                header.n & 0xFF,
            ]
        )
        + bytes(
            [
                (header.pn >> 24) & 0xFF,
                (header.pn >> 16) & 0xFF,
                (header.pn >> 8) & 0xFF,
                header.pn & 0xFF,
            ]
        )
    )


def _message_key_to_nonce(mk: bytes, n: int) -> bytes:
    """Deterministic 12-byte nonce from message key and message number (no reuse)."""
    if len(mk) < AAD_NONCE_LEN:
        raise ValueError("message key too short for nonce derivation")
    base = bytearray(mk[:AAD_NONCE_LEN])
    for i in range(4):
        base[-1 - i] ^= (n >> (8 * i)) & 0xFF
    return bytes(base)


def _b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _encode_received_id(dh: bytes, n: int) -> str:
    return _b64_encode(
        bytes(dh)
        + bytes(
            [
                (n >> 24) & 0xFF,
                (n >> 16) & 0xFF,
                (n >> 8) & 0xFF,
                n & 0xFF,
            ]
        )
    )


def _decode_received_id(s: str) -> Tuple[bytes, int]:
    raw = _b64_decode(s)
    if len(raw) != 36:
        raise ValueError("received id must decode to 36 bytes")
    return raw[:32], (raw[32] << 24) | (raw[33] << 16) | (raw[34] << 8) | raw[35]


@dataclass
class ReceivedIdsStore:
    """
    Bounded store of (dh, n) message ids we have already accepted (anti-replay).
    FIFO eviction when at capacity. Persisted so replay after restore is rejected.
    """
    max_size: int = 2000
    _order: "OrderedDict[Tuple[bytes, int], None]" = field(default_factory=OrderedDict)

    def contains(self, dh_pub: bytes, n: int) -> bool:
        return (bytes(dh_pub), n) in self._order

    def add(self, dh_pub: bytes, n: int) -> None:
        key = (bytes(dh_pub), n)
        if key in self._order:
            return
        while len(self._order) >= self.max_size:
            self._order.popitem(last=False)
        self._order[key] = None

    def to_dict(self) -> Dict[str, List[str]]:
        return {"ids": [_encode_received_id(dh, n) for (dh, n) in self._order.keys()]}

    @classmethod
    def from_dict(
        cls,
        data: Optional[Dict[str, List[str]]],
        max_size: int = 2000,
    ) -> "ReceivedIdsStore":
        store = cls(max_size=max_size)
        if not data or not isinstance(data, dict):
            return store
        ids = data.get("ids")
        if not isinstance(ids, list):
            return store
        for s in ids:
            if not isinstance(s, str):
                continue
            try:
                dh, n = _decode_received_id(s)
                if not store.contains(dh, n):
                    store.add(dh, n)
            except (ValueError, Exception):
                continue
        return store


@dataclass
class SkippedMessageKeys:
    """
    Bounded store for skipped message keys: (dh_pub, n) -> message_key.
    FIFO eviction when at capacity. Keys are deleted after use.
    """
    max_keys: int = 1000
    _store: "OrderedDict[Tuple[bytes, int], bytes]" = field(default_factory=OrderedDict)

    def add(self, dh_pub: bytes, n: int, key: bytes) -> None:
        if len(dh_pub) != DH_PUB_LEN:
            raise ValueError("dh_pub must be 32 bytes")
        if len(key) != DH_PUB_LEN:
            raise ValueError("message key must be 32 bytes")
        if n < 0:
            raise ValueError("message number n must be non-negative")
        key_tuple = (bytes(dh_pub), n)
        while len(self._store) >= self.max_keys:
            self._store.popitem(last=False)
        self._store[key_tuple] = bytes(key)

    def pop(self, dh_pub: bytes, n: int) -> bytes:
        key = (bytes(dh_pub), n)
        if key not in self._store:
            raise SkippedKeyNotFoundError("No skipped key for header")
        return self._store.pop(key)

    def has(self, dh_pub: bytes, n: int) -> bool:
        return (bytes(dh_pub), n) in self._store

    def to_dict(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for (dh, n), key in self._store.items():
            k = _b64_encode(
                dh
                + bytes(
                    [
                        (n >> 24) & 0xFF,
                        (n >> 16) & 0xFF,
                        (n >> 8) & 0xFF,
                        n & 0xFF,
                    ]
                )
            )
            out[k] = _b64_encode(key)
        return out

    @classmethod
    def from_dict(
        cls,
        d: Dict[str, str],
        max_keys: int = 1000,
    ) -> "SkippedMessageKeys":
        """
        Deserialize from dict. Raises CorruptedSessionError (via caller) or ValueError
        on malformed entries. Rejects stores exceeding max_keys.
        """
        if not isinstance(d, dict):
            raise TypeError("skipped keys must be a dict")
        store: OrderedDict[Tuple[bytes, int], bytes] = OrderedDict()
        for k_str, v_str in d.items():
            if not isinstance(k_str, str) or not isinstance(v_str, str):
                raise ValueError("skipped key entry must be str keys and values")
            raw = _b64_decode(k_str)
            if len(raw) != 36:
                raise ValueError("skipped key index must decode to 36 bytes (32 dh + 4 n)")
            dh_pub = raw[:32]
            n = (raw[32] << 24) | (raw[33] << 16) | (raw[34] << 8) | raw[35]
            if n < 0:
                raise ValueError("skipped key message number must be non-negative")
            key = _b64_decode(v_str)
            if len(key) != 32:
                raise ValueError("skipped message key must decode to 32 bytes")
            store[(dh_pub, n)] = key
        if len(store) > max_keys:
            raise SkippedKeyStorageLimitError(
                f"Skipped key store has {len(store)} entries, max allowed is {max_keys}"
            )
        sk = cls(max_keys=max_keys)
        sk._store = store
        return sk


@dataclass
class DoubleRatchetState:
    """
    Double Ratchet state: root key, chain keys, DH keys, counters, skipped keys,
    received message ids (anti-replay), and session version (anti-rollback).
    """
    root_key: bytes
    sending_chain_key: Optional[bytes] = None
    receiving_chain_key: Optional[bytes] = None
    dhs_private: Optional[bytes] = None   # our current sending ratchet private (32 bytes)
    dhr: Optional[bytes] = None           # their current ratchet public (32 bytes)
    Ns: int = 0
    Nr: int = 0
    PN: int = 0
    skipped_message_keys: SkippedMessageKeys = field(default_factory=lambda: SkippedMessageKeys(1000))
    received_ids: ReceivedIdsStore = field(default_factory=lambda: ReceivedIdsStore(2000))
    session_version: int = 1

    def dhs_public_bytes(self) -> bytes:
        if self.dhs_private is None:
            raise ValueError("dhs_private not set")
        return bytes(X25519PrivateKey(self.dhs_private).public_key)


class DoubleRatchetEngine:
    """
    Double Ratchet encrypt/decrypt with DH ratchet steps and skipped keys.
    """

    def __init__(self, state: DoubleRatchetState) -> None:
        self._state = state

    @property
    def state(self) -> DoubleRatchetState:
        return self._state

    def ratchet_encrypt(self, plaintext: bytes) -> RatchetWireMessage:
        """
        Encrypt plaintext. Derive message key from sending chain, advance chain, increment Ns.
        If no sending chain yet (e.g. after DH ratchet), perform DH ratchet step first.
        Header is bound as AAD so tampering fails at decrypt.
        """
        state = self._state
        if state.sending_chain_key is None:
            self._dh_ratchet_step_send()
        ck_s, mk = kdf_chain(state.sending_chain_key)
        state.sending_chain_key = ck_s
        header = RatchetMessageHeader(
            dh=state.dhs_public_bytes(),
            n=state.Ns,
            pn=state.PN,
        )
        nonce = _message_key_to_nonce(mk, state.Ns)
        ad = _header_aad(header)
        ciphertext = aead_encrypt(mk, plaintext, nonce, ad)
        state.Ns += 1
        return RatchetWireMessage(header=header, ciphertext=ciphertext, nonce=nonce)

    def ratchet_decrypt(self, msg: RatchetWireMessage) -> bytes:
        """
        Decrypt. Reject duplicate (replay) early; handle skipped keys, DH ratchet step if new key,
        then derive receiving message key. All decryption uses header as AAD.
        """
        state = self._state
        h = msg.header
        if len(h.dh) != DH_PUB_LEN:
            raise DecryptionError("Invalid header: dh must be 32 bytes")
        if h.n < 0:
            raise DecryptionError("Invalid header: message number must be non-negative")
        if len(msg.nonce) != AAD_NONCE_LEN:
            raise DecryptionError("Invalid message: nonce must be 12 bytes")

        # Duplicate header detection: reject (dh, n) we have already accepted (anti-replay, survives restore).
        if state.received_ids.contains(h.dh, h.n):
            raise DuplicateMessageError("Message already processed (replay or duplicate header)")

        # Skipped-key path: out-of-order message we already stored a key for.
        if state.skipped_message_keys.has(h.dh, h.n):
            mk = state.skipped_message_keys.pop(h.dh, h.n)
            nonce = _message_key_to_nonce(mk, h.n)
            if msg.nonce != nonce:
                raise DecryptionError("Nonce mismatch (tampering or corruption)")
            ad = _header_aad(h)
            try:
                plaintext = aead_decrypt(mk, msg.ciphertext, nonce, ad)
                state.received_ids.add(h.dh, h.n)
                return plaintext
            except InvalidTag as e:
                raise DecryptionError("AEAD verification failed (skipped-key path)") from e
            except Exception as e:
                raise DecryptionError("AEAD verification failed (skipped-key path)") from e

        # Early duplicate check: same ratchet, already processed this n (replay).
        if state.dhr is not None and h.dh == state.dhr and h.n < state.Nr:
            raise DuplicateMessageError("Message number already processed (replay)")

        if state.dhr is None and state.receiving_chain_key is not None and state.sending_chain_key is None:
            state.dhr = h.dh
        elif state.dhr is None and state.sending_chain_key is not None:
            self._skip_receiving_until(state.Nr)
            self._dh_ratchet_receive(h.dh)
        elif state.receiving_chain_key is None and state.dhr is None:
            self._skip_receiving_until(state.Nr)
            self._dh_ratchet_receive_first(h.dh)
        elif state.receiving_chain_key is None and state.dhr is not None and h.dh == state.dhr:
            peer_pub = X25519PublicKey(state.dhr)
            dhs = X25519PrivateKey(state.dhs_private)
            rk, ck_r = kdf_root(state.root_key, _dh(dhs, peer_pub))
            state.root_key = rk
            state.receiving_chain_key = ck_r
        if state.dhr is not None and h.dh != state.dhr:
            self._skip_receiving_until(state.Nr)
            self._dh_ratchet_receive(h.dh)
        if h.n < state.Nr:
            raise DuplicateMessageError("Message number already processed (replay)")
        self._skip_receiving_until(h.n)
        state.receiving_chain_key, mk = kdf_chain(state.receiving_chain_key)
        state.Nr += 1
        nonce = _message_key_to_nonce(mk, h.n)
        if msg.nonce != nonce:
            raise DecryptionError("Nonce mismatch (tampering or corruption)")
        ad = _header_aad(h)
        try:
            plaintext = aead_decrypt(mk, msg.ciphertext, nonce, ad)
            state.received_ids.add(h.dh, h.n)
            return plaintext
        except InvalidTag as e:
            raise DecryptionError("AEAD verification failed") from e
        except Exception as e:
            raise DecryptionError("AEAD verification failed") from e

    def _skip_receiving_until(self, until: int) -> None:
        """Advance receiving chain to 'until', storing message keys in skipped store for out-of-order delivery."""
        state = self._state
        if state.receiving_chain_key is None:
            return
        if state.dhr is None:
            return
        while state.Nr < until:
            state.receiving_chain_key, mk = kdf_chain(state.receiving_chain_key)
            state.skipped_message_keys.add(state.dhr, state.Nr, mk)
            state.Nr += 1

    def _dh_ratchet_receive_first(self, new_remote_dh: bytes) -> None:
        """First receive: bootstrap receiving chain from root_key (same as initiator send)."""
        state = self._state
        state.dhr = new_remote_dh
        state.receiving_chain_key = kdf_initial_chain(state.root_key)

    def _dh_ratchet_receive(self, new_remote_dh: bytes) -> None:
        state = self._state
        state.PN = state.Ns
        state.Ns = 0
        state.Nr = 0
        state.dhr = new_remote_dh
        peer_pub = X25519PublicKey(new_remote_dh)
        dhs = X25519PrivateKey(state.dhs_private)
        rk, ck_r = kdf_root(state.root_key, _dh(dhs, peer_pub))
        state.root_key = rk
        state.receiving_chain_key = ck_r
        state.dhs_private = bytes(X25519PrivateKey.generate())
        state.sending_chain_key = None

    def _dh_ratchet_step_send(self) -> None:
        state = self._state
        if state.dhr is None:
            return
        peer_pub = X25519PublicKey(state.dhr)
        dhs = X25519PrivateKey(state.dhs_private)
        rk, ck_s = kdf_root(state.root_key, _dh(dhs, peer_pub))
        state.root_key = rk
        state.sending_chain_key = ck_s
        state.Ns = 0


def create_initial_state(
    root_key: bytes,
    is_initiator: bool = True,
    dhr: Optional[bytes] = None,
    max_skipped_keys: int = 1000,
) -> DoubleRatchetState:
    """
    Create initial Double Ratchet state from X3DH root key.
    If dhr is provided, derive one chain from DH. Otherwise bootstrap with kdf_initial_chain
    so initiator can send first message (initiator send chain = responder recv chain).
    """
    if len(root_key) != 32:
        raise ValueError("root_key must be 32 bytes")
    dhs = X25519PrivateKey.generate()
    dhs_bytes = bytes(dhs)
    ck_s: Optional[bytes] = None
    ck_r: Optional[bytes] = None
    if dhr is not None:
        peer_pub = X25519PublicKey(dhr)
        rk, ck = kdf_root(root_key, _dh(dhs, peer_pub))
        root_key = rk
        if is_initiator:
            ck_s = ck
        else:
            ck_r = ck
    else:
        initial_ck = kdf_initial_chain(root_key)
        if is_initiator:
            ck_s = initial_ck
        else:
            ck_r = initial_ck
    return DoubleRatchetState(
        root_key=root_key,
        sending_chain_key=ck_s,
        receiving_chain_key=ck_r,
        dhs_private=dhs_bytes,
        dhr=dhr,
        Ns=0,
        Nr=0,
        PN=0,
        skipped_message_keys=SkippedMessageKeys(max_keys=max_skipped_keys),
        received_ids=ReceivedIdsStore(max_size=2000),
        session_version=1,
    )

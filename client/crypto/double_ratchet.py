"""
Double Ratchet state machine for GhostChat client.

State machine summary
--------------------
- Core keys: root_key (KDF state), sending_chain_key, receiving_chain_key.
- DH ratchet: dhs_private (local), dhr (remote public). On new remote key we
  perform a DH ratchet: update root_key, derive new chains, rotate dhs_private.
- Counters: Ns = messages sent in current sending chain; Nr = messages received
  in current receiving chain; PN = length of previous sending chain (sent in header).
- Replay/ordering: received_ids = bounded FIFO of (dh, n) we accepted; skipped_message_keys
  = bounded (dh, n) -> message_key for out-of-order delivery. Keys are single-use.
- Persistence: session_version is monotonic; save rejects rollback (on-disk version > in-memory).

Key invariants (security-critical)
----------------------------------
- Each message key is used at most once; replay of (dh, n) within cache is rejected.
- AAD = encode(dh || n || pn) binds header; tampering causes AEAD auth failure.
- Ns, Nr are monotonic within a chain; out-of-order allowed only within bounded window.
- MAX_SKIP_DISTANCE caps how far ahead n can be from Nr (limits CPU/memory from gaps).
- Replay protection is bounded (FIFO received_ids); very old messages may fall outside cache.
- Corrupted or rolled-back persisted state is rejected; no partial acceptance.
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
    SkipDistanceExceededError,
    SkippedKeyNotFoundError,
    SkippedKeyStorageLimitError,
)
from client.crypto.symmetric import aead_decrypt, aead_encrypt

# Wire / AEAD constants
AAD_NONCE_LEN = 12
DH_PUB_LEN = 32
# Skip distance: max allowed gap (h.n - Nr). Reject larger gaps to bound CPU/memory (DoS).
MAX_SKIP_DISTANCE = 5000


def _dh(priv: X25519PrivateKey, pub: X25519PublicKey) -> bytes:
    """X25519 shared secret for KDF. Must not be used as a key directly."""
    return Box(priv, pub)._shared_key


def _header_aad(header: RatchetMessageHeader) -> bytes:
    """
    AAD = encode(dh || n || pn). All security-critical header fields are bound
    to the ciphertext so that tampering with dh, n, or pn causes AEAD auth failure
    at decrypt (no plaintext leakage). Format: dh (32 bytes) || n (uint32 BE) || pn (uint32 BE).
    """
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
    Bounded replay cache of accepted (dh, n) message ids.

    - Purpose: reject recent duplicates and replays across process restarts.
    - Shape: FIFO window of up to max_size entries; older entries are evicted
      when the window is full.
    - Trade-off: this provides strong protection against replays for *recent*
      messages, while keeping memory usage bounded. Very old messages that have
      fallen out of the window are not guaranteed to be rejected solely by
      this cache; additional ordering checks in the double ratchet (Nr, PN,
      and DH ratchet state) still make exploiting such replays difficult.
    """
    max_size: int = 2000
    _order: "OrderedDict[Tuple[bytes, int], None]" = field(default_factory=OrderedDict)

    def contains(self, dh_pub: bytes, n: int) -> bool:
        return (bytes(dh_pub), n) in self._order

    def add(self, dh_pub: bytes, n: int) -> None:
        if n < 0 or n > 0xFFFF_FFFF:
            raise ValueError("message number must be in range [0, 2^32-1]")
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
        """Deserialize; raises ValueError on malformed id (no silent skip)."""
        store = cls(max_size=max_size)
        if not data or not isinstance(data, dict):
            return store
        ids = data.get("ids")
        if not isinstance(ids, list):
            return store
        for s in ids:
            if not isinstance(s, str):
                raise ValueError("received_ids entry must be a string")
            dh, n = _decode_received_id(s)
            if n < 0 or n > 0xFFFF_FFFF:
                raise ValueError("received_ids message number must be in range [0, 2^32-1]")
            if not store.contains(dh, n):
                store.add(dh, n)
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
        if n < 0 or n > 0xFFFF_FFFF:
            raise ValueError("message number n must be in range [0, 2^32-1]")
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
    Full Double Ratchet session state (spec-aligned).

    Core keys:
      root_key         — root KDF state; updated on DH ratchet.
      sending_chain_key — current sending chain key; None until first DH step.
      receiving_chain_key — current receiving chain key; None until we see peer's dh.

    DH ratchet:
      dhs_private — our local DH private key (32 bytes); rotated on new remote key.
      dhr — remote peer's current ratchet public key (header.dh we last accepted).

    Counters (monotonic within a chain):
      Ns — number of messages sent in current sending chain.
      Nr — number of messages received in current receiving chain.
      PN — number of messages in previous sending chain (sent in header as pn).

    Replay / ordering:
      skipped_message_keys — bounded map (dhr, n) -> message_key for out-of-order; FIFO eviction.
      received_ids — bounded FIFO set of (dh, n) already accepted; replay within cache rejected.

    Persistence:
      session_version — monotonic; older state cannot overwrite newer (anti-rollback).
    """
    root_key: bytes
    sending_chain_key: Optional[bytes] = None
    receiving_chain_key: Optional[bytes] = None
    dhs_private: Optional[bytes] = None  # local DH private (32 bytes); public = header.dh we send
    dhr: Optional[bytes] = None         # remote DH public (32 bytes); header.dh we last accepted
    Ns: int = 0   # messages sent in current sending chain
    Nr: int = 0   # messages received in current receiving chain
    PN: int = 0   # length of previous sending chain (included in header as pn)
    skipped_message_keys: SkippedMessageKeys = field(default_factory=lambda: SkippedMessageKeys(1000))
    received_ids: ReceivedIdsStore = field(default_factory=lambda: ReceivedIdsStore(2000))
    session_version: int = 1  # strictly increasing on save; anti-rollback

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

    @staticmethod
    def _snapshot_state(state: DoubleRatchetState) -> DoubleRatchetState:
        skipped = SkippedMessageKeys(max_keys=state.skipped_message_keys.max_keys)
        skipped._store = state.skipped_message_keys._store.copy()
        received = ReceivedIdsStore(max_size=state.received_ids.max_size)
        received._order = state.received_ids._order.copy()
        return DoubleRatchetState(
            root_key=state.root_key,
            sending_chain_key=state.sending_chain_key,
            receiving_chain_key=state.receiving_chain_key,
            dhs_private=state.dhs_private,
            dhr=state.dhr,
            Ns=state.Ns,
            Nr=state.Nr,
            PN=state.PN,
            skipped_message_keys=skipped,
            received_ids=received,
            session_version=state.session_version,
        )

    @staticmethod
    def _restore_state(state: DoubleRatchetState, snapshot: DoubleRatchetState) -> None:
        state.root_key = snapshot.root_key
        state.sending_chain_key = snapshot.sending_chain_key
        state.receiving_chain_key = snapshot.receiving_chain_key
        state.dhs_private = snapshot.dhs_private
        state.dhr = snapshot.dhr
        state.Ns = snapshot.Ns
        state.Nr = snapshot.Nr
        state.PN = snapshot.PN
        state.skipped_message_keys = snapshot.skipped_message_keys
        state.received_ids = snapshot.received_ids
        state.session_version = snapshot.session_version

    def ratchet_encrypt(self, plaintext: bytes) -> RatchetWireMessage:
        """
        Encrypt (send). Spec: 3.1 Encrypt.

        Preconditions: sending_chain_key must be initialized (or we perform _dh_ratchet_step_send first).
        Steps:
          - If sending_chain_key is None, perform DH ratchet step (derive sending chain from root_key, dhr).
          - Derive (new_chain_key, message_key) from sending_chain_key; update sending_chain_key.
          - Build header: dh = dhs_public, n = Ns, pn = PN.
          - Encrypt with AEAD(mk, plaintext, nonce, AAD); AAD = encode(dh||n||pn).
          - Increment Ns.
        Postconditions: Message key is single-use; Ns strictly increases.
        """
        state = self._state
        if state.sending_chain_key is None:
            self._dh_ratchet_step_send()
        if state.sending_chain_key is None:
            raise DecryptionError("No sending chain key (protocol not initialized or peer DH missing)")
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
        Decrypt (receive). Spec: 3.2 (same DH) and 3.3 (new DH ratchet).

        Preconditions: Valid header (dh 32 bytes, n >= 0, nonce 12 bytes).
        Steps (order matters):
          1. Reject if (h.dh, h.n) in received_ids (replay / duplicate). Bounded cache; very old (dh,n) may be evicted.
          2. If (h.dh, h.n) in skipped_message_keys: pop key, decrypt with AAD, add to received_ids, return. (Same DH, out-of-order.)
          3. If same ratchet (h.dh == dhr) and n < Nr: reject (replay).
          4. If new DH (h.dh != dhr or first receive): perform DH ratchet (PN=Ns, reset chains, KDF root, new dhs_private), then continue.
          5. Reject if n < Nr (already processed). Reject if n - Nr > MAX_SKIP_DISTANCE (skip distance limit).
          6. Advance receiving chain to n (store skipped keys for Nr..n-1), derive mk for n, decrypt with AAD, add (dh,n) to received_ids, Nr = n+1.
        Postconditions: Message key used at most once; Nr increases; AAD tampering yields DecryptionError.
        """
        state = self._state
        h = msg.header
        if len(h.dh) != DH_PUB_LEN:
            raise DecryptionError("Invalid header: dh must be 32 bytes")
        if h.n < 0:
            raise DecryptionError("Invalid header: message number must be non-negative")
        if len(msg.nonce) != AAD_NONCE_LEN:
            raise DecryptionError("Invalid message: nonce must be 12 bytes")

        # Replay: (dh, n) already accepted. received_ids is bounded FIFO; very old ids may be evicted.
        if state.received_ids.contains(h.dh, h.n):
            raise DuplicateMessageError("Message already processed (replay or duplicate header)")

        snapshot = self._snapshot_state(state)
        try:
            # Same DH ratchet, out-of-order: use skipped key if we have it.
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

            # Same ratchet, n already consumed (replay).
            if state.dhr is not None and h.dh == state.dhr and h.n < state.Nr:
                raise DuplicateMessageError("Message number already processed (replay)")

            # New DH or bootstrap: ensure dhr and receiving_chain_key are set (spec 3.3).
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
            # Skip distance: refuse to derive keys for n too far ahead of Nr (DoS bound).
            if state.receiving_chain_key is not None and h.n - state.Nr > MAX_SKIP_DISTANCE:
                raise SkipDistanceExceededError(
                    f"Skip distance {h.n - state.Nr} exceeds MAX_SKIP_DISTANCE={MAX_SKIP_DISTANCE}"
                )
            # Advance receiving chain to n, storing skipped keys for out-of-order delivery.
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
        except Exception:
            self._restore_state(state, snapshot)
            raise

    def _skip_receiving_until(self, until: int) -> None:
        """
        Advance receiving chain from Nr to until; store message keys in skipped_message_keys.
        Used when we receive message n > Nr: we must derive (and store) keys for Nr..until-1
        so out-of-order delivery can decrypt them later. Invariant: keys are single-use (pop on decrypt).
        """
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
        """
        First receive (no dhr yet): set dhr = header.dh, derive receiving_chain_key from root_key
        (same as initiator's initial send chain). Spec: bootstrap receiving chain.
        """
        state = self._state
        state.dhr = new_remote_dh
        state.receiving_chain_key = kdf_initial_chain(state.root_key)

    def _dh_ratchet_receive(self, new_remote_dh: bytes) -> None:
        """
        New DH ratchet (spec 3.3). Precondition: header.dh != dhr (new remote key).
        Steps: PN = Ns; Ns = 0; Nr = 0; dhr = new_remote_dh; root_key, receiving_chain_key = KDF(root_key, DH(dhs_private, new_remote_dh));
        generate new dhs_private; sending_chain_key = None (until _dh_ratchet_step_send).
        Postconditions: Old chains isolated; forward secrecy preserved.
        """
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
        """
        Derive sending chain when we have dhr but no sending_chain_key (e.g. after _dh_ratchet_receive).
        Precondition: dhr is set. Steps: root_key, sending_chain_key = KDF(root_key, DH(dhs_private, dhr)); Ns = 0.
        Postcondition: sending_chain_key set so ratchet_encrypt can derive message keys.
        """
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

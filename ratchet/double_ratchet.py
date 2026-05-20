from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from nacl.public import PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey, Box

from .errors import DuplicateMessageError
from .kdf import kdf_chain, kdf_root
from .skipped_keys import SkippedKeyStore
from .state import RatchetHeader, RatchetState


def _dh(a_priv: X25519PrivateKey, b_pub: X25519PublicKey) -> bytes:
    box = Box(a_priv, b_pub)
    return box._shared_key


def _aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, ad: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    return aead.encrypt(nonce, plaintext, ad)


def _aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, ad: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext, ad)


def _mk_to_nonce(mk: bytes, n: int) -> bytes:
    """
    Derive a 12-byte nonce from the message key and message number.
    """

    # Simple construction: first 12 bytes of mk XOR message number.
    base = bytearray(mk[:12])
    for i in range(4):
        base[-1 - i] ^= (n >> (8 * i)) & 0xFF
    return bytes(base)


def _clone_state(state: RatchetState) -> RatchetState:
    return RatchetState(
        root_key=state.root_key,
        dhs=state.dhs,
        dhr=state.dhr,
        ck_s=state.ck_s,
        ck_r=state.ck_r,
        Ns=state.Ns,
        Nr=state.Nr,
        PN=state.PN,
        skipped_keys=SkippedKeyStore(
            max_keys=state.skipped_keys.max_keys,
            _store=dict(state.skipped_keys._store),
        ),
    )


@dataclass
class EncryptedMessage:
    header: RatchetHeader
    ciphertext: bytes


class DoubleRatchet:
    """
    Double Ratchet engine implementing:
    - root key and chain key evolution
    - skipped message key storage
    - out-of-order delivery handling
    - simultaneous send race handling
    """

    def __init__(
        self,
        *,
        root_key: bytes,
        dhs: Optional[X25519PrivateKey] = None,
        dhr: Optional[bytes] = None,
        is_initiator: bool = True,
        max_skipped_keys: int = 1000,
    ) -> None:
        dhs_key = dhs or X25519PrivateKey.generate()
        skipped_store = SkippedKeyStore(max_keys=max_skipped_keys)

        ck_s: Optional[bytes] = None
        ck_r: Optional[bytes] = None
        Ns = 0
        Nr = 0
        PN = 0

        # Initial shared secret establishment, if we know the peer's DH.
        if dhr is not None:
            peer_pub = X25519PublicKey(dhr)
            rk, ck = kdf_root(root_key, _dh(dhs_key, peer_pub))
            root_key = rk
            if is_initiator:
                ck_s = ck
            else:
                ck_r = ck

        self.state = RatchetState(
            root_key=root_key,
            dhs=dhs_key,
            dhr=dhr,
            ck_s=ck_s,
            ck_r=ck_r,
            Ns=Ns,
            Nr=Nr,
            PN=PN,
            skipped_keys=skipped_store,
        )

    # --- public API ---

    def encrypt(self, plaintext: bytes, ad: bytes = b"") -> EncryptedMessage:
        """
        Encrypt a message using the current sending chain.
        """

        if self.state.ck_s is None:
            # First message we send after receiving a new remote DH: perform
            # a DH ratchet step to derive a fresh sending chain.
            self._dh_ratchet_step()

        ck_s, mk = kdf_chain(self.state.ck_s)  # type: ignore[arg-type]
        self.state.ck_s = ck_s

        header = RatchetHeader(
            dh_pub=self.state.dhs_public_bytes,
            pn=self.state.PN,
            n=self.state.Ns,
        )

        nonce = _mk_to_nonce(mk, self.state.Ns)
        ciphertext = _aead_encrypt(mk, nonce, plaintext, ad)

        self.state.Ns += 1

        return EncryptedMessage(header=header, ciphertext=ciphertext)

    def decrypt(self, message: EncryptedMessage, ad: bytes = b"") -> bytes:
        """
        Decrypt a message, handling out-of-order delivery and skipped keys.

        Receive state is mutated on a trial copy first and committed only after
        AEAD authentication succeeds so forged ciphertext cannot consume chain
        counters or skipped keys.
        """
        trial = DoubleRatchet.__new__(DoubleRatchet)
        trial.state = _clone_state(self.state)
        plaintext = trial._decrypt_mutating(message, ad)
        self.state = trial.state
        return plaintext

    def _decrypt_mutating(self, message: EncryptedMessage, ad: bytes = b"") -> bytes:
        h = message.header

        # 1. Skipped message keys first.
        if self.state.skipped_keys.has(h.dh_pub, h.n):
            mk = self.state.skipped_keys.pop(h.dh_pub, h.n)
            nonce = _mk_to_nonce(mk, h.n)
            return _aead_decrypt(mk, nonce, message.ciphertext, ad)

        # 2a. If we have no receiving chain yet but the DH public key matches
        # our stored DHR, derive the initial receiving chain.
        if self.state.ck_r is None and self.state.dhr is not None and h.dh_pub == self.state.dhr:
            peer_pub = X25519PublicKey(self.state.dhr)
            rk, ck_r = kdf_root(self.state.root_key, _dh(self.state.dhs, peer_pub))
            self.state.root_key = rk
            self.state.ck_r = ck_r

        # 2b. Maybe advance the DH ratchet if the DH public key changed.
        if self.state.dhr is None or h.dh_pub != self.state.dhr:
            self._skip_message_keys(until=self.state.Nr)
            self._dh_ratchet_receive(h.dh_pub)

        # 3. Now derive/skip within the current receiving chain.
        if h.n < self.state.Nr:
            raise DuplicateMessageError("Message number already processed in this chain")

        # Skip any unseen messages up to n-1, caching their keys.
        self._skip_message_keys(until=h.n)

        # Derive key for this message.
        self.state.ck_r, mk = kdf_chain(self.state.ck_r)  # type: ignore[arg-type]
        self.state.Nr += 1

        nonce = _mk_to_nonce(mk, h.n)
        return _aead_decrypt(mk, nonce, message.ciphertext, ad)

    # --- internal helpers ---

    def _skip_message_keys(self, *, until: int) -> None:
        """
        Derive and store keys for any skipped messages in the current
        receiving chain up to (but not including) `until`.
        """

        if self.state.ck_r is None:
            return

        while self.state.Nr < until:
            self.state.ck_r, mk = kdf_chain(self.state.ck_r)
            self.state.skipped_keys.add(self.state.dhr or b"", self.state.Nr, mk)
            self.state.Nr += 1

    def _dh_ratchet_receive(self, new_remote_dh: bytes) -> None:
        """
        Handle receipt of a message whose DH public key starts a new sending
        chain from the peer.
        """

        self.state.PN = self.state.Ns
        self.state.Ns = 0
        self.state.Nr = 0

        self.state.dhr = new_remote_dh

        # New receiving chain from DH(DHs, DHR).
        peer_pub = X25519PublicKey(new_remote_dh)
        rk, ck_r = kdf_root(self.state.root_key, _dh(self.state.dhs, peer_pub))
        self.state.root_key = rk
        self.state.ck_r = ck_r

        # Prepare a new local DH for our next sending chain; the chain key
        # itself will be derived on first use during encrypt().
        self.state.dhs = X25519PrivateKey.generate()
        self.state.ck_s = None
        return

    def _dh_ratchet_step(self) -> None:
        """
        Perform a DH ratchet step to establish a new sending chain using the
        peer's current DHR and our freshly generated DH private key.
        """

        if self.state.dhr is None:
            # No remote ratchet key yet; nothing to do.
            return

        peer_pub = X25519PublicKey(self.state.dhr)
        rk, ck_s = kdf_root(self.state.root_key, _dh(self.state.dhs, peer_pub))
        self.state.root_key = rk
        self.state.ck_s = ck_s
        self.state.Ns = 0


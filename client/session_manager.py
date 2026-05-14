from __future__ import annotations

"""
Session manager.

For this stage, the session manager provides a minimal integration
between the double ratchet, protocol envelopes, replay protection, fork
detection, and session reset state. Handshake and identity management
are intentionally simplified for tests.
"""

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Dict, Tuple

from nacl.public import PrivateKey as X25519PrivateKey

from protocol.envelope import ProtocolEnvelope, CURRENT_VERSION
from protocol.replay_protection import SessionReplayCache
from protocol.fork_detection import ForkDetectionState, detect_fork
from protocol.session_reset import SessionResetState, mark_for_reset
from protocol.sealed_sender import (
    SealedOuterEnvelope,
    derive_sealing_key,
    seal,
    unseal,
    SEALED_SENDER_VERSION,
)
from protocol.message_format import InnerSenderPackage
from ratchet.double_ratchet import DoubleRatchet, EncryptedMessage
from ratchet.state import RatchetHeader


@dataclass
class SessionContext:
    session_id: bytes
    ratchet: DoubleRatchet
    replay_cache: SessionReplayCache
    fork_state: ForkDetectionState
    reset_state: SessionResetState


@dataclass
class SessionManager:
    profile: str
    _sessions: Dict[bytes, SessionContext] = field(default_factory=dict)

    # ---- session creation helpers (for tests / higher-level bootstrap) ----

    def create_symmetric_session(
        self,
        peer_id: bytes,
        root_key: bytes,
        dhs: X25519PrivateKey,
        dhr: bytes,
        is_initiator: bool,
    ) -> None:
        """
        Create a symmetric session for tests where both parties share a
        known root key and DH parameters. Real X3DH integration would
        supply these values after handshake.
        """

        ratchet = DoubleRatchet(root_key=root_key, dhs=dhs, dhr=dhr, is_initiator=is_initiator)
        ctx = SessionContext(
            session_id=peer_id,  # simplistic session_id for tests
            ratchet=ratchet,
            replay_cache=SessionReplayCache(),
            fork_state=ForkDetectionState(),
            reset_state=SessionResetState(),
        )
        self._sessions[peer_id] = ctx

    # ---- core API used by message layer ----

    def _get_ctx(self, peer_id: bytes) -> SessionContext:
        ctx = self._sessions.get(peer_id)
        if ctx is None:
            raise KeyError(f"No session for peer {peer_id!r}")
        return ctx

    def encrypt_for(self, peer_id: bytes, plaintext: bytes) -> ProtocolEnvelope:
        ctx = self._get_ctx(peer_id)
        em = ctx.ratchet.encrypt(plaintext)
        header: RatchetHeader = em.header

        env = ProtocolEnvelope(
            version=CURRENT_VERSION,
            session_id=ctx.session_id,
            sender_ratchet_key=header.dh_pub,
            message_number=header.n,
            previous_chain_length=header.pn,
            ciphertext=em.ciphertext,
            nonce=b"",  # nonce derivation is internal to the double ratchet
            meta={"profile": self.profile},
        )
        return env

    def decrypt_from(self, peer_id: bytes, env: ProtocolEnvelope) -> bytes:
        ctx = self._get_ctx(peer_id)

        # Replay protection first, but only record after authentication.
        if not ctx.replay_cache.check(env):
            mark_for_reset(ctx.reset_state, "replay-detected")
            raise ValueError("replayed or stale envelope")

        # Fork detection next.
        fork_snapshot = deepcopy(ctx.fork_state)
        if detect_fork(
            ctx.fork_state,
            env.sender_ratchet_key,
            env.message_number,
            env.previous_chain_length,
        ):
            mark_for_reset(ctx.reset_state, "fork-detected")
            raise ValueError("fork detected")

        # Construct ratchet header and decrypt.
        header = RatchetHeader(
            dh_pub=env.sender_ratchet_key,
            pn=env.previous_chain_length,
            n=env.message_number,
        )
        em = EncryptedMessage(header=header, ciphertext=env.ciphertext)
        try:
            plaintext = ctx.ratchet.decrypt(em)
        except Exception:
            ctx.fork_state = fork_snapshot
            raise
        ctx.replay_cache.record(env)
        return plaintext

    # ---- sealed sender ----

    def encrypt_sealed(
        self,
        peer_id: bytes,
        plaintext: bytes,
        recipient_locator: str,
        ttl: int = 60,
    ) -> Dict[str, Any]:
        """
        Encrypt and wrap in a sealed sender outer envelope. The relay sees
        only recipient_locator and opaque sealed_payload, not sender identity.
        """
        ctx = self._get_ctx(peer_id)
        em = ctx.ratchet.encrypt(plaintext)
        inner = InnerSenderPackage(
            sender_id=self.profile.encode(),
            session_id=ctx.session_id,
            dh_pub=em.header.dh_pub,
            pn=em.header.pn,
            n=em.header.n,
            ciphertext=em.ciphertext,
        )
        sealing_key = derive_sealing_key(ctx.ratchet.state.root_key)
        sealed_payload = seal(inner, sealing_key)
        outer = SealedOuterEnvelope(
            version=SEALED_SENDER_VERSION,
            recipient_locator=recipient_locator,
            ttl=ttl,
            sealed_payload=sealed_payload,
            padding=b"",
        )
        return outer.to_dict()

    def decrypt_sealed(self, outer_dict: Dict[str, Any]) -> Tuple[bytes, bytes]:
        """
        Try to unseal with each session; run replay/fork and ratchet decrypt.
        Returns (peer_id, plaintext). Raises ValueError if no session decrypts
        or replay/fork is detected.
        """
        env = SealedOuterEnvelope.from_dict(outer_dict)
        last_error: Exception | None = None
        for peer_id, ctx in self._sessions.items():
            try:
                sealing_key = derive_sealing_key(ctx.ratchet.state.root_key)
                inner = unseal(env.sealed_payload, sealing_key)
            except (ValueError, Exception) as e:
                last_error = e
                continue
            # Replay and fork checks using synthetic protocol envelope.
            syn = ProtocolEnvelope(
                version=CURRENT_VERSION,
                session_id=inner.session_id,
                sender_ratchet_key=inner.dh_pub,
                message_number=inner.n,
                previous_chain_length=inner.pn,
                ciphertext=inner.ciphertext,
                nonce=b"",
                meta={},
            )
            if not ctx.replay_cache.check(syn):
                mark_for_reset(ctx.reset_state, "replay-detected")
                raise ValueError("replayed or stale sealed envelope")
            fork_snapshot = deepcopy(ctx.fork_state)
            if detect_fork(ctx.fork_state, inner.dh_pub, inner.n, inner.pn):
                mark_for_reset(ctx.reset_state, "fork-detected")
                raise ValueError("fork detected")
            header = RatchetHeader(
                dh_pub=inner.dh_pub,
                pn=inner.pn,
                n=inner.n,
            )
            try:
                plaintext = ctx.ratchet.decrypt(
                    EncryptedMessage(header=header, ciphertext=inner.ciphertext)
                )
            except Exception:
                ctx.fork_state = fork_snapshot
                raise
            ctx.replay_cache.record(syn)
            return (peer_id, plaintext)
        raise ValueError(
            "sealed payload could not be decrypted with any session"
        ) from last_error


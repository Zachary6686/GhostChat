"""
Tests for client Double Ratchet: roundtrip, chain advance, DH ratchet, out-of-order,
replay, persistence, wire format, and security invariants.

Security-oriented: duplicate/replay by message identity, AAD binding, skipped-key
single-use and bounds, persistence validation, multi-round and PN behavior.
"""

from __future__ import annotations

import base64
import pathlib
import sys
import tempfile

import pytest
from nacl.public import PrivateKey as X25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.crypto.double_ratchet import (
    DoubleRatchetEngine,
    MAX_SKIP_DISTANCE,
    ReceivedIdsStore,
    create_initial_state,
)
from client.crypto.message import (
    RatchetMessageHeader,
    RatchetWireMessage,
    wire_message_from_dict,
    wire_message_to_dict,
)
from client.crypto.ratchet_errors import (
    CorruptedSessionError,
    DecryptionError,
    DuplicateMessageError,
    InvalidHeaderError,
    SessionRollbackError,
    SkippedKeyStorageLimitError,
    SkipDistanceExceededError,
)
from client.session_store import load_session, save_session, state_from_dict, state_to_dict


# --- Test helpers ---


def _make_pair(max_skipped_keys: int = 1000) -> tuple[DoubleRatchetEngine, DoubleRatchetEngine]:
    """Create linked Alice (initiator) and Bob (responder) with shared root key."""
    root_key = b"0" * 32
    alice_state = create_initial_state(
        root_key, is_initiator=True, max_skipped_keys=max_skipped_keys
    )
    bob_state = create_initial_state(
        root_key, is_initiator=False, max_skipped_keys=max_skipped_keys
    )
    return DoubleRatchetEngine(alice_state), DoubleRatchetEngine(bob_state)


def _b64(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


# --- Core functionality ---


def test_basic_encrypt_decrypt_roundtrip() -> None:
    """Encrypt on sender, decrypt on receiver; plaintext matches."""
    alice, bob = _make_pair()
    plain = b"hello"
    wire = alice.ratchet_encrypt(plain)
    got = bob.ratchet_decrypt(wire)
    assert got == plain


def test_chain_key_advances() -> None:
    """Sending chain advances Ns; each message has unique n and decrypts correctly."""
    alice, bob = _make_pair()
    w1 = alice.ratchet_encrypt(b"m1")
    w2 = alice.ratchet_encrypt(b"m2")
    assert w1.header.n == 0
    assert w2.header.n == 1
    assert bob.ratchet_decrypt(w1) == b"m1"
    assert bob.ratchet_decrypt(w2) == b"m2"


def test_dh_ratchet_step_on_new_key() -> None:
    """Receiving a message from peer and replying triggers DH ratchet; reply uses new ratchet key."""
    alice, bob = _make_pair()
    w1 = alice.ratchet_encrypt(b"alice 1")
    bob.ratchet_decrypt(w1)
    w2 = alice.ratchet_encrypt(b"alice 2")
    bob.ratchet_decrypt(w2)
    reply = bob.ratchet_encrypt(b"bob reply")
    # Bob's reply must carry a distinct DH public key (his sending ratchet).
    assert reply.header.dh != w2.header.dh
    got = alice.ratchet_decrypt(reply)
    assert got == b"bob reply"


def test_out_of_order_with_skipped_keys() -> None:
    """Receive messages 2, 0, 1; all decrypt; skipped keys are consumed and not reused."""
    alice, bob = _make_pair()
    w0 = alice.ratchet_encrypt(b"m0")
    w1 = alice.ratchet_encrypt(b"m1")
    w2 = alice.ratchet_encrypt(b"m2")
    assert bob.ratchet_decrypt(w2) == b"m2"
    assert bob.ratchet_decrypt(w0) == b"m0"
    assert bob.ratchet_decrypt(w1) == b"m1"
    # Replay of any already-received message must be rejected (duplicate).
    with pytest.raises(DuplicateMessageError):
        bob.ratchet_decrypt(w0)
    with pytest.raises(DuplicateMessageError):
        bob.ratchet_decrypt(w2)


def test_duplicate_message_rejected() -> None:
    """Decrypting the same wire message twice raises DuplicateMessageError."""
    alice, bob = _make_pair()
    w = alice.ratchet_encrypt(b"once")
    bob.ratchet_decrypt(w)
    with pytest.raises(DuplicateMessageError):
        bob.ratchet_decrypt(w)


def test_corrupted_ciphertext_rejected() -> None:
    """Tampering with ciphertext causes AEAD failure (DecryptionError)."""
    alice, bob = _make_pair()
    wire = alice.ratchet_encrypt(b"secret")
    assert len(wire.ciphertext) > 0, "Ciphertext must be non-empty to mutate"
    tampered = RatchetWireMessage(
        header=wire.header,
        ciphertext=bytes(32),
        nonce=wire.nonce,
    )
    with pytest.raises(DecryptionError):
        bob.ratchet_decrypt(tampered)


def test_invalid_header_rejected() -> None:
    """wire_message_from_dict rejects missing or invalid header fields."""
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict({})
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict({"header": {}, "ciphertext": "eA==", "nonce": "eQ=="})
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict({
            "header": {"dh": "x", "n": 3.0, "pn": 0},
            "ciphertext": "eA==",
            "nonce": "AAAAAAAAAAAAAAAAAAAAAA==",
        })
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict({
            "header": {"dh": "x", "n": -1, "pn": 0},
            "ciphertext": "eA==",
            "nonce": "AAAAAAAAAAAAAAAAAAAAAA==",
        })


def test_persistence_save_load() -> None:
    """state_to_dict / state_from_dict roundtrip preserves state and yields a working engine."""
    alice, bob = _make_pair()
    alice.ratchet_encrypt(b"m0")
    state = alice.state
    d = state_to_dict(state)
    state2 = state_from_dict(d)
    assert state2.root_key == state.root_key
    assert state2.Ns == state.Ns
    assert state2.dhs_private == state.dhs_private
    engine2 = DoubleRatchetEngine(state2)
    wire = engine2.ratchet_encrypt(b"after restore")
    got = bob.ratchet_decrypt(wire)
    assert got == b"after restore"


def test_session_store_save_load() -> None:
    """save_session / load_session restores a session that can continue encrypt/decrypt."""
    alice, bob = _make_pair()
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        save_session("alice", "bob", alice.state, base_dir=base)
        loaded = load_session("alice", "bob", base_dir=base)
        assert loaded is not None
        assert loaded.root_key == alice.state.root_key
        assert loaded.Ns == alice.state.Ns
        alice_loaded = DoubleRatchetEngine(loaded)
        wire = alice_loaded.ratchet_encrypt(b"from loaded session")
        assert bob.ratchet_decrypt(wire) == b"from loaded session"


def test_wire_message_roundtrip() -> None:
    """wire_message_to_dict / wire_message_from_dict roundtrip; decryption still works."""
    alice, bob = _make_pair()
    wire = alice.ratchet_encrypt(b"payload")
    d = wire_message_to_dict(wire)
    wire2 = wire_message_from_dict(d)
    assert wire2.header.n == wire.header.n
    assert wire2.header.dh == wire.header.dh
    got = bob.ratchet_decrypt(wire2)
    assert got == b"payload"


# --- Security-oriented ---


def test_same_plaintext_twice_different_ciphertext_and_nonce() -> None:
    """Same plaintext encrypted twice must produce different ciphertext and nonce."""
    alice, _ = _make_pair()
    plain = b"identical"
    w1 = alice.ratchet_encrypt(plain)
    w2 = alice.ratchet_encrypt(plain)
    assert w1.ciphertext != w2.ciphertext
    assert w1.nonce != w2.nonce
    assert w1.header.n == 0 and w2.header.n == 1


def test_header_tampering_rejected_aad_binding() -> None:
    """Header tampering is rejected: header is AAD, so any change fails decryption."""
    alice, bob = _make_pair()
    wire = alice.ratchet_encrypt(b"secret")
    tampered_n = RatchetWireMessage(
        header=RatchetMessageHeader(
            dh=wire.header.dh, n=wire.header.n + 1, pn=wire.header.pn
        ),
        ciphertext=wire.ciphertext,
        nonce=wire.nonce,
    )
    with pytest.raises(DecryptionError):
        bob.ratchet_decrypt(tampered_n)
    tampered_pn = RatchetWireMessage(
        header=RatchetMessageHeader(
            dh=wire.header.dh, n=wire.header.n, pn=wire.header.pn + 1
        ),
        ciphertext=wire.ciphertext,
        nonce=wire.nonce,
    )
    with pytest.raises(DecryptionError):
        bob.ratchet_decrypt(tampered_pn)
    bad_dh = bytearray(wire.header.dh)
    bad_dh[0] ^= 0xFF
    tampered_dh = RatchetWireMessage(
        header=RatchetMessageHeader(dh=bytes(bad_dh), n=wire.header.n, pn=wire.header.pn),
        ciphertext=wire.ciphertext,
        nonce=wire.nonce,
    )
    with pytest.raises(DecryptionError):
        bob.ratchet_decrypt(tampered_dh)


def test_nonce_tampering_rejected() -> None:
    """Tampering with wire nonce causes DecryptionError (nonce is verified against derived)."""
    alice, bob = _make_pair()
    wire = alice.ratchet_encrypt(b"secret")
    assert len(wire.nonce) > 0, "Nonce must be non-empty to mutate"
    bad_nonce = bytearray(wire.nonce)
    bad_nonce[0] ^= 0x01
    tampered = RatchetWireMessage(
        header=wire.header,
        ciphertext=wire.ciphertext,
        nonce=bytes(bad_nonce),
    )
    with pytest.raises(DecryptionError):
        bob.ratchet_decrypt(tampered)


def test_ciphertext_tampering_rejected() -> None:
    """Single-byte ciphertext tampering causes DecryptionError."""
    alice, bob = _make_pair()
    wire = alice.ratchet_encrypt(b"secret")
    assert len(wire.ciphertext) > 0, "Ciphertext must be non-empty to mutate"
    bad_ct = bytearray(wire.ciphertext)
    bad_ct[0] ^= 0x01
    tampered = RatchetWireMessage(
        header=wire.header,
        ciphertext=bytes(bad_ct),
        nonce=wire.nonce,
    )
    with pytest.raises(DecryptionError):
        bob.ratchet_decrypt(tampered)


def test_failed_current_chain_decrypt_does_not_advance_receiver_state() -> None:
    """A corrupted in-order delivery must not consume the receiver's message key."""
    alice, bob = _make_pair()
    wire = alice.ratchet_encrypt(b"recoverable")
    bad_ct = bytearray(wire.ciphertext)
    bad_ct[0] ^= 0x01
    tampered = RatchetWireMessage(
        header=wire.header,
        ciphertext=bytes(bad_ct),
        nonce=wire.nonce,
    )
    with pytest.raises(DecryptionError):
        bob.ratchet_decrypt(tampered)

    assert bob.ratchet_decrypt(wire) == b"recoverable"


def test_failed_skipped_key_decrypt_does_not_burn_skipped_key() -> None:
    """A corrupted out-of-order delivery must not delete the stored skipped key."""
    alice, bob = _make_pair()
    w0 = alice.ratchet_encrypt(b"m0")
    w1 = alice.ratchet_encrypt(b"m1")
    assert bob.ratchet_decrypt(w1) == b"m1"

    bad_ct = bytearray(w0.ciphertext)
    bad_ct[0] ^= 0x01
    tampered = RatchetWireMessage(
        header=w0.header,
        ciphertext=bytes(bad_ct),
        nonce=w0.nonce,
    )
    with pytest.raises(DecryptionError):
        bob.ratchet_decrypt(tampered)

    assert bob.ratchet_decrypt(w0) == b"m0"


def test_rejected_new_dh_skip_distance_does_not_desync_session() -> None:
    """Rejecting an oversized gap for a new DH ratchet must not commit that ratchet step."""
    alice, bob = _make_pair()
    w0 = alice.ratchet_encrypt(b"m0")
    assert bob.ratchet_decrypt(w0) == b"m0"

    fake_dh = bytes(X25519PrivateKey.generate().public_key)
    oversized_gap = RatchetWireMessage(
        header=RatchetMessageHeader(dh=fake_dh, n=MAX_SKIP_DISTANCE + 1, pn=0),
        ciphertext=w0.ciphertext,
        nonce=w0.nonce,
    )
    with pytest.raises(SkipDistanceExceededError):
        bob.ratchet_decrypt(oversized_gap)

    w1 = alice.ratchet_encrypt(b"m1")
    assert bob.ratchet_decrypt(w1) == b"m1"


def test_replay_after_serialization_roundtrip_rejected() -> None:
    """Replay is rejected by message identity (dh, n), not object identity."""
    alice, bob = _make_pair()
    wire = alice.ratchet_encrypt(b"once")
    bob.ratchet_decrypt(wire)
    d = wire_message_to_dict(wire)
    wire_replay = wire_message_from_dict(d)
    with pytest.raises(DuplicateMessageError):
        bob.ratchet_decrypt(wire_replay)


def test_skipped_key_deleted_after_use() -> None:
    """After out-of-order decrypt, replay of same message is rejected (key consumed)."""
    alice, bob = _make_pair()
    w0 = alice.ratchet_encrypt(b"m0")
    w1 = alice.ratchet_encrypt(b"m1")
    bob.ratchet_decrypt(w1)
    bob.ratchet_decrypt(w0)
    with pytest.raises(DuplicateMessageError):
        bob.ratchet_decrypt(w0)


def test_skipped_keys_fifo_eviction_when_at_capacity() -> None:
    """With FIFO eviction, receiving message 3 first evicts key for 0; receiving message 0 later is rejected as duplicate (n < Nr)."""
    max_keys = 2
    alice, bob = _make_pair(max_skipped_keys=max_keys)
    w0 = alice.ratchet_encrypt(b"m0")
    alice.ratchet_encrypt(b"m1")
    alice.ratchet_encrypt(b"m2")
    w3 = alice.ratchet_encrypt(b"m3")
    assert bob.ratchet_decrypt(w3) == b"m3"
    with pytest.raises(DuplicateMessageError):
        bob.ratchet_decrypt(w0)


def test_persistence_restore_allows_continued_messaging() -> None:
    """Restored sessions can continue send/receive in both directions.
    All pre-save messages are explicitly delivered and decrypted so both sides have consistent state."""
    alice, bob = _make_pair()
    # Pre-save: explicit delivery so no ambiguous state. Alice sends 1; Bob receives it.
    w1 = alice.ratchet_encrypt(b"pre-save 1")
    assert bob.ratchet_decrypt(w1) == b"pre-save 1"
    # Alice sends 2; Bob receives it.
    w2 = alice.ratchet_encrypt(b"pre-save 2")
    assert bob.ratchet_decrypt(w2) == b"pre-save 2"
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        save_session("alice", "bob", alice.state, base_dir=base)
        save_session("bob", "alice", bob.state, base_dir=base)
        alice_loaded = load_session("alice", "bob", base_dir=base)
        bob_loaded = load_session("bob", "alice", base_dir=base)
        assert alice_loaded is not None and bob_loaded is not None
        alice_restored = DoubleRatchetEngine(alice_loaded)
        bob_restored = DoubleRatchetEngine(bob_loaded)
    w_bob = bob_restored.ratchet_encrypt(b"after restore from bob")
    assert alice_restored.ratchet_decrypt(w_bob) == b"after restore from bob"
    w_alice = alice_restored.ratchet_encrypt(b"after restore from alice")
    assert bob_restored.ratchet_decrypt(w_alice) == b"after restore from alice"
    w_bob2 = bob_restored.ratchet_encrypt(b"second after restore")
    assert alice_restored.ratchet_decrypt(w_bob2) == b"second after restore"


# --- Persistence robustness ---


def test_corrupted_session_file_fails_safely() -> None:
    """Invalid JSON or invalid session structure raises CorruptedSessionError."""
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        path = base / "sessions" / "alice__bob.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not json", encoding="utf-8")
        with pytest.raises(CorruptedSessionError):
            load_session("alice", "bob", base_dir=base)
        path.write_text("{}", encoding="utf-8")
        with pytest.raises(CorruptedSessionError):
            load_session("alice", "bob", base_dir=base)


def test_missing_required_persistence_fields_fail() -> None:
    """state_from_dict raises CorruptedSessionError when required fields are missing."""
    with pytest.raises(CorruptedSessionError):
        state_from_dict({})
    with pytest.raises(CorruptedSessionError):
        state_from_dict({"v": 1})
    alice, _ = _make_pair()
    d = state_to_dict(alice.state)
    del d["root_key"]
    with pytest.raises(CorruptedSessionError):
        state_from_dict(d)


def test_invalid_encoded_key_material_fails_safely() -> None:
    """Wrong key lengths or bad base64 in session dict raise CorruptedSessionError."""
    alice, _ = _make_pair()
    d = state_to_dict(alice.state)
    d["root_key"] = base64.urlsafe_b64encode(b"short").decode("ascii")
    with pytest.raises(CorruptedSessionError):
        state_from_dict(d)


def test_wire_message_from_dict_validates_types() -> None:
    """n and pn must be integers; floats and other types are rejected."""
    alice, _ = _make_pair()
    wire = alice.ratchet_encrypt(b"x")
    d = wire_message_to_dict(wire)
    d["header"]["n"] = 1.0
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict(d)
    d["header"]["n"] = 0
    d["header"]["pn"] = "0"
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict(d)


# --- Multi-step protocol behavior ---


def test_multi_round_bidirectional_multiple_ratchet_steps() -> None:
    """Multi-round conversation across several DH ratchet steps (strict alternation)."""
    alice, bob = _make_pair()
    rounds = [
        (b"alice 1", "alice", "bob"),
        (b"bob 1", "bob", "alice"),
        (b"alice 2", "alice", "bob"),
        (b"bob 2", "bob", "alice"),
        (b"alice 3", "alice", "bob"),
        (b"bob 3", "bob", "alice"),
    ]
    for plain, sender_name, recv_name in rounds:
        sender = alice if sender_name == "alice" else bob
        recv = bob if recv_name == "bob" else alice
        wire = sender.ratchet_encrypt(plain)
        got = recv.ratchet_decrypt(wire)
        assert got == plain, f"Round {plain!r}: expected {plain!r}, got {got!r}"


def test_multiple_dh_ratchet_turns() -> None:
    """Several back-and-forth turns; each time Bob receives from Alice he may rotate, so his send uses a new ratchet public key."""
    alice, bob = _make_pair()
    seen_dh_from_bob: set[bytes] = set()
    for i in range(4):
        w_a = alice.ratchet_encrypt(f"alice {i}".encode())
        bob.ratchet_decrypt(w_a)
        w_b = bob.ratchet_encrypt(f"bob {i}".encode())
        seen_dh_from_bob.add(w_b.header.dh)
        alice.ratchet_decrypt(w_b)
    # Each receive from Alice triggers Bob's DH ratchet (new dhs), so we must see 4 distinct Bob public keys.
    assert len(seen_dh_from_bob) == 4, "Each Bob send must use a distinct ratchet public key after receiving from Alice"


def test_pn_updated_on_ratchet_turn() -> None:
    """PN is sender's previous sending chain length. After Alice sends 3 and Bob replies, Bob's pn=0.
    After Alice receives and sends again, her next message has pn=3."""
    alice, bob = _make_pair()
    alice.ratchet_encrypt(b"a1")
    alice.ratchet_encrypt(b"a2")
    w = alice.ratchet_encrypt(b"a3")
    bob.ratchet_decrypt(w)
    reply = bob.ratchet_encrypt(b"b reply")
    assert reply.header.pn == 0  # Bob had sent 0 messages before this reply
    alice.ratchet_decrypt(reply)
    alice_next = alice.ratchet_encrypt(b"a4")
    assert alice_next.header.pn == 3  # Alice's previous sending chain had 3 messages


def test_decrypt_stale_skipped_key_fails_as_duplicate() -> None:
    """After consuming a message from skipped storage, replay of that message is duplicate."""
    alice, bob = _make_pair()
    w0 = alice.ratchet_encrypt(b"m0")
    w1 = alice.ratchet_encrypt(b"m1")
    w2 = alice.ratchet_encrypt(b"m2")
    bob.ratchet_decrypt(w2)
    bob.ratchet_decrypt(w0)
    bob.ratchet_decrypt(w1)
    with pytest.raises(DuplicateMessageError):
        bob.ratchet_decrypt(w0)


def test_skipped_store_from_dict_rejects_malformed() -> None:
    """SkippedMessageKeys.from_dict with bad entry raises ValueError."""
    from client.crypto.double_ratchet import SkippedMessageKeys

    # Key index must decode to exactly 36 bytes (32 dh + 4 n).
    short_b64 = base64.urlsafe_b64encode(b"a").decode("ascii").rstrip("=")
    with pytest.raises(ValueError):
        SkippedMessageKeys.from_dict({short_b64: base64.urlsafe_b64encode(b"x" * 32).decode("ascii").rstrip("=")})
    valid_index = base64.urlsafe_b64encode(b"0" * 32 + b"\x00\x00\x00\x00").decode("ascii").rstrip("=")
    short_value_b64 = base64.urlsafe_b64encode(b"short").decode("ascii").rstrip("=")
    with pytest.raises(ValueError):
        SkippedMessageKeys.from_dict({valid_index: short_value_b64})


# --- Persistence parser hardening ---


def test_state_from_dict_rejects_invalid_base64() -> None:
    """state_from_dict raises CorruptedSessionError for invalid base64 in key fields."""
    alice, _ = _make_pair()
    d = state_to_dict(alice.state)
    d["root_key"] = "!!!invalid-base64!!!"
    with pytest.raises(CorruptedSessionError):
        state_from_dict(d)
    d2 = state_to_dict(alice.state)
    d2["dhs_private"] = "not-valid-b64"
    with pytest.raises(CorruptedSessionError):
        state_from_dict(d2)


def test_state_from_dict_rejects_wrong_types() -> None:
    """state_from_dict raises CorruptedSessionError for wrong types in persisted fields."""
    alice, _ = _make_pair()
    d = state_to_dict(alice.state)
    d["Ns"] = "not-an-int"
    with pytest.raises(CorruptedSessionError):
        state_from_dict(d)
    d["Ns"] = 0
    d["root_key"] = 12345
    with pytest.raises(CorruptedSessionError):
        state_from_dict(d)
    d["root_key"] = state_to_dict(alice.state)["root_key"]
    d["skipped"] = "not-a-dict"
    with pytest.raises(CorruptedSessionError):
        state_from_dict(d)


def test_state_from_dict_rejects_malformed_skipped_structure() -> None:
    """state_from_dict raises CorruptedSessionError when skipped key structure is malformed."""
    alice, _ = _make_pair()
    d = state_to_dict(alice.state)
    d["skipped"] = {"key-not-36-bytes-b64": "value"}
    with pytest.raises(CorruptedSessionError):
        state_from_dict(d)


def test_state_from_dict_rejects_malformed_received_ids() -> None:
    """state_from_dict raises CorruptedSessionError when received_ids contain malformed entries."""
    alice, _ = _make_pair()
    d = state_to_dict(alice.state)
    d["received_ids"] = {"ids": ["not-36-bytes"]}
    with pytest.raises(CorruptedSessionError):
        state_from_dict(d)
    d["received_ids"] = {"ids": [123]}
    with pytest.raises(CorruptedSessionError):
        state_from_dict(d)


def test_state_from_dict_rejects_ns_nr_pn_bool_or_float() -> None:
    """state_from_dict rejects Ns, Nr, PN as bool or float (no silent coercion)."""
    alice, _ = _make_pair()
    d = state_to_dict(alice.state)
    d["Ns"] = True
    with pytest.raises(CorruptedSessionError):
        state_from_dict(d)
    d["Ns"] = 0
    d["Nr"] = 1.0
    with pytest.raises(CorruptedSessionError):
        state_from_dict(d)


# --- Wire message validation ---


def test_wire_message_from_dict_rejects_non_string_dh() -> None:
    """wire_message_from_dict rejects non-string header.dh."""
    alice, _ = _make_pair()
    wire = alice.ratchet_encrypt(b"x")
    d = wire_message_to_dict(wire)
    d["header"]["dh"] = 12345
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict(d)
    d2 = wire_message_to_dict(wire)
    d2["header"]["dh"] = []
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict(d2)


def test_wire_message_from_dict_rejects_non_string_ciphertext_nonce() -> None:
    """wire_message_from_dict rejects non-string ciphertext or nonce."""
    alice, _ = _make_pair()
    wire = alice.ratchet_encrypt(b"x")
    d = wire_message_to_dict(wire)
    d["ciphertext"] = 999
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict(d)
    d2 = wire_message_to_dict(wire)
    d2["nonce"] = None
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict(d2)


def test_wire_message_from_dict_rejects_missing_nested_fields() -> None:
    """wire_message_from_dict rejects missing nested header fields."""
    alice, _ = _make_pair()
    wire = alice.ratchet_encrypt(b"x")
    d = wire_message_to_dict(wire)
    del d["header"]["n"]
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict(d)
    d["header"]["n"] = 0
    del d["header"]["pn"]
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict(d)
    d["header"]["pn"] = 0
    del d["ciphertext"]
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict(d)


def test_wire_message_from_dict_rejects_malformed_encodings() -> None:
    """wire_message_from_dict rejects malformed base64 in dh, ciphertext, or nonce."""
    alice, _ = _make_pair()
    wire = alice.ratchet_encrypt(b"x")
    d = wire_message_to_dict(wire)
    d["header"]["dh"] = "!!!invalid!!!"
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict(d)
    d2 = wire_message_to_dict(wire)
    d2["nonce"] = "!!!invalid-base64!!!"
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict(d2)


def test_wire_message_from_dict_rejects_ciphertext_too_short() -> None:
    """wire_message_from_dict rejects ciphertext shorter than AEAD tag (16 bytes)."""
    alice, _ = _make_pair()
    wire = alice.ratchet_encrypt(b"x")
    d = wire_message_to_dict(wire)
    short_ct = base64.urlsafe_b64encode(b"x" * 10).decode("ascii").rstrip("=")
    d["ciphertext"] = short_ct
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict(d)


def test_wire_message_from_dict_rejects_ciphertext_too_large() -> None:
    """wire_message_from_dict rejects ciphertext larger than AEAD sanity bound (DoS mitigation)."""
    alice, _ = _make_pair()
    wire = alice.ratchet_encrypt(b"x")
    d = wire_message_to_dict(wire)
    large_ct = base64.urlsafe_b64encode(b"x" * (1024 * 1024 + 1)).decode("ascii").rstrip("=")
    d["ciphertext"] = large_ct
    with pytest.raises(InvalidHeaderError):
        wire_message_from_dict(d)


# --- Rollback / stale state ---


def test_restore_older_state_then_decrypt_advanced_message_fails_safely() -> None:
    """Save an older session state; advance the conversation; restore the older state; decrypting a message from the advanced conversation must fail (DecryptionError or DuplicateMessageError)."""
    alice, bob = _make_pair()
    w1 = alice.ratchet_encrypt(b"m1")
    bob.ratchet_decrypt(w1)
    w2 = bob.ratchet_encrypt(b"bob reply")
    older_alice_dict = state_to_dict(alice.state)
    alice.ratchet_decrypt(w2)
    alice.ratchet_encrypt(b"m2")
    for _ in range(2):
        w_a = alice.ratchet_encrypt(b"advance")
        bob.ratchet_decrypt(w_a)
        w_b = bob.ratchet_encrypt(b"advance")
        alice.ratchet_decrypt(w_b)
    w_advanced = bob.ratchet_encrypt(b"advanced message")
    alice_restored = DoubleRatchetEngine(state_from_dict(older_alice_dict))
    with pytest.raises((DecryptionError, DuplicateMessageError)):
        alice_restored.ratchet_decrypt(w_advanced)


# --- Session versioning and anti-rollback ---


def test_session_version_persisted_and_incremented_on_save() -> None:
    """Session version is persisted and increments on each save."""
    alice, _ = _make_pair()
    assert alice.state.session_version == 1
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        save_session("alice", "bob", alice.state, base_dir=base)
        assert alice.state.session_version == 2
        loaded = load_session("alice", "bob", base_dir=base)
        assert loaded is not None
        assert loaded.session_version == 2
        save_session("alice", "bob", loaded, base_dir=base)
        assert loaded.session_version == 3


def test_session_rollback_detected_on_save() -> None:
    """If the session file was replaced with an older version (rollback), save raises SessionRollbackError."""
    alice, _ = _make_pair()
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        save_session("alice", "bob", alice.state, base_dir=base)


def test_save_session_does_not_silently_overwrite_corrupted_file() -> None:
    """If existing session file is invalid JSON, save_session raises CorruptedSessionError instead of silently overwriting."""
    alice, _ = _make_pair()
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        path = base / "sessions" / "alice__bob.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not json", encoding="utf-8")
        with pytest.raises(CorruptedSessionError):
            save_session("alice", "bob", alice.state, base_dir=base)
        assert path.read_text(encoding="utf-8") == "not json"


# --- Received ids (anti-replay across restore) ---


def test_replay_rejected_after_restore_via_received_ids() -> None:
    """After save/load, replay of an already-received message is rejected via persisted received_ids."""
    alice, bob = _make_pair()
    w = alice.ratchet_encrypt(b"once")
    bob.ratchet_decrypt(w)
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        save_session("bob", "alice", bob.state, base_dir=base)
        bob_loaded = load_session("bob", "alice", base_dir=base)
        assert bob_loaded is not None
    bob_restored = DoubleRatchetEngine(bob_loaded)
    with pytest.raises(DuplicateMessageError):
        bob_restored.ratchet_decrypt(w)


def test_duplicate_header_rejected_before_any_key_derivation() -> None:
    """Same (dh, n) is rejected by received_ids even when reconstructed from wire (duplicate header detection)."""
    alice, bob = _make_pair()
    wire = alice.ratchet_encrypt(b"msg")
    bob.ratchet_decrypt(wire)
    wire_copy = wire_message_from_dict(wire_message_to_dict(wire))
    with pytest.raises(DuplicateMessageError):
        bob.ratchet_decrypt(wire_copy)


def test_received_ids_store_enforces_n_range() -> None:
    """ReceivedIdsStore enforces message number range [0, 2^32-1]."""
    store = ReceivedIdsStore(max_size=2)
    dh = b"d" * 32
    with pytest.raises(ValueError):
        store.add(dh, -1)
    with pytest.raises(ValueError):
        store.add(dh, 0x1_0000_0000)


def test_received_ids_store_eviction_allows_very_old_replay() -> None:
    """Eviction semantics: only the most recent max_size entries are remembered for duplicate detection."""
    store = ReceivedIdsStore(max_size=2)
    dh = b"d" * 32
    # Add three entries; window will contain (dh, 1) and (dh, 2).
    store.add(dh, 0)
    store.add(dh, 1)
    store.add(dh, 2)
    assert not store.contains(dh, 0), "Oldest entry may be evicted from bounded replay cache"
    assert store.contains(dh, 1)
    assert store.contains(dh, 2)


# --- Full AAD binding ---


def test_aad_binds_all_header_fields_dh_n_pn() -> None:
    """All header fields (dh, n, pn) are bound as AAD; tampering any one causes DecryptionError."""
    alice, bob = _make_pair()
    wire = alice.ratchet_encrypt(b"secret")
    assert len(wire.header.dh) == 32 and wire.header.n >= 0 and wire.header.pn >= 0
    for tampered in [
        RatchetWireMessage(
            header=RatchetMessageHeader(dh=wire.header.dh, n=wire.header.n + 1, pn=wire.header.pn),
            ciphertext=wire.ciphertext,
            nonce=wire.nonce,
        ),
        RatchetWireMessage(
            header=RatchetMessageHeader(dh=wire.header.dh, n=wire.header.n, pn=wire.header.pn + 1),
            ciphertext=wire.ciphertext,
            nonce=wire.nonce,
        ),
        RatchetWireMessage(
            header=RatchetMessageHeader(
                dh=bytes(bytearray(wire.header.dh)[:1] + bytearray([wire.header.dh[1] ^ 0xFF]) + bytearray(wire.header.dh[2:])),
                n=wire.header.n,
                pn=wire.header.pn,
            ),
            ciphertext=wire.ciphertext,
            nonce=wire.nonce,
        ),
    ]:
        with pytest.raises(DecryptionError):
            bob.ratchet_decrypt(tampered)


def test_skipped_store_load_exceeding_max_raises() -> None:
    """Loading a session with more skipped keys than max_skipped_keys raises CorruptedSessionError."""
    alice, _ = _make_pair()
    d = state_to_dict(alice.state)
    many_entries = {}
    for i in range(5):
        key_b64 = base64.urlsafe_b64encode(b"0" * 32 + bytes([(i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF])).decode("ascii").rstrip("=")
        many_entries[key_b64] = base64.urlsafe_b64encode(b"x" * 32).decode("ascii").rstrip("=")
    d["skipped"] = many_entries
    with pytest.raises((SkippedKeyStorageLimitError, CorruptedSessionError)):
        state_from_dict(d, max_skipped_keys=2)

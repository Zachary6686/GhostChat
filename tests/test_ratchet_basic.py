from __future__ import annotations

import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.exceptions import InvalidTag
import pytest
from nacl.public import PrivateKey as X25519PrivateKey

from ratchet.double_ratchet import DoubleRatchet, EncryptedMessage


def _linked_sessions() -> tuple[DoubleRatchet, DoubleRatchet]:
    root_key = os.urandom(32)
    alice_dh = X25519PrivateKey.generate()
    bob_dh = X25519PrivateKey.generate()

    alice = DoubleRatchet(
        root_key=root_key,
        dhs=alice_dh,
        dhr=bytes(bob_dh.public_key),
        is_initiator=True,
    )
    bob = DoubleRatchet(
        root_key=root_key,
        dhs=bob_dh,
        dhr=bytes(alice_dh.public_key),
        is_initiator=False,
    )
    return alice, bob


def test_basic_send_receive() -> None:
    alice, bob = _linked_sessions()

    plaintext = b"hello from alice"
    msg = alice.encrypt(plaintext)

    received = bob.decrypt(msg)
    assert received == plaintext

    reply = b"hi alice, this is bob"
    msg2 = bob.encrypt(reply)
    received2 = alice.decrypt(msg2)
    assert received2 == reply


def test_failed_decrypt_does_not_consume_message_key() -> None:
    alice, bob = _linked_sessions()

    msg = alice.encrypt(b"secret")
    bad_ct = bytearray(msg.ciphertext)
    bad_ct[0] ^= 0x01
    tampered = EncryptedMessage(header=msg.header, ciphertext=bytes(bad_ct))

    with pytest.raises(InvalidTag):
        bob.decrypt(tampered)

    assert bob.decrypt(msg) == b"secret"


from __future__ import annotations

import os
import pathlib
import sys
from typing import List

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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


def test_out_of_order_delivery_and_skipped_keys() -> None:
    alice, bob = _linked_sessions()

    # Alice sends three messages; Bob receives them out of order.
    m1 = alice.encrypt(b"m1")
    m2 = alice.encrypt(b"m2")
    m3 = alice.encrypt(b"m3")

    # Deliver 1, then 3, then 2.
    r1 = bob.decrypt(m1)
    assert r1 == b"m1"

    r3 = bob.decrypt(m3)
    assert r3 == b"m3"

    r2 = bob.decrypt(m2)
    assert r2 == b"m2"


def test_simultaneous_send_race_handling() -> None:
    alice, bob = _linked_sessions()

    # Initial exchange to get both sides into a state with sending and
    # receiving chains established.
    first = alice.encrypt(b"bootstrap")
    _ = bob.decrypt(first)
    reply = bob.encrypt(b"ack")
    _ = alice.decrypt(reply)

    # Now both sides send a message "simultaneously" without having seen
    # the other's new message yet.
    alice_msg = alice.encrypt(b"alice-race")
    bob_msg = bob.encrypt(b"bob-race")

    # Deliver Bob's message to Alice, then Alice's to Bob.
    r_from_bob = alice.decrypt(bob_msg)
    r_from_alice = bob.decrypt(alice_msg)

    assert r_from_bob == b"bob-race"
    assert r_from_alice == b"alice-race"


from __future__ import annotations

"""
High-level message API.

For this stage, the message API provides a minimal in-memory transport
for tests, wiring the session manager and protocol envelope together.
It is not meant as a final CLI.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from protocol.envelope import ProtocolEnvelope
from protocol.sealed_sender import is_sealed_envelope
from protocol.message_format import group_message_envelope_to_dict, group_message_envelope_from_dict
from client.session_manager import SessionManager
from client.group_manager import GroupManager
from group.group_messaging import GroupMessage


@dataclass
class InMemoryEndpoint:
    manager: SessionManager
    inbox: List[Union[ProtocolEnvelope, Dict[str, Any]]] = field(default_factory=list)
    group_inbox: Dict[bytes, List[dict]] = field(default_factory=dict)  # group_id -> list of envelope dicts
    group_manager: Optional[GroupManager] = None


_endpoints: Dict[str, InMemoryEndpoint] = {}


def register_endpoint(
    profile: str,
    manager: SessionManager,
    group_manager: Optional[GroupManager] = None,
) -> None:
    """
    Register a profile and its session manager with the in-memory
    transport. Optionally attach a GroupManager for group messaging.
    """
    _endpoints[profile] = InMemoryEndpoint(
        manager=manager,
        group_manager=group_manager,
    )


def send_text(
    profile: str,
    recipient_profile: str,
    peer_id: bytes,
    text: str,
    sealed_sender: bool = False,
) -> None:
    """
    Encrypt and enqueue a one-to-one message from `profile` to
    `recipient_profile` using the given peer_id for session lookup.
    If sealed_sender=True, the relay sees only recipient locator and
    opaque sealed payload (no plaintext sender identity).
    """

    endpoint = _endpoints[profile]
    recipient = _endpoints[recipient_profile]
    if sealed_sender:
        outer = endpoint.manager.encrypt_sealed(
            peer_id,
            text.encode("utf-8"),
            recipient_locator=recipient_profile,
        )
        recipient.inbox.append(outer)
    else:
        env = endpoint.manager.encrypt_for(peer_id, text.encode("utf-8"))
        recipient.inbox.append(env)


def recv_text(profile: str, peer_id: bytes) -> list[str]:
    """
    Decrypt all pending non-sealed messages for `profile` from the peer
    identified by `peer_id` and return their plaintext strings.
    Sealed envelopes are left in the inbox; use recv_sealed() for those.
    """

    endpoint = _endpoints[profile]
    mgr = endpoint.manager
    out: list[str] = []
    i = 0
    while i < len(endpoint.inbox):
        item = endpoint.inbox[i]
        if isinstance(item, ProtocolEnvelope):
            plaintext = mgr.decrypt_from(peer_id, item)
            out.append(plaintext.decode("utf-8"))
            endpoint.inbox.pop(i)
        else:
            i += 1
    return out


def recv_sealed(
    profile: str,
    drop_undecryptable: bool = True,
) -> list[tuple[bytes, str]]:
    """
    Decrypt all pending sealed-sender envelopes for `profile`.
    Returns a list of (sender_peer_id, plaintext_str). Sealed envelopes
    are removed from the inbox. If drop_undecryptable is True (default),
    envelopes that fail to decrypt (e.g. dummies/cover) are dropped
    without raising; replay/fork errors still raise.
    """

    endpoint = _endpoints[profile]
    mgr = endpoint.manager
    out: list[tuple[bytes, str]] = []
    i = 0
    while i < len(endpoint.inbox):
        item = endpoint.inbox[i]
        if isinstance(item, dict) and is_sealed_envelope(item):
            try:
                peer_id, plaintext = mgr.decrypt_sealed(item)
                out.append((peer_id, plaintext.decode("utf-8")))
                endpoint.inbox.pop(i)
            except ValueError as e:
                if drop_undecryptable and "could not be decrypted" in str(e):
                    endpoint.inbox.pop(i)
                    continue  # dummy or cover, drop
                raise
        else:
            i += 1
    return out


def get_pending_cover_packets(
    scheduler: Any,
    now: float | None = None,
) -> list[dict]:
    """
    Cover traffic hook: return zero or more envelope dicts that the client
    should send this tick. Use with network.cover_traffic.CoverTrafficScheduler.
    """
    pkt = getattr(scheduler, "maybe_generate_cover_packet", None)
    if pkt is None:
        return []
    out = pkt(now=now)
    if out is None:
        return []
    return [out.envelope]


def send_group_text(
    profile: str,
    group_id: bytes,
    text: str,
    member_profiles: List[str],
) -> None:
    """
    Encrypt and deliver a group message. Appends serialized group message
    to each member's group_inbox (excluding sender if not in member_profiles).
    """
    endpoint = _endpoints[profile]
    if endpoint.group_manager is None:
        raise ValueError("No group_manager registered for profile")
    messenger = endpoint.group_manager.get_messenger(group_id)
    if messenger is None:
        raise ValueError("No group state for group_id")
    msg = messenger.encrypt(text.encode("utf-8"))
    payload = msg.to_dict()
    envelope = group_message_envelope_to_dict(group_id, payload)
    for p in member_profiles:
        if p not in _endpoints:
            continue
        _endpoints[p].group_inbox.setdefault(group_id, []).append(envelope)


def recv_group_text(profile: str, group_id: bytes) -> List[str]:
    """
    Decrypt all pending group messages for this profile in the group.
    Returns list of plaintext strings. Invalid/stale messages raise.
    """
    endpoint = _endpoints[profile]
    if endpoint.group_manager is None:
        return []
    receiver = endpoint.group_manager.get_receiver(group_id)
    if receiver is None:
        return []
    out: List[str] = []
    inbox = endpoint.group_inbox.get(group_id, [])
    while inbox:
        envelope = inbox.pop(0)
        try:
            _, payload = group_message_envelope_from_dict(envelope)
            msg = GroupMessage.from_dict(payload)
            plaintext = receiver.decrypt(msg)
            out.append(plaintext.decode("utf-8"))
        except Exception:
            inbox.insert(0, envelope)
            break
    return out


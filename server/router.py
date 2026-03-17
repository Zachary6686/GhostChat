from __future__ import annotations

"""
Routing helpers for the relay server.

This module is intended to encapsulate mailbox routing decisions. The
relay routes using recipient locator only; sender identity is never
read from the envelope for routing (sealed sender: sender is inside
opaque payload). Optional mix-style delayed delivery keeps envelopes
in RAM until deliver_at.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from network.mix_router import MixRouter, ScheduledEnvelope


def get_routing_recipient(envelope: dict) -> str:
    """
    Extract the recipient key for routing. Supports both sealed sender
    outer envelopes (recipient_locator) and legacy envelope dicts that
    may have a recipient field. The relay must not require sender
    plaintext for routing.
    """
    if "recipient_locator" in envelope:
        return envelope["recipient_locator"]
    if envelope.get("recipient"):
        return envelope["recipient"]
    raise ValueError("Envelope has no recipient_locator or recipient")


@dataclass
class Mailbox:
    messages: List[dict] = field(default_factory=list)


@dataclass
class Router:
    mailboxes: Dict[str, Mailbox] = field(default_factory=dict)
    mix_router: Optional[MixRouter] = None
    _scheduled: List[ScheduledEnvelope] = field(default_factory=list)

    def enqueue(self, recipient: str, envelope: dict) -> None:
        box = self.mailboxes.setdefault(recipient, Mailbox())
        box.messages.append(envelope)

    def enqueue_by_envelope(
        self,
        envelope: dict,
        use_mix: bool = False,
        now: Optional[float] = None,
    ) -> None:
        """
        Route using only recipient information. If use_mix is True and
        mix_router is set and enabled, the envelope is scheduled for
        delayed delivery; otherwise it is enqueued immediately.
        """
        if use_mix and self.mix_router is not None and self.mix_router.config.enabled:
            scheduled = self.mix_router.schedule_envelope(envelope, now=now)
            self._scheduled.append(scheduled)
        else:
            recipient = get_routing_recipient(envelope)
            self.enqueue(recipient, envelope)

    def deliver_due(self, now: Optional[float] = None) -> int:
        """
        Move all scheduled envelopes with deliver_at <= now into their
        recipient mailboxes. Returns the number of envelopes delivered.
        """
        import time as _time

        now_ts = now if now is not None else _time.time()
        due: List[ScheduledEnvelope] = []
        remaining: List[ScheduledEnvelope] = []
        for s in self._scheduled:
            if s.deliver_at <= now_ts:
                due.append(s)
            else:
                remaining.append(s)
        self._scheduled = remaining
        for s in due:
            recipient = get_routing_recipient(s.envelope)
            self.enqueue(recipient, s.envelope)
        return len(due)

    def dequeue_all(self, recipient: str) -> List[dict]:
        box = self.mailboxes.get(recipient)
        if not box:
            return []
        msgs = list(box.messages)
        box.messages.clear()
        return msgs


from __future__ import annotations

"""
Session reset helpers.

This module defines simple flags and utilities for marking sessions as
requiring a reset (e.g., after suspected fork or unrecoverable
desynchronization). The actual handshake re-initiation is handled by
the client/session manager.
"""

from dataclasses import dataclass


@dataclass
class SessionResetState:
    needs_reset: bool = False
    reason: str | None = None


def mark_for_reset(state: SessionResetState, reason: str) -> None:
    state.needs_reset = True
    state.reason = reason


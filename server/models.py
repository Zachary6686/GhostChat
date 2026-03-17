from __future__ import annotations

"""
Pydantic models for server APIs.

This module defines lightweight models for envelopes and health checks.
"""

from pydantic import BaseModel


class EnvelopeIn(BaseModel):
    recipient: str | None
    ttl: int
    opaque_payload: bytes


class HealthResponse(BaseModel):
    status: str


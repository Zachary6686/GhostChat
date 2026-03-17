from __future__ import annotations

"""
TLS transport abstraction (skeleton).

In a full implementation, this module would wrap connections in TLS,
handle certificate verification, and expose a simple async send/receive
API for higher layers.
"""

from dataclasses import dataclass


@dataclass
class TLSTransport:
    host: str
    port: int

    async def send(self, data: bytes) -> None:
        raise NotImplementedError("TLSTransport.send is not implemented yet")

    async def recv(self) -> bytes:
        raise NotImplementedError("TLSTransport.recv is not implemented yet")


from __future__ import annotations

"""
Server configuration helpers.

In a real deployment, these values would come from environment
variables or configuration files. Here they are simple defaults.
"""

from dataclasses import dataclass


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8000
    use_tls: bool = False


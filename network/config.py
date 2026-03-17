from __future__ import annotations

"""
Configuration helpers for network hardening.

This module centralizes default parameters for mix delays, cover
traffic, and timing defenses. Deterministic modes are available for tests.
"""

from dataclasses import dataclass

from .cover_traffic import CoverTrafficConfig
from .mix_router import MixConfig
from .timing_defense import TimingDefenseConfig


def default_network_config() -> NetworkConfig:
    return NetworkConfig()


def deterministic_network_config() -> NetworkConfig:
    """Config with all hardening in deterministic mode for tests."""
    return NetworkConfig(
        mix=MixConfig(
            enabled=True,
            deterministic_mode=True,
            fixed_delay_sec=0.01,
        ),
        cover=CoverTrafficConfig(
            enabled=True,
            deterministic_mode=True,
            deterministic_interval_sec=1.0,
        ),
        timing=TimingDefenseConfig(use_deterministic=True),
    )


@dataclass
class NetworkConfig:
    mix: MixConfig = MixConfig()
    cover: CoverTrafficConfig = CoverTrafficConfig()
    timing: TimingDefenseConfig = TimingDefenseConfig()


"""
Persist Double Ratchet session state to disk.

Store path: sessions/{local_username}__{remote_username}.json
No plaintext messages stored.
"""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from typing import Optional

from client.crypto.double_ratchet import DoubleRatchetState, ReceivedIdsStore, SkippedMessageKeys
from client.crypto.ratchet_errors import CorruptedSessionError, SessionRollbackError, SkippedKeyStorageLimitError

logger = logging.getLogger(__name__)

SESSIONS_DIR = Path("sessions")
VERSION = 1


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    """Decode base64url string to bytes. Raises CorruptedSessionError on invalid encoding."""
    if not isinstance(s, str):
        raise CorruptedSessionError("Base64 field must be a string")
    try:
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode((s + pad).encode("ascii"))
    except Exception as e:
        raise CorruptedSessionError(f"Invalid base64: {e}") from e


def _session_path(local_username: str, remote_username: str, base_dir: Optional[Path] = None) -> Path:
    base = base_dir or Path.cwd()
    safe_local = "".join(c if c.isalnum() or c in "-_" else "_" for c in local_username)
    safe_remote = "".join(c if c.isalnum() or c in "-_" else "_" for c in remote_username)
    return base / SESSIONS_DIR / f"{safe_local}__{safe_remote}.json"


def state_to_dict(state: DoubleRatchetState) -> dict:
    """Serialize state to JSON-serializable dict. No plaintext."""
    return {
        "v": VERSION,
        "session_version": getattr(state, "session_version", 1),
        "root_key": _b64(state.root_key),
        "sending_chain_key": _b64(state.sending_chain_key) if state.sending_chain_key else None,
        "receiving_chain_key": _b64(state.receiving_chain_key) if state.receiving_chain_key else None,
        "dhs_private": _b64(state.dhs_private) if state.dhs_private else None,
        "dhr": _b64(state.dhr) if state.dhr else None,
        "Ns": state.Ns,
        "Nr": state.Nr,
        "PN": state.PN,
        "skipped": state.skipped_message_keys.to_dict(),
        "received_ids": getattr(state, "received_ids", ReceivedIdsStore(2000)).to_dict(),
    }


def _require_b64_key(name: str, raw: bytes, length: int = 32) -> None:
    if len(raw) != length:
        raise CorruptedSessionError(f"Invalid {name} length: expected {length}, got {len(raw)}")


def state_from_dict(data: dict, max_skipped_keys: int = 1000) -> DoubleRatchetState:
    """
    Deserialize from dict. Validates version, key lengths, and required fields.
    Raises CorruptedSessionError on invalid or missing data.
    """
    if not isinstance(data, dict):
        raise CorruptedSessionError("Session data must be a dict")
    if data.get("v") != VERSION:
        raise CorruptedSessionError("Unsupported session version")
    try:
        root_key_b64 = data["root_key"]
    except KeyError:
        raise CorruptedSessionError("Missing root_key")

    def _b64_field(raw: object, name: str) -> bytes:
        s = raw if isinstance(raw, str) else str(raw)
        out = _b64d(s)
        _require_b64_key(name, out)
        return out

    root_key = _b64_field(root_key_b64, "root_key")

    ck_s: Optional[bytes] = None
    if data.get("sending_chain_key") is not None:
        ck_s = _b64_field(data["sending_chain_key"], "sending_chain_key")

    ck_r: Optional[bytes] = None
    if data.get("receiving_chain_key") is not None:
        ck_r = _b64_field(data["receiving_chain_key"], "receiving_chain_key")

    dhs_private = data.get("dhs_private")
    if dhs_private is not None:
        dhs_private = _b64_field(dhs_private, "dhs_private")

    dhr = data.get("dhr")
    if dhr is not None:
        dhr = _b64_field(dhr, "dhr")

    try:
        Ns = int(data.get("Ns", 0))
        Nr = int(data.get("Nr", 0))
        PN = int(data.get("PN", 0))
    except (TypeError, ValueError) as e:
        raise CorruptedSessionError(f"Invalid Ns/Nr/PN: {e}") from e
    if Ns < 0 or Nr < 0 or PN < 0:
        raise CorruptedSessionError("Ns, Nr, PN must be non-negative")

    skipped_data = data.get("skipped")
    if skipped_data is not None and not isinstance(skipped_data, dict):
        raise CorruptedSessionError("skipped must be a dict")
    try:
        skipped = SkippedMessageKeys.from_dict(skipped_data or {}, max_keys=max_skipped_keys)
    except (ValueError, SkippedKeyStorageLimitError) as e:
        raise CorruptedSessionError(f"Invalid skipped keys: {e}") from e

    session_version = int(data.get("session_version", 1))
    if session_version < 1:
        raise CorruptedSessionError("session_version must be >= 1")
    received_ids_data = data.get("received_ids")
    received_ids = ReceivedIdsStore.from_dict(
        received_ids_data if isinstance(received_ids_data, dict) else None,
        max_size=2000,
    )

    return DoubleRatchetState(
        root_key=root_key,
        sending_chain_key=ck_s,
        receiving_chain_key=ck_r,
        dhs_private=dhs_private,
        dhr=dhr,
        Ns=Ns,
        Nr=Nr,
        PN=PN,
        skipped_message_keys=skipped,
        received_ids=received_ids,
        session_version=session_version,
    )


def save_session(
    local_username: str,
    remote_username: str,
    state: DoubleRatchetState,
    base_dir: Optional[Path] = None,
) -> Path:
    """Write session state to file. Creates sessions dir if needed. Anti-rollback: if file exists with a higher session_version, raises SessionRollbackError."""
    path = _session_path(local_username, remote_username, base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    current_version = getattr(state, "session_version", 1)
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                existing = json.load(f)
            file_version = int(existing.get("session_version", 0))
            if file_version > current_version:
                raise SessionRollbackError(
                    f"Session rollback detected: file version {file_version} > in-memory version {current_version}"
                )
        except json.JSONDecodeError:
            pass
    state.session_version = current_version + 1
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state_to_dict(state), f, indent=0)
    logger.debug("Session saved: %s", path)
    return path


def load_session(
    local_username: str,
    remote_username: str,
    base_dir: Optional[Path] = None,
    max_skipped_keys: int = 1000,
) -> Optional[DoubleRatchetState]:
    """
    Load session state from file. Returns None if file missing or unreadable.
    Raises CorruptedSessionError if file exists but is invalid.
    """
    path = _session_path(local_username, remote_username, base_dir)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return state_from_dict(data, max_skipped_keys=max_skipped_keys)
    except json.JSONDecodeError as e:
        raise CorruptedSessionError(f"Invalid JSON: {e}") from e

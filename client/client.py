"""
GhostChat secure messaging client — CLI entrypoint.

Usage:
  python -m client.client --username alice --server ws://localhost:8765/ws
  python -m client.client --username alice --server ws://localhost:8765/ws --generate-identity
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import logging
import sys
from pathlib import Path

from nacl.public import PrivateKey as X25519PrivateKey

from crypto.identity import IdentityKeyPair

from client.crypto.double_ratchet import DoubleRatchetEngine, create_initial_state
from client.crypto.key_exchange import KeyExchange
from client.crypto.prekey import (
    ClientPreKeyBundle,
    PeerBundle,
    deserialize_bundle_private,
    generate_prekey_bundle,
    load_bundle_from_file,
    save_bundle_to_file,
    serialize_bundle,
)
from client.crypto.ratchet import SessionCrypto
from client.crypto.x3dh import x3dh_initiator, x3dh_responder
from client.session_store import load_session, save_session
from client.identity import (
    generate_identity,
    load_identity,
    public_key_base64,
    save_identity,
)
from client.network.websocket_client import GhostChatWebSocketClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="GhostChat secure messaging client",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--username",
        required=True,
        help="Your username (e.g. alice)",
    )
    p.add_argument(
        "--server",
        default="ws://localhost:8765/ws",
        help="WebSocket relay URL",
    )
    p.add_argument(
        "--identity-file",
        type=Path,
        default=None,
        help="Path to identity file (default: cwd/identity.json)",
    )
    p.add_argument(
        "--generate-identity",
        action="store_true",
        help="Generate a new identity and save it; then exit (optional: --identity-file)",
    )
    p.add_argument(
        "--peer",
        default=None,
        help="Peer username to chat with (e.g. bob). If omitted, prompt at runtime.",
    )
    p.add_argument(
        "--bundle-file",
        type=Path,
        default=None,
        help="Path to PreKey bundle file (default: cwd/bundle.json). Created if missing.",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.generate_identity:
        keypair = generate_identity()
        path = save_identity(keypair, args.identity_file)
        print(f"Identity saved to {path}")
        print(f"Public key (base64): {public_key_base64(keypair)}")
        return 0

    try:
        keypair = load_identity(args.identity_file)
    except FileNotFoundError:
        logger.error(
            "No identity file found. Create one with: python -m client.client --generate-identity --username %s",
            args.username,
        )
        return 1
    except Exception as e:
        logger.error("Failed to load identity: %s", e)
        return 1

    print(f"Loaded identity for {args.username} (public key: {public_key_base64(keypair)[:16]}...)")

    bundle_path = args.bundle_file or Path.cwd() / "bundle.json"
    try:
        if bundle_path.exists():
            data = load_bundle_from_file(bundle_path)
            bundle = deserialize_bundle_private(data, keypair)
            logger.info("Loaded bundle from %s", bundle_path)
        else:
            bundle = generate_prekey_bundle(keypair)
            save_bundle_to_file(bundle, bundle_path, for_upload=False)
            logger.info("Generated and saved bundle to %s", bundle_path)
    except Exception as e:
        logger.error("Bundle load/generate failed: %s", e)
        return 1

    return asyncio.run(async_main(args, keypair, bundle))


async def async_main(args: argparse.Namespace, keypair: IdentityKeyPair, bundle: ClientPreKeyBundle) -> int:

    uri = args.server
    username = args.username
    peer = args.peer

    client = GhostChatWebSocketClient(uri=uri, username=username)
    try:
        await client.connect()
    except Exception as e:
        logger.error("Connection failed: %s", e)
        return 1

    kex = KeyExchange.generate_ephemeral()
    try:
        await client.register(kex.get_ephemeral_public())
        await client.upload_bundle(serialize_bundle(bundle, for_upload=True))
    except Exception as e:
        logger.error("Registration/bundle upload failed: %s", e)
        await client.close()
        return 1

    while not peer:
        peer = input("Enter peer username to chat with: ").strip()
        if not peer:
            print("Peer username cannot be empty.")

    session_peer_ref: list[str] = [peer]
    engine_ref: list = [None]

    try:
        bundle_dict = await client.get_peer_bundle(peer)
    except Exception:
        bundle_dict = None
    if bundle_dict:
        try:
            peer_bundle = PeerBundle.from_dict(bundle_dict)
            opk_id_and_pub = peer_bundle.opks[0] if peer_bundle.opks else None
            eph_priv = X25519PrivateKey.generate()
            result, eph_pub = x3dh_initiator(
                bundle.identity_dh_private,
                eph_priv,
                peer_bundle,
                opk_id_and_pub=opk_id_and_pub,
            )
            await client.send_session_init(peer, bundle.identity_dh_public, eph_pub, result.used_opk_id)
            root_key = result.root_key
            is_initiator = True
            dr_state = load_session(username, peer)
            if dr_state is None:
                dr_state = create_initial_state(root_key, is_initiator=True)
                save_session(username, peer, dr_state)
            engine = DoubleRatchetEngine(dr_state)
            client.set_double_ratchet(engine)
            engine_ref[0] = engine
            print(f"Session with {peer} established (X3DH + Double Ratchet). Type messages and press Enter (Ctrl+C to quit).")
        except Exception as e:
            logger.error("X3DH failed: %s; falling back to legacy.", e)
            bundle_dict = None
    if not bundle_dict:
        try:
            peer_pub = await client.get_peer_key(peer)
        except Exception as e:
            logger.error("Could not get peer key (is %s connected?): %s", peer, e)
            await client.close()
            return 1
        secret = kex.derive_shared_secret(peer_pub)
        root_key = KeyExchange.derive_root_key(secret)
        is_initiator = username < peer
        dr_state = load_session(username, peer)
        if dr_state is None:
            dr_state = create_initial_state(root_key, is_initiator=is_initiator)
            save_session(username, peer, dr_state)
        engine = DoubleRatchetEngine(dr_state)
        client.set_double_ratchet(engine)
        engine_ref[0] = engine
        print(f"Session with {peer} established (legacy + Double Ratchet). Type messages and press Enter (Ctrl+C to quit).")

    recv_task = asyncio.create_task(client.run_receiver())

    async def handle_session_inits() -> None:
        while True:
            init = await client.recv_session_init()
            from_user = init.get("from", "")
            id_dh_b64 = init.get("identity_dh_pub", "")
            eph_b64 = init.get("eph_pub", "")
            opk_id = init.get("opk_id_used")
            padding_id = "=" * (-len(id_dh_b64) % 4)
            padding_eph = "=" * (-len(eph_b64) % 4)
            id_dh_pub = base64.urlsafe_b64decode((id_dh_b64 + padding_id).encode("ascii"))
            eph_pub = base64.urlsafe_b64decode((eph_b64 + padding_eph).encode("ascii"))
            try:
                result = x3dh_responder(bundle, id_dh_pub, eph_pub, opk_id)
                dr_state = create_initial_state(result.root_key, is_initiator=False)
                save_session(username, from_user, dr_state)
                engine = DoubleRatchetEngine(dr_state)
                client.set_double_ratchet(engine)
                engine_ref[0] = engine
                session_peer_ref[0] = from_user
                print(f"Session established with {from_user} (X3DH + Double Ratchet).")
            except Exception as e:
                logger.exception("X3DH responder failed for %s: %s", from_user, e)

    init_handler_task = asyncio.create_task(handle_session_inits())

    loop = asyncio.get_event_loop()

    async def sender_loop() -> None:
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            line = line.rstrip("\n\r")
            if line:
                to = session_peer_ref[0]
                await client.send_message(to, line.encode("utf-8"))
                if engine_ref[0] is not None:
                    try:
                        save_session(username, to, engine_ref[0].state)
                    except Exception as e:
                        logger.debug("Session save after send: %s", e)
                print(f"[you -> {to}] {line}")

    async def recv_loop() -> None:
        while True:
            try:
                from_user, plaintext = await client.recv_message()
                if engine_ref[0] is not None:
                    try:
                        save_session(username, from_user, engine_ref[0].state)
                    except Exception as e:
                        logger.debug("Session save after recv: %s", e)
                text = plaintext.decode("utf-8", errors="replace")
                print(f"[{from_user}] {text}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception("Recv error: %s", e)

    recv_loop_task = asyncio.create_task(recv_loop())
    try:
        await sender_loop()
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        init_handler_task.cancel()
        try:
            await init_handler_task
        except asyncio.CancelledError:
            pass
        recv_loop_task.cancel()
        try:
            await recv_loop_task
        except asyncio.CancelledError:
            pass
        recv_task.cancel()
        try:
            await recv_task
        except asyncio.CancelledError:
            pass
        await client.close()
        print("Disconnected.")

    return 0


if __name__ == "__main__":
    sys.exit(main())

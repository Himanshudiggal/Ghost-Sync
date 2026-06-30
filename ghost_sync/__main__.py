"""CLI entry point for Ghost Sync.

Provides commands for identity management, trust store operations,
clipboard watching, peer discovery, and full clipboard sync.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time

from ghost_sync.common.config import APP_DIR, IDENTITY_FILE, PAIR_PORT, SYNC_PORT
from ghost_sync.common.crypto_utils import derive_store_key
from ghost_sync.identity.keys import DeviceIdentity
from ghost_sync.identity.trust_store import TrustStore, TrustedDevice


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _load_identity() -> DeviceIdentity:
    """Load identity or exit with a helpful message."""
    try:
        return DeviceIdentity.load()
    except FileNotFoundError:
        print("No identity found. Run 'ghostsync init' first.", file=sys.stderr)
        sys.exit(1)


def _load_trust_store(identity: DeviceIdentity) -> TrustStore:
    """Load the trust store using the identity's derived encryption key."""
    store_key = derive_store_key(identity.signing_key.encode())
    return TrustStore.load(store_key)


# ── Commands ──────────────────────────────────────────────────────────


def cmd_init(args: argparse.Namespace) -> None:
    """Generate device identity."""
    identity = DeviceIdentity.load_or_generate(device_name=args.name)
    print(f"Device ID:     {identity.device_id}")
    print(f"Device Name:   {identity.device_name}")
    print(f"Fingerprint:   {identity.fingerprint_str}")
    print(f"Identity file: {IDENTITY_FILE}")


def cmd_identity(args: argparse.Namespace) -> None:
    """Display current identity."""
    identity = _load_identity()
    print(f"Device ID:     {identity.device_id}")
    print(f"Device Name:   {identity.device_name}")
    print(f"Fingerprint:   {identity.fingerprint_str}")
    print(f"Public Key:    {identity.public_key_bytes.hex()}")


def cmd_trust_list(args: argparse.Namespace) -> None:
    """List trusted devices."""
    identity = _load_identity()
    store = _load_trust_store(identity)
    devices = store.list_devices()

    if not devices:
        print("No trusted devices.")
        return

    print(f"{'Device ID':<18} {'Name':<24} {'Paired At'}")
    print("-" * 60)
    for dev in devices:
        import datetime

        paired = datetime.datetime.fromtimestamp(dev.paired_at).strftime("%Y-%m-%d %H:%M")
        print(f"{dev.device_id:<18} {dev.name:<24} {paired}")


def cmd_trust_remove(args: argparse.Namespace) -> None:
    """Remove a trusted device."""
    identity = _load_identity()
    store = _load_trust_store(identity)

    if store.remove_device(args.device_id):
        print(f"Removed device {args.device_id}")
    else:
        print(f"Device {args.device_id} not found in trust store.", file=sys.stderr)
        sys.exit(1)


def cmd_watch(args: argparse.Namespace) -> None:
    """Start clipboard watcher (debug mode)."""
    setup_logging(debug=args.debug)

    async def _on_change(event):  # type: ignore[no-untyped-def]
        print(f"[CLIPBOARD] {len(event.text)} chars | hash={event.content_hash[:8].hex()}")
        if args.debug:
            preview = event.text[:80].replace("\n", "\\n")
            print(f"  preview: {preview}")

    async def _run() -> None:
        from ghost_sync.clipboard.watcher import create_watcher

        watcher = create_watcher(_on_change, poll_interval=0.3)
        await watcher.start()
        print("Clipboard watcher running. Copy text to see events. Ctrl+C to stop.")
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await watcher.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        print("\nStopped.")


def cmd_discover(args: argparse.Namespace) -> None:
    """Discover Ghost Sync peers on the local network."""
    setup_logging(debug=args.debug)
    identity = _load_identity()

    from ghost_sync.network.discovery import GhostSyncDiscovery

    def on_discovered(peer):  # type: ignore[no-untyped-def]
        print(f"  [+] {peer.device_name} (id={peer.device_id}, host={peer.host}:{peer.port})")

    def on_lost(device_id):  # type: ignore[no-untyped-def]
        print(f"  [-] Device lost: {device_id}")

    discovery = GhostSyncDiscovery(
        device_id=identity.device_id,
        device_name=identity.device_name,
        fingerprint_str=identity.fingerprint_str,
        on_peer_discovered=on_discovered,
        on_peer_lost=on_lost,
    )

    discovery.start()
    print(f"Discovering Ghost Sync peers on the network... (Ctrl+C to stop)")
    print(f"This device: {identity.device_name} (id={identity.device_id})")
    print()

    try:
        import time

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        discovery.stop()
        print("\nDiscovery stopped.")


def cmd_pair(args: argparse.Namespace) -> None:
    """Pair with a discovered device via real key-exchange handshake."""
    setup_logging(debug=False)
    identity = _load_identity()
    store = _load_trust_store(identity)

    if store.is_trusted(args.device_id):
        print(f"Device {args.device_id} is already trusted.")
        return

    from ghost_sync.network.discovery import GhostSyncDiscovery
    from ghost_sync.network.pair import initiate_pairing

    print(f"Searching for device {args.device_id} on the network...")

    found_peer = None

    def on_discovered(peer):  # type: ignore[no-untyped-def]
        nonlocal found_peer
        if peer.device_id == args.device_id:
            found_peer = peer

    discovery = GhostSyncDiscovery(
        device_id=identity.device_id,
        device_name=identity.device_name,
        fingerprint_str=identity.fingerprint_str,
        on_peer_discovered=on_discovered,
    )
    discovery.start()

    # Wait up to 10 seconds for the peer to appear
    for _ in range(20):
        if found_peer is not None:
            break
        time.sleep(0.5)

    discovery.stop()

    if found_peer is None:
        print(f"  ✗ Device {args.device_id} not found on the network.", file=sys.stderr)
        print(f"    Make sure the other device is running 'ghostsync sync'.", file=sys.stderr)
        sys.exit(1)

    print(f"  Found: {found_peer.device_name} at {found_peer.host}:{found_peer.port}")

    # Run the real key-exchange pairing handshake
    async def _do_pair() -> None:
        success = await initiate_pairing(
            identity=identity,
            trust_store=store,
            peer_host=found_peer.host,
            peer_port=PAIR_PORT,
        )
        if not success:
            sys.exit(1)

    try:
        asyncio.run(_do_pair())
    except KeyboardInterrupt:
        print("\nPairing cancelled.")
        sys.exit(1)


def cmd_sync(args: argparse.Namespace) -> None:
    """Start full clipboard sync with trusted peers."""
    setup_logging(debug=args.debug)
    identity = _load_identity()
    store = _load_trust_store(identity)

    async def _run() -> None:
        from ghost_sync.clipboard.watcher import create_watcher
        from ghost_sync.network.discovery import GhostSyncDiscovery
        from ghost_sync.network.sync import SyncClient, SyncServer
        from ghost_sync.network.pair import PairingServer

        # Create sync client and clipboard handler
        sync_client = SyncClient(identity)

        async def on_clipboard_change(event):  # type: ignore[no-untyped-def]
            """When local clipboard changes, broadcast to trusted peers."""
            if event.source == "local":
                await sync_client.broadcast_clipboard(event)
                connected = len(sync_client.connected_peers)
                if connected > 0:
                    preview = event.text[:50].replace("\n", "\\n")
                    print(f"[SYNC→] Sent to {connected} peer(s): {preview}...")

        # Start clipboard watcher
        watcher = create_watcher(on_clipboard_change, poll_interval=0.3)
        await watcher.start()

        # Start sync server (receives clipboard from peers)
        sync_server = SyncServer(identity, store, watcher)
        await sync_server.start()

        # Start pairing server (accepts pair requests from new devices)
        pair_server = PairingServer(identity, store)
        await pair_server.start()

        # Start mDNS discovery
        # NOTE: discovery callbacks run in Zeroconf's background thread,
        # so we use run_coroutine_threadsafe to schedule async work
        # back onto the main asyncio event loop.
        loop = asyncio.get_running_loop()

        def on_peer_discovered(peer):  # type: ignore[no-untyped-def]
            if store.is_trusted(peer.device_id):
                print(f"[PEER+] Trusted peer found: {peer.device_name} — connecting...")
                asyncio.run_coroutine_threadsafe(
                    sync_client.connect_to_peer(peer), loop
                )
            else:
                print(f"[PEER?] Untrusted peer: {peer.device_name} (id={peer.device_id})")
                print(f"        Run 'ghostsync pair {peer.device_id}' to trust this device.")

        def on_peer_lost(device_id):  # type: ignore[no-untyped-def]
            print(f"[PEER-] Peer lost: {device_id}")
            asyncio.run_coroutine_threadsafe(
                sync_client.disconnect_peer(device_id), loop
            )

        discovery = GhostSyncDiscovery(
            device_id=identity.device_id,
            device_name=identity.device_name,
            fingerprint_str=identity.fingerprint_str,
            on_peer_discovered=on_peer_discovered,
            on_peer_lost=on_peer_lost,
        )
        discovery.start()

        print("=" * 60)
        print(f"  Ghost Sync running — {identity.device_name}")
        print(f"  Device ID:    {identity.device_id}")
        print(f"  Fingerprint:  {identity.fingerprint_str}")
        print(f"  Sync port:    {SYNC_PORT}")
        print(f"  Trusted peers: {len(store)}")
        print("=" * 60)
        print("Waiting for peers... Copy text to sync. Ctrl+C to stop.\n")

        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await sync_client.disconnect_all()
            await sync_server.stop()
            await pair_server.stop()
            await watcher.stop()
            discovery.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        print("\nGhost Sync stopped.")


# ── Main ──────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ghostsync",
        description="Ghost Sync — Cross-device P2P clipboard synchronizer",
    )
    subparsers = parser.add_subparsers(dest="command")

    # init
    p_init = subparsers.add_parser("init", help="Generate device identity")
    p_init.add_argument("--name", default=None, help="Device name (default: hostname)")

    # identity
    subparsers.add_parser("identity", help="Display current device identity")

    # trust
    p_trust = subparsers.add_parser("trust", help="Manage trusted devices")
    trust_sub = p_trust.add_subparsers(dest="trust_command")
    trust_sub.add_parser("list", help="List trusted devices")
    p_remove = trust_sub.add_parser("remove", help="Remove a trusted device")
    p_remove.add_argument("device_id", help="Device ID to remove")

    # watch
    p_watch = subparsers.add_parser("watch", help="Start clipboard watcher (debug)")
    p_watch.add_argument("--debug", action="store_true", help="Enable debug output")

    # discover
    p_discover = subparsers.add_parser("discover", help="Discover peers on the network")
    p_discover.add_argument("--debug", action="store_true", help="Enable debug output")

    # pair
    p_pair = subparsers.add_parser("pair", help="Pair with a discovered device")
    p_pair.add_argument("device_id", help="Device ID to pair with")

    # sync
    p_sync = subparsers.add_parser("sync", help="Start clipboard sync with trusted peers")
    p_sync.add_argument("--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    commands = {
        "init": cmd_init,
        "identity": cmd_identity,
        "watch": cmd_watch,
        "discover": cmd_discover,
        "pair": cmd_pair,
        "sync": cmd_sync,
    }

    if args.command == "trust":
        if args.trust_command == "list":
            cmd_trust_list(args)
        elif args.trust_command == "remove":
            cmd_trust_remove(args)
        else:
            p_trust.print_help()
    elif args.command in commands:
        commands[args.command](args)


if __name__ == "__main__":
    main()

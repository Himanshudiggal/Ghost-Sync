"""TCP-based clipboard synchronization between trusted peers.

Messages are signed with Ed25519 for authenticity but sent unencrypted
over the local network. This is Phase 1's deliberate trade-off — acceptable
on trusted local Wi-Fi. Phase 2 adds the Noise protocol for end-to-end
encryption.

Message format (msgpack):
    {
        "device_id": str,       # sender's device ID
        "text": str,            # clipboard content
        "timestamp": float,     # time.time() when copied
        "signature": str,       # hex-encoded Ed25519 signature of text bytes
    }
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, Optional, Set

import msgpack
from nacl.signing import VerifyKey

from ghost_sync.clipboard.watcher import ClipboardEvent, ClipboardWatcher
from ghost_sync.common.config import SYNC_PORT
from ghost_sync.identity.keys import DeviceIdentity
from ghost_sync.identity.trust_store import TrustStore
from ghost_sync.network.discovery import DiscoveredPeer

logger = logging.getLogger(__name__)

# 4-byte length prefix for framing TCP messages
HEADER_SIZE = 4
MAX_MESSAGE_SIZE = 2_000_000  # 2 MB max message


class SyncServer:
    """Async TCP server that receives clipboard updates from peers."""

    def __init__(
        self,
        identity: DeviceIdentity,
        trust_store: TrustStore,
        watcher: ClipboardWatcher,
        port: int = SYNC_PORT,
    ) -> None:
        self._identity = identity
        self._trust_store = trust_store
        self._watcher = watcher
        self._port = port
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        """Start listening for incoming clipboard messages."""
        self._server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", self._port
        )
        logger.info("Sync server listening on port %d", self._port)

    async def stop(self) -> None:
        """Stop the sync server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("Sync server stopped")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle an incoming TCP connection from a peer."""
        addr = writer.get_extra_info("peername")
        logger.debug("Incoming connection from %s", addr)

        try:
            while True:
                # Read length-prefixed message
                header = await reader.readexactly(HEADER_SIZE)
                msg_len = int.from_bytes(header, "big")

                if msg_len > MAX_MESSAGE_SIZE:
                    logger.warning("Message too large (%d bytes) from %s", msg_len, addr)
                    break

                data = await reader.readexactly(msg_len)
                msg = msgpack.unpackb(data, raw=False)

                self._process_message(msg)

        except asyncio.IncompleteReadError:
            logger.debug("Connection closed by %s", addr)
        except Exception:
            logger.exception("Error handling client %s", addr)
        finally:
            writer.close()
            await writer.wait_closed()

    def _process_message(self, msg: dict) -> None:
        """Verify and process an incoming clipboard message."""
        device_id = msg.get("device_id", "")
        text = msg.get("text", "")
        signature_hex = msg.get("signature", "")

        # Check if sender is trusted
        if not self._trust_store.is_trusted(device_id):
            logger.warning("Rejected message from untrusted device: %s", device_id)
            return

        # Verify Ed25519 signature
        trusted_device = self._trust_store.get_device(device_id)
        if trusted_device is None:
            return

        try:
            vk = VerifyKey(trusted_device.public_key_bytes())
            signature = bytes.fromhex(signature_hex)
            vk.verify(text.encode("utf-8"), signature)
        except Exception:
            logger.warning("Invalid signature from device %s", device_id)
            return

        # Write to clipboard with anti-echo suppression
        self._watcher.write(text, source=device_id)
        self._trust_store.update_last_seen(device_id)
        logger.info(
            "Synced clipboard from %s (%d chars)",
            device_id,
            len(text),
        )


class SyncClient:
    """Manages outgoing TCP connections to trusted peers for clipboard sync."""

    def __init__(self, identity: DeviceIdentity) -> None:
        self._identity = identity
        self._connections: Dict[str, tuple] = {}  # device_id -> (reader, writer)

    async def connect_to_peer(self, peer: DiscoveredPeer) -> bool:
        """Establish a TCP connection to a discovered peer.

        Returns True if connection was successful.
        """
        if peer.device_id in self._connections:
            return True  # Already connected

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(peer.host, peer.port),
                timeout=5.0,
            )
            self._connections[peer.device_id] = (reader, writer)
            logger.info("Connected to peer %s at %s:%d", peer.device_id, peer.host, peer.port)
            return True
        except Exception:
            logger.warning(
                "Failed to connect to peer %s at %s:%d",
                peer.device_id, peer.host, peer.port,
            )
            return False

    async def disconnect_peer(self, device_id: str) -> None:
        """Close connection to a peer."""
        if device_id in self._connections:
            _, writer = self._connections.pop(device_id)
            writer.close()
            await writer.wait_closed()
            logger.info("Disconnected from peer %s", device_id)

    async def disconnect_all(self) -> None:
        """Close all peer connections."""
        for device_id in list(self._connections.keys()):
            await self.disconnect_peer(device_id)

    async def broadcast_clipboard(self, event: ClipboardEvent) -> None:
        """Send clipboard content to all connected peers.

        Signs the text with our Ed25519 key before sending.
        """
        if not self._connections:
            return

        # Sign the clipboard text
        signature = self._identity.sign(event.text.encode("utf-8"))

        msg = msgpack.packb({
            "device_id": self._identity.device_id,
            "text": event.text,
            "timestamp": event.timestamp,
            "signature": signature.hex(),
        })

        # Length-prefixed framing
        frame = len(msg).to_bytes(HEADER_SIZE, "big") + msg

        # Send to all connected peers
        disconnected: list[str] = []
        for device_id, (reader, writer) in self._connections.items():
            try:
                writer.write(frame)
                await writer.drain()
                logger.debug("Sent clipboard to peer %s (%d bytes)", device_id, len(event.text))
            except Exception:
                logger.warning("Failed to send to peer %s, marking for disconnect", device_id)
                disconnected.append(device_id)

        # Clean up failed connections
        for device_id in disconnected:
            await self.disconnect_peer(device_id)

    @property
    def connected_peers(self) -> Set[str]:
        """Set of currently connected peer device IDs."""
        return set(self._connections.keys())

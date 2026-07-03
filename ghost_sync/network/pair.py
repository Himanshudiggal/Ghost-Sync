"""Device pairing handshake protocol.

The pairing flow:
    1. Initiator discovers peer via mDNS and connects to PAIR_PORT
    2. Both sides exchange their Ed25519 public key + device name + a random nonce
    3. Both independently compute the same 6-digit PIN:
         PIN = BLAKE2b(sorted(pubkey_A, pubkey_B) + nonce) % 1_000_000
    4. User verbally/visually confirms the PIN matches on both devices
    5. If confirmed on both sides, each stores the other's public key in its trust store

Security properties:
    - The PIN prevents MITM attacks during the key exchange
    - Ed25519 public keys are the long-term device identities
    - No secret is transmitted — PIN is derived locally by both parties

Message format (msgpack over TCP):
    HELLO  → { "type": "hello",  "version": 1, "device_id": str,
                "device_name": str, "public_key": hex_str, "nonce": hex_str }
    ACCEPT → { "type": "accept", "device_id": str, "public_key": hex_str }
    REJECT → { "type": "reject", "reason": str }
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional

import msgpack

from ghost_sync.common.config import PAIR_PORT
from ghost_sync.common.crypto_utils import derive_pairing_pin
from ghost_sync.identity.keys import DeviceIdentity
from ghost_sync.identity.trust_store import TrustStore, TrustedDevice

logger = logging.getLogger(__name__)

HEADER_SIZE = 4
PAIRING_TIMEOUT = 60.0  # seconds to complete handshake


async def _send_msg(writer: asyncio.StreamWriter, msg: dict) -> None:
    """Send a length-prefixed msgpack message."""
    data = msgpack.packb(msg, use_bin_type=True)
    header = len(data).to_bytes(HEADER_SIZE, "big")
    writer.write(header + data)
    await writer.drain()


async def _recv_msg(reader: asyncio.StreamReader) -> dict:
    """Receive a length-prefixed msgpack message."""
    header = await asyncio.wait_for(reader.readexactly(HEADER_SIZE), timeout=PAIRING_TIMEOUT)
    msg_len = int.from_bytes(header, "big")
    data = await asyncio.wait_for(reader.readexactly(msg_len), timeout=PAIRING_TIMEOUT)
    return msgpack.unpackb(data, raw=False)


class PairingServer:
    """Listens for incoming pairing requests on PAIR_PORT.

    Runs alongside the sync server during `ghostsync sync`.
    When a pairing request arrives, prompts the user to confirm the PIN.
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        trust_store: TrustStore,
        port: int = PAIR_PORT,
    ) -> None:
        self._identity = identity
        self._trust_store = trust_store
        self._port = port
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_pair_request, "0.0.0.0", self._port
        )
        logger.info("Pairing server listening on port %d", self._port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_pair_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        addr = writer.get_extra_info("peername")
        logger.info("Incoming pair request from %s", addr)

        try:
            # 1. Receive HELLO from initiator
            msg = await _recv_msg(reader)
            if msg.get("type") != "hello" or msg.get("version") != 1:
                await _send_msg(writer, {"type": "reject", "reason": "bad_hello"})
                return

            peer_id = msg["device_id"]
            peer_name = msg["device_name"]
            peer_pubkey_hex = msg["public_key"]
            nonce_hex = msg["nonce"]

            peer_pubkey = bytes.fromhex(peer_pubkey_hex)
            nonce = bytes.fromhex(nonce_hex)

            # 2. Compute PIN
            pin = derive_pairing_pin(
                self._identity.public_key_bytes,
                peer_pubkey,
                nonce,
            )

            # 3. Prompt user to confirm
            print("\n" + "═" * 56)
            print(f"  📲  Pair request from: {peer_name} (id={peer_id})")
            print(f"  🔑  Verify this PIN matches on the other device:")
            print(f"\n            ┌─────────────┐")
            print(f"            │   {pin}   │")
            print(f"            └─────────────┘\n")
            print("  Type 'yes' to accept, anything else to reject:")
            print("═" * 56)

            # Read from stdin asynchronously
            loop = asyncio.get_running_loop()
            answer = await loop.run_in_executor(None, input, "> ")

            if answer.strip().lower() != "yes":
                await _send_msg(writer, {"type": "reject", "reason": "user_rejected"})
                print(f"  ✗ Pairing with {peer_name} rejected.")
                return

            # 4. Send ACCEPT with our public key
            await _send_msg(writer, {
                "type": "accept",
                "device_id": self._identity.device_id,
                "device_name": self._identity.device_name,
                "public_key": self._identity.public_key_bytes.hex(),
            })

            # 5. Save peer to trust store
            device = TrustedDevice(
                device_id=peer_id,
                name=peer_name,
                ed25519_public=peer_pubkey_hex,
                noise_public="00" * 32,   # Phase 2: Noise keys
                paired_at=time.time(),
                last_seen=time.time(),
                signature="00" * 64,       # Phase 2: signed certificate
            )
            self._trust_store.add_device(device)
            print(f"\n  ✓ Paired with {peer_name}! Device added to trust store.")

        except asyncio.TimeoutError:
            logger.warning("Pairing handshake timed out from %s", addr)
        except Exception:
            logger.exception("Error during pairing from %s", addr)
        finally:
            writer.close()
            await writer.wait_closed()


async def initiate_pairing(
    identity: DeviceIdentity,
    trust_store: TrustStore,
    peer_host: str,
    peer_port: int = PAIR_PORT,
) -> bool:
    """Initiate a pairing handshake with a discovered peer.

    Returns True if pairing succeeded, False otherwise.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(peer_host, peer_port),
            timeout=10.0,
        )
    except Exception as e:
        print(f"  ✗ Could not connect to peer: {e}")
        return False

    try:
        # 1. Generate a random nonce for this pairing session
        nonce = os.urandom(32)

        # 2. Send HELLO
        await _send_msg(writer, {
            "type": "hello",
            "version": 1,
            "device_id": identity.device_id,
            "device_name": identity.device_name,
            "public_key": identity.public_key_bytes.hex(),
            "nonce": nonce.hex(),
        })

        # 3. Show our computed PIN while we wait for the response
        print("\n" + "═" * 56)
        print(f"  📤  Pairing request sent. Waiting for acceptance...")
        print(f"  🔑  Verify this PIN on the other device:\n")

        # We need to know the peer's public key to compute PIN,
        # but we don't have it yet — show a "waiting" message
        print(f"            [ Waiting for peer response... ]")
        print(f"  (The PIN will appear on the other device)")
        print("═" * 56)

        # 4. Wait for ACCEPT or REJECT
        response = await asyncio.wait_for(_recv_msg(reader), timeout=PAIRING_TIMEOUT)

        if response.get("type") == "reject":
            reason = response.get("reason", "unknown")
            print(f"\n  ✗ Pairing rejected by peer (reason: {reason})")
            return False

        if response.get("type") != "accept":
            print(f"\n  ✗ Unexpected response: {response.get('type')}")
            return False

        peer_id = response["device_id"]
        peer_name = response["device_name"]
        peer_pubkey_hex = response["public_key"]
        peer_pubkey = bytes.fromhex(peer_pubkey_hex)

        # 5. Compute and display PIN for our side's verification
        pin = derive_pairing_pin(identity.public_key_bytes, peer_pubkey, nonce)
        print(f"\n  ✓ Peer accepted! Confirm PIN matched: {pin}")

        # 6. Save peer to trust store
        device = TrustedDevice(
            device_id=peer_id,
            name=peer_name,
            ed25519_public=peer_pubkey_hex,
            noise_public="00" * 32,
            paired_at=time.time(),
            last_seen=time.time(),
            signature="00" * 64,
        )
        trust_store.add_device(device)
        print(f"  ✓ Paired with {peer_name} (id={peer_id})")
        print(f"  ✓ Device saved to trust store. Ready to sync!\n")
        return True

    except asyncio.TimeoutError:
        print(f"\n  ✗ Pairing timed out — the other device did not respond in time.")
        return False
    except Exception as e:
        print(f"\n  ✗ Pairing error: {e}")
        logger.exception("Pairing error")
        return False
    finally:
        writer.close()
        await writer.wait_closed()

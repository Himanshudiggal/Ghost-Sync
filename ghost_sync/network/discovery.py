"""mDNS service discovery for Ghost Sync peers on the local network.

Uses the zeroconf library to register this device as a Ghost Sync service
and browse for other instances. Peers are discovered automatically without
any manual IP configuration.

Supports both synchronous usage (cmd_discover) and async usage (cmd_sync)
by running Zeroconf in a dedicated background thread.
"""

from __future__ import annotations

import logging
import socket
import threading
from typing import Callable, Dict, Optional

from zeroconf import (
    IPVersion,
    ServiceBrowser,
    ServiceInfo,
    ServiceStateChange,
    Zeroconf,
)

from ghost_sync.common.config import PAIR_PORT, SERVICE_TYPE, SYNC_PORT

logger = logging.getLogger(__name__)


class DiscoveredPeer:
    """Represents a peer discovered via mDNS."""

    def __init__(
        self,
        device_id: str,
        device_name: str,
        fingerprint: str,
        host: str,
        port: int,
    ) -> None:
        self.device_id = device_id
        self.device_name = device_name
        self.fingerprint = fingerprint
        self.host = host
        self.port = port

    def __repr__(self) -> str:
        return (
            f"DiscoveredPeer(id={self.device_id}, name={self.device_name!r}, "
            f"host={self.host}:{self.port})"
        )


class GhostSyncDiscovery:
    """mDNS service registration and discovery for Ghost Sync.

    Registers this device as a _ghostsync._tcp.local. service and browses
    for other instances on the local network.

    Zeroconf runs in its own background thread to avoid event-loop
    conflicts when called from an asyncio context (e.g., cmd_sync).
    """

    def __init__(
        self,
        device_id: str,
        device_name: str,
        fingerprint_str: str,
        port: int = SYNC_PORT,
        on_peer_discovered: Optional[Callable[[DiscoveredPeer], None]] = None,
        on_peer_lost: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._device_id = device_id
        self._device_name = device_name
        self._fingerprint = fingerprint_str
        self._port = port
        self._on_peer_discovered = on_peer_discovered
        self._on_peer_lost = on_peer_lost

        self._zeroconf: Optional[Zeroconf] = None
        self._browser: Optional[ServiceBrowser] = None
        self._service_info: Optional[ServiceInfo] = None
        self._peers: Dict[str, DiscoveredPeer] = {}
        self._thread: Optional[threading.Thread] = None
        self._started = threading.Event()

    @property
    def peers(self) -> Dict[str, DiscoveredPeer]:
        """Currently discovered peers, keyed by device_id."""
        return dict(self._peers)

    def start(self) -> None:
        """Register this device and start browsing for peers.

        Runs Zeroconf setup in a background thread to avoid blocking
        the asyncio event loop.
        """
        self._thread = threading.Thread(target=self._start_in_thread, daemon=True)
        self._thread.start()
        # Wait for Zeroconf to finish registration (up to 10s)
        self._started.wait(timeout=10.0)

    def _start_in_thread(self) -> None:
        """Thread target: initializes Zeroconf, registers service, starts browser."""
        try:
            self._zeroconf = Zeroconf(ip_version=IPVersion.V4Only)

            local_ip = self._get_local_ip()
            self._service_info = ServiceInfo(
                SERVICE_TYPE,
                f"{self._device_id}.{SERVICE_TYPE}",
                addresses=[socket.inet_aton(local_ip)],
                port=self._port,
                properties={
                    "device_id": self._device_id,
                    "device_name": self._device_name,
                    "fingerprint": self._fingerprint,
                    "pair_port": str(PAIR_PORT),
                    "version": "1",
                },
            )
            self._zeroconf.register_service(self._service_info)
            logger.info(
                "Registered mDNS service: %s at %s:%d",
                self._device_id,
                local_ip,
                self._port,
            )

            self._browser = ServiceBrowser(
                self._zeroconf,
                SERVICE_TYPE,
                handlers=[self._on_service_state_change],
            )
            logger.info("Started browsing for Ghost Sync peers")
        except Exception:
            logger.exception("Failed to start mDNS discovery")
        finally:
            self._started.set()

    def stop(self) -> None:
        """Unregister service and stop browsing."""
        if self._zeroconf:
            try:
                if self._service_info:
                    self._zeroconf.unregister_service(self._service_info)
                    logger.info("Unregistered mDNS service")
                self._zeroconf.close()
            except Exception:
                logger.exception("Error stopping mDNS discovery")
            self._zeroconf = None
        self._browser = None
        self._peers.clear()
        logger.info("mDNS discovery stopped")

    def _on_service_state_change(
        self,
        zeroconf: Zeroconf,
        service_type: str,
        name: str,
        state_change: ServiceStateChange,
    ) -> None:
        """Handle mDNS service state changes."""
        if state_change == ServiceStateChange.Added:
            info = zeroconf.get_service_info(service_type, name)
            if info is None:
                return

            props = {
                k.decode("utf-8") if isinstance(k, bytes) else k:
                v.decode("utf-8") if isinstance(v, bytes) else v
                for k, v in (info.properties or {}).items()
            }

            peer_id = props.get("device_id", "")

            # Skip our own service
            if peer_id == self._device_id:
                return

            # Extract host address
            addresses = info.parsed_addresses()
            if not addresses:
                return

            peer = DiscoveredPeer(
                device_id=peer_id,
                device_name=props.get("device_name", "unknown"),
                fingerprint=props.get("fingerprint", ""),
                host=addresses[0],
                port=info.port,
            )

            self._peers[peer_id] = peer
            logger.info("Discovered peer: %s", peer)

            if self._on_peer_discovered:
                self._on_peer_discovered(peer)

        elif state_change == ServiceStateChange.Removed:
            # Extract device_id from service name
            peer_id = name.split(".")[0] if "." in name else name

            if peer_id in self._peers:
                removed = self._peers.pop(peer_id)
                logger.info("Peer lost: %s", removed)

                if self._on_peer_lost:
                    self._on_peer_lost(peer_id)

    @staticmethod
    def _get_local_ip() -> str:
        """Get the local IP address used for LAN communication."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

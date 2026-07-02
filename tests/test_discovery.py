"""Tests for mDNS discovery."""

import pytest
from unittest.mock import MagicMock, patch

from ghost_sync.network.discovery import GhostSyncDiscovery, DiscoveredPeer


class TestDiscoveredPeer:
    def test_creation(self):
        """DiscoveredPeer should store all fields correctly."""
        peer = DiscoveredPeer(
            device_id="abc123",
            device_name="Test-Phone",
            fingerprint="SHA256:abcdef",
            host="192.168.1.100",
            port=43210,
        )
        assert peer.device_id == "abc123"
        assert peer.device_name == "Test-Phone"
        assert peer.host == "192.168.1.100"
        assert peer.port == 43210

    def test_repr(self):
        """repr should include device name, ID, and host."""
        peer = DiscoveredPeer(
            device_id="abc123",
            device_name="Test-Phone",
            fingerprint="SHA256:abcdef",
            host="192.168.1.100",
            port=43210,
        )
        r = repr(peer)
        assert "abc123" in r
        assert "Test-Phone" in r
        assert "192.168.1.100" in r


class TestGhostSyncDiscovery:
    def test_initial_state(self):
        """Discovery should start with no peers."""
        discovery = GhostSyncDiscovery(
            device_id="my-id",
            device_name="my-device",
            fingerprint_str="SHA256:test",
        )
        assert discovery.peers == {}

    def test_callbacks_stored(self):
        """Callbacks should be stored for later invocation."""
        on_discovered = MagicMock()
        on_lost = MagicMock()

        discovery = GhostSyncDiscovery(
            device_id="my-id",
            device_name="my-device",
            fingerprint_str="SHA256:test",
            on_peer_discovered=on_discovered,
            on_peer_lost=on_lost,
        )
        assert discovery._on_peer_discovered is on_discovered
        assert discovery._on_peer_lost is on_lost

    def test_get_local_ip_returns_string(self):
        """_get_local_ip should return a valid IP string."""
        ip = GhostSyncDiscovery._get_local_ip()
        assert isinstance(ip, str)
        # Should be either a real IP or fallback 127.0.0.1
        parts = ip.split(".")
        assert len(parts) == 4

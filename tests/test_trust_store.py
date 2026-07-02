"""Tests for TrustStore."""

import time

import pytest
from nacl.utils import random as nacl_random

from ghost_sync.identity.trust_store import TrustStore, TrustedDevice


@pytest.fixture
def enc_key():
    """Random 32-byte encryption key for tests."""
    return nacl_random(32)


@pytest.fixture
def sample_device():
    return TrustedDevice(
        device_id="abcdef0123456789",
        name="Test-Phone",
        ed25519_public="aa" * 32,
        noise_public="bb" * 32,
        paired_at=time.time(),
        last_seen=time.time(),
        signature="cc" * 64,
    )


@pytest.fixture
def second_device():
    return TrustedDevice(
        device_id="1234567890abcdef",
        name="Test-Tablet",
        ed25519_public="dd" * 32,
        noise_public="ee" * 32,
        paired_at=time.time(),
        last_seen=time.time(),
        signature="ff" * 64,
    )


class TestTrustStoreBasic:
    def test_empty_store(self, enc_key, trust_store_path):
        """A fresh store should be empty."""
        store = TrustStore.load(enc_key, trust_store_path)
        assert len(store) == 0
        assert store.list_devices() == []

    def test_add_device(self, enc_key, trust_store_path, sample_device):
        """Adding a device should make it queryable."""
        store = TrustStore.load(enc_key, trust_store_path)
        store.add_device(sample_device)
        assert len(store) == 1
        assert store.is_trusted(sample_device.device_id)
        assert store.get_device(sample_device.device_id) == sample_device

    def test_remove_device(self, enc_key, trust_store_path, sample_device):
        """Removing a device should make it untrusted."""
        store = TrustStore.load(enc_key, trust_store_path)
        store.add_device(sample_device)
        assert store.remove_device(sample_device.device_id)
        assert not store.is_trusted(sample_device.device_id)
        assert len(store) == 0

    def test_remove_nonexistent(self, enc_key, trust_store_path):
        """Removing a nonexistent device should return False."""
        store = TrustStore.load(enc_key, trust_store_path)
        assert not store.remove_device("nonexistent")

    def test_contains(self, enc_key, trust_store_path, sample_device):
        """The 'in' operator should work for device IDs."""
        store = TrustStore.load(enc_key, trust_store_path)
        store.add_device(sample_device)
        assert sample_device.device_id in store
        assert "nonexistent" not in store


class TestTrustStorePersistence:
    def test_save_and_load_roundtrip(self, enc_key, trust_store_path, sample_device):
        """Save then reload should preserve all device data."""
        store = TrustStore.load(enc_key, trust_store_path)
        store.add_device(sample_device)

        reloaded = TrustStore.load(enc_key, trust_store_path)
        assert len(reloaded) == 1
        retrieved = reloaded.get_device(sample_device.device_id)
        assert retrieved.name == sample_device.name
        assert retrieved.ed25519_public == sample_device.ed25519_public

    def test_encrypted_at_rest(self, enc_key, trust_store_path, sample_device):
        """The stored file should not contain plaintext device names."""
        store = TrustStore.load(enc_key, trust_store_path)
        store.add_device(sample_device)

        raw = trust_store_path.read_bytes()
        assert b"Test-Phone" not in raw

    def test_wrong_key_fails(self, enc_key, trust_store_path, sample_device):
        """Loading with the wrong key should raise an exception."""
        store = TrustStore.load(enc_key, trust_store_path)
        store.add_device(sample_device)

        wrong_key = nacl_random(32)
        with pytest.raises(Exception):
            TrustStore.load(wrong_key, trust_store_path)

    def test_multiple_devices(self, enc_key, trust_store_path, sample_device, second_device):
        """Multiple devices should persist and reload correctly."""
        store = TrustStore.load(enc_key, trust_store_path)
        store.add_device(sample_device)
        store.add_device(second_device)

        reloaded = TrustStore.load(enc_key, trust_store_path)
        assert len(reloaded) == 2
        names = [d.name for d in reloaded.list_devices()]
        assert "Test-Phone" in names
        assert "Test-Tablet" in names

    def test_update_last_seen(self, enc_key, trust_store_path, sample_device):
        """update_last_seen should persist a newer timestamp."""
        store = TrustStore.load(enc_key, trust_store_path)
        old_time = sample_device.last_seen
        store.add_device(sample_device)

        time.sleep(0.01)
        store.update_last_seen(sample_device.device_id)

        reloaded = TrustStore.load(enc_key, trust_store_path)
        assert reloaded.get_device(sample_device.device_id).last_seen > old_time

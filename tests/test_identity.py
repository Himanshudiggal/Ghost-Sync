"""Tests for DeviceIdentity."""

import os
import socket

import pytest
from nacl.signing import VerifyKey

from ghost_sync.identity.keys import DeviceIdentity


class TestDeviceIdentityGeneration:
    def test_generate_creates_valid_identity(self):
        """Generated identity should have valid fields."""
        identity = DeviceIdentity.generate(device_name="test-device")
        assert identity.device_name == "test-device"
        assert len(identity.device_id) == 16  # 8 bytes as hex
        assert len(identity.public_key_bytes) == 32
        assert identity.fingerprint_str.startswith("SHA256:")

    def test_generate_uses_hostname_by_default(self):
        """Default device name should be the system hostname."""
        identity = DeviceIdentity.generate()
        assert identity.device_name == socket.gethostname()

    def test_generate_produces_unique_keys(self):
        """Each generation should produce a unique keypair."""
        id1 = DeviceIdentity.generate()
        id2 = DeviceIdentity.generate()
        assert id1.device_id != id2.device_id
        assert id1.public_key_bytes != id2.public_key_bytes

    def test_noise_keys_are_derived(self):
        """Noise (Curve25519) keys should be 32 bytes and differ from Ed25519."""
        identity = DeviceIdentity.generate()
        assert len(identity.noise_private_key) == 32
        assert len(identity.noise_public_key) == 32
        # Noise keys differ from Ed25519 keys (different curve representation)
        assert identity.noise_public_key != identity.public_key_bytes


class TestDeviceIdentityPersistence:
    def test_save_and_load(self, identity_path):
        """Save then load should produce identical identity."""
        original = DeviceIdentity.generate(device_name="persist-test")
        original.save(identity_path)

        loaded = DeviceIdentity.load(identity_path)
        assert loaded.device_id == original.device_id
        assert loaded.device_name == original.device_name
        assert loaded.public_key_bytes == original.public_key_bytes

    def test_save_sets_permissions_0600(self, identity_path):
        """Identity file should have owner-only read/write permissions."""
        identity = DeviceIdentity.generate()
        identity.save(identity_path)
        mode = os.stat(identity_path).st_mode & 0o777
        assert mode == 0o600

    def test_load_nonexistent_raises(self, tmp_dir):
        """Loading from a nonexistent path should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            DeviceIdentity.load(tmp_dir / "missing.key")

    def test_load_or_generate_creates_new(self, identity_path):
        """load_or_generate should create and save a new identity."""
        identity = DeviceIdentity.load_or_generate(identity_path)
        assert identity_path.exists()
        reloaded = DeviceIdentity.load(identity_path)
        assert reloaded.device_id == identity.device_id

    def test_load_or_generate_loads_existing(self, identity_path):
        """load_or_generate should load existing identity, not generate new."""
        original = DeviceIdentity.generate(device_name="first")
        original.save(identity_path)

        loaded = DeviceIdentity.load_or_generate(identity_path, device_name="second")
        # Should load the existing one, not generate with "second"
        assert loaded.device_name == "first"


class TestDeviceIdentitySignatures:
    def test_sign_and_verify(self):
        """Signatures should be verifiable with the public key."""
        identity = DeviceIdentity.generate()
        message = b"hello world"
        signature = identity.sign(message)
        assert len(signature) == 64

        vk = VerifyKey(identity.public_key_bytes)
        vk.verify(message, signature)  # Raises if invalid

    def test_sign_produces_different_sigs_for_different_data(self):
        """Different messages should produce different signatures."""
        identity = DeviceIdentity.generate()
        sig1 = identity.sign(b"message1")
        sig2 = identity.sign(b"message2")
        assert sig1 != sig2


class TestDeviceIdentityRepr:
    def test_repr_contains_key_info(self):
        """repr should include device name, ID, and fingerprint."""
        identity = DeviceIdentity.generate(device_name="repr-test")
        r = repr(identity)
        assert "repr-test" in r
        assert identity.device_id in r
        assert "SHA256:" in r

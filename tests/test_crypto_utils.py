"""Tests for crypto_utils module."""

import pytest
from ghost_sync.common.crypto_utils import (
    sha256,
    derive_device_id,
    fingerprint,
    derive_store_key,
    derive_pairing_pin,
    constant_time_compare,
)


class TestSha256:
    def test_known_vector(self):
        """SHA-256 of empty string should match the known hash."""
        result = sha256(b"")
        assert result.hex().startswith("e3b0c44298fc")

    def test_deterministic(self):
        """Same input must always produce the same hash."""
        assert sha256(b"hello") == sha256(b"hello")

    def test_different_inputs(self):
        """Different inputs must produce different hashes."""
        assert sha256(b"a") != sha256(b"b")

    def test_returns_32_bytes(self):
        """SHA-256 always produces a 32-byte (256-bit) digest."""
        assert len(sha256(b"anything")) == 32


class TestDeriveDeviceId:
    def test_length(self):
        """Device ID should be 16 hex characters (8 bytes)."""
        device_id = derive_device_id(b"x" * 32)
        assert len(device_id) == 16

    def test_is_hex(self):
        """Device ID should be a valid hex string."""
        device_id = derive_device_id(b"x" * 32)
        int(device_id, 16)  # Should not raise

    def test_deterministic(self):
        """Same key must always produce the same device ID."""
        key = b"k" * 32
        assert derive_device_id(key) == derive_device_id(key)

    def test_different_keys(self):
        """Different keys must produce different device IDs."""
        assert derive_device_id(b"a" * 32) != derive_device_id(b"b" * 32)


class TestFingerprint:
    def test_format(self):
        """Fingerprint should be 'SHA256:' followed by 12 base64 chars."""
        fp = fingerprint(b"x" * 32)
        assert fp.startswith("SHA256:")
        assert len(fp) == 7 + 12  # "SHA256:" + 12 base64 chars

    def test_deterministic(self):
        """Same key must always produce the same fingerprint."""
        key = b"test" * 8
        assert fingerprint(key) == fingerprint(key)


class TestDeriveStoreKey:
    def test_returns_32_bytes(self):
        """Store key must be exactly 32 bytes for SecretBox."""
        key = derive_store_key(b"x" * 32)
        assert len(key) == 32

    def test_deterministic(self):
        """Same signing key must produce the same store key."""
        sk = b"signing" * 5  # 35 bytes, will use first 32
        assert derive_store_key(sk) == derive_store_key(sk)

    def test_different_inputs(self):
        """Different signing keys must produce different store keys."""
        assert derive_store_key(b"a" * 32) != derive_store_key(b"b" * 32)


class TestDerivePairingPin:
    def test_six_digits(self):
        """PIN must be exactly 6 digits."""
        pin = derive_pairing_pin(b"a" * 32, b"b" * 32, b"n" * 32)
        assert len(pin) == 6
        assert pin.isdigit()

    def test_deterministic(self):
        """Same inputs must always produce the same PIN."""
        a, b, n = b"a" * 32, b"b" * 32, b"n" * 32
        assert derive_pairing_pin(a, b, n) == derive_pairing_pin(a, b, n)

    def test_order_independent(self):
        """PIN must be the same regardless of key order (commutative)."""
        a, b, n = b"a" * 32, b"b" * 32, b"n" * 32
        assert derive_pairing_pin(a, b, n) == derive_pairing_pin(b, a, n)

    def test_different_nonce_different_pin(self):
        """Different nonces must produce different PINs."""
        a, b = b"a" * 32, b"b" * 32
        pin1 = derive_pairing_pin(a, b, b"n1" + b"\x00" * 30)
        pin2 = derive_pairing_pin(a, b, b"n2" + b"\x00" * 30)
        assert pin1 != pin2

    def test_zero_padded(self):
        """PINs less than 100000 should be zero-padded to 6 digits."""
        # We can't easily force a specific PIN, but verify format
        pin = derive_pairing_pin(b"x" * 32, b"y" * 32, b"z" * 32)
        assert len(pin) == 6


class TestConstantTimeCompare:
    def test_equal(self):
        """Equal byte strings should compare as True."""
        assert constant_time_compare(b"abc", b"abc")

    def test_not_equal(self):
        """Different byte strings should compare as False."""
        assert not constant_time_compare(b"abc", b"abd")

    def test_different_length(self):
        """Strings of different lengths should compare as False."""
        assert not constant_time_compare(b"ab", b"abc")

    def test_empty(self):
        """Empty byte strings should compare as True."""
        assert constant_time_compare(b"", b"")

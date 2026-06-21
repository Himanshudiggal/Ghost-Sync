"""Device identity management: keypair generation, loading, saving.

Each device gets a long-lived Ed25519 keypair. The public key is used as
the device's identity — other devices recognize us by our public key
(or its fingerprint / derived device_id).

For the Noise protocol handshake, we derive Curve25519 keys from the
Ed25519 pair (libsodium handles the conversion).
"""

from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from nacl.signing import SigningKey, VerifyKey

from ghost_sync.common.config import IDENTITY_FILE
from ghost_sync.common.crypto_utils import derive_device_id, fingerprint


@dataclass(frozen=True)
class DeviceIdentity:
    """This device's cryptographic identity.

    Immutable (frozen) to prevent accidental modification of key material.
    """

    signing_key: SigningKey
    verify_key: VerifyKey
    device_id: str
    device_name: str

    @staticmethod
    def generate(device_name: Optional[str] = None) -> DeviceIdentity:
        """Generate a new identity with a fresh Ed25519 keypair.

        Args:
            device_name: Human-readable name. Defaults to hostname.
        """
        if device_name is None:
            device_name = socket.gethostname()

        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        device_id = derive_device_id(verify_key.encode())

        return DeviceIdentity(
            signing_key=signing_key,
            verify_key=verify_key,
            device_id=device_id,
            device_name=device_name,
        )

    def save(self, path: Optional[Path] = None) -> None:
        """Save identity to disk with owner-only permissions (0600).

        The file contains a JSON object with the version, hex-encoded
        signing key, and device name. The verify key and device ID are
        derived from the signing key on load.

        Args:
            path: File path. Defaults to IDENTITY_FILE.
        """
        path = path or IDENTITY_FILE
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "version": 1,
            "signing_key": self.signing_key.encode().hex(),
            "device_name": self.device_name,
        }

        path.write_text(json.dumps(data, indent=2))
        os.chmod(path, 0o600)

    @staticmethod
    def load(path: Optional[Path] = None) -> DeviceIdentity:
        """Load identity from disk.

        Args:
            path: File path. Defaults to IDENTITY_FILE.

        Raises:
            FileNotFoundError: If identity file doesn't exist.
            ValueError: If file is corrupt or version mismatch.
        """
        path = path or IDENTITY_FILE

        data = json.loads(path.read_text())
        if data.get("version") != 1:
            raise ValueError(f"Unsupported identity version: {data.get('version')}")

        signing_key = SigningKey(bytes.fromhex(data["signing_key"]))
        verify_key = signing_key.verify_key
        device_id = derive_device_id(verify_key.encode())

        return DeviceIdentity(
            signing_key=signing_key,
            verify_key=verify_key,
            device_id=device_id,
            device_name=data["device_name"],
        )

    @staticmethod
    def load_or_generate(
        path: Optional[Path] = None,
        device_name: Optional[str] = None,
    ) -> DeviceIdentity:
        """Load existing identity or generate and save a new one."""
        path = path or IDENTITY_FILE
        try:
            return DeviceIdentity.load(path)
        except FileNotFoundError:
            identity = DeviceIdentity.generate(device_name)
            identity.save(path)
            return identity

    @property
    def public_key_bytes(self) -> bytes:
        """Raw Ed25519 public key bytes (32 bytes)."""
        return self.verify_key.encode()

    @property
    def fingerprint_str(self) -> str:
        """Human-readable fingerprint string."""
        return fingerprint(self.public_key_bytes)

    @property
    def noise_private_key(self) -> bytes:
        """Curve25519 private key bytes for Noise protocol."""
        return self.signing_key.to_curve25519_private_key().encode()

    @property
    def noise_public_key(self) -> bytes:
        """Curve25519 public key bytes for Noise protocol."""
        return self.verify_key.to_curve25519_public_key().encode()

    def sign(self, data: bytes) -> bytes:
        """Sign data with this device's Ed25519 key. Returns 64-byte signature."""
        return self.signing_key.sign(data).signature

    def __repr__(self) -> str:
        return (
            f"DeviceIdentity(id={self.device_id}, "
            f"name={self.device_name!r}, "
            f"fp={self.fingerprint_str})"
        )

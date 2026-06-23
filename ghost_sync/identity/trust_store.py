"""Encrypted trust store: manages device_id -> public_key mappings.

Persisted as JSON encrypted with NaCl SecretBox (XSalsa20-Poly1305).
The encryption key is derived from the local device's signing key,
so an attacker with filesystem access (but without the private key)
cannot read the store.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from nacl.secret import SecretBox

from ghost_sync.common.config import TRUST_STORE_FILE


@dataclass
class TrustedDevice:
    """A single trusted peer device."""

    device_id: str
    name: str
    ed25519_public: str  # hex-encoded 32 bytes
    noise_public: str  # hex-encoded 32 bytes
    paired_at: float  # Unix timestamp
    last_seen: float  # Unix timestamp
    signature: str  # hex-encoded Ed25519 signature

    def public_key_bytes(self) -> bytes:
        return bytes.fromhex(self.ed25519_public)

    def noise_public_bytes(self) -> bytes:
        return bytes.fromhex(self.noise_public)


@dataclass
class TrustStore:
    """Manages the set of trusted peer devices.

    The store is encrypted at rest using NaCl SecretBox (XSalsa20-Poly1305).
    Every mutation (add, remove, update) automatically persists to disk.
    """

    devices: Dict[str, TrustedDevice] = field(default_factory=dict)
    _encryption_key: Optional[bytes] = field(default=None, repr=False)
    _path: Path = field(default=TRUST_STORE_FILE)

    @staticmethod
    def load(encryption_key: bytes, path: Optional[Path] = None) -> TrustStore:
        """Load and decrypt trust store from disk.

        Args:
            encryption_key: 32-byte key derived from device signing key.
            path: File path. Defaults to TRUST_STORE_FILE.

        Returns:
            TrustStore with all trusted devices loaded.
        """
        path = path or TRUST_STORE_FILE
        store = TrustStore(_encryption_key=encryption_key, _path=path)

        if not path.exists():
            return store

        encrypted = path.read_bytes()
        box = SecretBox(encryption_key)
        plaintext = box.decrypt(encrypted)
        data = json.loads(plaintext.decode("utf-8"))

        if data.get("version") != 1:
            raise ValueError(f"Unsupported trust store version: {data.get('version')}")

        for dev_id, dev_data in data.get("devices", {}).items():
            store.devices[dev_id] = TrustedDevice(**dev_data)

        return store

    def save(self) -> None:
        """Encrypt and save trust store to disk."""
        if self._encryption_key is None:
            raise RuntimeError("No encryption key set")

        data = {
            "version": 1,
            "devices": {dev_id: asdict(dev) for dev_id, dev in self.devices.items()},
        }

        plaintext = json.dumps(data, indent=2).encode("utf-8")
        box = SecretBox(self._encryption_key)
        encrypted = box.encrypt(plaintext)

        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_bytes(encrypted)

    def add_device(self, device: TrustedDevice) -> None:
        """Add or update a trusted device and persist."""
        self.devices[device.device_id] = device
        self.save()

    def remove_device(self, device_id: str) -> bool:
        """Remove a device from the trust store. Returns True if found."""
        if device_id in self.devices:
            del self.devices[device_id]
            self.save()
            return True
        return False

    def get_device(self, device_id: str) -> Optional[TrustedDevice]:
        """Look up a trusted device by ID."""
        return self.devices.get(device_id)

    def is_trusted(self, device_id: str) -> bool:
        """Check if a device ID is in the trust store."""
        return device_id in self.devices

    def update_last_seen(self, device_id: str) -> None:
        """Update last_seen timestamp for a device."""
        if device_id in self.devices:
            self.devices[device_id].last_seen = time.time()
            self.save()

    def list_devices(self) -> List[TrustedDevice]:
        """Return all trusted devices sorted by name."""
        return sorted(self.devices.values(), key=lambda d: d.name)

    def __len__(self) -> int:
        return len(self.devices)

    def __contains__(self, device_id: str) -> bool:
        return device_id in self.devices

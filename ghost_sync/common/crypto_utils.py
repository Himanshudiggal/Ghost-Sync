"""Low-level cryptographic utilities.

Provides hashing, key derivation, fingerprinting, pairing PIN generation,
and constant-time comparison functions used throughout Ghost Sync.
"""

import base64
import hashlib
import hmac

import nacl.encoding
from nacl.hash import blake2b


def sha256(data: bytes) -> bytes:
    """Return SHA-256 digest of the given data."""
    return hashlib.sha256(data).digest()


def derive_device_id(public_key_bytes: bytes) -> str:
    """Derive 8-byte hex device ID from an Ed25519 public key.

    The device ID is the first 8 bytes of the SHA-256 hash of the
    public key, encoded as a 16-character hexadecimal string.
    """
    return sha256(public_key_bytes)[:8].hex()


def fingerprint(public_key_bytes: bytes) -> str:
    """Human-readable key fingerprint: 'SHA256:Ab3d...Kx9z' (12 base64 chars).

    Follows the same format convention as SSH key fingerprints.
    """
    digest = sha256(public_key_bytes)
    b64 = base64.b64encode(digest).decode("ascii")
    return f"SHA256:{b64[:12]}"


def derive_store_key(signing_key_bytes: bytes) -> bytes:
    """Derive 32-byte encryption key for the trust store from a signing key.

    Uses BLAKE2b in keyed mode with a domain separator string to ensure
    the derived key is cryptographically independent from the signing key
    and cannot be confused with keys derived for other purposes.
    """
    return blake2b(
        b"ghost-sync-trust-store-encryption",
        key=signing_key_bytes[:32],
        digest_size=32,
        encoder=nacl.encoding.RawEncoder,
    )


def derive_pairing_pin(pub_a: bytes, pub_b: bytes, nonce: bytes) -> str:
    """Derive a 6-digit PIN from two public keys and a nonce.

    The PIN is order-independent: derive_pairing_pin(A, B, n) ==
    derive_pairing_pin(B, A, n). This is achieved by sorting the keys
    lexicographically before hashing.

    Used during device pairing so both devices display the same PIN
    for human verification, preventing MITM attacks.
    """
    sorted_keys = b"".join(sorted([pub_a, pub_b]))
    material = blake2b(
        sorted_keys + nonce,
        digest_size=32,
        encoder=nacl.encoding.RawEncoder,
    )
    pin_int = int.from_bytes(material[:4], "big") % 1_000_000
    return f"{pin_int:06d}"


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time byte comparison to prevent timing side-channel attacks.

    Uses Python's stdlib hmac.compare_digest which is implemented in C
    and guaranteed to take the same time regardless of where inputs differ.
    """
    return hmac.compare_digest(a, b)

# Ghost Sync

**Cross-device P2P clipboard synchronization over local Wi-Fi.**

Copy on one device, paste on another — no cloud, no accounts, no hassle.

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Status: In Development](https://img.shields.io/badge/status-in%20development-yellow)

---

## What Is This?

Ghost Sync is a peer-to-peer clipboard synchronizer that works over your local Wi-Fi network. When you copy text on your laptop, it's instantly available to paste on any other paired device on the same network — and vice versa.

**No cloud server. No account sign-up. No data leaves your local network.**

### Key Features

- **P2P Architecture** — devices communicate directly, no central server
- **Encrypted Trust Store** — paired device keys stored with NaCl SecretBox (XSalsa20-Poly1305)
- **Ed25519 Device Identity** — each device gets a long-lived cryptographic identity
- **mDNS Auto-Discovery** — devices find each other automatically via Zeroconf
- **Anti-Echo Suppression** — clipboard writes from remote peers don't trigger sync loops
- **SHA-256 Deduplication** — identical clipboard content is never re-synced
- **Cross-Platform** — macOS and Windows clipboard backends

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│                   Ghost Sync                     │
├──────────────┬───────────────┬───────────────────┤
│  Clipboard   │   Identity    │     Network       │
│   Watcher    │   Manager     │    Discovery      │
│              │               │                   │
│ ┌──────────┐ │ ┌───────────┐ │ ┌───────────────┐ │
│ │ Platform │ │ │  Ed25519  │ │ │ mDNS/Zeroconf │ │
│ │ Backend  │ │ │  Keypair  │ │ │   Browser     │ │
│ └──────────┘ │ └───────────┘ │ └───────────────┘ │
│              │ ┌───────────┐ │                   │
│              │ │Encrypted  │ │                   │
│              │ │Trust Store│ │                   │
│              │ └───────────┘ │                   │
├──────────────┴───────────────┴───────────────────┤
│              Common Utilities                    │
│     EventBus  │  Config  │  Crypto Utils         │
└──────────────────────────────────────────────────┘
```

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Language | Python 3.9+ | Core runtime |
| Cryptography | PyNaCl (libsodium) | Ed25519 signatures, SecretBox encryption, BLAKE2b |
| Serialization | msgpack | Efficient binary message encoding |
| Discovery | zeroconf | mDNS service discovery on local network |
| Secure Channel | noiseprotocol | Noise framework for encrypted P2P communication |
| System Tray | pystray + Pillow | Background UI (planned) |
| QR Pairing | qrcode | Visual device pairing (planned) |

---

## Project Structure

```
ghost_sync/
├── common/
│   ├── config.py          # App-wide constants and paths
│   ├── crypto_utils.py    # SHA-256, key derivation, fingerprinting
│   └── events.py          # Async pub/sub EventBus
├── identity/
│   ├── keys.py            # DeviceIdentity (Ed25519 keypair management)
│   └── trust_store.py     # Encrypted trusted peer storage
├── clipboard/
│   ├── watcher.py         # Abstract clipboard monitor with anti-echo
│   ├── platform_darwin.py # macOS clipboard backend (NSPasteboard)
│   └── platform_win32.py  # Windows clipboard backend (win32 API)
├── network/
│   └── discovery.py       # mDNS auto-discovery via Zeroconf
└── __main__.py            # CLI entry point
```

---

## Quick Start

### Prerequisites

- Python 3.9 or higher
- macOS or Windows
- Two devices on the same Wi-Fi network

### Installation

```bash
# Clone the repository
git clone https://github.com/Himanshudiggal/Ghost-Sync.git
cd Ghost-Sync

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows

# Install in development mode
pip install -e ".[dev]"

# macOS: install platform dependencies
pip install -e ".[macos]"
```

### Usage

```bash
# Initialize device identity
ghostsync init --name "My-Laptop"

# View your device identity
ghostsync identity

# Start clipboard watcher (debug mode)
ghostsync watch --debug

# Discover peers on the network
ghostsync discover

# List trusted devices
ghostsync trust list

# Remove a trusted device
ghostsync trust remove <device_id>
```

---

## Security Model

Ghost Sync is designed with a **zero-trust network** philosophy:

1. **Device Identity** — Each device generates a long-lived Ed25519 keypair. The public key serves as the device's identity.
2. **Trust-on-First-Use (TOFU)** — Devices must be explicitly paired. A 6-digit PIN (derived from both public keys) prevents MITM attacks during pairing.
3. **Encrypted Trust Store** — Paired device keys are stored encrypted with NaCl SecretBox, using a key derived from the local device's signing key via BLAKE2b.
4. **Signed Messages** — All clipboard sync messages are signed with Ed25519 to verify sender authenticity.
5. **Local Network Only** — No data leaves your local Wi-Fi network. No cloud, no relay servers.

---

## Development

### Running Tests

```bash
python -m pytest tests/ -v
```

### Type Checking

```bash
python -m mypy ghost_sync/ --strict
```

### Linting

```bash
python -m ruff check ghost_sync/
```

---

## Roadmap

- [x] Core configuration and path management
- [x] Async EventBus (pub/sub)
- [ ] Cryptographic utilities (SHA-256, BLAKE2b key derivation, fingerprinting)
- [ ] Device identity management (Ed25519 keypair)
- [ ] Encrypted trust store (NaCl SecretBox)
- [ ] Clipboard watcher with anti-echo suppression
- [ ] Platform backends (macOS, Windows)
- [ ] mDNS auto-discovery (Zeroconf)
- [ ] CLI interface
- [ ] Noise protocol encrypted P2P channel
- [ ] System tray UI
- [ ] QR code pairing

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [PyNaCl](https://pynacl.readthedocs.io/) — Python binding to libsodium
- [Zeroconf](https://python-zeroconf.readthedocs.io/) — Pure-Python mDNS/DNS-SD
- [Noise Protocol Framework](https://noiseprotocol.org/) — Modern cryptographic handshake framework

"""Application-wide constants and path configuration."""

import os
from pathlib import Path

APP_NAME = "ghostsync"
APP_DIR = Path(os.environ.get("GHOSTSYNC_DIR", str(Path.home() / ".ghostsync")))
IDENTITY_FILE = APP_DIR / "identity.key"
TRUST_STORE_FILE = APP_DIR / "trust_store.json.enc"
LOG_FILE = APP_DIR / "ghostsync.log"
CONFIG_FILE = APP_DIR / "config.json"

PROTOCOL_VERSION = 1
SERVICE_TYPE = "_ghostsync._tcp.local."

CLIPBOARD_POLL_INTERVAL = 0.5  # seconds
MAX_CLIPBOARD_SIZE = 1_000_000  # 1 MB text limit

SYNC_PORT = 43210   # TCP port for clipboard sync
PAIR_PORT = 43211   # TCP port for pairing handshake
MDNS_BROWSE_TIMEOUT = 5  # seconds to wait for mDNS responses

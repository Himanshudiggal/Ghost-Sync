"""Platform-agnostic clipboard monitoring.

Detects clipboard changes via polling and deduplicates via SHA-256 hashing.
Anti-echo suppression works by updating _last_hash when we write to the
clipboard — the hash check naturally prevents re-detecting our own writes.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from ghost_sync.common.config import CLIPBOARD_POLL_INTERVAL, MAX_CLIPBOARD_SIZE

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ClipboardEvent:
    """Emitted when clipboard content changes.

    Frozen (immutable) because events may be passed to multiple async
    handlers concurrently — mutation by one handler would corrupt data
    for others.
    """

    text: str
    content_hash: bytes  # SHA-256 of UTF-8 encoded text
    timestamp: float  # time.time()
    source: str  # "local" or device_id of remote sender


class ClipboardWatcher(ABC):
    """Abstract clipboard watcher with polling, dedup, and anti-echo.

    Subclasses implement _read_clipboard() and _write_clipboard() for
    their specific platform (macOS, Windows, etc.).
    """

    def __init__(
        self,
        on_change: Callable[[ClipboardEvent], Awaitable[None]],
        poll_interval: float = CLIPBOARD_POLL_INTERVAL,
    ) -> None:
        self._on_change = on_change
        self._poll_interval = poll_interval
        self._last_hash: bytes = b""
        self._running = False
        self._task: Optional[asyncio.Task] = None  # type: ignore[type-arg]

    async def start(self) -> None:
        """Start the clipboard polling loop."""
        self._running = True
        current = self._read_clipboard()
        if current:
            self._last_hash = self._hash(current)
        self._task = asyncio.create_task(self._poll_loop())
        logger.info("Clipboard watcher started (interval=%.1fs)", self._poll_interval)

    async def stop(self) -> None:
        """Stop the clipboard polling loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Clipboard watcher stopped")

    def write(self, text: str, source: str = "remote") -> None:
        """Write text to clipboard without triggering a sync event.

        Anti-echo works by setting _last_hash to the new content's hash.
        The hash-based dedup in _check_clipboard() will then see matching
        hashes and silently ignore the change we caused.

        Args:
            text: Text to write.
            source: Device ID or description of origin.
        """
        if len(text.encode("utf-8")) > MAX_CLIPBOARD_SIZE:
            logger.warning("Rejecting clipboard write: exceeds %d bytes", MAX_CLIPBOARD_SIZE)
            return
        self._write_clipboard(text)
        self._last_hash = self._hash(text)
        logger.debug("Wrote to clipboard from %s (%d bytes)", source, len(text))

    async def _poll_loop(self) -> None:
        """Main polling loop."""
        while self._running:
            try:
                await asyncio.sleep(self._poll_interval)
                self._check_clipboard()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in clipboard poll loop")
                await asyncio.sleep(1.0)

    def _check_clipboard(self) -> None:
        """Check for clipboard changes and emit events."""
        text = self._read_clipboard()
        if text is None:
            return

        content_hash = self._hash(text)
        if content_hash == self._last_hash:
            return

        self._last_hash = content_hash

        if len(text.encode("utf-8")) > MAX_CLIPBOARD_SIZE:
            logger.warning("Ignoring clipboard: exceeds %d bytes", MAX_CLIPBOARD_SIZE)
            return

        event = ClipboardEvent(
            text=text,
            content_hash=content_hash,
            timestamp=time.time(),
            source="local",
        )
        logger.info(
            "Clipboard changed: %d chars, hash=%s",
            len(text),
            content_hash[:8].hex(),
        )
        asyncio.create_task(self._on_change(event))

    @abstractmethod
    def _read_clipboard(self) -> Optional[str]:
        """Read current clipboard text. Returns None if empty or non-text."""

    @abstractmethod
    def _write_clipboard(self, text: str) -> None:
        """Write text to system clipboard."""

    @staticmethod
    def _hash(text: str) -> bytes:
        """SHA-256 hash of UTF-8 encoded text."""
        return hashlib.sha256(text.encode("utf-8")).digest()


def create_watcher(
    on_change: Callable[[ClipboardEvent], Awaitable[None]],
    poll_interval: float = CLIPBOARD_POLL_INTERVAL,
) -> ClipboardWatcher:
    """Factory: create the appropriate ClipboardWatcher for this platform.

    Raises:
        NotImplementedError: If the current platform is not supported.
    """
    if sys.platform == "darwin":
        from ghost_sync.clipboard.platform_darwin import DarwinClipboardWatcher

        return DarwinClipboardWatcher(on_change, poll_interval)
    elif sys.platform == "win32":
        from ghost_sync.clipboard.platform_win32 import Win32ClipboardWatcher

        return Win32ClipboardWatcher(on_change, poll_interval)
    else:
        raise NotImplementedError(
            f"Clipboard watching not implemented for {sys.platform}. "
            f"Supported: darwin, win32"
        )

"""Windows clipboard watcher using ctypes Win32 API.

Uses direct ctypes calls to OpenClipboard / GetClipboardData / SetClipboardData
rather than requiring pywin32 as a dependency.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
from typing import Awaitable, Callable, Optional

from ghost_sync.clipboard.watcher import ClipboardWatcher

logger = logging.getLogger(__name__)

# Win32 constants
CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002

# Win32 API functions
user32 = ctypes.windll.user32  # type: ignore[attr-defined]
kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]


class Win32ClipboardWatcher(ClipboardWatcher):
    """Windows clipboard watcher using Win32 API via ctypes."""

    def __init__(
        self,
        on_change: Callable[..., Awaitable[None]],
        poll_interval: float = 0.5,
    ) -> None:
        super().__init__(on_change, poll_interval)
        self._last_sequence: int = user32.GetClipboardSequenceNumber()

    def _read_clipboard(self) -> Optional[str]:
        seq = user32.GetClipboardSequenceNumber()
        if seq == self._last_sequence:
            return None
        self._last_sequence = seq

        if not user32.OpenClipboard(0):
            logger.warning("Failed to open clipboard")
            return None

        try:
            if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                return None

            handle = user32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return None

            ptr = kernel32.GlobalLock(handle)
            if not ptr:
                return None

            try:
                text = ctypes.wstring_at(ptr)
                return text if text else None
            finally:
                kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()

    def _write_clipboard(self, text: str) -> None:
        if not user32.OpenClipboard(0):
            logger.warning("Failed to open clipboard for writing")
            return

        try:
            user32.EmptyClipboard()

            # Allocate global memory for the text
            encoded = text.encode("utf-16-le") + b"\x00\x00"
            h_mem = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(encoded))
            if not h_mem:
                logger.warning("Failed to allocate memory for clipboard")
                return

            ptr = kernel32.GlobalLock(h_mem)
            if not ptr:
                kernel32.GlobalFree(h_mem)
                return

            try:
                ctypes.memmove(ptr, encoded, len(encoded))
            finally:
                kernel32.GlobalUnlock(h_mem)

            user32.SetClipboardData(CF_UNICODETEXT, h_mem)
            self._last_sequence = user32.GetClipboardSequenceNumber()
        finally:
            user32.CloseClipboard()

"""macOS clipboard watcher using pyobjc NSPasteboard.

Uses changeCount polling — NSPasteboard offers no notification-based API,
so polling is the standard approach. Apple's own Universal Clipboard does
the same thing internally.
"""

from __future__ import annotations

import logging
from typing import Awaitable, Callable, Optional

from ghost_sync.clipboard.watcher import ClipboardWatcher

logger = logging.getLogger(__name__)


class DarwinClipboardWatcher(ClipboardWatcher):
    """macOS clipboard watcher using NSPasteboard."""

    def __init__(
        self,
        on_change: Callable[..., Awaitable[None]],
        poll_interval: float = 0.5,
    ) -> None:
        super().__init__(on_change, poll_interval)
        from AppKit import NSPasteboard

        self._pasteboard = NSPasteboard.generalPasteboard()
        self._last_change_count: int = self._pasteboard.changeCount()

    def _read_clipboard(self) -> Optional[str]:
        from AppKit import NSPasteboardTypeString

        pb = self._pasteboard
        cc = pb.changeCount()

        if cc == self._last_change_count:
            return None
        self._last_change_count = cc

        text = pb.stringForType_(NSPasteboardTypeString)
        if text is None:
            return None
        return str(text)

    def _write_clipboard(self, text: str) -> None:
        from AppKit import NSPasteboardTypeString

        pb = self._pasteboard
        pb.clearContents()
        pb.setString_forType_(text, NSPasteboardTypeString)
        self._last_change_count = pb.changeCount()

"""Tests for ClipboardWatcher base logic using a mock implementation."""

import asyncio
import hashlib

import pytest

from ghost_sync.clipboard.watcher import ClipboardWatcher, ClipboardEvent


class MockClipboardWatcher(ClipboardWatcher):
    """Concrete test implementation that simulates a system clipboard."""

    def __init__(self, on_change, poll_interval=0.05):
        super().__init__(on_change, poll_interval)
        self._mock_clipboard: str = ""

    def _read_clipboard(self):
        return self._mock_clipboard if self._mock_clipboard else None

    def _write_clipboard(self, text):
        self._mock_clipboard = text

    def simulate_copy(self, text):
        """Simulate a user copying text (external clipboard change)."""
        self._mock_clipboard = text


class TestClipboardWatcherDetection:
    @pytest.mark.asyncio
    async def test_detects_change(self):
        """Watcher should detect when clipboard content changes."""
        events: list[ClipboardEvent] = []

        async def handler(event):
            events.append(event)

        watcher = MockClipboardWatcher(handler, poll_interval=0.02)
        await watcher.start()

        await asyncio.sleep(0.05)
        watcher.simulate_copy("hello world")
        await asyncio.sleep(0.15)

        await watcher.stop()
        assert len(events) == 1
        assert events[0].text == "hello world"
        assert events[0].source == "local"

    @pytest.mark.asyncio
    async def test_ignores_duplicate(self):
        """Watcher should not fire for the same content twice."""
        events: list[ClipboardEvent] = []

        async def handler(event):
            events.append(event)

        watcher = MockClipboardWatcher(handler, poll_interval=0.02)
        await watcher.start()

        watcher.simulate_copy("same text")
        await asyncio.sleep(0.15)
        # Same text still on clipboard — should not fire again
        await asyncio.sleep(0.1)

        await watcher.stop()
        assert len(events) == 1

    @pytest.mark.asyncio
    async def test_detects_multiple_changes(self):
        """Watcher should detect each distinct clipboard change."""
        events: list[ClipboardEvent] = []

        async def handler(event):
            events.append(event)

        watcher = MockClipboardWatcher(handler, poll_interval=0.02)
        await watcher.start()

        watcher.simulate_copy("first")
        await asyncio.sleep(0.1)
        watcher.simulate_copy("second")
        await asyncio.sleep(0.1)

        await watcher.stop()
        assert len(events) == 2
        assert events[0].text == "first"
        assert events[1].text == "second"


class TestClipboardWatcherAntiEcho:
    @pytest.mark.asyncio
    async def test_write_suppresses_detection(self):
        """Writing via write() should not trigger a change event."""
        events: list[ClipboardEvent] = []

        async def handler(event):
            events.append(event)

        watcher = MockClipboardWatcher(handler, poll_interval=0.02)
        await watcher.start()

        # Write from remote — should NOT trigger event
        watcher.write("remote text", source="peer-123")
        await asyncio.sleep(0.15)

        await watcher.stop()
        assert len(events) == 0

    @pytest.mark.asyncio
    async def test_detects_after_suppressed_write(self):
        """A genuine local copy after a suppressed write should be detected."""
        events: list[ClipboardEvent] = []

        async def handler(event):
            events.append(event)

        watcher = MockClipboardWatcher(handler, poll_interval=0.02)
        await watcher.start()

        watcher.write("remote text")
        await asyncio.sleep(0.1)

        # Genuine local copy
        watcher.simulate_copy("local text")
        await asyncio.sleep(0.1)

        await watcher.stop()
        assert len(events) == 1
        assert events[0].text == "local text"


class TestClipboardEvent:
    def test_hash_computation(self):
        """ClipboardEvent should store the correct SHA-256 hash."""
        text = "test content"
        expected = hashlib.sha256(text.encode("utf-8")).digest()
        event = ClipboardEvent(
            text=text,
            content_hash=expected,
            timestamp=0,
            source="local",
        )
        assert event.content_hash == expected

    def test_event_is_frozen(self):
        """ClipboardEvent should be immutable (frozen dataclass)."""
        event = ClipboardEvent(
            text="test",
            content_hash=b"\x00" * 32,
            timestamp=0,
            source="local",
        )
        with pytest.raises(AttributeError):
            event.text = "modified"  # type: ignore[misc]

"""Event definitions and async pub/sub event bus."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Awaitable, Callable, Dict, List

logger = logging.getLogger(__name__)


class EventType(Enum):
    CLIPBOARD_CHANGED = auto()
    CLIPBOARD_RECEIVED = auto()
    PEER_DISCOVERED = auto()
    PEER_LOST = auto()
    PEER_CONNECTED = auto()
    PEER_DISCONNECTED = auto()
    PAIR_REQUEST = auto()
    PAIR_COMPLETE = auto()


@dataclass
class Event:
    type: EventType
    data: Any = None


class EventBus:
    """Simple async pub/sub event bus.

    Components publish events; other components subscribe to event types.
    All handlers run as asyncio tasks (non-blocking).
    """

    def __init__(self) -> None:
        self._handlers: Dict[EventType, List[Callable[[Event], Awaitable[None]]]] = {}

    def subscribe(
        self,
        event_type: EventType,
        handler: Callable[[Event], Awaitable[None]],
    ) -> None:
        """Register a handler for an event type."""
        self._handlers.setdefault(event_type, []).append(handler)

    def unsubscribe(
        self,
        event_type: EventType,
        handler: Callable[[Event], Awaitable[None]],
    ) -> None:
        """Remove a handler."""
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)

    async def publish(self, event: Event) -> None:
        """Publish an event to all subscribed handlers."""
        for handler in self._handlers.get(event.type, []):
            try:
                asyncio.create_task(handler(event))
            except Exception:
                logger.exception("Error dispatching event %s", event.type)
"""Base collector abstract class."""

from __future__ import annotations

import abc
from collections.abc import AsyncIterator

from ghostsiem._types import Event


class BaseCollector(abc.ABC):
    """Abstract base class for all log collectors.

    Subclasses must implement the ``collect`` async generator method,
    which yields normalized ``Event`` objects from the underlying log source.
    """

    def __init__(self, name: str, **kwargs: object) -> None:
        self.name = name
        self._running = False

    @abc.abstractmethod
    async def collect(self) -> AsyncIterator[Event]:
        """Yield events from the log source.

        This is an async generator that should tail the log source and
        yield new events as they appear.  It runs until cancelled.
        """
        yield  # type: ignore[misc]

    async def start(self) -> None:
        """Called once before collection begins.  Override for setup."""
        self._running = True

    async def stop(self) -> None:
        """Called to signal the collector to stop."""
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

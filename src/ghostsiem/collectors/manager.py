"""Collector manager for running multiple collectors concurrently."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ghostsiem._types import Event
from ghostsiem.collectors.auth import AuthLogCollector
from ghostsiem.collectors.base import BaseCollector
from ghostsiem.collectors.jsonfile import JSONFileCollector
from ghostsiem.collectors.syslog import SyslogCollector

logger = logging.getLogger(__name__)

# Registry of collector types
COLLECTOR_TYPES: dict[str, type[BaseCollector]] = {
    "syslog": SyslogCollector,
    "auth": AuthLogCollector,
    "json": JSONFileCollector,
}


class CollectorManager:
    """Manage multiple collectors and feed events into a shared queue.

    The manager runs each collector as an independent async task and
    forwards all events into a single ``asyncio.Queue`` for downstream
    processing (normalization, detection, storage).
    """

    def __init__(self, queue: asyncio.Queue[Event] | None = None) -> None:
        self.queue: asyncio.Queue[Event] = queue or asyncio.Queue()
        self._collectors: list[BaseCollector] = []
        self._tasks: list[asyncio.Task[None]] = []

    def add_collector(self, collector: BaseCollector) -> None:
        """Register a collector instance."""
        self._collectors.append(collector)

    @classmethod
    def from_config(
        cls,
        collectors_cfg: list[dict[str, Any]],
        queue: asyncio.Queue[Event] | None = None,
    ) -> CollectorManager:
        """Create a CollectorManager from a list of collector configurations.

        Each config dict should have at least a ``type`` key matching
        a registered collector type.  Remaining keys are passed as kwargs.
        """
        manager = cls(queue=queue)
        for cfg in collectors_cfg:
            cfg = dict(cfg)  # shallow copy
            ctype = cfg.pop("type", None)
            if ctype is None:
                logger.warning("Collector config missing 'type', skipping: %s", cfg)
                continue

            collector_cls = COLLECTOR_TYPES.get(ctype)
            if collector_cls is None:
                logger.warning("Unknown collector type '%s', skipping", ctype)
                continue

            try:
                collector = collector_cls(**cfg)
                manager.add_collector(collector)
                logger.info("Registered collector: %s (%s)", collector.name, ctype)
            except Exception:
                logger.exception("Failed to create collector '%s'", ctype)

        return manager

    async def _run_collector(self, collector: BaseCollector) -> None:
        """Run a single collector and feed events into the queue."""
        try:
            async for event in collector.collect():
                await self.queue.put(event)
        except FileNotFoundError as exc:
            logger.error("Collector '%s' failed: %s", collector.name, exc)
        except asyncio.CancelledError:
            logger.info("Collector '%s' cancelled", collector.name)
        except Exception:
            logger.exception("Collector '%s' crashed", collector.name)
        finally:
            await collector.stop()

    async def start(self) -> None:
        """Start all collectors as concurrent async tasks."""
        for collector in self._collectors:
            task = asyncio.create_task(
                self._run_collector(collector),
                name=f"collector-{collector.name}",
            )
            self._tasks.append(task)
            logger.info("Started collector: %s", collector.name)

    async def stop(self) -> None:
        """Stop all collectors and cancel their tasks."""
        for collector in self._collectors:
            await collector.stop()

        for task in self._tasks:
            task.cancel()

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    @property
    def collector_names(self) -> list[str]:
        """Return names of all registered collectors."""
        return [c.name for c in self._collectors]

    @property
    def collector_count(self) -> int:
        return len(self._collectors)

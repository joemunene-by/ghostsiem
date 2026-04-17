"""Alert manager with deduplication and handler dispatch."""

from __future__ import annotations

import logging
import time
from typing import Any

from ghostsiem._types import Alert
from ghostsiem.alerts.handlers import (
    BaseAlertHandler,
    ConsoleHandler,
    FileHandler,
    WebhookHandler,
)

logger = logging.getLogger(__name__)


class AlertManager:
    """Manage alert dispatch with deduplication.

    Alerts are deduplicated based on (rule_id, event.source, event.hostname).
    Identical alerts within the dedup window are suppressed.
    """

    def __init__(self, dedup_window: int = 300) -> None:
        """Initialize the alert manager.

        Args:
            dedup_window: Seconds to suppress duplicate alerts (default 5 min).
        """
        self._handlers: list[BaseAlertHandler] = []
        self._dedup_window = dedup_window
        # dedup_key -> last_seen_timestamp
        self._seen: dict[str, float] = {}
        self._total_alerts = 0
        self._suppressed_alerts = 0

    def add_handler(self, handler: BaseAlertHandler) -> None:
        """Register an alert handler."""
        self._handlers.append(handler)

    @classmethod
    def from_config(
        cls,
        handlers_cfg: list[dict[str, Any]],
        dedup_window: int = 300,
    ) -> AlertManager:
        """Create an AlertManager from configuration.

        Args:
            handlers_cfg: List of handler config dicts with 'type' key.
            dedup_window: Dedup window in seconds.
        """
        manager = cls(dedup_window=dedup_window)

        for cfg in handlers_cfg:
            cfg = dict(cfg)
            handler_type = cfg.pop("type", None)

            if handler_type == "console":
                manager.add_handler(ConsoleHandler())
            elif handler_type == "file":
                path = cfg.get("path", "alerts.jsonl")
                manager.add_handler(FileHandler(path=path))
            elif handler_type == "webhook":
                url = cfg.get("url", "")
                if url:
                    headers = cfg.get("headers")
                    manager.add_handler(WebhookHandler(url=url, headers=headers))
                else:
                    logger.warning("Webhook handler missing 'url', skipping")
            else:
                logger.warning("Unknown alert handler type: %s", handler_type)

        return manager

    def _dedup_key(self, alert: Alert) -> str:
        """Generate a deduplication key for an alert."""
        return f"{alert.rule_id}:{alert.event.source}:{alert.event.hostname}"

    def _is_duplicate(self, alert: Alert) -> bool:
        """Check if an alert is a duplicate within the dedup window."""
        key = self._dedup_key(alert)
        now = time.time()

        # Clean expired entries
        expired = [k for k, ts in self._seen.items() if now - ts > self._dedup_window]
        for k in expired:
            del self._seen[k]

        if key in self._seen:
            self._suppressed_alerts += 1
            return True

        self._seen[key] = now
        return False

    async def dispatch(self, alert: Alert) -> bool:
        """Dispatch an alert to all registered handlers.

        Returns:
            True if the alert was dispatched, False if suppressed as duplicate.
        """
        if self._is_duplicate(alert):
            logger.debug("Suppressed duplicate alert: %s", alert.rule_name)
            return False

        self._total_alerts += 1

        for handler in self._handlers:
            try:
                await handler.handle(alert)
            except Exception:
                logger.exception(
                    "Handler %s failed for alert %s",
                    type(handler).__name__,
                    alert.id,
                )

        return True

    @property
    def stats(self) -> dict[str, int]:
        """Return alert dispatch statistics."""
        return {
            "total_dispatched": self._total_alerts,
            "total_suppressed": self._suppressed_alerts,
            "active_handlers": len(self._handlers),
        }

"""JSON file collector for newline-delimited JSON logs."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghostsiem._types import Event, Severity
from ghostsiem.collectors.base import BaseCollector


class JSONFileCollector(BaseCollector):
    """Collect events from newline-delimited JSON log files.

    Supports configurable field mapping to translate arbitrary JSON
    fields to the standard Event structure.
    """

    # Default field mapping: JSON key -> Event attribute
    DEFAULT_FIELD_MAP: dict[str, str] = {
        "timestamp": "timestamp",
        "time": "timestamp",
        "@timestamp": "timestamp",
        "host": "hostname",
        "hostname": "hostname",
        "source": "source",
        "level": "severity",
        "severity": "severity",
        "msg": "message",
        "message": "message",
    }

    def __init__(
        self,
        path: str | Path,
        name: str = "json",
        field_map: dict[str, str] | None = None,
        poll_interval: float = 1.0,
        **kwargs: object,
    ) -> None:
        super().__init__(name=name, **kwargs)
        self.path = Path(path)
        self.field_map = field_map or self.DEFAULT_FIELD_MAP
        self.poll_interval = poll_interval

    async def collect(self) -> AsyncIterator[Event]:
        """Tail the JSON log file and yield parsed events."""
        await self.start()

        if not self.path.exists():
            raise FileNotFoundError(f"Log file not found: {self.path}")

        with open(self.path) as fh:
            fh.seek(0, 2)

            while self._running:
                line = fh.readline()
                if not line:
                    await asyncio.sleep(self.poll_interval)
                    continue

                line = line.strip()
                if not line:
                    continue

                event = self._parse_line(line)
                if event is not None:
                    yield event

    def _parse_line(self, line: str) -> Event | None:
        """Parse a JSON line into an Event."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        if not isinstance(data, dict):
            return None

        mapped = self._map_fields(data)

        # Parse timestamp
        ts_raw = mapped.get("timestamp")
        timestamp = self._parse_timestamp(ts_raw)

        # Severity
        sev_raw = mapped.get("severity", "low")
        severity = Severity.from_string(str(sev_raw)) if sev_raw else Severity.LOW

        return Event(
            timestamp=timestamp,
            source=mapped.get("source", self.name),
            hostname=mapped.get("hostname", "unknown"),
            severity=severity,
            message=mapped.get("message", json.dumps(data)),
            raw=line,
            parsed_fields=data,
        )

    def _map_fields(self, data: dict[str, Any]) -> dict[str, Any]:
        """Map JSON fields to standard event fields using the field map."""
        result: dict[str, Any] = {}
        for json_key, event_field in self.field_map.items():
            if json_key in data and event_field not in result:
                result[event_field] = data[json_key]
        return result

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        """Parse various timestamp formats."""
        if value is None:
            return datetime.now(timezone.utc)

        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)

        if isinstance(value, str):
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
            ):
                try:
                    dt = datetime.strptime(value, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except ValueError:
                    continue

            # Try fromisoformat as a fallback
            try:
                dt = datetime.fromisoformat(value)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                pass

        return datetime.now(timezone.utc)

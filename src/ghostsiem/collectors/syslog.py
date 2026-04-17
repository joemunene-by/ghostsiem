"""Syslog file collector."""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path

from ghostsiem._types import Event, Severity
from ghostsiem.collectors.base import BaseCollector

# Standard syslog line format:
# Apr 10 12:34:56 hostname process[pid]: message
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)


def _parse_syslog_timestamp(ts_str: str) -> datetime:
    """Parse syslog timestamp into datetime, assuming current year."""
    now = datetime.now(timezone.utc)
    try:
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        return dt.replace(year=now.year, tzinfo=timezone.utc)
    except ValueError:
        return now


def _classify_severity(message: str) -> Severity:
    """Heuristic severity classification from message content."""
    lower = message.lower()
    if any(kw in lower for kw in ("error", "fail", "denied", "critical", "panic")):
        return Severity.HIGH
    if any(kw in lower for kw in ("warn", "timeout", "refused", "invalid")):
        return Severity.MEDIUM
    return Severity.LOW


class SyslogCollector(BaseCollector):
    """Collect events from /var/log/syslog or compatible log files.

    Supports file tailing: seeks to end on start, then follows new lines.
    """

    def __init__(
        self,
        path: str | Path = "/var/log/syslog",
        name: str = "syslog",
        poll_interval: float = 1.0,
        **kwargs: object,
    ) -> None:
        super().__init__(name=name, **kwargs)
        self.path = Path(path)
        self.poll_interval = poll_interval

    async def collect(self) -> AsyncIterator[Event]:
        """Tail the syslog file and yield parsed events."""
        await self.start()

        if not self.path.exists():
            raise FileNotFoundError(f"Log file not found: {self.path}")

        with open(self.path) as fh:
            # Seek to end to only get new lines
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
        """Parse a single syslog line into an Event."""
        match = _SYSLOG_RE.match(line)
        if not match:
            return None

        groups = match.groupdict()
        timestamp = _parse_syslog_timestamp(groups["timestamp"])
        message = groups["message"]

        parsed_fields: dict[str, object] = {
            "process": groups["process"],
        }
        if groups.get("pid"):
            parsed_fields["pid"] = groups["pid"]

        return Event(
            timestamp=timestamp,
            source=self.name,
            hostname=groups["hostname"],
            severity=_classify_severity(message),
            message=message,
            raw=line,
            parsed_fields=parsed_fields,
        )

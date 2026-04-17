"""SQLite-based event and alert storage with async support."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import aiosqlite

from ghostsiem._types import Alert, Event

logger = logging.getLogger(__name__)

_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT 'unknown',
    severity TEXT NOT NULL DEFAULT 'low',
    message TEXT NOT NULL,
    raw_json TEXT,
    parsed_json TEXT
)
"""

_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'low',
    event_id TEXT,
    timestamp TEXT NOT NULL,
    description TEXT,
    FOREIGN KEY (event_id) REFERENCES events (id)
)
"""

_EVENTS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity)",
    "CREATE INDEX IF NOT EXISTS idx_events_source ON events (source)",
    "CREATE INDEX IF NOT EXISTS idx_events_hostname ON events (hostname)",
]

_ALERTS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts (rule_id)",
]


class EventStore:
    """Async SQLite storage for events and alerts.

    Uses WAL mode for concurrent read/write access.
    """

    def __init__(self, db_path: str | Path = "ghostsiem.db") -> None:
        self.db_path = str(db_path)
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Open the database connection and create tables."""
        self._db = await aiosqlite.connect(self.db_path)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute(_EVENTS_TABLE)
        await self._db.execute(_ALERTS_TABLE)
        for idx in _EVENTS_INDEXES + _ALERTS_INDEXES:
            await self._db.execute(idx)
        await self._db.commit()
        logger.info("Database initialized at %s", self.db_path)

    async def close(self) -> None:
        """Close the database connection."""
        if self._db:
            await self._db.close()
            self._db = None

    async def _ensure_db(self) -> aiosqlite.Connection:
        """Ensure the database is initialized."""
        if self._db is None:
            await self.initialize()
        assert self._db is not None
        return self._db

    async def store_event(self, event: Event) -> None:
        """Store a single event."""
        db = await self._ensure_db()
        await db.execute(
            """INSERT OR IGNORE INTO events
               (id, timestamp, source, hostname, severity, message, raw_json, parsed_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.id,
                event.timestamp.isoformat(),
                event.source,
                event.hostname,
                event.severity.value,
                event.message,
                event.raw,
                json.dumps(event.parsed_fields),
            ),
        )
        await db.commit()

    async def store_alert(self, alert: Alert) -> None:
        """Store a single alert."""
        db = await self._ensure_db()
        await db.execute(
            """INSERT OR IGNORE INTO alerts
               (id, rule_id, rule_name, severity, event_id, timestamp, description)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.id,
                alert.rule_id,
                alert.rule_name,
                alert.severity.value,
                alert.event.id,
                alert.timestamp.isoformat(),
                alert.description,
            ),
        )
        await db.commit()

    async def query_events(
        self,
        severity: str | None = None,
        source: str | None = None,
        hostname: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query events with optional filters.

        Args:
            severity: Filter by severity level.
            source: Filter by event source.
            hostname: Filter by hostname.
            start_time: ISO format start time (inclusive).
            end_time: ISO format end time (inclusive).
            limit: Maximum number of results.
            offset: Pagination offset.

        Returns:
            List of event dictionaries.
        """
        db = await self._ensure_db()
        conditions: list[str] = []
        params: list[Any] = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if source:
            conditions.append("source = ?")
            params.append(source)
        if hostname:
            conditions.append("hostname = ?")
            params.append(hostname)
        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with db.execute(query, params) as cursor:
            columns = [desc[0] for desc in cursor.description]
            rows = await cursor.fetchall()

        results = []
        for row in rows:
            d = dict(zip(columns, row, strict=True))
            if d.get("parsed_json"):
                d["parsed_fields"] = json.loads(d.pop("parsed_json"))
            else:
                d.pop("parsed_json", None)
                d["parsed_fields"] = {}
            results.append(d)

        return results

    async def query_alerts(
        self,
        severity: str | None = None,
        rule_id: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query alerts with optional filters."""
        db = await self._ensure_db()
        conditions: list[str] = []
        params: list[Any] = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if rule_id:
            conditions.append("rule_id = ?")
            params.append(rule_id)
        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with db.execute(query, params) as cursor:
            columns = [desc[0] for desc in cursor.description]
            rows = await cursor.fetchall()

        return [dict(zip(columns, row, strict=True)) for row in rows]

    async def stats(self) -> dict[str, Any]:
        """Return summary statistics for events and alerts."""
        db = await self._ensure_db()

        # Total counts
        async with db.execute("SELECT COUNT(*) FROM events") as cursor:
            event_count = (await cursor.fetchone())[0]

        async with db.execute("SELECT COUNT(*) FROM alerts") as cursor:
            alert_count = (await cursor.fetchone())[0]

        # Events by severity
        async with db.execute(
            "SELECT severity, COUNT(*) FROM events GROUP BY severity"
        ) as cursor:
            events_by_severity = dict(await cursor.fetchall())

        # Alerts by severity
        async with db.execute(
            "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
        ) as cursor:
            alerts_by_severity = dict(await cursor.fetchall())

        # Top rules
        async with db.execute(
            "SELECT rule_name, COUNT(*) as cnt FROM alerts "
            "GROUP BY rule_name ORDER BY cnt DESC LIMIT 10"
        ) as cursor:
            top_rules = [
                {"rule": row[0], "count": row[1]} for row in await cursor.fetchall()
            ]

        # Events per hour (last 24h)
        async with db.execute(
            """SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour, COUNT(*)
               FROM events
               WHERE timestamp >= datetime('now', '-24 hours')
               GROUP BY hour ORDER BY hour"""
        ) as cursor:
            events_per_hour = [
                {"hour": row[0], "count": row[1]} for row in await cursor.fetchall()
            ]

        return {
            "total_events": event_count,
            "total_alerts": alert_count,
            "events_by_severity": events_by_severity,
            "alerts_by_severity": alerts_by_severity,
            "top_rules": top_rules,
            "events_per_hour": events_per_hour,
        }

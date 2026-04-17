"""Tests for the event store."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ghostsiem._types import Alert, Event, Severity
from ghostsiem.storage.store import EventStore


@pytest.mark.asyncio
class TestEventStore:
    """Test suite for async SQLite event/alert storage."""

    async def test_store_and_query_event(self, temp_store: EventStore) -> None:
        """Store an event and retrieve it."""
        event = Event(
            timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="auth",
            hostname="server01",
            severity=Severity.HIGH,
            message="Failed password for root from 1.2.3.4 port 22 ssh2",
            raw=(
                "Apr 15 10:00:00 server01 sshd[1]: "
                "Failed password for root from 1.2.3.4 port 22 ssh2"
            ),
            parsed_fields={"user": "root", "src_ip": "1.2.3.4"},
        )

        await temp_store.store_event(event)
        results = await temp_store.query_events()

        assert len(results) == 1
        assert results[0]["id"] == event.id
        assert results[0]["source"] == "auth"
        assert results[0]["hostname"] == "server01"
        assert results[0]["severity"] == "high"

    async def test_store_and_query_alert(self, temp_store: EventStore) -> None:
        """Store an alert and retrieve it."""
        event = Event(
            timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="auth",
            hostname="server01",
            severity=Severity.HIGH,
            message="test event",
            raw="test event",
        )
        await temp_store.store_event(event)

        alert = Alert(
            rule_id="test-rule-1",
            rule_name="Test Rule",
            severity=Severity.HIGH,
            event=event,
            timestamp=datetime(2026, 4, 15, 10, 0, 1, tzinfo=timezone.utc),
            description="Test alert",
        )
        await temp_store.store_alert(alert)

        results = await temp_store.query_alerts()
        assert len(results) == 1
        assert results[0]["rule_name"] == "Test Rule"
        assert results[0]["severity"] == "high"

    async def test_query_events_by_severity(self, temp_store: EventStore) -> None:
        """Filter events by severity."""
        for sev in (Severity.LOW, Severity.MEDIUM, Severity.HIGH):
            event = Event(
                timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
                source="test",
                hostname="server01",
                severity=sev,
                message=f"Event with severity {sev.value}",
                raw=f"Event with severity {sev.value}",
            )
            await temp_store.store_event(event)

        high_events = await temp_store.query_events(severity="high")
        assert len(high_events) == 1
        assert high_events[0]["severity"] == "high"

    async def test_query_events_by_source(self, temp_store: EventStore) -> None:
        """Filter events by source."""
        for src in ("auth", "syslog", "auth"):
            event = Event(
                timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
                source=src,
                hostname="server01",
                severity=Severity.LOW,
                message=f"Event from {src}",
                raw=f"Event from {src}",
            )
            await temp_store.store_event(event)

        auth_events = await temp_store.query_events(source="auth")
        assert len(auth_events) == 2

    async def test_query_events_pagination(self, temp_store: EventStore) -> None:
        """Test pagination with limit and offset."""
        for i in range(10):
            event = Event(
                timestamp=datetime(2026, 4, 15, 10, i, 0, tzinfo=timezone.utc),
                source="test",
                hostname="server01",
                severity=Severity.LOW,
                message=f"Event {i}",
                raw=f"Event {i}",
            )
            await temp_store.store_event(event)

        page1 = await temp_store.query_events(limit=3, offset=0)
        page2 = await temp_store.query_events(limit=3, offset=3)

        assert len(page1) == 3
        assert len(page2) == 3
        assert page1[0]["id"] != page2[0]["id"]

    async def test_stats(self, temp_store: EventStore) -> None:
        """Test statistics retrieval."""
        for sev in (Severity.LOW, Severity.HIGH, Severity.HIGH):
            event = Event(
                timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
                source="test",
                hostname="server01",
                severity=sev,
                message="test",
                raw="test",
            )
            await temp_store.store_event(event)

        stats = await temp_store.stats()
        assert stats["total_events"] == 3
        assert stats["total_alerts"] == 0

    async def test_duplicate_event_ignored(self, temp_store: EventStore) -> None:
        """Storing the same event twice should not create duplicates."""
        event = Event(
            id="fixed-id-123",
            timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="test",
            hostname="server01",
            severity=Severity.LOW,
            message="test event",
            raw="test event",
        )

        await temp_store.store_event(event)
        await temp_store.store_event(event)

        results = await temp_store.query_events()
        assert len(results) == 1

"""API route definitions for GhostSIEM."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Query

from ghostsiem.storage.store import EventStore

router = APIRouter()

# Global store reference, set by the app factory
_store: EventStore | None = None


def set_store(store: EventStore) -> None:
    """Set the global event store for routes."""
    global _store
    _store = store


def _get_store() -> EventStore:
    """Get the event store or raise an error."""
    if _store is None:
        raise RuntimeError("Event store not initialized")
    return _store


@router.get("/health")
async def health() -> dict[str, Any]:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "ghostsiem",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/events")
async def list_events(
    severity: str | None = Query(
        None, description="Filter by severity (low, medium, high, critical)"
    ),
    source: str | None = Query(None, description="Filter by event source"),
    hostname: str | None = Query(None, description="Filter by hostname"),
    start_time: str | None = Query(None, description="Start time (ISO format)"),
    end_time: str | None = Query(None, description="End time (ISO format)"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> dict[str, Any]:
    """Query events with optional filters and pagination."""
    store = _get_store()
    events = await store.query_events(
        severity=severity,
        source=source,
        hostname=hostname,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )
    return {
        "count": len(events),
        "limit": limit,
        "offset": offset,
        "events": events,
    }


@router.get("/alerts")
async def list_alerts(
    severity: str | None = Query(None, description="Filter by severity"),
    rule_id: str | None = Query(None, description="Filter by rule ID"),
    start_time: str | None = Query(None, description="Start time (ISO format)"),
    end_time: str | None = Query(None, description="End time (ISO format)"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> dict[str, Any]:
    """Query alerts with optional filters and pagination."""
    store = _get_store()
    alerts = await store.query_alerts(
        severity=severity,
        rule_id=rule_id,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )
    return {
        "count": len(alerts),
        "limit": limit,
        "offset": offset,
        "alerts": alerts,
    }


@router.get("/stats")
async def get_stats() -> dict[str, Any]:
    """Get summary statistics for events and alerts."""
    store = _get_store()
    return await store.stats()

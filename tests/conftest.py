"""Shared test fixtures for GhostSIEM tests."""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio

from ghostsiem._types import Event, Severity
from ghostsiem.detection.builtin_rules import load_builtin_rules
from ghostsiem.detection.engine import DetectionEngine
from ghostsiem.storage.store import EventStore


@pytest.fixture
def sample_failed_ssh_event() -> Event:
    """Event representing a failed SSH login."""
    return Event(
        timestamp=datetime(2026, 4, 15, 10, 30, 0, tzinfo=timezone.utc),
        source="auth",
        hostname="webserver01",
        severity=Severity.HIGH,
        message="Failed password for invalid user admin from 203.0.113.50 port 22 ssh2",
        raw=(
            "Apr 15 10:30:00 webserver01 sshd[12345]: "
            "Failed password for invalid user admin from 203.0.113.50 port 22 ssh2"
        ),
        parsed_fields={
            "process": "sshd",
            "pid": "12345",
            "event_type": "ssh_failed",
            "user": "admin",
            "src_ip": "203.0.113.50",
            "port": "22",
        },
    )


@pytest.fixture
def sample_accepted_ssh_event() -> Event:
    """Event representing a successful SSH login."""
    return Event(
        timestamp=datetime(2026, 4, 15, 10, 31, 0, tzinfo=timezone.utc),
        source="auth",
        hostname="webserver01",
        severity=Severity.MEDIUM,
        message="Accepted publickey for deploy from 10.0.1.5 port 54321 ssh2",
        raw=(
            "Apr 15 10:31:00 webserver01 sshd[12346]: "
            "Accepted publickey for deploy from 10.0.1.5 port 54321 ssh2"
        ),
        parsed_fields={
            "process": "sshd",
            "pid": "12346",
            "event_type": "ssh_accepted",
            "user": "deploy",
            "src_ip": "10.0.1.5",
            "port": "54321",
        },
    )


@pytest.fixture
def sample_sudo_event() -> Event:
    """Event representing a sudo command execution."""
    return Event(
        timestamp=datetime(2026, 4, 15, 10, 32, 0, tzinfo=timezone.utc),
        source="auth",
        hostname="webserver01",
        severity=Severity.MEDIUM,
        message="joe : TTY=pts/0 ; PWD=/home/joe ; USER=root ; COMMAND=/usr/bin/apt update",
        raw=(
            "Apr 15 10:32:00 webserver01 sudo[12347]: "
            "joe : TTY=pts/0 ; PWD=/home/joe ; USER=root ; COMMAND=/usr/bin/apt update"
        ),
        parsed_fields={
            "process": "sudo",
            "pid": "12347",
            "event_type": "sudo",
            "user": "joe",
            "target_user": "root",
            "command": "/usr/bin/apt update",
        },
    )


@pytest.fixture
def sample_useradd_event() -> Event:
    """Event representing a new user creation."""
    return Event(
        timestamp=datetime(2026, 4, 15, 10, 33, 0, tzinfo=timezone.utc),
        source="auth",
        hostname="webserver01",
        severity=Severity.HIGH,
        message="new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor",
        raw=(
            "Apr 15 10:33:00 webserver01 useradd[12348]: "
            "new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor"
        ),
        parsed_fields={
            "process": "useradd",
            "pid": "12348",
            "event_type": "user_created",
            "user": "backdoor",
        },
    )


@pytest.fixture
def sample_clean_event() -> Event:
    """A benign event that should not trigger any alerts."""
    return Event(
        timestamp=datetime(2026, 4, 15, 10, 34, 0, tzinfo=timezone.utc),
        source="syslog",
        hostname="webserver01",
        severity=Severity.LOW,
        message="logrotate: rotating /var/log/syslog",
        raw="Apr 15 10:34:00 webserver01 logrotate[12349]: logrotate: rotating /var/log/syslog",
        parsed_fields={"process": "logrotate"},
    )


@pytest.fixture
def sample_firewall_event() -> Event:
    """Event representing a firewall rule change."""
    return Event(
        timestamp=datetime(2026, 4, 15, 10, 35, 0, tzinfo=timezone.utc),
        source="syslog",
        hostname="firewall01",
        severity=Severity.HIGH,
        message="iptables -A INPUT -p tcp --dport 4444 -j ACCEPT",
        raw=(
            "Apr 15 10:35:00 firewall01 root[12350]: "
            "iptables -A INPUT -p tcp --dport 4444 -j ACCEPT"
        ),
        parsed_fields={"process": "root"},
    )


@pytest.fixture
def sample_service_event() -> Event:
    """Event representing a service state change."""
    return Event(
        timestamp=datetime(2026, 4, 15, 10, 36, 0, tzinfo=timezone.utc),
        source="syslog",
        hostname="webserver01",
        severity=Severity.LOW,
        message="Started nginx.service - A high performance web server",
        raw=(
            "Apr 15 10:36:00 webserver01 systemd[1]: "
            "Started nginx.service - A high performance web server"
        ),
        parsed_fields={"process": "systemd"},
    )


@pytest.fixture
def detection_engine() -> DetectionEngine:
    """Detection engine loaded with built-in rules."""
    engine = DetectionEngine()
    engine.add_rules(load_builtin_rules())
    return engine


@pytest_asyncio.fixture
async def temp_store() -> EventStore:
    """Temporary event store using an in-memory-like temp file."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = EventStore(db_path=db_path)
    await store.initialize()
    yield store
    await store.close()

    # Clean up
    for suffix in ("", "-wal", "-shm"):
        p = Path(db_path + suffix)
        if p.exists():
            p.unlink()

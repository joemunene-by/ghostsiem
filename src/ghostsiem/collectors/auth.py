"""Auth log collector for SSH, sudo, and user management events."""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path

from ghostsiem._types import Event, Severity
from ghostsiem.collectors.base import BaseCollector

# Standard auth.log line format (same as syslog)
_AUTH_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

# Specific auth patterns
_FAILED_SSH_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED_SSH_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)"
)
_SUDO_RE = re.compile(
    r"(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)"
)
_USERADD_RE = re.compile(
    r"new user: name=(?P<user>\S+),.*"
)
_USERDEL_RE = re.compile(
    r"delete user '(?P<user>\S+)'"
)


def _parse_auth_timestamp(ts_str: str) -> datetime:
    """Parse auth.log timestamp into datetime."""
    now = datetime.now(timezone.utc)
    try:
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        return dt.replace(year=now.year, tzinfo=timezone.utc)
    except ValueError:
        return now


class AuthLogCollector(BaseCollector):
    """Collect and parse events from /var/log/auth.log.

    Detects:
    - Failed/successful SSH logins
    - Sudo command execution
    - User creation and deletion
    """

    def __init__(
        self,
        path: str | Path = "/var/log/auth.log",
        name: str = "auth",
        poll_interval: float = 1.0,
        **kwargs: object,
    ) -> None:
        super().__init__(name=name, **kwargs)
        self.path = Path(path)
        self.poll_interval = poll_interval

    async def collect(self) -> AsyncIterator[Event]:
        """Tail auth.log and yield parsed events."""
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

                event = self.parse_line(line)
                if event is not None:
                    yield event

    def parse_line(self, line: str) -> Event | None:
        """Parse a single auth.log line into an Event.

        Enriches the event with specific parsed fields for SSH, sudo,
        and user management operations.
        """
        match = _AUTH_RE.match(line)
        if not match:
            return None

        groups = match.groupdict()
        timestamp = _parse_auth_timestamp(groups["timestamp"])
        message = groups["message"]
        parsed_fields: dict[str, object] = {
            "process": groups["process"],
        }
        if groups.get("pid"):
            parsed_fields["pid"] = groups["pid"]

        severity = Severity.LOW

        # Failed SSH login
        ssh_fail = _FAILED_SSH_RE.search(message)
        if ssh_fail:
            severity = Severity.HIGH
            parsed_fields["event_type"] = "ssh_failed"
            parsed_fields["user"] = ssh_fail.group("user")
            parsed_fields["src_ip"] = ssh_fail.group("src_ip")
            parsed_fields["port"] = ssh_fail.group("port")

        # Successful SSH login
        ssh_ok = _ACCEPTED_SSH_RE.search(message)
        if ssh_ok:
            severity = Severity.MEDIUM
            parsed_fields["event_type"] = "ssh_accepted"
            parsed_fields["user"] = ssh_ok.group("user")
            parsed_fields["src_ip"] = ssh_ok.group("src_ip")
            parsed_fields["port"] = ssh_ok.group("port")

        # Sudo
        sudo_match = _SUDO_RE.search(message)
        if sudo_match:
            severity = Severity.MEDIUM
            parsed_fields["event_type"] = "sudo"
            parsed_fields["user"] = sudo_match.group("user")
            parsed_fields["target_user"] = sudo_match.group("target_user")
            parsed_fields["command"] = sudo_match.group("command")
            parsed_fields["pwd"] = sudo_match.group("pwd")

        # User creation
        useradd = _USERADD_RE.search(message)
        if useradd:
            severity = Severity.HIGH
            parsed_fields["event_type"] = "user_created"
            parsed_fields["user"] = useradd.group("user")

        # User deletion
        userdel = _USERDEL_RE.search(message)
        if userdel:
            severity = Severity.HIGH
            parsed_fields["event_type"] = "user_deleted"
            parsed_fields["user"] = userdel.group("user")

        return Event(
            timestamp=timestamp,
            source=self.name,
            hostname=groups["hostname"],
            severity=severity,
            message=message,
            raw=line,
            parsed_fields=parsed_fields,
        )

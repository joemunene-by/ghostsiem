"""Tests for the auth log collector parser."""

from __future__ import annotations

import pytest

from ghostsiem._types import Severity
from ghostsiem.collectors.auth import AuthLogCollector


class TestAuthLogCollector:
    """Test auth.log line parsing."""

    @pytest.fixture
    def collector(self) -> AuthLogCollector:
        return AuthLogCollector(path="/dev/null", name="test-auth")

    def test_parse_failed_ssh(self, collector: AuthLogCollector) -> None:
        """Parse a failed SSH login line."""
        line = (
            "Apr 15 10:30:00 webserver01 sshd[12345]: "
            "Failed password for invalid user admin from 203.0.113.50 port 22 ssh2"
        )
        event = collector.parse_line(line)

        assert event is not None
        assert event.hostname == "webserver01"
        assert event.severity == Severity.HIGH
        assert event.parsed_fields["event_type"] == "ssh_failed"
        assert event.parsed_fields["user"] == "admin"
        assert event.parsed_fields["src_ip"] == "203.0.113.50"
        assert event.parsed_fields["port"] == "22"

    def test_parse_accepted_ssh(self, collector: AuthLogCollector) -> None:
        """Parse a successful SSH login line."""
        line = (
            "Apr 15 10:31:00 webserver01 sshd[12346]: "
            "Accepted publickey for deploy from 10.0.1.5 port 54321 ssh2"
        )
        event = collector.parse_line(line)

        assert event is not None
        assert event.severity == Severity.MEDIUM
        assert event.parsed_fields["event_type"] == "ssh_accepted"
        assert event.parsed_fields["user"] == "deploy"
        assert event.parsed_fields["src_ip"] == "10.0.1.5"

    def test_parse_sudo(self, collector: AuthLogCollector) -> None:
        """Parse a sudo command line."""
        line = (
            "Apr 15 10:32:00 webserver01 sudo[12347]: "
            "joe : TTY=pts/0 ; PWD=/home/joe ; USER=root ; COMMAND=/usr/bin/apt update"
        )
        event = collector.parse_line(line)

        assert event is not None
        assert event.severity == Severity.MEDIUM
        assert event.parsed_fields["event_type"] == "sudo"
        assert event.parsed_fields["user"] == "joe"
        assert event.parsed_fields["target_user"] == "root"
        assert event.parsed_fields["command"] == "/usr/bin/apt update"

    def test_parse_useradd(self, collector: AuthLogCollector) -> None:
        """Parse a user creation line."""
        line = (
            "Apr 15 10:33:00 webserver01 useradd[12348]: "
            "new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor"
        )
        event = collector.parse_line(line)

        assert event is not None
        assert event.severity == Severity.HIGH
        assert event.parsed_fields["event_type"] == "user_created"
        assert event.parsed_fields["user"] == "backdoor"

    def test_parse_userdel(self, collector: AuthLogCollector) -> None:
        """Parse a user deletion line."""
        line = "Apr 15 10:34:00 webserver01 userdel[12349]: delete user 'olduser'"
        event = collector.parse_line(line)

        assert event is not None
        assert event.severity == Severity.HIGH
        assert event.parsed_fields["event_type"] == "user_deleted"
        assert event.parsed_fields["user"] == "olduser"

    def test_parse_failed_ssh_valid_user(self, collector: AuthLogCollector) -> None:
        """Parse failed SSH for a valid (existing) user."""
        line = (
            "Apr 15 10:35:00 webserver01 sshd[12350]: "
            "Failed password for root from 192.168.1.100 port 44123 ssh2"
        )
        event = collector.parse_line(line)

        assert event is not None
        assert event.parsed_fields["user"] == "root"
        assert event.parsed_fields["src_ip"] == "192.168.1.100"

    def test_parse_invalid_line(self, collector: AuthLogCollector) -> None:
        """Invalid lines should return None."""
        event = collector.parse_line("this is not a valid syslog line")
        assert event is None

    def test_parse_empty_line(self, collector: AuthLogCollector) -> None:
        """Empty lines should return None."""
        event = collector.parse_line("")
        assert event is None

    def test_event_source(self, collector: AuthLogCollector) -> None:
        """Events should have the collector name as their source."""
        line = "Apr 15 10:30:00 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
        event = collector.parse_line(line)
        assert event is not None
        assert event.source == "test-auth"

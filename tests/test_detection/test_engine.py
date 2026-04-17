"""Tests for the detection engine."""

from __future__ import annotations

from datetime import datetime, timezone

from ghostsiem._types import Event, Severity
from ghostsiem.detection.builtin_rules import load_builtin_rules
from ghostsiem.detection.engine import DetectionEngine
from ghostsiem.detection.sigma_loader import load_sigma_rule


class TestDetectionEngine:
    """Test suite for the SIGMA-based detection engine."""

    def test_failed_ssh_detected(
        self, detection_engine: DetectionEngine, sample_failed_ssh_event: Event
    ) -> None:
        """Failed SSH login should trigger the failed SSH rule."""
        alerts = detection_engine.evaluate(sample_failed_ssh_event)
        rule_names = [a.rule_name for a in alerts]
        assert "Failed SSH Login" in rule_names

    def test_accepted_ssh_detected(
        self, detection_engine: DetectionEngine, sample_accepted_ssh_event: Event
    ) -> None:
        """Accepted SSH login should trigger the unusual source rule."""
        alerts = detection_engine.evaluate(sample_accepted_ssh_event)
        rule_names = [a.rule_name for a in alerts]
        assert "SSH Login From Unusual Source" in rule_names

    def test_sudo_command_detected(
        self, detection_engine: DetectionEngine, sample_sudo_event: Event
    ) -> None:
        """Sudo command execution should trigger the sudo rule."""
        alerts = detection_engine.evaluate(sample_sudo_event)
        rule_names = [a.rule_name for a in alerts]
        assert "Sudo Command Executed" in rule_names

    def test_new_user_detected(
        self, detection_engine: DetectionEngine, sample_useradd_event: Event
    ) -> None:
        """User creation should trigger the new user rule."""
        alerts = detection_engine.evaluate(sample_useradd_event)
        rule_names = [a.rule_name for a in alerts]
        assert "New User Account Created" in rule_names

    def test_clean_event_no_alerts(
        self, detection_engine: DetectionEngine, sample_clean_event: Event
    ) -> None:
        """A benign logrotate event should not trigger any alerts."""
        alerts = detection_engine.evaluate(sample_clean_event)
        assert len(alerts) == 0

    def test_firewall_change_detected(
        self, detection_engine: DetectionEngine, sample_firewall_event: Event
    ) -> None:
        """Firewall rule change should trigger the firewall rule."""
        alerts = detection_engine.evaluate(sample_firewall_event)
        rule_names = [a.rule_name for a in alerts]
        assert "Firewall Rule Change Detected" in rule_names

    def test_service_change_detected(
        self, detection_engine: DetectionEngine, sample_service_event: Event
    ) -> None:
        """Service start should trigger the service state change rule."""
        alerts = detection_engine.evaluate(sample_service_event)
        rule_names = [a.rule_name for a in alerts]
        assert "Service Started or Stopped" in rule_names

    def test_multiple_rules_can_match(self, detection_engine: DetectionEngine) -> None:
        """An event can match multiple rules simultaneously."""
        # An event that contains both "useradd" and "new user"
        event = Event(
            timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="auth",
            hostname="server01",
            severity=Severity.HIGH,
            message="useradd: new user: name=testuser, UID=1002",
            raw="Apr 15 10:00:00 server01 useradd: new user: name=testuser, UID=1002",
            parsed_fields={},
        )
        alerts = detection_engine.evaluate(event)
        # Should match "New User Account Created" (useradd + new user both match)
        assert len(alerts) >= 1

    def test_filter_exclusion(self) -> None:
        """A rule with 'not filter' should exclude matching events."""
        engine = DetectionEngine()
        rule = load_sigma_rule(
            {
                "title": "Test Filter Rule",
                "detection": {
                    "selection": {"message|contains": "COMMAND="},
                    "filter": {"message|contains": "pam_unix"},
                    "condition": "selection and not filter",
                },
                "level": "medium",
            }
        )
        engine.add_rule(rule)

        # Event that matches selection but also matches filter -> should be excluded
        filtered_event = Event(
            timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="auth",
            hostname="server01",
            severity=Severity.MEDIUM,
            message="pam_unix(sudo:session): COMMAND=/bin/ls",
            raw="pam_unix(sudo:session): COMMAND=/bin/ls",
            parsed_fields={},
        )
        alerts = engine.evaluate(filtered_event)
        assert len(alerts) == 0

        # Event that matches selection but NOT the filter -> should trigger
        unfiltered_event = Event(
            timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="auth",
            hostname="server01",
            severity=Severity.MEDIUM,
            message="joe : TTY=pts/0 ; PWD=/home/joe ; USER=root ; COMMAND=/usr/bin/apt update",
            raw="joe : TTY=pts/0 ; PWD=/home/joe ; USER=root ; COMMAND=/usr/bin/apt update",
            parsed_fields={},
        )
        alerts = engine.evaluate(unfiltered_event)
        assert len(alerts) == 1

    def test_brute_force_threshold(self) -> None:
        """Brute force rule should only fire after threshold is reached."""
        engine = DetectionEngine()
        rule = load_sigma_rule(
            {
                "title": "Brute Force Test",
                "id": "bf-test",
                "detection": {
                    "selection": {"message|contains": "Failed password"},
                    "threshold": {"field": "src_ip", "value": 3},
                    "timeframe": "60s",
                    "condition": "selection",
                },
                "level": "critical",
            }
        )
        engine.add_rule(rule)

        def make_event(ip: str) -> Event:
            return Event(
                timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
                source="auth",
                hostname="server01",
                severity=Severity.HIGH,
                message=f"Failed password for root from {ip} port 22 ssh2",
                raw=f"Failed password for root from {ip} port 22 ssh2",
                parsed_fields={"src_ip": ip},
            )

        # First two from same IP -- should not trigger
        assert len(engine.evaluate(make_event("1.2.3.4"))) == 0
        assert len(engine.evaluate(make_event("1.2.3.4"))) == 0

        # Third from same IP -- should trigger (threshold=3)
        assert len(engine.evaluate(make_event("1.2.3.4"))) == 1

        # Different IP -- should not trigger yet
        assert len(engine.evaluate(make_event("5.6.7.8"))) == 0

    def test_contains_modifier(self) -> None:
        """The |contains modifier should do substring matching."""
        engine = DetectionEngine()
        rule = load_sigma_rule(
            {
                "title": "Contains Test",
                "detection": {
                    "selection": {"message|contains": "error"},
                    "condition": "selection",
                },
                "level": "low",
            }
        )
        engine.add_rule(rule)

        event = Event(
            timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="syslog",
            hostname="server01",
            severity=Severity.LOW,
            message="disk I/O error on /dev/sda1",
            raw="disk I/O error on /dev/sda1",
            parsed_fields={},
        )
        alerts = engine.evaluate(event)
        assert len(alerts) == 1

    def test_startswith_modifier(self) -> None:
        """The |startswith modifier should match the beginning of a field."""
        engine = DetectionEngine()
        rule = load_sigma_rule(
            {
                "title": "Startswith Test",
                "detection": {
                    "selection": {"message|startswith": "kernel"},
                    "condition": "selection",
                },
                "level": "low",
            }
        )
        engine.add_rule(rule)

        match_event = Event(
            timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="syslog",
            hostname="server01",
            severity=Severity.LOW,
            message="kernel: BUG at mm/page_alloc.c",
            raw="kernel: BUG at mm/page_alloc.c",
            parsed_fields={},
        )
        no_match_event = Event(
            timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="syslog",
            hostname="server01",
            severity=Severity.LOW,
            message="sshd: kernel module loaded",
            raw="sshd: kernel module loaded",
            parsed_fields={},
        )

        assert len(engine.evaluate(match_event)) == 1
        assert len(engine.evaluate(no_match_event)) == 0

    def test_regex_modifier(self) -> None:
        """The |re modifier should match using regex."""
        engine = DetectionEngine()
        rule = load_sigma_rule(
            {
                "title": "Regex Test",
                "detection": {
                    "selection": {"message|re": r"port \d{4,5}"},
                    "condition": "selection",
                },
                "level": "low",
            }
        )
        engine.add_rule(rule)

        event = Event(
            timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="auth",
            hostname="server01",
            severity=Severity.LOW,
            message="connection from 10.0.0.1 port 54321",
            raw="connection from 10.0.0.1 port 54321",
            parsed_fields={},
        )
        assert len(engine.evaluate(event)) == 1

    def test_builtin_rules_load(self) -> None:
        """All 8 built-in rules should load successfully."""
        rules = load_builtin_rules()
        assert len(rules) == 8

    def test_or_condition(self) -> None:
        """OR conditions should match if any selection matches."""
        engine = DetectionEngine()
        rule = load_sigma_rule(
            {
                "title": "OR Test",
                "detection": {
                    "selection_a": {"message|contains": "alpha"},
                    "selection_b": {"message|contains": "beta"},
                    "condition": "selection_a or selection_b",
                },
                "level": "low",
            }
        )
        engine.add_rule(rule)

        event_a = Event(
            timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="test",
            hostname="server01",
            severity=Severity.LOW,
            message="alpha event",
            raw="alpha event",
            parsed_fields={},
        )
        event_b = Event(
            timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="test",
            hostname="server01",
            severity=Severity.LOW,
            message="beta event",
            raw="beta event",
            parsed_fields={},
        )
        event_c = Event(
            timestamp=datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="test",
            hostname="server01",
            severity=Severity.LOW,
            message="gamma event",
            raw="gamma event",
            parsed_fields={},
        )

        assert len(engine.evaluate(event_a)) == 1
        assert len(engine.evaluate(event_b)) == 1
        assert len(engine.evaluate(event_c)) == 0

    def test_alert_severity_matches_rule(
        self, detection_engine: DetectionEngine, sample_failed_ssh_event: Event
    ) -> None:
        """Alert severity should match the triggering rule's severity."""
        alerts = detection_engine.evaluate(sample_failed_ssh_event)
        ssh_alerts = [a for a in alerts if a.rule_name == "Failed SSH Login"]
        assert len(ssh_alerts) >= 1
        assert ssh_alerts[0].severity == Severity.HIGH

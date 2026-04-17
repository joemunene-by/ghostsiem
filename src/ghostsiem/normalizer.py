"""Event normalizer for enriching and standardizing events."""

from __future__ import annotations

import re
from typing import Any

from ghostsiem._types import Event, Severity

# Common regex patterns for extraction
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USERNAME_RE = re.compile(
    r"(?:user[= ]|for (?:invalid user )?)(\S+)",
    re.IGNORECASE,
)
_PROCESS_RE = re.compile(r"^(\S+?)(?:\[\d+\])?:")

# Private/reserved IP ranges
_PRIVATE_RANGES = (
    ("10.", "10."),
    ("172.16.", "172.31."),
    ("192.168.", "192.168."),
    ("127.", "127."),
)


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    return any(ip.startswith(start) for start, _ in _PRIVATE_RANGES)


class EventNormalizer:
    """Enrich and normalize events into a common format.

    Performs:
    - IP address extraction from message text
    - Username extraction
    - Process name extraction
    - Severity re-classification based on content
    - GeoIP stub (marks IPs as internal/external)
    """

    def normalize(self, event: Event) -> Event:
        """Normalize and enrich a single event in place.

        Args:
            event: The event to normalize.

        Returns:
            The same event, mutated with enriched parsed_fields.
        """
        self._extract_ips(event)
        self._extract_usernames(event)
        self._extract_process(event)
        self._classify_severity(event)
        self._geoip_stub(event)
        return event

    def _extract_ips(self, event: Event) -> None:
        """Extract all IP addresses from the message."""
        ips = _IP_RE.findall(event.message)
        if ips:
            event.parsed_fields.setdefault("ip_addresses", ips)
            if "src_ip" not in event.parsed_fields:
                event.parsed_fields["src_ip"] = ips[0]

    def _extract_usernames(self, event: Event) -> None:
        """Extract usernames from the message."""
        if "user" not in event.parsed_fields:
            match = _USERNAME_RE.search(event.message)
            if match:
                event.parsed_fields["user"] = match.group(1)

    def _extract_process(self, event: Event) -> None:
        """Extract process name if not already set."""
        if "process" not in event.parsed_fields:
            match = _PROCESS_RE.match(event.message)
            if match:
                event.parsed_fields["process"] = match.group(1)

    def _classify_severity(self, event: Event) -> None:
        """Re-classify severity based on message content analysis."""
        msg = event.message.lower()

        critical_indicators = [
            "kernel panic",
            "out of memory",
            "segfault",
            "buffer overflow",
            "root compromise",
        ]
        high_indicators = [
            "failed password",
            "authentication failure",
            "permission denied",
            "unauthorized",
            "invalid user",
            "break-in attempt",
        ]
        medium_indicators = [
            "sudo",
            "session opened",
            "session closed",
            "connection refused",
            "timeout",
        ]

        if any(ind in msg for ind in critical_indicators):
            event.severity = Severity.CRITICAL
        elif any(ind in msg for ind in high_indicators):
            event.severity = Severity.HIGH
        elif any(ind in msg for ind in medium_indicators):
            event.severity = Severity.MEDIUM

    def _geoip_stub(self, event: Event) -> None:
        """Stub GeoIP enrichment -- marks IPs as internal or external."""
        ips: list[str] = event.parsed_fields.get("ip_addresses", [])
        geo_info: dict[str, Any] = {}

        for ip in ips:
            if _is_private_ip(ip):
                geo_info[ip] = {"type": "internal", "country": "N/A"}
            else:
                geo_info[ip] = {"type": "external", "country": "unknown"}

        if geo_info:
            event.parsed_fields["geo"] = geo_info

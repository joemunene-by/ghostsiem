"""Alert handlers for different output destinations."""

from __future__ import annotations

import abc
import json
import logging
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ghostsiem._types import Alert, Severity

logger = logging.getLogger(__name__)


class BaseAlertHandler(abc.ABC):
    """Abstract base class for alert handlers."""

    @abc.abstractmethod
    async def handle(self, alert: Alert) -> None:
        """Process an alert."""
        ...


class ConsoleHandler(BaseAlertHandler):
    """Print alerts to the console using Rich formatting."""

    SEVERITY_COLORS: dict[Severity, str] = {
        Severity.LOW: "blue",
        Severity.MEDIUM: "yellow",
        Severity.HIGH: "red",
        Severity.CRITICAL: "bold red on white",
    }

    def __init__(self) -> None:
        self.console = Console(stderr=True)

    async def handle(self, alert: Alert) -> None:
        """Print a formatted alert to the console."""
        color = self.SEVERITY_COLORS.get(alert.severity, "white")
        severity_text = Text(alert.severity.value.upper(), style=color)

        content = Text()
        content.append("Rule: ", style="bold")
        content.append(f"{alert.rule_name}\n")
        content.append("Severity: ", style="bold")
        content.append(severity_text)
        content.append("\n")
        content.append("Description: ", style="bold")
        content.append(f"{alert.description}\n")
        content.append("Event: ", style="bold")
        content.append(f"{alert.event.message[:200]}\n")
        content.append("Source: ", style="bold")
        content.append(f"{alert.event.source} @ {alert.event.hostname}\n")
        content.append("Time: ", style="bold")
        content.append(f"{alert.timestamp.isoformat()}")

        panel = Panel(
            content,
            title=f"[{color}]ALERT[/{color}]",
            border_style=color,
            expand=False,
        )
        self.console.print(panel)


class FileHandler(BaseAlertHandler):
    """Append alerts as JSON lines to a file."""

    def __init__(self, path: str | Path = "alerts.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    async def handle(self, alert: Alert) -> None:
        """Append a JSON-serialized alert to the file."""
        try:
            with open(self.path, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
        except OSError:
            logger.exception("Failed to write alert to %s", self.path)


class WebhookHandler(BaseAlertHandler):
    """Send alerts to a webhook URL via HTTP POST."""

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}

    async def handle(self, alert: Alert) -> None:
        """POST the alert to the configured webhook URL."""
        try:
            import httpx

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.url,
                    json=alert.to_dict(),
                    headers=self.headers,
                    timeout=10.0,
                )
                if response.status_code >= 400:
                    logger.warning(
                        "Webhook returned %d for alert %s",
                        response.status_code,
                        alert.id,
                    )
        except Exception:
            logger.exception("Failed to send alert to webhook %s", self.url)

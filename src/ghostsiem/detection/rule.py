"""Detection rule data structures."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from ghostsiem._types import Severity


@dataclass
class Rule:
    """A SIGMA-format detection rule.

    Attributes:
        id: Unique rule identifier.
        title: Human-readable rule title.
        description: Detailed description of what the rule detects.
        severity: Alert severity when the rule matches.
        detection: Detection logic containing selections, conditions, and filters.
        tags: Optional list of MITRE ATT&CK or custom tags.
        status: Rule status (experimental, testing, stable).
        author: Rule author.
        logsource: Log source specification (product, service, category).
    """

    title: str
    description: str
    severity: Severity
    detection: dict[str, Any]
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tags: list[str] = field(default_factory=list)
    status: str = "experimental"
    author: str = ""
    logsource: dict[str, str] = field(default_factory=dict)

    @property
    def selections(self) -> dict[str, Any]:
        """Return all selection blocks from the detection logic."""
        result: dict[str, Any] = {}
        for key, value in self.detection.items():
            if key.startswith("selection") and isinstance(value, dict):
                result[key] = value
        return result

    @property
    def condition(self) -> str:
        """Return the condition string from the detection logic."""
        return self.detection.get("condition", "selection")

    @property
    def filters(self) -> dict[str, Any]:
        """Return all filter blocks from the detection logic."""
        result: dict[str, Any] = {}
        for key, value in self.detection.items():
            if key.startswith("filter") and isinstance(value, dict):
                result[key] = value
        return result

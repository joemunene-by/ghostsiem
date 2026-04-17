"""SIGMA rule loader and validator."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from ghostsiem._types import Severity
from ghostsiem.detection.rule import Rule

logger = logging.getLogger(__name__)

_REQUIRED_FIELDS = {"title", "detection"}


def load_sigma_rule(source: str | Path | dict[str, Any]) -> Rule:
    """Load a single SIGMA rule from a file path, YAML string, or dict.

    Args:
        source: A file path, raw YAML string, or pre-parsed dict.

    Returns:
        A validated Rule object.

    Raises:
        ValueError: If the rule is missing required fields or is invalid.
    """
    if isinstance(source, dict):
        data = source
    elif isinstance(source, Path) or (
        isinstance(source, str)
        and "\n" not in source
        and Path(source).suffix in (".yml", ".yaml")
    ):
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"Rule file not found: {path}")
        with open(path) as f:
            data = yaml.safe_load(f)
    else:
        # Treat as YAML string
        data = yaml.safe_load(source)

    if not isinstance(data, dict):
        raise ValueError(f"SIGMA rule must be a YAML mapping, got {type(data).__name__}")

    return _validate_and_build(data)


def load_sigma_rules_from_directory(directory: str | Path) -> list[Rule]:
    """Load all SIGMA rules from a directory.

    Args:
        directory: Path to a directory containing .yml/.yaml rule files.

    Returns:
        List of validated Rule objects.
    """
    path = Path(directory)
    if not path.is_dir():
        raise NotADirectoryError(f"Rules directory not found: {path}")

    rules: list[Rule] = []
    for rule_file in sorted(path.glob("*.y*ml")):
        try:
            rule = load_sigma_rule(rule_file)
            rules.append(rule)
            logger.debug("Loaded rule: %s (%s)", rule.title, rule_file.name)
        except Exception:
            logger.exception("Failed to load rule from %s", rule_file)

    logger.info("Loaded %d rules from %s", len(rules), path)
    return rules


def _validate_and_build(data: dict[str, Any]) -> Rule:
    """Validate a parsed SIGMA rule dict and build a Rule object."""
    missing = _REQUIRED_FIELDS - set(data.keys())
    if missing:
        raise ValueError(f"SIGMA rule missing required fields: {missing}")

    detection = data["detection"]
    if not isinstance(detection, dict):
        raise ValueError("'detection' must be a mapping")

    if "condition" not in detection:
        # Default condition if not specified
        detection["condition"] = "selection"

    # Check that at least one selection exists
    has_selection = any(key.startswith("selection") for key in detection)
    if not has_selection:
        raise ValueError("Detection must contain at least one 'selection' block")

    # Parse severity
    level_str = data.get("level", data.get("severity", "low"))
    severity = Severity.from_string(str(level_str))

    # Parse logsource
    logsource = data.get("logsource", {})
    if not isinstance(logsource, dict):
        logsource = {}

    return Rule(
        id=data.get("id", ""),
        title=data["title"],
        description=data.get("description", ""),
        severity=severity,
        detection=detection,
        tags=data.get("tags", []),
        status=data.get("status", "experimental"),
        author=data.get("author", ""),
        logsource=logsource,
    )

"""Configuration management for GhostSIEM."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings


class GhostSIEMSettings(BaseSettings):
    """Application settings loaded from environment or config file."""

    model_config = {"env_prefix": "GHOSTSIEM_"}

    # Storage
    db_path: str = "ghostsiem.db"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8080

    # Alert dedup window in seconds
    alert_dedup_window: int = 300

    # Log level
    log_level: str = "INFO"

    # Rules directory
    rules_dir: str = "examples/rules"

    # Collectors
    collectors: list[dict[str, Any]] = Field(default_factory=list)

    # Alert handlers
    alert_handlers: list[dict[str, Any]] = Field(default_factory=lambda: [
        {"type": "console"},
    ])


def load_config(config_path: str | Path) -> dict[str, Any]:
    """Load configuration from a YAML file.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        Parsed configuration dictionary.

    Raises:
        FileNotFoundError: If the config file doesn't exist.
        yaml.YAMLError: If the config file is invalid YAML.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path) as f:
        config = yaml.safe_load(f)

    if not isinstance(config, dict):
        raise ValueError(f"Config file must contain a YAML mapping, got {type(config).__name__}")

    return config


def settings_from_config(config: dict[str, Any]) -> GhostSIEMSettings:
    """Create settings from a parsed config dictionary.

    Args:
        config: Parsed YAML configuration dictionary.

    Returns:
        Populated GhostSIEMSettings instance.
    """
    flat: dict[str, Any] = {}

    if "storage" in config:
        storage = config["storage"]
        if "path" in storage:
            flat["db_path"] = storage["path"]

    if "api" in config:
        api = config["api"]
        if "host" in api:
            flat["api_host"] = api["host"]
        if "port" in api:
            flat["api_port"] = api["port"]

    if "alerts" in config:
        alerts_cfg = config["alerts"]
        if "dedup_window" in alerts_cfg:
            flat["alert_dedup_window"] = alerts_cfg["dedup_window"]
        if "handlers" in alerts_cfg:
            flat["alert_handlers"] = alerts_cfg["handlers"]

    if "detection" in config:
        detection = config["detection"]
        if "rules_dir" in detection:
            flat["rules_dir"] = detection["rules_dir"]

    if "collectors" in config:
        flat["collectors"] = config["collectors"]

    if "log_level" in config:
        flat["log_level"] = config["log_level"]

    return GhostSIEMSettings(**flat)

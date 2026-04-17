"""GhostSIEM - Lightweight Security Information and Event Management."""

from ghostsiem._types import Alert, Event, Severity
from ghostsiem.alerts.manager import AlertManager
from ghostsiem.collectors.manager import CollectorManager as Collector
from ghostsiem.detection.engine import DetectionEngine

__version__ = "0.1.0"
__all__ = [
    "Alert",
    "AlertManager",
    "Collector",
    "DetectionEngine",
    "Event",
    "Severity",
]

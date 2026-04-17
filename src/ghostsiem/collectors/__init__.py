"""Log collectors for GhostSIEM."""

from ghostsiem.collectors.auth import AuthLogCollector
from ghostsiem.collectors.base import BaseCollector
from ghostsiem.collectors.jsonfile import JSONFileCollector
from ghostsiem.collectors.manager import CollectorManager
from ghostsiem.collectors.syslog import SyslogCollector

__all__ = [
    "AuthLogCollector",
    "BaseCollector",
    "CollectorManager",
    "JSONFileCollector",
    "SyslogCollector",
]

"""Detection engine for SIGMA-based rule evaluation."""

from ghostsiem.detection.engine import DetectionEngine
from ghostsiem.detection.rule import Rule
from ghostsiem.detection.sigma_loader import load_sigma_rule, load_sigma_rules_from_directory

__all__ = [
    "DetectionEngine",
    "Rule",
    "load_sigma_rule",
    "load_sigma_rules_from_directory",
]

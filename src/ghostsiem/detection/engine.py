"""Detection engine -- evaluates events against SIGMA rules."""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from typing import Any

from ghostsiem._types import Alert, Event, Severity, now_utc
from ghostsiem.detection.rule import Rule
from ghostsiem.detection.sigma_loader import load_sigma_rules_from_directory

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Evaluate events against a set of SIGMA-format detection rules.

    Supports:
    - Field exact match (field: value)
    - field|contains modifier
    - field|startswith modifier
    - field|endswith modifier
    - field|re modifier (regex)
    - AND within a selection (all field conditions must match)
    - OR across selections in conditions (selection1 or selection2)
    - AND across selections in conditions (selection1 and selection2)
    - "not filter" exclusions
    - Stateful brute force detection (threshold within time window)

    Usage::

        engine = DetectionEngine()
        engine.load_rules_from_directory("rules/")
        alerts = engine.evaluate(event)
    """

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        # State tracking for threshold-based rules: rule_id -> {key -> [timestamps]}
        self._state: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))

    @property
    def rules(self) -> list[Rule]:
        """Return all loaded rules."""
        return list(self._rules)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def add_rule(self, rule: Rule) -> None:
        """Add a single rule to the engine."""
        self._rules.append(rule)
        logger.debug("Added rule: %s", rule.title)

    def add_rules(self, rules: list[Rule]) -> None:
        """Add multiple rules to the engine."""
        self._rules.extend(rules)

    def load_rules_from_directory(self, directory: str) -> None:
        """Load all SIGMA rules from a directory."""
        rules = load_sigma_rules_from_directory(directory)
        self.add_rules(rules)

    def evaluate(self, event: Event) -> list[Alert]:
        """Evaluate a single event against all loaded rules.

        Args:
            event: The event to evaluate.

        Returns:
            List of alerts for any rules that matched.
        """
        alerts: list[Alert] = []

        for rule in self._rules:
            try:
                if self._evaluate_rule(rule, event):
                    alert = Alert(
                        rule_id=rule.id,
                        rule_name=rule.title,
                        severity=rule.severity,
                        event=event,
                        timestamp=now_utc(),
                        description=rule.description,
                    )
                    alerts.append(alert)
                    logger.info("Rule matched: %s -> %s", rule.title, event.message[:80])
            except Exception:
                logger.exception("Error evaluating rule '%s'", rule.title)

        return alerts

    def _evaluate_rule(self, rule: Rule, event: Event) -> bool:
        """Evaluate a single rule against an event."""
        detection = rule.detection
        condition = rule.condition

        # Check for threshold/timeframe (brute force rules)
        timeframe = detection.get("timeframe")
        threshold = detection.get("threshold")

        if threshold and timeframe:
            return self._evaluate_threshold_rule(rule, event, threshold, timeframe)

        # Parse and evaluate the condition
        matched = self._evaluate_condition(condition, detection, event)

        return matched

    def _evaluate_condition(
        self, condition: str, detection: dict[str, Any], event: Event
    ) -> bool:
        """Parse and evaluate a SIGMA condition string.

        Supports:
        - "selection"
        - "selection1 and selection2"
        - "selection1 or selection2"
        - "selection and not filter"
        - "all of selection*"
        - "1 of selection*"
        """
        condition = condition.strip()

        # Handle "all of selection*"
        if condition.startswith("all of "):
            pattern = condition[7:].replace("*", "")
            matching_keys = [
                k for k in detection
                if k.startswith(pattern) and isinstance(detection[k], dict)
            ]
            if not matching_keys:
                return False
            return all(
                self._match_selection(detection[k], event) for k in matching_keys
            )

        # Handle "1 of selection*" or "<N> of selection*"
        of_match = re.match(r"(\d+)\s+of\s+(\S+)", condition)
        if of_match:
            count_needed = int(of_match.group(1))
            pattern = of_match.group(2).replace("*", "")
            matching_keys = [
                k for k in detection
                if k.startswith(pattern) and isinstance(detection[k], dict)
            ]
            matched_count = sum(
                1 for k in matching_keys if self._match_selection(detection[k], event)
            )
            return matched_count >= count_needed

        # Tokenize the condition for and/or/not parsing
        tokens = condition.split()

        # Simple single selection
        if len(tokens) == 1:
            sel_name = tokens[0]
            if sel_name in detection and isinstance(detection[sel_name], dict):
                return self._match_selection(detection[sel_name], event)
            return False

        # Parse compound conditions
        return self._parse_compound_condition(tokens, detection, event)

    def _parse_compound_condition(
        self,
        tokens: list[str],
        detection: dict[str, Any],
        event: Event,
    ) -> bool:
        """Evaluate compound conditions with and/or/not operators."""
        # Build an evaluation list: [(value, negated), operator, ...]
        # We process left-to-right respecting and/or precedence
        # (AND binds tighter than OR)

        # First, group into OR-separated segments, each with AND terms
        or_groups: list[list[tuple[str, bool]]] = [[]]
        i = 0

        while i < len(tokens):
            token = tokens[i].lower()

            if token == "or":
                or_groups.append([])
                i += 1
            elif token == "and":
                i += 1
            elif token == "not":
                if i + 1 < len(tokens):
                    or_groups[-1].append((tokens[i + 1], True))
                    i += 2
                else:
                    i += 1
            else:
                or_groups[-1].append((tokens[i], False))
                i += 1

        # Evaluate: OR between groups, AND within each group
        for group in or_groups:
            group_result = True
            for sel_name, negated in group:
                if sel_name in detection and isinstance(detection[sel_name], dict):
                    match = self._match_selection(detection[sel_name], event)
                else:
                    match = False

                if negated:
                    match = not match

                if not match:
                    group_result = False
                    break

            if group_result and group:
                return True

        return False

    def _match_selection(self, selection: dict[str, Any], event: Event) -> bool:
        """Match all field conditions in a selection (AND logic).

        Supports SIGMA modifiers:
        - field: value  (exact match or substring for strings)
        - field|contains: value
        - field|startswith: value
        - field|endswith: value
        - field|re: regex_pattern
        """
        for field_spec, expected in selection.items():
            # Parse field name and modifier
            parts = field_spec.split("|")
            field_name = parts[0]
            modifier = parts[1] if len(parts) > 1 else None

            # Get the actual value from the event
            actual = self._get_event_field(event, field_name)

            if actual is None:
                return False

            # Handle list of possible values (OR within field)
            if isinstance(expected, list):
                if not any(self._match_value(str(actual), str(v), modifier) for v in expected):
                    return False
            else:
                if not self._match_value(str(actual), str(expected), modifier):
                    return False

        return True

    def _match_value(self, actual: str, expected: str, modifier: str | None) -> bool:
        """Match a single value using the specified modifier."""
        if modifier == "contains":
            return expected.lower() in actual.lower()
        elif modifier == "startswith":
            return actual.lower().startswith(expected.lower())
        elif modifier == "endswith":
            return actual.lower().endswith(expected.lower())
        elif modifier == "re":
            try:
                return bool(re.search(expected, actual, re.IGNORECASE))
            except re.error:
                logger.warning("Invalid regex in rule: %s", expected)
                return False
        else:
            # Default: case-insensitive substring match for strings
            # This aligns with how SIGMA keywords work
            return expected.lower() in actual.lower()

    def _get_event_field(self, event: Event, field_name: str) -> Any | None:
        """Retrieve a field value from an event by name.

        Checks parsed_fields first, then top-level event attributes,
        then the raw message.
        """
        # Check parsed_fields
        if field_name in event.parsed_fields:
            return event.parsed_fields[field_name]

        # Check top-level attributes
        if hasattr(event, field_name):
            value = getattr(event, field_name)
            if isinstance(value, Severity):
                return value.value
            return value

        # For 'message' or keyword-style matching, search in message
        if field_name in ("keywords", "keyword"):
            return event.message

        return None

    def _evaluate_threshold_rule(
        self,
        rule: Rule,
        event: Event,
        threshold: dict[str, Any],
        timeframe: str,
    ) -> bool:
        """Evaluate a threshold/brute-force rule with state tracking.

        The threshold block specifies:
        - field: the field to group by
        - value: the minimum count to trigger

        The timeframe specifies the window (e.g., "60s", "5m").
        """
        # First check if the selection matches
        selections = rule.selections
        if not selections:
            return False

        any_selection_matched = any(
            self._match_selection(sel, event) for sel in selections.values()
        )
        if not any_selection_matched:
            return False

        # Check filters
        filters = rule.filters
        if filters:
            for filter_block in filters.values():
                if self._match_selection(filter_block, event):
                    return False

        # Parse threshold parameters
        group_field = threshold.get("field", "src_ip")
        count_needed = int(threshold.get("value", 1))

        # Parse timeframe
        window_seconds = self._parse_timeframe(timeframe)

        # Get the group key value
        group_value = self._get_event_field(event, group_field)
        if group_value is None:
            group_value = "__unknown__"
        group_value = str(group_value)

        # Track state
        now = time.time()
        state_key = f"{rule.id}:{group_field}"
        timestamps = self._state[state_key][group_value]

        # Add current timestamp
        timestamps.append(now)

        # Prune old entries outside the window
        cutoff = now - window_seconds
        self._state[state_key][group_value] = [
            ts for ts in timestamps if ts >= cutoff
        ]

        # Check if threshold is met
        return len(self._state[state_key][group_value]) >= count_needed

    @staticmethod
    def _parse_timeframe(timeframe: str) -> float:
        """Parse a SIGMA timeframe string into seconds.

        Supports: Xs, Xm, Xh, Xd
        """
        timeframe = timeframe.strip().lower()
        if timeframe.endswith("s"):
            return float(timeframe[:-1])
        elif timeframe.endswith("m"):
            return float(timeframe[:-1]) * 60
        elif timeframe.endswith("h"):
            return float(timeframe[:-1]) * 3600
        elif timeframe.endswith("d"):
            return float(timeframe[:-1]) * 86400
        else:
            # Try plain integer as seconds
            return float(timeframe)

    def clear_state(self) -> None:
        """Clear all stateful tracking data."""
        self._state.clear()

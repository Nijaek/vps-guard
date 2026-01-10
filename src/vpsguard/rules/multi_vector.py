"""Multi-vector attack detection rule.

Detects IPs that appear across multiple log sources (e.g., SSH + nginx),
indicating a multi-service scanning or coordinated attack.
"""

from collections import defaultdict

from vpsguard.config import MultiVectorConfig
from vpsguard.models.events import AuthEvent, RuleViolation, Severity


class MultiVectorRule:
    """Detects multi-vector attacks by correlating events across log sources.

    Triggers when an IP appears in multiple log sources with significant activity,
    suggesting coordinated scanning or attack across services.
    """

    def __init__(self, config: MultiVectorConfig):
        """Initialize rule with configuration.

        Args:
            config: Multi-vector detection configuration.
        """
        self.config = config
        self.name = "multi_vector"
        self.severity = config.severity
        self.enabled = config.enabled

    def evaluate(self, events: list[AuthEvent]) -> list[RuleViolation]:
        """Evaluate events for multi-vector attack patterns.

        Args:
            events: List of authentication events from potentially multiple sources.

        Returns:
            List of violations (one per IP appearing in multiple sources).
        """
        if not self.enabled:
            return []

        violations = []

        # Group events by IP, then by source
        # ip -> source -> list of events
        events_by_ip_source: dict[str, dict[str, list[AuthEvent]]] = defaultdict(
            lambda: defaultdict(list)
        )

        for event in events:
            if event.ip and event.log_source:
                events_by_ip_source[event.ip][event.log_source].append(event)

        # Check each IP for multi-vector pattern
        for ip, sources in events_by_ip_source.items():
            # Filter to sources with enough events
            active_sources = {
                source: events
                for source, events in sources.items()
                if len(events) >= self.config.min_events_per_source
            }

            if len(active_sources) < self.config.min_sources:
                continue

            # Found multi-vector pattern - IP active in multiple sources
            source_names = list(active_sources.keys())
            all_events = []
            total_events = 0
            failed_events = 0

            for source, source_events in active_sources.items():
                all_events.extend(source_events)
                total_events += len(source_events)
                failed_events += sum(1 for e in source_events if not e.success)

            # Get the most recent timestamp
            latest_event = max(all_events, key=lambda e: e.timestamp)

            violation = RuleViolation(
                rule_name=self.name,
                severity=Severity[self.severity.upper()],
                ip=ip,
                description=(
                    f"Multi-vector attack: IP active across {len(active_sources)} log sources "
                    f"({', '.join(sorted(source_names))})"
                ),
                timestamp=latest_event.timestamp,
                details={
                    "sources": sorted(source_names),
                    "source_count": len(active_sources),
                    "total_events": total_events,
                    "failed_events": failed_events,
                    "events_per_source": {
                        source: len(events) for source, events in active_sources.items()
                    },
                },
                affected_events=all_events
            )
            violations.append(violation)

        return violations

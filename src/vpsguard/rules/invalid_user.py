"""Invalid user detection rule - username enumeration attempts."""

from collections import defaultdict
from datetime import timedelta

from vpsguard.config import InvalidUserConfig
from vpsguard.models.events import AuthEvent, EventType, RuleViolation, Severity


class InvalidUserRule:
    """Detects username enumeration via invalid user attempts."""

    def __init__(self, config: InvalidUserConfig):
        """Initialize rule with configuration.

        Args:
            config: Invalid user detection configuration.
        """
        self.config = config
        self.name = "invalid_user"
        self.severity = config.severity
        self.enabled = config.enabled

    def evaluate(self, events: list[AuthEvent]) -> list[RuleViolation]:
        """Evaluate events for invalid user patterns.

        Detects IPs attempting to log in with many invalid usernames,
        which indicates username enumeration/scanning.

        Args:
            events: List of authentication events.

        Returns:
            List of violations (one per IP exceeding threshold).
        """
        if not self.enabled:
            return []

        violations = []

        # Group invalid user events by IP
        invalid_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
        for event in events:
            if event.event_type == EventType.INVALID_USER and event.ip:
                invalid_by_ip[event.ip].append(event)

        # Check each IP for enumeration pattern
        for ip, invalid_events in invalid_by_ip.items():
            if len(invalid_events) < self.config.threshold:
                continue

            # Sort events by timestamp
            sorted_events = sorted(invalid_events, key=lambda e: e.timestamp)

            # Check for threshold attempts within time window
            window = timedelta(minutes=self.config.window_minutes)

            for i in range(len(sorted_events) - self.config.threshold + 1):
                window_events = []
                start_time = sorted_events[i].timestamp

                for event in sorted_events[i:]:
                    if event.timestamp <= start_time + window:
                        window_events.append(event)
                    else:
                        break

                if len(window_events) >= self.config.threshold:
                    # Found enumeration pattern
                    usernames_tried = set(e.username for e in window_events if e.username)

                    violation = RuleViolation(
                        rule_name=self.name,
                        severity=Severity[self.severity.upper()],
                        ip=ip,
                        description=(
                            f"Username enumeration detected: {len(window_events)} invalid user attempts "
                            f"in {self.config.window_minutes} minutes (threshold: {self.config.threshold})"
                        ),
                        timestamp=window_events[-1].timestamp,
                        details={
                            "invalid_attempts": len(window_events),
                            "unique_usernames": len(usernames_tried),
                            "threshold": self.config.threshold,
                            "window_minutes": self.config.window_minutes,
                            "first_attempt": window_events[0].timestamp.isoformat(),
                            "last_attempt": window_events[-1].timestamp.isoformat(),
                            "sample_usernames": list(usernames_tried)[:10],  # Sample for debugging
                        },
                        affected_events=window_events
                    )
                    violations.append(violation)
                    break  # Only report once per IP

        return violations

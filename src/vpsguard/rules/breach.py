"""Breach detection rule - successful login after multiple failures."""

from collections import defaultdict

from vpsguard.config import BreachDetectionConfig
from vpsguard.models.events import AuthEvent, EventType, RuleViolation, Severity


class BreachDetectionRule:
    """Detects successful logins after multiple failures (breach indicator)."""

    def __init__(self, config: BreachDetectionConfig):
        """Initialize rule with configuration.

        Args:
            config: Breach detection configuration.
        """
        self.config = config
        self.name = "breach_detection"
        self.severity = config.severity
        self.enabled = config.enabled

    def evaluate(self, events: list[AuthEvent]) -> list[RuleViolation]:
        """Evaluate events for breach patterns.

        A breach is detected when an IP has N+ failed login attempts
        followed by a successful login. This is CRITICAL as it suggests
        credentials were compromised.

        Args:
            events: List of authentication events.

        Returns:
            List of violations (one per IP with breach pattern).
        """
        if not self.enabled:
            return []

        violations = []

        # Group events by IP and sort by timestamp
        events_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
        for event in events:
            if event.ip and event.event_type in (EventType.FAILED_LOGIN, EventType.SUCCESSFUL_LOGIN):
                events_by_ip[event.ip].append(event)

        # Check each IP for breach pattern
        for ip, ip_events in events_by_ip.items():
            # Sort by timestamp
            sorted_events = sorted(ip_events, key=lambda e: e.timestamp)

            # Look for pattern: N+ failures followed by success
            consecutive_failures = []

            for event in sorted_events:
                if event.event_type == EventType.FAILED_LOGIN:
                    consecutive_failures.append(event)
                elif event.event_type == EventType.SUCCESSFUL_LOGIN:
                    # Check if we had enough failures before this success
                    if len(consecutive_failures) >= self.config.failures_before_success:
                        # BREACH DETECTED!
                        all_events = consecutive_failures + [event]
                        violation = RuleViolation(
                            rule_name=self.name,
                            severity=Severity[self.severity.upper()],
                            ip=ip,
                            description=(
                                f"POSSIBLE BREACH: Successful login after {len(consecutive_failures)} "
                                f"failed attempts (threshold: {self.config.failures_before_success}). "
                                "Credentials may be compromised!"
                            ),
                            timestamp=event.timestamp,
                            details={
                                "failed_attempts": len(consecutive_failures),
                                "threshold": self.config.failures_before_success,
                                "successful_username": event.username,
                                "failed_usernames": list(set(e.username for e in consecutive_failures if e.username)),
                                "first_failure": consecutive_failures[0].timestamp.isoformat(),
                                "success_time": event.timestamp.isoformat(),
                                "time_to_breach": str(event.timestamp - consecutive_failures[0].timestamp),
                            },
                            affected_events=all_events
                        )
                        violations.append(violation)

                    # Reset failure counter after any success
                    consecutive_failures = []

        return violations

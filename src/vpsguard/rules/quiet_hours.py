"""Quiet hours detection rule - logins during unusual hours."""

from vpsguard.config import QuietHoursConfig
from vpsguard.models.events import AuthEvent, EventType, RuleViolation, Severity


class QuietHoursRule:
    """Detects successful logins during configured quiet hours."""

    def __init__(self, config: QuietHoursConfig):
        """Initialize rule with configuration.

        Args:
            config: Quiet hours configuration.
        """
        self.config = config
        self.name = "quiet_hours"
        self.severity = config.severity
        self.enabled = config.enabled

    def evaluate(self, events: list[AuthEvent]) -> list[RuleViolation]:
        """Evaluate events for quiet hours violations.

        Flags successful logins that occur during configured quiet hours
        (e.g., 11 PM - 6 AM). Legitimate servers typically don't see
        admin logins during these hours.

        Args:
            events: List of authentication events.

        Returns:
            List of violations (one per quiet hours login).
        """
        if not self.enabled:
            return []

        violations = []

        for event in events:
            # Only check successful logins
            if event.event_type != EventType.SUCCESSFUL_LOGIN or not event.ip:
                continue

            # Get hour in configured timezone (currently using event's timestamp as-is)
            # TODO: In production, convert to configured timezone
            hour = event.timestamp.hour

            # Check if hour falls within quiet hours
            # Handle wraparound (e.g., 23:00 to 06:00)
            is_quiet_hour = False
            if self.config.start > self.config.end:
                # Wraps around midnight (e.g., 23 to 6)
                is_quiet_hour = hour >= self.config.start or hour < self.config.end
            else:
                # Same day (e.g., 1 to 5)
                is_quiet_hour = self.config.start <= hour < self.config.end

            if is_quiet_hour:
                violation = RuleViolation(
                    rule_name=self.name,
                    severity=Severity[self.severity.upper()],
                    ip=event.ip,
                    description=(
                        f"Login during quiet hours: {hour:02d}:00 "
                        f"(quiet hours: {self.config.start:02d}:00-{self.config.end:02d}:00 {self.config.timezone})"
                    ),
                    timestamp=event.timestamp,
                    details={
                        "hour": hour,
                        "quiet_start": self.config.start,
                        "quiet_end": self.config.end,
                        "timezone": self.config.timezone,
                        "username": event.username,
                    },
                    affected_events=[event]
                )
                violations.append(violation)

        return violations

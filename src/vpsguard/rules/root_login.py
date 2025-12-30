"""Root login detection rule - direct root SSH attempts."""

from vpsguard.models.events import AuthEvent, RuleViolation, Severity, EventType
from vpsguard.config import RootLoginConfig


class RootLoginRule:
    """Detects direct root login attempts (security best practice violation)."""
    
    def __init__(self, config: RootLoginConfig):
        """Initialize rule with configuration.
        
        Args:
            config: Root login detection configuration.
        """
        self.config = config
        self.name = "root_login"
        self.severity = config.severity
        self.enabled = config.enabled
    
    def evaluate(self, events: list[AuthEvent]) -> list[RuleViolation]:
        """Evaluate events for root login attempts.
        
        Security best practice is to disable root SSH and use sudo instead.
        Any root login attempt (failed or successful) is flagged.
        
        Args:
            events: List of authentication events.
            
        Returns:
            List of violations (one per root login attempt).
        """
        if not self.enabled:
            return []
        
        violations = []
        
        for event in events:
            # Check if username is root (case-insensitive)
            if not event.username or event.username.lower() != "root":
                continue
            
            # Check if it's a login event (failed or successful)
            if event.event_type not in (EventType.FAILED_LOGIN, EventType.SUCCESSFUL_LOGIN):
                continue
            
            # Check if we have an IP
            if not event.ip:
                continue
            
            # Create violation
            success_str = "successful" if event.success else "failed"
            violation = RuleViolation(
                rule_name=self.name,
                severity=Severity[self.severity.upper()],
                ip=event.ip,
                description=(
                    f"Root login attempt detected ({success_str}). "
                    "Direct root SSH access violates security best practices."
                ),
                timestamp=event.timestamp,
                details={
                    "success": event.success,
                    "username": event.username,
                    "event_type": event.event_type.value,
                },
                affected_events=[event]
            )
            violations.append(violation)
        
        return violations

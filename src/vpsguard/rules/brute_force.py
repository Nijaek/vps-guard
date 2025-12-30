"""Brute force detection rule."""

from collections import defaultdict
from datetime import datetime, timedelta
from vpsguard.models.events import AuthEvent, RuleViolation, Severity, EventType
from vpsguard.config import BruteForceConfig


class BruteForceRule:
    """Detects brute force attacks based on failed login attempts."""
    
    def __init__(self, config: BruteForceConfig):
        """Initialize rule with configuration.
        
        Args:
            config: Brute force detection configuration.
        """
        self.config = config
        self.name = "brute_force"
        self.severity = config.severity
        self.enabled = config.enabled
    
    def evaluate(self, events: list[AuthEvent]) -> list[RuleViolation]:
        """Evaluate events for brute force patterns.
        
        Args:
            events: List of authentication events.
            
        Returns:
            List of violations (one per IP exceeding threshold).
        """
        if not self.enabled:
            return []
        
        violations = []
        
        # Group failed login attempts by IP
        failed_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
        for event in events:
            if event.event_type == EventType.FAILED_LOGIN and event.ip:
                failed_by_ip[event.ip].append(event)
        
        # Check each IP for brute force pattern
        for ip, failed_events in failed_by_ip.items():
            if len(failed_events) < self.config.threshold:
                continue
            
            # Sort events by timestamp
            sorted_events = sorted(failed_events, key=lambda e: e.timestamp)
            
            # Check for threshold failures within time window
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
                    # Found brute force pattern
                    violation = RuleViolation(
                        rule_name=self.name,
                        severity=Severity[self.severity.upper()],
                        ip=ip,
                        description=(
                            f"Brute force attack detected: {len(window_events)} failed login attempts "
                            f"in {self.config.window_minutes} minutes (threshold: {self.config.threshold})"
                        ),
                        timestamp=window_events[-1].timestamp,
                        details={
                            "failed_attempts": len(window_events),
                            "threshold": self.config.threshold,
                            "window_minutes": self.config.window_minutes,
                            "first_attempt": window_events[0].timestamp.isoformat(),
                            "last_attempt": window_events[-1].timestamp.isoformat(),
                            "usernames": list(set(e.username for e in window_events if e.username)),
                        },
                        affected_events=window_events
                    )
                    violations.append(violation)
                    break  # Only report once per IP
        
        return violations

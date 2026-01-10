"""Base protocol and classes for detection rules."""

from typing import Protocol

from vpsguard.models.events import AuthEvent, RuleViolation


class Rule(Protocol):
    """Protocol for detection rules.

    All rules must implement this protocol to be compatible with the RuleEngine.
    """

    name: str
    severity: str
    enabled: bool

    def evaluate(self, events: list[AuthEvent]) -> list[RuleViolation]:
        """Evaluate events and return violations.

        Args:
            events: List of authentication events to analyze.

        Returns:
            List of rule violations found. Empty list if no violations.
        """
        ...

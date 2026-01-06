"""Rule engine - orchestrates all detection rules."""

from vpsguard.models.events import AuthEvent, RuleViolation, RuleEngineOutput
from vpsguard.config import VPSGuardConfig
from vpsguard.rules.base import Rule
from vpsguard.rules.brute_force import BruteForceRule
from vpsguard.rules.breach import BreachDetectionRule
from vpsguard.rules.quiet_hours import QuietHoursRule
from vpsguard.rules.invalid_user import InvalidUserRule
from vpsguard.rules.root_login import RootLoginRule
from vpsguard.rules.multi_vector import MultiVectorRule


class RuleEngine:
    """Runs all enabled rules and produces dual output.
    
    The dual output is critical for Task 7 (ML detection):
    - violations: Events flagged by rules (malicious)
    - clean_events: Events NOT flagged (normal, for ML training)
    """
    
    def __init__(self, config: VPSGuardConfig):
        """Initialize rule engine with configuration.
        
        Args:
            config: VPSGuard configuration with rule settings.
        """
        self.config = config
        self.rules = self._initialize_rules()
    
    def _initialize_rules(self) -> list[Rule]:
        """Create rule instances from config.

        Returns:
            List of initialized rules (only enabled ones will run).
        """
        rules: list[Rule] = [
            BruteForceRule(self.config.rules.brute_force),
            BreachDetectionRule(self.config.rules.breach_detection),
            QuietHoursRule(self.config.rules.quiet_hours),
            InvalidUserRule(self.config.rules.invalid_user),
            RootLoginRule(self.config.rules.root_login),
            MultiVectorRule(self.config.rules.multi_vector),
        ]
        return rules
    
    def evaluate(self, events: list[AuthEvent]) -> RuleEngineOutput:
        """Run all rules and return dual output.
        
        This is the core of the detection engine. It:
        1. Runs all enabled rules
        2. Collects all violations
        3. Filters whitelisted IPs
        4. Separates clean events (not flagged by any rule)
        
        Args:
            events: List of authentication events to analyze.
            
        Returns:
            RuleEngineOutput with:
            - violations: All rule violations found
            - clean_events: Events not flagged by any rule (for ML)
            - flagged_ips: Set of IPs that triggered rules
        """
        all_violations: list[RuleViolation] = []
        flagged_event_ids: set[int] = set()  # Track which events were flagged
        
        # Run all enabled rules
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            violations = rule.evaluate(events)
            
            # Track which events were flagged by this rule
            for violation in violations:
                for event in violation.affected_events:
                    flagged_event_ids.add(id(event))
            
            all_violations.extend(violations)
        
        # Filter out whitelisted IPs
        filtered_violations = []
        flagged_ips: set[str] = set()
        
        for violation in all_violations:
            if violation.ip in self.config.whitelist_ips:
                continue  # Skip whitelisted IPs
            
            filtered_violations.append(violation)
            flagged_ips.add(violation.ip)
        
        # Separate clean events (not flagged by any rule)
        # These are used for ML training in Task 7
        clean_events = [
            event for event in events 
            if id(event) not in flagged_event_ids
        ]
        
        return RuleEngineOutput(
            violations=filtered_violations,
            clean_events=clean_events,
            flagged_ips=flagged_ips
        )

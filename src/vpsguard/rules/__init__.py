"""Detection rules module."""

from vpsguard.rules.base import Rule
from vpsguard.rules.brute_force import BruteForceRule
from vpsguard.rules.breach import BreachDetectionRule
from vpsguard.rules.quiet_hours import QuietHoursRule
from vpsguard.rules.invalid_user import InvalidUserRule
from vpsguard.rules.root_login import RootLoginRule
from vpsguard.rules.multi_vector import MultiVectorRule
from vpsguard.rules.geo_velocity import GeoVelocityRule
from vpsguard.rules.engine import RuleEngine

__all__ = [
    "Rule",
    "BruteForceRule",
    "BreachDetectionRule",
    "QuietHoursRule",
    "InvalidUserRule",
    "RootLoginRule",
    "MultiVectorRule",
    "GeoVelocityRule",
    "RuleEngine",
]

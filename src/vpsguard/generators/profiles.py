"""Attack profiles for synthetic log generation."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AttackProfile(Enum):
    """Attack patterns for synthetic log generation."""

    BRUTE_FORCE = "brute"       # Single IP, many attempts, common usernames
    BOTNET = "botnet"           # Many IPs, coordinated timing, same targets
    CREDENTIAL_STUFFING = "stuffing"  # Many IPs, many usernames
    LOW_AND_SLOW = "low-slow"   # Few attempts per day, spread over weeks
    BREACH = "breach"           # Failed attempts → eventual success
    RECON = "recon"             # Probing for valid usernames


@dataclass
class AttackConfig:
    """Configuration for a specific attack profile.

    Attributes:
        profile: The attack profile to generate
        ratio: Fraction of total events for this attack (0.0 to 1.0)
        ips_count: Number of attacker IPs to use
        attempts_per_ip: Number of attempts per IP
        target_users: Specific users to target (None for defaults)
        time_window_minutes: Attack duration in minutes
    """

    profile: AttackProfile
    ratio: float  # What fraction of total events should be this attack

    # Profile-specific parameters (optional, with sensible defaults)
    ips_count: int = 1           # Number of attacker IPs
    attempts_per_ip: int = 50    # Attempts per IP
    target_users: Optional[list[str]] = field(default_factory=lambda: None)  # Specific users to target
    time_window_minutes: int = 10   # Attack duration

    def __post_init__(self):
        """Validate configuration parameters."""
        if not 0.0 <= self.ratio <= 1.0:
            raise ValueError(f"ratio must be between 0.0 and 1.0, got {self.ratio}")

        if self.ips_count < 1:
            raise ValueError(f"ips_count must be at least 1, got {self.ips_count}")

        if self.attempts_per_ip < 1:
            raise ValueError(f"attempts_per_ip must be at least 1, got {self.attempts_per_ip}")

        if self.time_window_minutes < 1:
            raise ValueError(f"time_window_minutes must be at least 1, got {self.time_window_minutes}")

        # Breach profile requires at least 2 attempts (1 failure + 1 success)
        if self.profile == AttackProfile.BREACH and self.attempts_per_ip < 2:
            raise ValueError(f"BREACH profile requires attempts_per_ip >= 2 (at least 1 failure + 1 success), got {self.attempts_per_ip}")

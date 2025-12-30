"""Configuration management for VPSGuard.

Loads and validates TOML configuration files with dataclass-based structure.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import tomllib  # Python 3.11+ stdlib


@dataclass
class BruteForceConfig:
    """Configuration for brute force detection rule."""
    enabled: bool = True
    threshold: int = 10
    window_minutes: int = 60
    severity: str = "high"


@dataclass
class BreachDetectionConfig:
    """Configuration for breach detection rule (success after failures)."""
    enabled: bool = True
    failures_before_success: int = 5
    severity: str = "critical"


@dataclass
class QuietHoursConfig:
    """Configuration for quiet hours detection rule."""
    enabled: bool = True
    start: int = 23  # 11 PM
    end: int = 6     # 6 AM
    timezone: str = "UTC"
    severity: str = "medium"


@dataclass
class RootLoginConfig:
    """Configuration for root login detection rule."""
    enabled: bool = True
    severity: str = "medium"


@dataclass
class InvalidUserConfig:
    """Configuration for invalid user detection rule."""
    enabled: bool = True
    threshold: int = 5  # Flag if >5 invalid user attempts from same IP
    window_minutes: int = 60
    severity: str = "medium"


@dataclass
class RulesConfig:
    """Container for all rule configurations."""
    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    breach_detection: BreachDetectionConfig = field(default_factory=BreachDetectionConfig)
    quiet_hours: QuietHoursConfig = field(default_factory=QuietHoursConfig)
    root_login: RootLoginConfig = field(default_factory=RootLoginConfig)
    invalid_user: InvalidUserConfig = field(default_factory=InvalidUserConfig)


@dataclass
class OutputConfig:
    """Configuration for output formatting."""
    format: str = "terminal"
    verbosity: int = 1


@dataclass
class VPSGuardConfig:
    """Main configuration container for VPSGuard."""
    rules: RulesConfig = field(default_factory=RulesConfig)
    whitelist_ips: list[str] = field(default_factory=list)
    output: OutputConfig = field(default_factory=OutputConfig)


def load_config(path: Path | str | None = None) -> VPSGuardConfig:
    """Load config from TOML file, or return defaults if not found.

    Args:
        path: Path to TOML config file. If None, returns default config.

    Returns:
        VPSGuardConfig instance with loaded or default values.

    Raises:
        FileNotFoundError: If path is provided but file doesn't exist.
        ValueError: If TOML parsing fails or config is invalid.
    """
    if path is None:
        return VPSGuardConfig()

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        raise ValueError(f"Failed to parse TOML config: {e}") from e

    return _build_config(data)


def _build_config(data: dict[str, Any]) -> VPSGuardConfig:
    """Build VPSGuardConfig from parsed TOML data."""
    config = VPSGuardConfig()

    # Load rules configuration
    if "rules" in data:
        rules_data = data["rules"]

        if "brute_force" in rules_data:
            bf = rules_data["brute_force"]
            config.rules.brute_force = BruteForceConfig(
                enabled=bf.get("enabled", True),
                threshold=bf.get("threshold", 10),
                window_minutes=bf.get("window_minutes", 60),
                severity=bf.get("severity", "high")
            )

        if "breach_detection" in rules_data:
            bd = rules_data["breach_detection"]
            config.rules.breach_detection = BreachDetectionConfig(
                enabled=bd.get("enabled", True),
                failures_before_success=bd.get("failures_before_success", 5),
                severity=bd.get("severity", "critical")
            )

        if "quiet_hours" in rules_data:
            qh = rules_data["quiet_hours"]
            config.rules.quiet_hours = QuietHoursConfig(
                enabled=qh.get("enabled", True),
                start=qh.get("start", 23),
                end=qh.get("end", 6),
                timezone=qh.get("timezone", "UTC"),
                severity=qh.get("severity", "medium")
            )

        if "root_login" in rules_data:
            rl = rules_data["root_login"]
            config.rules.root_login = RootLoginConfig(
                enabled=rl.get("enabled", True),
                severity=rl.get("severity", "medium")
            )

        if "invalid_user" in rules_data:
            iu = rules_data["invalid_user"]
            config.rules.invalid_user = InvalidUserConfig(
                enabled=iu.get("enabled", True),
                threshold=iu.get("threshold", 5),
                window_minutes=iu.get("window_minutes", 60),
                severity=iu.get("severity", "medium")
            )

    # Load whitelist
    if "whitelist" in data:
        config.whitelist_ips = data["whitelist"].get("ips", [])

    # Load output configuration
    if "output" in data:
        output_data = data["output"]
        config.output = OutputConfig(
            format=output_data.get("format", "terminal"),
            verbosity=output_data.get("verbosity", 1)
        )

    return config


def validate_config(config: VPSGuardConfig) -> list[str]:
    """Validate config and return list of warnings/errors.

    Args:
        config: VPSGuardConfig instance to validate.

    Returns:
        List of warning/error messages. Empty list if config is valid.
    """
    warnings = []

    # Validate brute force config
    bf = config.rules.brute_force
    if bf.threshold < 1:
        warnings.append("brute_force.threshold must be >= 1")
    if bf.window_minutes < 1:
        warnings.append("brute_force.window_minutes must be >= 1")
    if bf.severity not in ("critical", "high", "medium", "low"):
        warnings.append(f"brute_force.severity '{bf.severity}' is not valid")

    # Validate breach detection config
    bd = config.rules.breach_detection
    if bd.failures_before_success < 1:
        warnings.append("breach_detection.failures_before_success must be >= 1")
    if bd.severity not in ("critical", "high", "medium", "low"):
        warnings.append(f"breach_detection.severity '{bd.severity}' is not valid")

    # Validate quiet hours config
    qh = config.rules.quiet_hours
    if not (0 <= qh.start <= 23):
        warnings.append(f"quiet_hours.start must be 0-23, got {qh.start}")
    if not (0 <= qh.end <= 23):
        warnings.append(f"quiet_hours.end must be 0-23, got {qh.end}")
    if qh.severity not in ("critical", "high", "medium", "low"):
        warnings.append(f"quiet_hours.severity '{qh.severity}' is not valid")

    # Validate root login config
    rl = config.rules.root_login
    if rl.severity not in ("critical", "high", "medium", "low"):
        warnings.append(f"root_login.severity '{rl.severity}' is not valid")

    # Validate invalid user config
    iu = config.rules.invalid_user
    if iu.threshold < 1:
        warnings.append("invalid_user.threshold must be >= 1")
    if iu.window_minutes < 1:
        warnings.append("invalid_user.window_minutes must be >= 1")
    if iu.severity not in ("critical", "high", "medium", "low"):
        warnings.append(f"invalid_user.severity '{iu.severity}' is not valid")

    # Validate output config
    if config.output.format not in ("terminal", "json"):
        warnings.append(f"output.format '{config.output.format}' is not valid (use 'terminal' or 'json')")
    if not (0 <= config.output.verbosity <= 3):
        warnings.append(f"output.verbosity must be 0-3, got {config.output.verbosity}")

    # Validate whitelist IPs (basic check)
    for ip in config.whitelist_ips:
        if not isinstance(ip, str) or len(ip) == 0:
            warnings.append(f"Invalid whitelist IP: {ip}")

    return warnings

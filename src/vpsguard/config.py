"""Configuration management for VPSGuard.

Loads and validates TOML configuration files with dataclass-based structure.
"""

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# tomllib is stdlib in Python 3.11+, use tomli for 3.10
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


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
class MultiVectorConfig:
    """Configuration for multi-vector attack detection rule."""
    enabled: bool = True
    min_sources: int = 2  # Minimum log sources IP must appear in
    min_events_per_source: int = 3  # Minimum events per source to count
    severity: str = "high"


@dataclass
class GeoVelocityConfig:
    """Configuration for geographic velocity (impossible travel) detection rule."""
    enabled: bool = True
    max_velocity_km_h: float = 1000.0  # Max reasonable travel speed (~commercial jet)
    min_distance_km: float = 100.0  # Minimum distance to consider (avoid false positives)
    severity: str = "high"


@dataclass
class RulesConfig:
    """Container for all rule configurations."""
    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    breach_detection: BreachDetectionConfig = field(default_factory=BreachDetectionConfig)
    quiet_hours: QuietHoursConfig = field(default_factory=QuietHoursConfig)
    root_login: RootLoginConfig = field(default_factory=RootLoginConfig)
    invalid_user: InvalidUserConfig = field(default_factory=InvalidUserConfig)
    multi_vector: MultiVectorConfig = field(default_factory=MultiVectorConfig)
    geo_velocity: GeoVelocityConfig = field(default_factory=GeoVelocityConfig)


@dataclass
class OutputConfig:
    """Configuration for output formatting."""
    format: str = "terminal"
    verbosity: int = 1


@dataclass
class WatchOutputConfig:
    """Output configuration for watch mode reports."""
    directory: str = "~/.vpsguard/reports"
    formats: list[str] = field(default_factory=lambda: ["markdown", "json"])


@dataclass
class WatchScheduleConfig:
    """Configuration for watch daemon scheduling."""
    interval: str = "1h"  # Duration: 5m, 1h, 6h, 24h
    retention_days: int = 30
    alerts: dict = field(default_factory=lambda: {
        "critical_threshold": 1,
        "high_threshold": 5,
        "anomaly_threshold": 3
    })


@dataclass
class GeoIPConfig:
    """Configuration for GeoIP lookups."""
    enabled: bool = True
    database_path: str = "~/.vpsguard/GeoLite2-City.mmdb"


@dataclass
class VPSGuardConfig:
    """Main configuration container for VPSGuard."""
    rules: RulesConfig = field(default_factory=RulesConfig)
    whitelist_ips: list[str] = field(default_factory=list)
    output: OutputConfig = field(default_factory=OutputConfig)
    watch_schedule: WatchScheduleConfig = field(default_factory=WatchScheduleConfig)
    watch_output: WatchOutputConfig = field(default_factory=WatchOutputConfig)
    geoip: GeoIPConfig = field(default_factory=GeoIPConfig)


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

        if "multi_vector" in rules_data:
            mv = rules_data["multi_vector"]
            config.rules.multi_vector = MultiVectorConfig(
                enabled=mv.get("enabled", True),
                min_sources=mv.get("min_sources", 2),
                min_events_per_source=mv.get("min_events_per_source", 3),
                severity=mv.get("severity", "high")
            )

        if "geo_velocity" in rules_data:
            gv = rules_data["geo_velocity"]
            config.rules.geo_velocity = GeoVelocityConfig(
                enabled=gv.get("enabled", True),
                max_velocity_km_h=gv.get("max_velocity_km_h", 1000.0),
                min_distance_km=gv.get("min_distance_km", 100.0),
                severity=gv.get("severity", "high")
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

    # Load watch configuration
    if "watch" in data:
        watch_data = data["watch"]

        if "schedule" in watch_data:
            schedule = watch_data["schedule"]
            alerts = schedule.get("alerts", {})

            config.watch_schedule = WatchScheduleConfig(
                interval=schedule.get("interval", "1h"),
                retention_days=schedule.get("retention_days", 30),
                alerts={
                    "critical_threshold": alerts.get("critical_threshold", 1),
                    "high_threshold": alerts.get("high_threshold", 5),
                    "anomaly_threshold": alerts.get("anomaly_threshold", 3)
                }
            )

        if "output" in watch_data:
            output = watch_data["output"]
            config.watch_output = WatchOutputConfig(
                directory=output.get("directory", "~/.vpsguard/reports"),
                formats=output.get("formats", ["markdown", "json"])
            )

    # Load GeoIP configuration
    if "geoip" in data:
        geoip_data = data["geoip"]
        config.geoip = GeoIPConfig(
            enabled=geoip_data.get("enabled", True),
            database_path=geoip_data.get("database_path", "~/.vpsguard/GeoLite2-City.mmdb")
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

    # Validate multi vector config
    mv = config.rules.multi_vector
    if mv.min_sources < 2:
        warnings.append("multi_vector.min_sources must be >= 2")
    if mv.min_events_per_source < 1:
        warnings.append("multi_vector.min_events_per_source must be >= 1")
    if mv.severity not in ("critical", "high", "medium", "low"):
        warnings.append(f"multi_vector.severity '{mv.severity}' is not valid")

    # Validate geo velocity config
    gv = config.rules.geo_velocity
    if gv.max_velocity_km_h <= 0:
        warnings.append("geo_velocity.max_velocity_km_h must be > 0")
    if gv.min_distance_km < 0:
        warnings.append("geo_velocity.min_distance_km must be >= 0")
    if gv.severity not in ("critical", "high", "medium", "low"):
        warnings.append(f"geo_velocity.severity '{gv.severity}' is not valid")

    # Validate output config
    if config.output.format not in ("terminal", "markdown", "json", "html"):
        warnings.append(
            f"output.format '{config.output.format}' is not valid "
            "(use 'terminal', 'markdown', 'json', or 'html')"
        )
    if not (0 <= config.output.verbosity <= 3):
        warnings.append(f"output.verbosity must be 0-3, got {config.output.verbosity}")

    # Validate watch schedule config
    valid_intervals = {"5m", "15m", "30m", "1h", "6h", "12h", "24h"}
    if config.watch_schedule.interval not in valid_intervals:
        warnings.append(f"watch.schedule.interval '{config.watch_schedule.interval}' must be one of: {', '.join(sorted(valid_intervals))}")

    if config.watch_schedule.retention_days < 1:
        warnings.append("watch.schedule.retention_days must be >= 1")

    for threshold_name, threshold_value in config.watch_schedule.alerts.items():
        if threshold_value < 0:
            warnings.append(f"watch.schedule.alerts.{threshold_name} must be >= 0")

    # Validate whitelist IPs (basic check)
    for ip in config.whitelist_ips:
        if not isinstance(ip, str) or len(ip) == 0:
            warnings.append(f"Invalid whitelist IP: {ip}")

    # Validate GeoIP config
    if not isinstance(config.geoip.database_path, str) or len(config.geoip.database_path) == 0:
        warnings.append("geoip.database_path must be a non-empty string")

    return warnings

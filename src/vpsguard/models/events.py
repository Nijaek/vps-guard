from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class EventType(Enum):
    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"
    INVALID_USER = "invalid_user"
    SUDO = "sudo"
    DISCONNECT = "disconnect"
    OTHER = "other"

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class Confidence(Enum):
    HIGH = "high"      # score > 0.8
    MEDIUM = "medium"  # score 0.6 - 0.8
    LOW = "low"        # score 0.4 - 0.6

@dataclass
class AuthEvent:
    timestamp: datetime
    event_type: EventType
    ip: Optional[str]
    username: Optional[str]
    success: bool
    raw_line: str
    port: Optional[int] = None
    pid: Optional[int] = None
    service: Optional[str] = None
    log_source: Optional[str] = None  # Source file/type for multi-log correlation

@dataclass
class ParsedLog:
    events: list[AuthEvent]
    source_file: Optional[str]
    format_type: str  # "auth.log", "secure", "journald"
    parse_errors: list[str]

@dataclass
class RuleViolation:
    rule_name: str
    severity: Severity
    ip: str
    description: str
    timestamp: datetime
    details: dict
    affected_events: list[AuthEvent]

    @property
    def log_sources(self) -> list[str]:
        """Extract unique log sources from affected events.

        Returns:
            Sorted list of unique log source names.
        """
        sources = set()
        for event in self.affected_events:
            if event.log_source:
                sources.add(event.log_source)
        return sorted(sources)

@dataclass
class RuleEngineOutput:
    violations: list[RuleViolation]
    clean_events: list[AuthEvent]  # Events not flagged by rules (for ML training)
    flagged_ips: set[str]

@dataclass
class AnomalyResult:
    ip: str
    score: float  # 0.0 (normal) to 1.0 (anomalous)
    confidence: Confidence
    explanation: list[str]  # Human-readable reasons
    features: dict[str, float]  # Feature values that contributed

@dataclass
class BaselineStats:
    trained_at: datetime
    event_count: int
    feature_means: dict[str, float]
    feature_stds: dict[str, float]
    model_path: Optional[str] = None

@dataclass
class AnalysisReport:
    timestamp: datetime
    log_source: str
    total_events: int
    rule_violations: list[RuleViolation]
    anomalies: list[AnomalyResult]
    baseline_drift: Optional[dict] = None
    summary: Optional[dict] = None
    geo_data: Optional[dict] = None  # IP -> GeoLocation mapping


@dataclass
class WatchState:
    """Persistent state for watch daemon tracking.

    Tracks where we left off in the log file to enable incremental parsing.
    """
    log_path: str                      # File being monitored
    inode: int                         # File inode (detect log rotation)
    byte_offset: int                   # Last read position
    last_run_time: datetime            # When we last ran analysis
    run_count: int                     # Total analysis runs
    last_findings_counts: dict         # {severity: count} from last run

# VPSGuard Design Document

**Date:** 2024-12-30
**Status:** Approved — **MVP Complete (Phases 1-3)**

*Last updated: 2024-12-31*

---

## Executive Summary

VPSGuard is an ML-first log analyzer that catches subtle attack patterns rule-based tools miss — specifically distributed attacks and successful breaches.

**Core differentiator:** While fail2ban, OSSEC, and similar tools rely on per-IP thresholds, VPSGuard uses machine learning to detect coordinated attacks across multiple IPs and identify successful breaches (failed attempts followed by success).

---

## Key Design Decisions

| Area | Decision |
|------|----------|
| Core differentiator | ML-first (catch what rules miss) |
| Baseline problem | Hybrid: rules filter known attacks before ML training |
| Phase structure | Keep rules/ML separate, design for integration |
| Log formats | auth.log + secure + journald JSON from day one |
| Key ML features | Temporal clustering + behavioral sequences |
| MVP scope | Phases 1-3, defer multi-log/geo/notifications |
| New capabilities | Explainable anomalies, baseline drift, confidence scoring |
| Data handling | Pure Python dataclasses → numpy for ML |
| Detection pipeline | Single model + rich features (MVP), pluggable interface |
| Synthetic generator | 6 attack profiles |
| Output hierarchy | Severity-first |
| pandas | Removed — too heavy for CLI tool |

---

## Architecture

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              INPUT LAYER                                │
├─────────────────────────────────────────────────────────────────────────┤
│  auth.log  ──┐                                                          │
│  secure    ──┼──▶  Parser  ──▶  List[AuthEvent]  (dataclasses)          │
│  journald  ──┘     (regex)                                              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           DETECTION LAYER                               │
├─────────────────────────────────────────────────────────────────────────┤
│  Rule Engine ──▶ Known attack patterns (brute force, invalid users)     │
│       │                                                                 │
│       ▼                                                                 │
│  "Cleaned" events (attacks filtered out)                                │
│       │                                                                 │
│       ▼                                                                 │
│  Feature Extractor ──▶ numpy arrays (temporal, behavioral, clustering)  │
│       │                                                                 │
│       ▼                                                                 │
│  ML Detector ──▶ Anomaly scores + explanations + confidence             │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            OUTPUT LAYER                                 │
├─────────────────────────────────────────────────────────────────────────┤
│  Report Generator ──▶ Severity-first hierarchy                          │
│       │                                                                 │
│       ├──▶ Terminal (Rich)                                              │
│       ├──▶ Markdown                                                     │
│       └──▶ JSON                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key insight:** Rules and ML are a pipeline, not alternatives. Rules filter known-bad data to create clean training data, then ML catches what rules miss.

---

## Feature Engineering

### Feature Categories

| Category | Features | Catches |
|----------|----------|---------|
| **Volume** | Attempts per IP per hour, failure count, success count | Basic brute force |
| **Temporal** | Hour of day, day of week, time since last attempt | Off-hours attacks |
| **Behavioral** | Longest failure streak before success, failure→success ratio | Successful breaches |
| **Target patterns** | Unique usernames per IP, username entropy (random vs common) | Credential stuffing |
| **Clustering** | Other IPs hitting same targets in ±N minute window, correlation score | Distributed/botnet attacks |

### Clustering Features (The Differentiator)

```python
@dataclass
class ClusteringFeatures:
    same_target_ips_5min: int    # How many other IPs hit same username within 5 min
    same_target_ips_30min: int   # Same, but 30 min window
    temporal_correlation: float   # Correlation of this IP's activity with others
    unique_targets_shared: int    # How many usernames this IP shares with others
```

This transforms "50 IPs each with 1 attempt" from invisible (to rules) to obvious (high `same_target_ips` scores).

### Explainability

For each anomaly, compute feature z-scores vs. baseline:

```
"This IP scored high because:
 - same_target_ips_5min: 47 (baseline: 0.3) ← 156σ above normal
 - failure_streak_before_success: 31 (baseline: 1.2) ← 25σ above normal"
```

---

## Rule Engine

### Rule Types

| Rule | Trigger | Severity |
|------|---------|----------|
| Brute force | >N failures from IP in M minutes | HIGH |
| Invalid user spray | >N attempts on non-existent users | MEDIUM |
| Successful breach | Success after >N failures | CRITICAL |
| Off-hours login | Success during quiet hours | MEDIUM |
| Root direct login | Any attempt to login as root directly | MEDIUM |

### Configuration (vpsguard.toml)

```toml
[rules.brute_force]
enabled = true
threshold = 10
window_minutes = 60
severity = "high"

[rules.breach_detection]
enabled = true
failures_before_success = 5
severity = "critical"

[rules.quiet_hours]
enabled = true
start = 23
end = 6
timezone = "UTC"
severity = "medium"
```

### Dual Output

```python
@dataclass
class RuleEngineOutput:
    violations: list[RuleViolation]     # Feed to reporter
    clean_events: list[AuthEvent]       # Feed to ML trainer
    flagged_ips: set[str]               # IPs with known-bad behavior
```

---

## ML Detector

### Core Model

Isolation Forest (scikit-learn) — unsupervised, fast, interpretable scores.

### Pluggable Interface

```python
class Detector(Protocol):
    name: str

    def train(self, features: np.ndarray, config: DetectorConfig) -> None: ...
    def detect(self, features: np.ndarray) -> list[AnomalyResult]: ...
    def save(self, path: Path) -> None: ...
    def load(self, path: Path) -> None: ...
```

### Confidence Scoring

```python
@dataclass
class AnomalyResult:
    ip: str
    score: float              # 0.0 (normal) to 1.0 (anomalous)
    confidence: Confidence    # HIGH, MEDIUM, LOW
    explanation: list[str]    # Human-readable reasons

class Confidence(Enum):
    HIGH = "high"       # score > 0.8
    MEDIUM = "medium"   # score 0.6 - 0.8
    LOW = "low"         # score 0.4 - 0.6
```

### Baseline Drift Detection

```python
@dataclass
class BaselineStats:
    trained_at: datetime
    event_count: int
    feature_means: dict[str, float]
    feature_stds: dict[str, float]
```

On each run, compare current stats to baseline. Flag significant deviations.

---

## Output & Reporting

### Terminal Output (Severity-First)

```
╔══════════════════════════════════════════════════════════════════════╗
║                    VPSGUARD SECURITY REPORT                          ║
║                    2024-01-15 03:47 UTC                              ║
╠══════════════════════════════════════════════════════════════════════╣
║  CRITICAL: 2    HIGH: 7    MEDIUM: 23    Scanned: 48,291             ║
╚══════════════════════════════════════════════════════════════════════╝

CRITICAL FINDINGS

┌─ Successful Breach Detected ─────────────────────────────────────────┐
│ IP: 45.33.32.156                                                     │
│ User: deploy                                                         │
│ Time: 2024-01-15 03:12:47                                           │
│ Pattern: 31 failed attempts → successful login                       │
│ Confidence: HIGH (0.94)                                             │
│ Why: failure_streak=31 (baseline: 1.2), success_after_failures=true │
└──────────────────────────────────────────────────────────────────────┘
```

### Output Formats

| Format | Use case |
|--------|----------|
| Terminal (default) | Interactive review |
| Markdown | Commit to repo, share with team |
| JSON | Pipe to other tools, automation |

### Verbosity Levels

```bash
vpsguard analyze log.txt                    # Summary + critical/high only
vpsguard analyze log.txt -v                 # Include medium
vpsguard analyze log.txt -vv                # Include low + all details
```

---

## Synthetic Log Generator

### Attack Profiles

| Profile | Description |
|---------|-------------|
| `brute` | Single IP, many attempts, common usernames |
| `botnet` | Many IPs, coordinated timing, same targets |
| `stuffing` | Many IPs, realistic usernames |
| `low-slow` | Few attempts per day, spread over weeks |
| `breach` | Failures → eventual success |
| `recon` | Probing for valid usernames |

### CLI Usage

```bash
vpsguard generate --entries 5000 --attack-profile botnet --attack-ratio 0.1

vpsguard generate --entries 10000 \
    --attack-profile botnet:0.05 \
    --attack-profile breach:0.01

vpsguard generate --format journald  # Test journald parser
```

---

## CLI Commands

### Core Commands (MVP)

| Command | Purpose |
|---------|---------|
| `parse` | Parse logs, output structured data |
| `analyze` | Run rules + ML detection, generate report |
| `train` | Train/retrain ML model on baseline data |
| `generate` | Create synthetic logs for testing |
| `init` | Generate default config file |

### Examples

```bash
# Parse and inspect
vpsguard parse /var/log/auth.log --stats
cat journald.json | vpsguard parse --input-format journald-json

# Full analysis
vpsguard analyze /var/log/auth.log
vpsguard analyze /var/log/auth.log --config ./vpsguard.toml
vpsguard analyze /var/log/auth.log --rules-only
vpsguard analyze /var/log/auth.log --ml-only

# Training
vpsguard train /var/log/auth.log
vpsguard train --check  # Show baseline stats

# Generate test data
vpsguard generate --entries 5000 --attack-profile botnet:0.1

# Initialize
vpsguard init
```

---

## Project Structure

```
vpsguard/
├── src/
│   └── vpsguard/
│       ├── __init__.py
│       ├── cli.py
│       ├── config.py
│       │
│       ├── parsers/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── auth.py
│       │   ├── secure.py
│       │   └── journald.py
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   └── events.py
│       │
│       ├── rules/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── brute_force.py
│       │   ├── breach.py
│       │   ├── invalid_user.py
│       │   └── quiet_hours.py
│       │
│       ├── ml/
│       │   ├── __init__.py
│       │   ├── features.py
│       │   ├── detector.py
│       │   ├── isolation.py
│       │   ├── baseline.py
│       │   └── explain.py
│       │
│       ├── reporters/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── terminal.py
│       │   ├── markdown.py
│       │   └── json.py
│       │
│       └── generators/
│           ├── __init__.py
│           ├── synthetic.py
│           └── profiles.py
│
├── tests/
│   ├── test_parsers.py
│   ├── test_rules.py
│   ├── test_ml.py
│   ├── test_generators.py
│   └── fixtures/
│
├── vpsguard.example.toml
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## Phase Plan

### Phase 1: Foundation (Parsing + Generator) ✅ COMPLETE

- [x] Project scaffolding (pyproject.toml, src layout)
- [x] Core dataclasses: `AuthEvent`, `ParsedLog`
- [x] Parser protocol + implementations (auth.log, secure, journald JSON)
- [x] Stdin support
- [x] Synthetic generator with 6 attack profiles
- [x] CLI commands: `parse`, `generate`, `init`
- [x] Basic tests

**Exit criteria:** Can parse all 3 formats, generate test data with attack patterns.

### Phase 2: Rule-Based Detection ✅ COMPLETE

- [x] TOML config loader with validation
- [x] Rule protocol + implementations
- [x] Rule engine (outputs violations AND clean events)
- [x] Reporters (Terminal, Markdown, JSON)
- [x] CLI command: `analyze --rules-only`
- [x] Tests for rules

**Exit criteria:** Can detect obvious attacks, generate severity-sorted reports.

### Phase 3: ML Detection (MVP Complete) ✅ COMPLETE

- [x] Feature extractor
- [x] Detector protocol + IsolationForestDetector
- [x] Model save/load
- [x] Explainability (z-score based)
- [x] Confidence scoring
- [x] Baseline drift detection
- [x] CLI commands: `train`, `analyze` (full)
- [x] Integration tests

**Exit criteria:** Full pipeline works. Catches distributed attacks that rules miss.

### Phase 4+ (Post-MVP)

| Phase | Scope |
|-------|-------|
| Phase 4 | Nginx/syslog parsers, GeoIP integration |
| Phase 5 | HTML reports, SQLite history, `--watch` mode |
| Phase 6 | Notifications (optional) |

---

## Tech Stack

| Component | Choice |
|-----------|--------|
| Language | Python 3.10+ |
| CLI | Typer |
| Data structures | Pure Python dataclasses |
| ML features | numpy arrays |
| ML models | scikit-learn (Isolation Forest) |
| Output | Rich |
| Config | TOML (tomllib stdlib) |

---

## Success Criteria

| Criterion | Metric | Status |
|-----------|--------|--------|
| Catches distributed attacks | Detects 47-IP botnet in synthetic data that rules miss | ✅ |
| Catches breaches | Flags "failed→success" pattern with CRITICAL severity | ✅ |
| Explainable output | Every anomaly shows WHY it scored high | ✅ |
| Fast enough | <10 seconds for 100K log lines on 2-core/8GB machine | ⏳ Needs benchmarking |
| Easy install | `pip install vpsguard` with no system dependencies | ✅ |
| Easy demo | `vpsguard generate && vpsguard analyze` shows value in 30 seconds | ✅ |

---

## What We're NOT Building

- Real-time daemon mode (use fail2ban)
- Automatic IP blocking (use fail2ban)
- Cloud/SaaS features
- Complex UI (CLI is the product)

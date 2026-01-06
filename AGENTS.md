# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
# Install in editable mode (enables vpsguard CLI)
python -m pip install -e .

# Run all tests
python -m pytest tests/ -v

# Run single test file
python -m pytest tests/test_ml.py -v

# Run single test
python -m pytest tests/test_ml.py::test_feature_extraction -v

# Run with coverage
python -m pytest tests/ --cov=vpsguard

# Lint (if ruff installed)
ruff check src/

# CLI usage after install
vpsguard --help
python -m vpsguard.cli --help
```

## Architecture

VPSGuard is an ML-first security analyzer for VPS logs. It detects distributed attacks (botnets, credential stuffing) that rule-based tools like fail2ban miss.

### Detection Pipeline

```
Log Files → Parser → RuleEngine → MLEngine → Reporter
                         ↓             ↓
                    violations    anomalies
                         ↓             ↓
                    clean_events → (training data)
```

The rule engine serves dual purposes: (1) detect known attack patterns and (2) filter out flagged events so ML trains only on "clean" baseline data.

### Module Structure

- **`cli.py`** — Typer CLI with 8 commands: parse, generate, init, train, analyze, watch, history, geoip
- **`parsers/`** — Log format parsers (auth.log, secure, journald, nginx, syslog). All return standardized `AuthEvent` objects.
- **`rules/`** — 7 detection rules (brute_force, breach_detection, quiet_hours, invalid_user, root_login, multi_vector, geo_velocity) + engine orchestrator
- **`ml/`** — Feature extraction (10 features per IP), IsolationForest detector, baseline drift detection, explainability
- **`reporters/`** — Output formatters (terminal/Rich, JSON, Markdown, HTML with filtering)
- **`generators/`** — Synthetic log generator with 6 attack profiles for testing
- **`models/events.py`** — Core dataclasses: AuthEvent, RuleViolation, AnomalyResult, AnalysisReport, WatchState
- **`config.py`** — TOML config loader with dataclass validation + watch schedule config
- **`history.py`** — SQLite persistence for analysis runs + watch state
- **`watch.py`** — Watch daemon for scheduled batch analysis with incremental parsing
- **`daemon.py`** — Daemon lifecycle management (PID files, signals, graceful shutdown)
- **`geo/`** — GeoIP integration for IP geolocation using MaxMind GeoLite2 database

### Key Design Patterns

- **Protocol-based abstractions**: Parsers, detectors, reporters implement protocols for extensibility
- **Dual detection**: Rules catch known patterns; ML catches novel/distributed attacks
- **Explainability**: Every ML anomaly includes Z-score deviation explanation
- **Clean data separation**: Rule-flagged events excluded from ML training to prevent poisoned baselines
- **Incremental parsing**: Watch daemon tracks byte offset to only process new log content

### Watch Daemon Architecture

The watch command provides scheduled batch monitoring:

```
vpsguard watch /var/log/auth.log
  │
  ├─► Daemonize (PID file: ~/.vpsguard/watch.pid)
  ├─► Load watch state from SQLite (byte_offset, inode)
  │
  └─► [Event Loop]
       │
       ├─► Check for log rotation (inode change, file size < offset)
       ├─► Parse log incrementally from saved byte_offset
       ├─► Run full analysis (rules + optional ML)
       ├─► Save new state to SQLite
       ├─► Generate reports if findings exceed thresholds
       └─► Sleep until next interval
```

Key watch features:
- **Cross-platform rotation detection**: inode (Unix) or creation time (Windows), plus size fallback
- **State persistence**: WatchState stored in SQLite with UPSERT semantics
- **Graceful shutdown**: Signal handlers (SIGTERM/SIGINT) for clean daemon termination

### ML Features (10 per IP)

Features designed to catch distributed attacks:
- `same_target_ips_5min/30min` — Detects coordinated botnet attacks (multiple IPs targeting same users)
- `has_success_after_failures` — Binary breach indicator
- `failure_ratio`, `max_failure_streak` — Attack intensity
- `username_entropy` — Detects generated/randomized usernames
- `attack_vectors` — Number of distinct log sources (multi-log correlation)

## Testing Patterns

300 tests across 16 files. Test files mirror source structure:
- `test_parsers.py` — Each parser format with edge cases
- `test_rules.py` — Each rule type + whitelist filtering
- `test_ml.py` — Feature extraction, detector, baseline drift
- `test_analyze.py` — Integration tests for full pipeline
- `test_generators.py` — All 6 attack profiles, all output formats
- `test_watch.py` — Watch daemon, incremental parsing, log rotation detection
- `test_daemon.py` — PID file management, signal handling
- `test_history.py` — SQLite persistence, watch state, cleanup
- `test_geoip.py` — GeoIP reader, database management, config loading
- `benchmark.py` — Performance benchmarks (100K lines parsing/analysis)

## Configuration

TOML-based (`vpsguard.toml`). Key sections:
- `[rules.*]` — Enable/disable rules, tune thresholds (brute_force, breach_detection, quiet_hours, invalid_user, root_login, multi_vector, geo_velocity)
- `[whitelist]` — IPs to exclude from detection
- `[output]` — Default format and verbosity
- `[watch.schedule]` — Watch daemon interval and alert thresholds
- `[watch.output]` — Report directory and output formats
- `[geoip]` — GeoIP database settings (enabled, database_path)

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds

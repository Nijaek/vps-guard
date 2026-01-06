# VPSGuard — Project Plan

An ML-first CLI tool that catches subtle attack patterns rule-based tools miss — specifically distributed attacks and successful breaches.

**Repository:** `vpsguard`
**CLI Command:** `vpsguard`
**Design Doc:** `docs/plans/2024-12-30-vpsguard-design.md`

---

## Progress Summary

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | ✅ Complete | Foundation — Parsing + Generator |
| Phase 2 | ✅ Complete | Rule-Based Detection |
| Phase 3 | ✅ Complete | ML Detection — **MVP Complete** |
| Phase 4 | ⏳ Not Started | Multi-Log Support & Geolocation |
| Phase 5 | 🔄 Partial (1/6) | Reporting & Polish |
| Phase 6 | ⏳ Not Started | Notifications (Optional) |

**Overall: ~70% complete** — MVP is fully implemented with 190+ tests.

*Last updated: 2024-12-31*

---

## Project Overview

**Goal:** Build a portfolio-worthy CLI tool that uses machine learning to detect security anomalies that traditional rule-based tools miss — coordinated botnet attacks, successful breaches after brute force attempts, and other subtle patterns.

**Core Differentiator:** While fail2ban bans an IP after 10 failures, attackers use 100 IPs with 1 failure each. VPSGuard's ML detects "47 IPs all targeted 'admin' in a 5-minute window" even though each IP individually looks benign.

**Target Users:** Sysadmins, DevOps engineers, security-conscious developers

**Constraints:**
- Runs fully local (no paid APIs)
- Must work on modest hardware (2 CPU cores, 8GB RAM)
- Batch processing model (not real-time)

---

## Tech Stack

| Component | Tool |
|-----------|------|
| Language | Python 3.10+ |
| CLI Framework | `Typer` |
| Log Parsing | `regex`, pure Python dataclasses |
| ML Features | `numpy` arrays |
| ML/Anomaly Detection | `scikit-learn` (Isolation Forest) |
| Data Storage | SQLite (Phase 5, for historical tracking) |
| Output | Terminal tables (`rich`), JSON, Markdown reports |
| Config | TOML (`tomllib` stdlib in 3.11+) |
| IP Geolocation | GeoLite2 (Phase 4) |
| Packaging | `pip` installable via `pyproject.toml` |

---

## Phases

### Phase 1: Foundation — Parsing + Generator ✅ COMPLETE
**Goal:** Parse auth logs from multiple formats and generate synthetic test data

**Tasks:**
- [x] Set up project structure (src layout, pyproject.toml)
- [x] Core dataclasses: `AuthEvent`, `ParsedLog`
- [x] Parser protocol + implementations:
  - `auth.log` (Debian/Ubuntu)
  - `secure` (RHEL/CentOS)
  - `journald` JSON format (`journalctl --output=json`)
- [x] Stdin support (`cat log | vpsguard parse -`)
- [x] CLI commands: `parse`, `generate`, `init`
- [x] Export to JSON
- [x] **Synthetic log generator** with attack profiles:
  - `brute` — Single IP, many attempts
  - `botnet` — Many IPs, coordinated timing (tests ML!)
  - `stuffing` — Many IPs, realistic usernames
  - `low-slow` — Few attempts, spread over time
  - `breach` — Failures → eventual success (tests ML!)
  - `recon` — Probing for valid usernames
- [x] Basic tests for parsers and generator

**CLI:**
```bash
vpsguard parse /var/log/auth.log --stats
journalctl -u sshd --output=json | vpsguard parse --input-format journald-json
vpsguard generate --entries 5000 --attack-profile botnet:0.1 --output test.log
```

**Exit Criteria:** Can parse all 3 formats, generate test data with attack patterns.

---

### Phase 2: Rule-Based Detection ✅ COMPLETE
**Goal:** Catch obvious threats AND produce clean data for ML training

**Key Insight:** Rules serve two purposes:
1. Detect known attack patterns (report to user)
2. Filter known-bad events from ML training data (prevents poisoned baseline)

**Tasks:**
- [x] TOML config loader with validation
- [x] Rule protocol + implementations:
  - Brute force (>N failures in M minutes)
  - Breach detection (success after >N failures) — CRITICAL severity
  - Invalid user spray
  - Quiet hours violations
  - Root direct login attempts
- [x] Rule engine outputs:
  - `violations` → feed to reporter
  - `clean_events` → feed to ML trainer
- [x] Reporters (severity-first hierarchy):
  - Terminal (Rich)
  - Markdown
  - JSON
- [x] CLI command: `vpsguard analyze --rules-only`
- [x] Tests for rules

**Sample `vpsguard.toml`:**
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

[whitelist]
ips = ["192.168.1.1", "10.0.0.1"]

[output]
format = "terminal"  # or "json", "markdown"
verbosity = 1        # 0=critical/high only, 1=+medium, 2=all
```

**Exit Criteria:** Can detect obvious attacks, generate severity-sorted reports.

---

### Phase 3: ML Detection — MVP Complete ✅ COMPLETE
**Goal:** Catch subtle patterns that rules miss

**Key Features:**

| Category | Features | Catches |
|----------|----------|---------|
| Volume | Attempts/hour, failure count | Basic brute force |
| Temporal | Hour of day, time between attempts | Off-hours attacks |
| Behavioral | Failure streak before success, fail/success ratio | Successful breaches |
| Clustering | Other IPs hitting same targets in ±N min window | Distributed attacks |

**Tasks:**
- [x] Feature extractor (dataclasses → numpy arrays)
- [x] Detector protocol (pluggable for future models)
- [x] IsolationForestDetector implementation
- [x] Model save/load
- [x] **Explainability:** z-score based explanations ("Why this IP scored high")
- [x] **Confidence scoring:** HIGH/MEDIUM/LOW based on thresholds
- [x] **Baseline drift detection:** Alert when patterns change significantly
- [x] CLI commands: `train`, `analyze` (full pipeline)
- [x] Integration: rules filter → ML train → detect → unified report
- [x] Tests for ML pipeline

**CLI:**
```bash
vpsguard train /var/log/auth.log                    # Train baseline
vpsguard train --check                              # Show baseline stats
vpsguard analyze /var/log/auth.log                  # Full analysis
vpsguard analyze /var/log/auth.log --rules-only    # Skip ML
vpsguard analyze /var/log/auth.log --ml-only       # Skip rules
```

**Exit Criteria:** Full parse→detect→report pipeline works. Catches distributed attacks that rules miss.

---

### Phase 4: Multi-Log Support & Geolocation (Post-MVP)
**Goal:** Expand beyond auth.log and add geographic insights

**Tasks:**
- [ ] Add parser for Nginx access logs
  - Unusual status codes (403/404 spikes)
  - Suspicious user agents
  - Path traversal attempts
- [ ] Add parser for syslog
- [ ] **IP Geolocation integration:**
  - Integrate GeoLite2 database
  - Geographic velocity feature (impossible travel)
  - CLI flag: `vpsguard analyze --geoip`
- [ ] Unified analysis across log types

---

### Phase 5: Reporting & Polish (Post-MVP)
**Goal:** Make it portfolio-ready

**Tasks:**
- [ ] Generate HTML report (single file, shareable)
- [ ] Add `--watch` mode for scheduled batch runs
- [ ] Historical comparison (SQLite storage)
- [x] Comprehensive README ~~with GIF demo~~
- [ ] GitHub Actions CI
- [ ] License: MIT

---

### Phase 6: Notifications (Optional)
**Goal:** Alert on critical findings

**Note:** Consider skipping — existing tools (fail2ban, alertmanager) handle notifications well.

**Tasks:**
- [ ] Email alerts via SMTP
- [ ] Slack webhook integration
- [ ] Discord webhook integration

---

## Project Structure

```
vpsguard/
├── src/
│   └── vpsguard/
│       ├── __init__.py
│       ├── cli.py                 # Typer CLI entry point
│       ├── config.py              # TOML config loader
│       │
│       ├── parsers/
│       │   ├── __init__.py
│       │   ├── base.py            # Parser protocol
│       │   ├── auth.py            # auth.log (Debian/Ubuntu)
│       │   ├── secure.py          # secure (RHEL/CentOS)
│       │   └── journald.py        # journalctl JSON
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   └── events.py          # AuthEvent, RuleViolation, etc.
│       │
│       ├── rules/
│       │   ├── __init__.py
│       │   ├── base.py            # Rule protocol
│       │   ├── brute_force.py
│       │   ├── breach.py
│       │   ├── invalid_user.py
│       │   └── quiet_hours.py
│       │
│       ├── ml/
│       │   ├── __init__.py
│       │   ├── features.py        # Feature extraction (→ numpy)
│       │   ├── detector.py        # Detector protocol
│       │   ├── isolation.py       # IsolationForestDetector
│       │   ├── baseline.py        # BaselineStats, drift detection
│       │   └── explain.py         # Explainability (z-scores)
│       │
│       ├── reporters/
│       │   ├── __init__.py
│       │   ├── base.py            # Reporter protocol
│       │   ├── terminal.py        # Rich output
│       │   ├── markdown.py
│       │   └── json.py
│       │
│       └── generators/
│           ├── __init__.py
│           ├── synthetic.py       # Main generator logic
│           └── profiles.py        # Attack profiles
│
├── tests/
│   ├── test_parsers.py
│   ├── test_rules.py
│   ├── test_ml.py
│   ├── test_generators.py
│   └── fixtures/                  # Sample log files
│
├── vpsguard.example.toml
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## Sample CLI Usage (Target State)

```bash
# Initialize config file
vpsguard init

# Generate synthetic test data
vpsguard generate --entries 5000 --attack-profile botnet:0.1 --output test.log
vpsguard generate --entries 10000 --attack-profile botnet:0.05 --attack-profile breach:0.01

# Parse and inspect logs
vpsguard parse /var/log/auth.log --stats
vpsguard parse /var/log/auth.log --format json
journalctl -u sshd --output=json --since "24 hours ago" | vpsguard parse --input-format journald-json

# Train ML baseline
vpsguard train /var/log/auth.log
vpsguard train --check                              # Show baseline stats

# Full analysis (rules + ML)
vpsguard analyze /var/log/auth.log
vpsguard analyze /var/log/auth.log --config ./vpsguard.toml
vpsguard analyze /var/log/auth.log -v               # Verbose (include medium severity)
vpsguard analyze /var/log/auth.log -vv              # Very verbose (all findings)
vpsguard analyze /var/log/auth.log --rules-only     # Skip ML
vpsguard analyze /var/log/auth.log --ml-only        # Skip rules

# Output formats
vpsguard analyze /var/log/auth.log --format markdown --output report.md
vpsguard analyze /var/log/auth.log --format json    # Machine-readable

# Analysis with geolocation (Phase 4+)
vpsguard analyze /var/log/auth.log --geoip

# Multi-log analysis (Phase 4+)
vpsguard analyze /var/log/auth.log /var/log/nginx/access.log
```

---

## Success Criteria

- [x] Catches distributed attacks (47-IP botnet detected in synthetic data that rules miss)
- [x] Catches breaches (flags "failed→success" pattern with CRITICAL severity)
- [x] Explainable output (every anomaly shows WHY it scored high)
- [ ] Fast enough (<10 seconds for 100K log lines on 2-core/8GB) — needs benchmarking
- [x] Easy install (`pip install vpsguard` with no system dependencies)
- [x] Easy demo (`vpsguard generate && vpsguard analyze` shows value in 30 seconds)
- [x] README good enough that a stranger could use it

---

## What We're NOT Building

- Real-time daemon mode (use fail2ban)
- Automatic IP blocking (use fail2ban)
- Cloud/SaaS features
- Complex UI (CLI is the product)

---

## Resources

- [scikit-learn Isolation Forest docs](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- [Typer CLI framework](https://typer.tiangolo.com/)
- [Rich terminal formatting](https://rich.readthedocs.io/)
- [GeoLite2 free IP database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

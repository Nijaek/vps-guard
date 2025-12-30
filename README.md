# VPSGuard

An ML-first CLI tool that catches subtle attack patterns rule-based tools miss — specifically distributed attacks and successful breaches.

## Why VPSGuard?

Traditional tools like fail2ban ban an IP after N failed attempts. But attackers adapt — they use **100 IPs with 1 attempt each**. VPSGuard's ML detects patterns like "47 IPs all targeted 'admin' in a 5-minute window" even though each IP individually looks benign.

**Core differentiator:** While rule-based tools catch obvious brute force, VPSGuard catches:
- **Coordinated botnet attacks** — distributed across many IPs
- **Successful breaches** — failed attempts followed by success (compromised credentials)
- **Low-and-slow attacks** — few attempts spread over time to evade detection

## Features

- **Dual detection**: Rule-based + ML anomaly detection
- **3 log formats**: auth.log (Debian/Ubuntu), secure (RHEL/CentOS), journald JSON
- **6 attack profiles**: Generate synthetic logs for testing
- **3 output formats**: Terminal (Rich), Markdown, JSON
- **Explainable ML**: Every anomaly shows WHY it scored high
- **Baseline drift detection**: Alerts when patterns change significantly

## Requirements

- Python 3.10+
- No external system dependencies

## Installation

```bash
# Clone the repository
git clone https://github.com/Nijaek/vps-guard.git
cd vps-guard

# Install in editable mode
python -m pip install -e .
```

## Quick Start

```bash
# Generate test data with a botnet attack pattern
python -m vpsguard.cli generate --entries 1000 --attack-profile botnet:0.1 --output test.log

# Analyze for threats (rules only)
python -m vpsguard.cli analyze test.log

# Analyze with verbose output (include medium severity)
python -m vpsguard.cli analyze test.log -v
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `parse` | Parse log files and display structured events |
| `generate` | Generate synthetic log files for testing |
| `init` | Create a default configuration file |
| `train` | Train ML model on baseline log data |
| `analyze` | Run security analysis (rules + ML) |

### Parse Logs

```bash
# Parse and show statistics
python -m vpsguard.cli parse /var/log/auth.log --stats

# Output as JSON
python -m vpsguard.cli parse /var/log/auth.log --format json

# Parse from stdin
cat /var/log/auth.log | python -m vpsguard.cli parse -

# Specify input format explicitly
python -m vpsguard.cli parse server.log --input-format secure
```

### Generate Test Data

```bash
# Generate 1000 entries with 10% botnet attacks
python -m vpsguard.cli generate --entries 1000 --attack-profile botnet:0.1 --output test.log

# Multiple attack profiles
python -m vpsguard.cli generate --entries 5000 \
    --attack-profile botnet:0.05 \
    --attack-profile breach:0.02 \
    --output mixed.log

# Different output formats
python -m vpsguard.cli generate --entries 1000 --format journald --output test.json

# Reproducible generation with seed
python -m vpsguard.cli generate --entries 1000 --seed 42 --output reproducible.log
```

**Available attack profiles:**

| Profile | Description |
|---------|-------------|
| `brute` | Single IP, many attempts, common usernames |
| `botnet` | Many IPs, coordinated timing, same targets |
| `stuffing` | Many IPs, realistic usernames (credential stuffing) |
| `low-slow` | Few attempts per day, spread over weeks |
| `breach` | Failures followed by eventual success |
| `recon` | Probing for valid usernames |

### Initialize Configuration

```bash
# Create default config file
python -m vpsguard.cli init

# Custom output path
python -m vpsguard.cli init --output myconfig.toml

# Overwrite existing
python -m vpsguard.cli init --force
```

### Analyze Logs

```bash
# Basic analysis (rules only, critical/high severity)
python -m vpsguard.cli analyze /var/log/auth.log

# Include medium severity findings
python -m vpsguard.cli analyze /var/log/auth.log -v

# Include all findings
python -m vpsguard.cli analyze /var/log/auth.log -vv

# Use custom config
python -m vpsguard.cli analyze /var/log/auth.log --config vpsguard.toml

# Output as Markdown
python -m vpsguard.cli analyze /var/log/auth.log --format markdown --output report.md

# Output as JSON
python -m vpsguard.cli analyze /var/log/auth.log --format json --output report.json
```

### Train ML Model

```bash
# Train on baseline data
python -m vpsguard.cli train /var/log/auth.log

# Custom model path
python -m vpsguard.cli train /var/log/auth.log --model mymodel.pkl

# Check baseline statistics
python -m vpsguard.cli train --check --model vpsguard_model.pkl
```

### Analyze with ML

```bash
# Full analysis with ML (requires trained model)
python -m vpsguard.cli analyze /var/log/auth.log --with-ml

# Specify model path
python -m vpsguard.cli analyze /var/log/auth.log --with-ml --model mymodel.pkl
```

## Configuration

Create a `vpsguard.toml` file to customize detection rules:

```toml
[rules.brute_force]
enabled = true
threshold = 10          # Failed attempts before triggering
window_minutes = 60     # Time window to count attempts
severity = "high"

[rules.breach_detection]
enabled = true
failures_before_success = 5   # Failed attempts before success = breach
severity = "critical"

[rules.quiet_hours]
enabled = true
start = 23              # 11 PM
end = 6                 # 6 AM
timezone = "UTC"
severity = "medium"

[whitelist]
ips = ["192.168.1.1", "10.0.0.1"]

[output]
format = "terminal"     # terminal, json, markdown
verbosity = 1           # 0=critical/high, 1=+medium, 2=all
```

## Detection Rules

| Rule | Severity | Description |
|------|----------|-------------|
| Brute Force | HIGH | N+ failed logins from same IP in M minutes |
| Breach Detection | CRITICAL | Successful login after N+ failures (compromised credentials) |
| Quiet Hours | MEDIUM | Successful login during off-hours |
| Invalid User | MEDIUM | Multiple attempts on non-existent usernames |
| Root Login | MEDIUM | Direct root login attempts |

## ML Features

VPSGuard extracts 9 features for anomaly detection:

| Feature | Description |
|---------|-------------|
| `attempts_per_hour` | Login attempt rate |
| `failure_ratio` | Failed / total attempts |
| `unique_usernames` | Number of different usernames tried |
| `username_entropy` | Randomness of usernames (detects generated names) |
| `max_failure_streak` | Longest consecutive failures |
| `has_success_after_failures` | Breach indicator |
| `hour_of_day` | Temporal pattern |
| `same_target_ips_5min` | Coordinated attack detection |
| `same_target_ips_30min` | Wider coordination window |

## Example Output

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

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_generators.py -v

# Run with coverage
python -m pytest tests/ --cov=vpsguard
```

## Project Structure

```
vpsguard/
├── src/vpsguard/
│   ├── cli.py              # Typer CLI entry point
│   ├── config.py           # TOML config loader
│   ├── parsers/            # Log parsers (auth.log, secure, journald)
│   ├── models/             # Data models (AuthEvent, RuleViolation, etc.)
│   ├── rules/              # Detection rules + engine
│   ├── ml/                 # ML features, detector, baseline, explainability
│   ├── reporters/          # Output formatters (terminal, markdown, json)
│   └── generators/         # Synthetic log generator
├── tests/                  # Test suite (190 tests)
├── vpsguard.example.toml   # Example configuration
└── pyproject.toml
```

## What VPSGuard is NOT

- **Not a real-time daemon** — use fail2ban for that
- **Not an IP blocker** — use fail2ban for that
- **Not a cloud/SaaS tool** — runs fully local
- **Not a complex UI** — CLI is the product

VPSGuard is a batch analysis tool for security review and forensics.

## License

MIT

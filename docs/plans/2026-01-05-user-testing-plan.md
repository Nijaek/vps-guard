# VPSGuard User Testing Plan

**Created:** 2026-01-05
**Purpose:** Comprehensive testing checklist for new users to validate all VPSGuard functionality
**Audience:** Testers with no prior VPSGuard experience

---

## Table of Contents

1. [Prerequisites & Installation](#1-prerequisites--installation)
2. [Quick Start Test](#2-quick-start-test)
3. [Command Testing](#3-command-testing)
   - [parse](#31-parse-command)
   - [generate](#32-generate-command)
   - [init](#33-init-command)
   - [train](#34-train-command)
   - [analyze](#35-analyze-command)
   - [watch](#36-watch-command)
   - [history](#37-history-command)
   - [geoip](#38-geoip-command)
4. [Detection Rule Testing](#4-detection-rule-testing)
5. [ML Anomaly Detection Testing](#5-ml-anomaly-detection-testing)
6. [GeoIP Feature Testing](#6-geoip-feature-testing)
7. [Multi-Log Correlation Testing](#7-multi-log-correlation-testing)
8. [Output Format Testing](#8-output-format-testing)
9. [Error Handling Testing](#9-error-handling-testing)
10. [Configuration Testing](#10-configuration-testing)
11. [End-to-End Scenarios](#11-end-to-end-scenarios)

---

## 1. Prerequisites & Installation

### System Requirements
- [ ] Python 3.10 or higher installed
- [ ] Git installed (for cloning repository)
- [ ] Terminal/command line access

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/Nijaek/vps-guard.git
cd vps-guard

# Install in editable mode
python -m pip install -e .
```

### Verify Installation

- [ ] Run `vpsguard --help` - should display 8 commands
- [ ] Run `python -m vpsguard.cli --help` - should display same output
- [ ] Run `python --version` - should show 3.10+

**Expected output for `vpsguard --help`:**
```
Usage: vpsguard [OPTIONS] COMMAND [ARGS]...

ML-first VPS log security analyzer

Commands:
  parse      Parse log files and display structured events.
  generate   Generate synthetic log files for testing.
  init       Initialize a default configuration file.
  train      Train ML model on log file using clean events.
  analyze    Analyze log files for security threats.
  watch      Run scheduled batch analysis on log file.
  history    View and manage analysis history.
  geoip      Manage GeoIP database for IP geolocation
```

---

## 2. Quick Start Test

This validates the primary use case: generating test data and analyzing it.

### Generate Test Data

```bash
# Generate 1000 log entries with 10% botnet attack traffic
vpsguard generate --entries 1000 --attack-profile botnet:0.1 --output test.log
```

- [ ] Command completes without error
- [ ] File `test.log` is created
- [ ] File contains ~1000 lines (use `wc -l test.log` on Unix or `find /c /v "" test.log` on Windows)

### Analyze Test Data

```bash
# Run security analysis
vpsguard analyze test.log
```

- [ ] Command completes without error
- [ ] Output shows security report header with timestamp
- [ ] Output shows severity counts (CRITICAL, HIGH, MEDIUM)
- [ ] Output shows at least one brute force finding (from botnet profile)

### Verbose Analysis

```bash
# Include medium severity findings
vpsguard analyze test.log -v
```

- [ ] More findings displayed than basic analysis
- [ ] Medium severity findings now visible

---

## 3. Command Testing

### 3.1 Parse Command

The parse command extracts structured events from log files.

#### Basic Parsing
```bash
vpsguard parse test.log
```
- [ ] Displays table of parsed events
- [ ] Shows columns: timestamp, IP, username, event_type, success

#### Parse with Statistics
```bash
vpsguard parse test.log --stats
```
- [ ] Shows event counts by type
- [ ] Shows unique IP count
- [ ] Shows unique username count
- [ ] Shows time range of events

#### JSON Output
```bash
vpsguard parse test.log --format json
```
- [ ] Output is valid JSON
- [ ] Each event has: timestamp, ip, username, event_type, success fields

#### Stdin Parsing
```bash
# Unix/Linux/Mac
cat test.log | vpsguard parse -

# Windows PowerShell
Get-Content test.log | vpsguard parse -
```
- [ ] Parses successfully from stdin
- [ ] Same output as file-based parsing

#### Explicit Format
```bash
vpsguard parse test.log --input-format auth.log
```
- [ ] Parses with explicit format specification
- [ ] No format auto-detection warnings

#### Nginx Log Format
```bash
# Generate nginx logs (if supported by generator, otherwise create manually)
echo '192.168.1.100 - admin [01/Jan/2024:10:00:00 +0000] "POST /login HTTP/1.1" 401 0' > nginx-test.log
echo '192.168.1.100 - admin [01/Jan/2024:10:00:05 +0000] "POST /login HTTP/1.1" 200 1234' >> nginx-test.log

vpsguard parse nginx-test.log --input-format nginx
```
- [ ] Parses nginx access log format
- [ ] Extracts IP, user, timestamp, status code
- [ ] 401 status mapped to failure, 200 to success

#### Syslog Format
```bash
# Create syslog format test file
echo 'Jan  1 10:00:00 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2' > syslog-test.log
echo 'Jan  1 10:00:05 server sshd[1234]: Accepted password for admin from 192.168.1.100 port 22 ssh2' >> syslog-test.log

vpsguard parse syslog-test.log --input-format syslog
```
- [ ] Parses standard syslog format
- [ ] Extracts timestamp, IP, username, event type
- [ ] Handles syslog timestamp format correctly

---

### 3.2 Generate Command

The generate command creates synthetic log files with various attack patterns.

#### Basic Generation
```bash
vpsguard generate --entries 500 --output basic.log
```
- [ ] Creates file with ~500 entries
- [ ] Contains mix of success/failure events

#### All Attack Profiles

Test each attack profile individually:

```bash
# Brute force - single IP, many attempts
vpsguard generate --entries 500 --attack-profile brute:0.2 --output brute.log

# Botnet - many IPs, coordinated attack
vpsguard generate --entries 500 --attack-profile botnet:0.2 --output botnet.log

# Credential stuffing - realistic usernames
vpsguard generate --entries 500 --attack-profile stuffing:0.2 --output stuffing.log

# Low and slow - spread over time
vpsguard generate --entries 500 --attack-profile low-slow:0.2 --output lowslow.log

# Breach - failures followed by success
vpsguard generate --entries 500 --attack-profile breach:0.2 --output breach.log

# Recon - username probing
vpsguard generate --entries 500 --attack-profile recon:0.2 --output recon.log
```

For each profile:
- [ ] File created successfully
- [ ] Analyze shows relevant detection (brute force, breach, etc.)

#### Multiple Attack Profiles
```bash
vpsguard generate --entries 1000 \
    --attack-profile botnet:0.05 \
    --attack-profile breach:0.02 \
    --output mixed.log
```
- [ ] File created with both attack patterns
- [ ] Analysis shows both botnet and breach detections

#### Different Output Formats
```bash
# Secure log format (RHEL/CentOS style)
vpsguard generate --entries 500 --format secure --output test.secure

# Journald JSON format
vpsguard generate --entries 500 --format journald --output test.json
```
- [ ] Secure format file created
- [ ] Journald JSON format file created
- [ ] Both can be parsed with `vpsguard parse`

#### Reproducible Generation
```bash
vpsguard generate --entries 100 --seed 42 --output seed1.log
vpsguard generate --entries 100 --seed 42 --output seed2.log
```
- [ ] Both files have identical structure (same IPs, usernames)
- [ ] Useful for reproducible testing

---

### 3.3 Init Command

The init command creates a configuration file.

#### Basic Init
```bash
vpsguard init
```
- [ ] Creates `vpsguard.toml` in current directory
- [ ] File contains `[rules.*]` sections
- [ ] File contains `[whitelist]` section
- [ ] File contains `[output]` section

#### Custom Output Path
```bash
vpsguard init --output custom-config.toml
```
- [ ] Creates file at specified path
- [ ] Content matches default config

#### Force Overwrite
```bash
vpsguard init --force
```
- [ ] Overwrites existing config file
- [ ] No confirmation prompt

#### Existing File Error
```bash
# First create a config
vpsguard init --output existing.toml

# Try to overwrite without --force
vpsguard init --output existing.toml
```
- [ ] Shows error about existing file
- [ ] Does not overwrite

---

### 3.4 Train Command

The train command creates an ML model from baseline (clean) log data.

#### Generate Clean Baseline Data
```bash
# Generate logs WITHOUT attack profiles for baseline
vpsguard generate --entries 2000 --output baseline.log
```

#### Train Model
```bash
vpsguard train baseline.log
```
- [ ] Training completes successfully
- [ ] Creates `vpsguard_model.pkl` file
- [ ] Shows baseline statistics (IP count, feature ranges)

#### Custom Model Path
```bash
vpsguard train baseline.log --model custom_model.pkl
```
- [ ] Creates model at specified path

#### Check Model
```bash
vpsguard train --check --model vpsguard_model.pkl
```
- [ ] Displays baseline statistics
- [ ] Shows feature ranges
- [ ] Does not modify model

#### Train with Explicit Input Format
```bash
vpsguard generate --entries 2000 --format secure --output baseline-secure.log
vpsguard train baseline-secure.log --input-format secure --model secure-model.pkl
```
- [ ] Parses with specified format
- [ ] Training completes successfully
- [ ] Model created

#### Train with Custom Config
```bash
vpsguard init --output train-config.toml
vpsguard train baseline.log --config train-config.toml
```
- [ ] Uses config for rule filtering during training
- [ ] Training completes successfully

---

### 3.5 Analyze Command

The analyze command runs security analysis on log files.

#### Basic Analysis
```bash
vpsguard analyze test.log
```
- [ ] Shows security report
- [ ] Displays critical and high severity findings

#### Verbosity Levels
```bash
# Default (critical + high only)
vpsguard analyze test.log

# Level 1: include medium
vpsguard analyze test.log -v

# Level 2: include all
vpsguard analyze test.log -vv
```
- [ ] Each level shows progressively more findings
- [ ] -vv shows low severity items

#### Custom Config
```bash
vpsguard init --output test-config.toml
vpsguard analyze test.log --config test-config.toml
```
- [ ] Uses custom configuration
- [ ] Rule thresholds from config are applied

#### Output Formats
```bash
# Terminal (default)
vpsguard analyze test.log --format terminal

# Markdown
vpsguard analyze test.log --format markdown --output report.md

# JSON
vpsguard analyze test.log --format json --output report.json

# HTML
vpsguard analyze test.log --format html --output report.html
```
- [ ] Each format produces appropriate output
- [ ] Files created at specified paths
- [ ] Markdown is valid markdown
- [ ] JSON is valid JSON
- [ ] HTML renders in browser

#### With ML
```bash
# First train a model
vpsguard train baseline.log

# Then analyze with ML
vpsguard analyze test.log --with-ml
```
- [ ] Shows anomaly scores for IPs
- [ ] Anomalies include explanation (feature deviations)

#### Multiple Log Files
```bash
# Generate logs in different formats
vpsguard generate --entries 500 --output auth.log
vpsguard generate --entries 500 --format secure --output secure.log

# Analyze multiple files together
vpsguard analyze auth.log secure.log
```
- [ ] Parses both files
- [ ] Correlates events across files
- [ ] Shows source attribution in findings

#### Save to History
```bash
vpsguard analyze test.log --save-history
```
- [ ] Analysis saved to history database
- [ ] Can view with `vpsguard history`

#### Stdin Analysis
```bash
# Unix/Linux/Mac
cat test.log | vpsguard analyze -

# Windows PowerShell
Get-Content test.log | vpsguard analyze -
```
- [ ] Analyzes successfully from stdin
- [ ] Same findings as file-based analysis
- [ ] All output formats work with stdin input

---

### 3.6 Watch Command

The watch command provides continuous monitoring.

#### Foreground Mode
```bash
# Run single analysis in foreground
vpsguard watch test.log --foreground --once
```
- [ ] Runs one analysis cycle
- [ ] Shows results in terminal
- [ ] Exits after completion

#### Custom Interval
```bash
vpsguard watch test.log --foreground --interval 1m --once
```
- [ ] Accepts interval parameter
- [ ] Valid intervals: 5m, 15m, 30m, 1h, 6h, 12h, 24h

#### Daemon Mode (Unix/Linux/Mac only)
```bash
# Start daemon
vpsguard watch test.log

# Check status
vpsguard watch test.log --status

# Stop daemon
vpsguard watch test.log --stop
```
- [ ] Daemon starts and runs in background
- [ ] Status shows running/stopped
- [ ] Stop terminates the daemon
- [ ] PID file created at ~/.vpsguard/watch.pid

#### Watch with Custom Config
```bash
vpsguard init --output watch-config.toml
vpsguard watch test.log --foreground --once --config watch-config.toml
```
- [ ] Uses custom configuration file
- [ ] Rule thresholds from config applied
- [ ] Watch schedule settings from config applied

#### Watch with Explicit Log Format
```bash
vpsguard generate --entries 500 --format secure --output watch-secure.log
vpsguard watch watch-secure.log --foreground --once --format secure
```
- [ ] Parses with specified format
- [ ] Analysis completes successfully

#### Watch Report Generation
```bash
# Run watch and check for generated reports
vpsguard watch test.log --foreground --once

# Check default report directory
ls ~/.vpsguard/reports/
# or on Windows: dir %USERPROFILE%\.vpsguard\reports\
```
- [ ] Reports saved to ~/.vpsguard/reports/
- [ ] Markdown report generated
- [ ] JSON report generated
- [ ] Reports contain analysis findings

---

### 3.7 History Command

The history command manages analysis run history.

#### Prerequisite: Create History
```bash
vpsguard analyze test.log --save-history
vpsguard analyze test.log --save-history
vpsguard analyze test.log --save-history
```

#### List Runs
```bash
vpsguard history
# or
vpsguard history list
```
- [ ] Shows list of recent analysis runs
- [ ] Each run has ID, timestamp, file, finding counts

#### Show Run Details
```bash
vpsguard history show --run 1
```
- [ ] Shows detailed findings for specific run
- [ ] Includes all violations and anomalies

#### Compare Runs
```bash
vpsguard history compare --run 1 --compare-to 2
```
- [ ] Shows differences between runs
- [ ] Highlights new/resolved findings

#### Daily Trend
```bash
vpsguard history trend --days 7
```
- [ ] Shows finding counts per day
- [ ] Useful for spotting patterns

#### Top Offenders
```bash
vpsguard history top --limit 10
```
- [ ] Shows IPs with most findings
- [ ] Ordered by severity/count

#### IP History
```bash
# Get an IP from analysis output first
vpsguard history ip --ip 192.168.1.100
```
- [ ] Shows all findings for specific IP
- [ ] Across all analysis runs

#### Cleanup Old Data
```bash
vpsguard history cleanup --days 30
```
- [ ] Removes runs older than 30 days
- [ ] Shows count of deleted runs

#### Custom Database Path
```bash
# Use custom database location
vpsguard history list --db ./custom-history.db

# Save to custom database
vpsguard analyze test.log --save-history
vpsguard history list --db ~/.vpsguard/history.db
```
- [ ] Reads from specified database path
- [ ] All history commands work with --db option
- [ ] Useful for separating test/production history

---

### 3.8 GeoIP Command

The geoip command manages the GeoLite2 database for IP geolocation.

#### Check Status
```bash
vpsguard geoip status
```
- [ ] Shows whether database is installed
- [ ] If installed: shows path, size, record count
- [ ] If not installed: shows "not found" message

#### Download Database
```bash
vpsguard geoip download
```
- [ ] Downloads GeoLite2-City.mmdb (~70MB)
- [ ] Saves to ~/.vpsguard/GeoLite2-City.mmdb
- [ ] Shows download progress
- [ ] Shows success message with file info

#### Force Re-download
```bash
# First download
vpsguard geoip download

# Try to download again without --force
vpsguard geoip download
# Should skip or warn that database exists

# Force re-download
vpsguard geoip download --force
```
- [ ] Without --force: skips download if database exists
- [ ] With --force: re-downloads even if database exists
- [ ] New database replaces old one

#### Verify Download
```bash
vpsguard geoip status
```
- [ ] Shows database is installed
- [ ] Shows file size (~70MB)
- [ ] Shows database date

#### Analyze with GeoIP
```bash
vpsguard analyze test.log --geoip
```
- [ ] IP addresses show country/city
- [ ] Geographic context in findings
- [ ] If database missing: shows warning and continues

#### Delete Database
```bash
vpsguard geoip delete
```
- [ ] Removes database file
- [ ] Confirms deletion
- [ ] `geoip status` shows not installed

---

## 4. Detection Rule Testing

VPSGuard has 7 detection rules. Test each one.

### 4.1 Brute Force Rule

Triggers when same IP has N+ failed logins in M minutes.

```bash
# Generate brute force pattern
vpsguard generate --entries 500 --attack-profile brute:0.3 --output brute-test.log
vpsguard analyze brute-test.log
```
- [ ] Detection: "Brute Force" or similar finding
- [ ] Severity: HIGH
- [ ] Shows IP address
- [ ] Shows failure count

### 4.2 Breach Detection Rule

Triggers when failed attempts followed by successful login.

```bash
vpsguard generate --entries 500 --attack-profile breach:0.2 --output breach-test.log
vpsguard analyze breach-test.log
```
- [ ] Detection: "Breach" or "Successful login after failures"
- [ ] Severity: CRITICAL
- [ ] Shows IP and username
- [ ] Shows failure count before success

### 4.3 Quiet Hours Rule

Triggers for successful logins during off-hours (11 PM - 6 AM by default).

```bash
# Generate logs and analyze with verbose to see medium severity
vpsguard generate --entries 1000 --output quiet-test.log
vpsguard analyze quiet-test.log -v
```
- [ ] If any logins during quiet hours: shows "Quiet Hours" finding
- [ ] Severity: MEDIUM
- [ ] Shows time of login

### 4.4 Invalid User Rule

Triggers for attempts on non-existent usernames.

```bash
vpsguard generate --entries 500 --attack-profile recon:0.2 --output recon-test.log
vpsguard analyze recon-test.log -v
```
- [ ] Detection: "Invalid User" attempts
- [ ] Severity: MEDIUM
- [ ] Shows attempted usernames

### 4.5 Root Login Rule

Triggers for direct root login attempts.

```bash
vpsguard generate --entries 500 --output root-test.log
vpsguard analyze root-test.log -v
```
- [ ] If root attempts in log: shows root login finding
- [ ] Severity: MEDIUM

### 4.6 Multi-Vector Rule

Triggers when same IP attacks multiple services (requires multi-log correlation).

```bash
# Generate two different log types
vpsguard generate --entries 500 --output multi-auth.log
vpsguard generate --entries 500 --format secure --output multi-secure.log

# Analyze together
vpsguard analyze multi-auth.log multi-secure.log
```
- [ ] Shows "Multi-Vector" findings for IPs in both logs
- [ ] Severity: HIGH
- [ ] Shows source files

### 4.7 Geo Velocity Rule

Triggers for impossible travel (logins from distant locations too quickly).

```bash
# Requires GeoIP database
vpsguard geoip download

# Generate and analyze with GeoIP
vpsguard generate --entries 1000 --output geo-test.log
vpsguard analyze geo-test.log --geoip
```
- [ ] If user has logins from distant IPs: shows velocity warning
- [ ] Severity: HIGH
- [ ] Shows travel speed and distance

---

## 5. ML Anomaly Detection Testing

ML detection catches distributed/novel attacks that rules miss.

### 5.1 Train Baseline Model

```bash
# Generate clean baseline (no attacks)
vpsguard generate --entries 5000 --output ml-baseline.log

# Train model
vpsguard train ml-baseline.log --model ml-test.pkl
```
- [ ] Training completes
- [ ] Shows baseline statistics
- [ ] Model file created

### 5.2 Analyze with ML

```bash
# Generate attack traffic
vpsguard generate --entries 1000 --attack-profile botnet:0.2 --output ml-test.log

# Analyze with ML
vpsguard analyze ml-test.log --with-ml --model ml-test.pkl
```
- [ ] Shows anomaly section in report
- [ ] Anomalies have scores (0.0 - 1.0)
- [ ] High scores (>0.5) indicate suspicious behavior

### 5.3 Explainability

```bash
vpsguard analyze ml-test.log --with-ml --model ml-test.pkl -v
```
- [ ] Anomalies show "Why" explanation
- [ ] Lists features that deviated from baseline
- [ ] Z-scores shown for each deviation

### 5.4 Baseline Drift Detection

```bash
# Train on clean data
vpsguard generate --entries 3000 --output drift-baseline.log
vpsguard train drift-baseline.log --model drift.pkl

# Analyze very different data
vpsguard generate --entries 1000 --attack-profile botnet:0.5 --output drift-attack.log
vpsguard analyze drift-attack.log --with-ml --model drift.pkl
```
- [ ] If data significantly different: shows drift warning
- [ ] Suggests retraining model

---

## 6. GeoIP Feature Testing

### 6.1 IP Geolocation

```bash
vpsguard geoip download
vpsguard generate --entries 500 --output geo-test.log
vpsguard analyze geo-test.log --geoip
```
- [ ] IPs show country code (US, RU, CN, etc.)
- [ ] IPs show city when available
- [ ] Private IPs (192.168.x.x, 10.x.x.x) show as local/unknown

### 6.2 Geographic Velocity Detection

```bash
vpsguard analyze geo-test.log --geoip -v
```
- [ ] If same user from distant IPs: velocity warning
- [ ] Shows km/h travel speed
- [ ] Shows from/to locations

### 6.3 Graceful Degradation

```bash
# Delete database
vpsguard geoip delete

# Try analysis with --geoip
vpsguard analyze test.log --geoip
```
- [ ] Shows warning that database not found
- [ ] Analysis continues without geo data
- [ ] No crash or error

---

## 7. Multi-Log Correlation Testing

### 7.1 Multiple File Analysis

```bash
# Generate different log types
vpsguard generate --entries 500 --output multi1.log
vpsguard generate --entries 500 --format secure --output multi2.log

# Analyze together
vpsguard analyze multi1.log multi2.log
```
- [ ] Both files parsed
- [ ] Events correlated by IP
- [ ] Report shows source attribution

### 7.2 Multi-Vector Attack Detection

```bash
vpsguard analyze multi1.log multi2.log -v
```
- [ ] IPs appearing in multiple logs flagged
- [ ] "Multi-Vector" or similar finding
- [ ] Shows which sources (auth.log, secure)

### 7.3 attack_vectors ML Feature

```bash
vpsguard train multi1.log multi2.log --model multi.pkl
vpsguard analyze multi1.log multi2.log --with-ml --model multi.pkl
```
- [ ] ML considers attack_vectors feature
- [ ] IPs in multiple sources score higher

---

## 8. Output Format Testing

### 8.1 Terminal Output

```bash
vpsguard analyze test.log --format terminal
```
- [ ] Colored output (if terminal supports)
- [ ] Box drawing characters for report
- [ ] Severity color-coded

### 8.2 Markdown Output

```bash
vpsguard analyze test.log --format markdown --output report.md
```
- [ ] Valid markdown syntax
- [ ] Headers, tables, lists
- [ ] Renders correctly in markdown viewer

### 8.3 JSON Output

```bash
vpsguard analyze test.log --format json --output report.json
```
- [ ] Valid JSON (use `python -m json.tool report.json`)
- [ ] Contains: summary, violations, anomalies
- [ ] Each finding has: ip, rule, severity, message

### 8.4 HTML Output

```bash
vpsguard analyze test.log --format html --output report.html
```
- [ ] Valid HTML
- [ ] Opens in browser
- [ ] Styled and readable
- [ ] Severity color-coded

---

## 9. Error Handling Testing

### 9.1 Missing File

```bash
vpsguard analyze nonexistent.log
```
- [ ] Clear error message
- [ ] Non-zero exit code
- [ ] No stack trace (unless debug mode)

### 9.2 Invalid Log Format

```bash
echo "this is not a valid log" > invalid.log
vpsguard parse invalid.log
```
- [ ] Handles gracefully
- [ ] May show 0 events parsed
- [ ] No crash

### 9.3 Invalid Config File

```bash
echo "invalid toml [[[ syntax" > bad-config.toml
vpsguard analyze test.log --config bad-config.toml
```
- [ ] Clear error about config syntax
- [ ] Non-zero exit code

### 9.4 Invalid Attack Profile

```bash
vpsguard generate --entries 100 --attack-profile invalid:0.1
```
- [ ] Error: unknown attack profile
- [ ] Lists valid profiles

### 9.5 Invalid Attack Ratio

```bash
vpsguard generate --entries 100 --attack-profile botnet:1.5
```
- [ ] Error: ratio must be 0.0-1.0
- [ ] Or handles by capping at 1.0

### 9.6 Missing Model for ML

```bash
rm -f vpsguard_model.pkl
vpsguard analyze test.log --with-ml
```
- [ ] Clear error about missing model
- [ ] Suggests running train command

---

## 10. Configuration Testing

Test configuration file options and their effects.

### 10.1 Whitelist IP Testing

Verify whitelisted IPs are excluded from detection.

```bash
# 1. Generate test data with known attack IP
vpsguard generate --entries 500 --attack-profile brute:0.3 --seed 42 --output whitelist-test.log

# 2. Analyze without whitelist - note the attacking IPs
vpsguard analyze whitelist-test.log

# 3. Create config with whitelist
vpsguard init --output whitelist-config.toml
```

Edit `whitelist-config.toml` to add an attacking IP:
```toml
[whitelist]
ips = ["<attacking-ip-from-step-2>"]
```

```bash
# 4. Analyze with whitelist config
vpsguard analyze whitelist-test.log --config whitelist-config.toml
```
- [ ] Whitelisted IP no longer appears in findings
- [ ] Other attacking IPs still detected
- [ ] Whitelist applies to all rules

### 10.2 Rule Threshold Tuning

Test adjusting rule thresholds via config.

```bash
# 1. Generate brute force data
vpsguard generate --entries 500 --attack-profile brute:0.2 --output threshold-test.log

# 2. Analyze with default thresholds
vpsguard analyze threshold-test.log

# 3. Create config with higher threshold
vpsguard init --output threshold-config.toml
```

Edit `threshold-config.toml`:
```toml
[rules.brute_force]
enabled = true
threshold = 50  # Increase from default 10
window_minutes = 5
```

```bash
# 4. Analyze with higher threshold
vpsguard analyze threshold-test.log --config threshold-config.toml
```
- [ ] Fewer brute force findings with higher threshold
- [ ] Only IPs with 50+ failures flagged
- [ ] Other rules unaffected

### 10.3 Disable Individual Rules

```bash
vpsguard init --output disable-rules.toml
```

Edit `disable-rules.toml`:
```toml
[rules.brute_force]
enabled = false

[rules.quiet_hours]
enabled = false
```

```bash
vpsguard generate --entries 1000 --attack-profile brute:0.2 --output disable-test.log
vpsguard analyze disable-test.log --config disable-rules.toml -v
```
- [ ] No brute force findings (rule disabled)
- [ ] No quiet hours findings (rule disabled)
- [ ] Other rules still active

### 10.4 Watch Output Configuration

Test watch daemon output settings.

```bash
vpsguard init --output watch-output-config.toml
```

Edit `watch-output-config.toml`:
```toml
[watch.output]
directory = "./test-reports"
formats = ["markdown", "json", "html"]

[watch.schedule]
interval = "5m"
alert_threshold_high = 3
alert_threshold_critical = 1
```

```bash
# Create report directory
mkdir -p ./test-reports

# Run watch with custom output config
vpsguard watch test.log --foreground --once --config watch-output-config.toml

# Check reports
ls ./test-reports/
```
- [ ] Reports saved to custom directory (./test-reports/)
- [ ] All three formats generated (markdown, json, html)
- [ ] Reports named with timestamp

### 10.5 Watch Alert Thresholds

Test alert threshold configuration.

```bash
# Generate data with many findings
vpsguard generate --entries 1000 --attack-profile botnet:0.3 --output alert-test.log

vpsguard init --output alert-config.toml
```

Edit `alert-config.toml`:
```toml
[watch.schedule]
alert_threshold_high = 10
alert_threshold_critical = 5
```

```bash
vpsguard watch alert-test.log --foreground --once --config alert-config.toml
```
- [ ] Alert triggered if findings exceed thresholds
- [ ] Report generated when thresholds exceeded
- [ ] Threshold counts visible in output

### 10.6 GeoIP Configuration

```bash
vpsguard init --output geoip-config.toml
```

Edit `geoip-config.toml`:
```toml
[geoip]
enabled = true
database_path = "~/.vpsguard/GeoLite2-City.mmdb"

[rules.geo_velocity]
enabled = true
max_velocity_km_h = 500  # Stricter than default 1000
```

```bash
vpsguard analyze test.log --geoip --config geoip-config.toml
```
- [ ] GeoIP lookups enabled
- [ ] Custom database path used (if specified)
- [ ] Geo velocity rule uses configured max speed

---

## 11. End-to-End Scenarios

### Scenario 1: New Server Setup

Simulate setting up VPSGuard on a new server.

```bash
# 1. Initialize config
vpsguard init

# 2. Download GeoIP database
vpsguard geoip download

# 3. Analyze real logs (or generated)
vpsguard generate --entries 5000 --attack-profile botnet:0.05 --output server.log
vpsguard analyze server.log --geoip --save-history

# 4. Set up continuous monitoring
vpsguard watch server.log --foreground --once
```

- [ ] All steps complete without error
- [ ] Config file created
- [ ] GeoIP working
- [ ] Analysis shows findings
- [ ] History saved

### Scenario 2: Security Incident Investigation

Simulate investigating after an alert.

```bash
# 1. Generate logs with breach
vpsguard generate --entries 2000 --attack-profile breach:0.1 --output incident.log

# 2. Quick analysis
vpsguard analyze incident.log

# 3. Get more details
vpsguard analyze incident.log -vv --geoip

# 4. Save report
vpsguard analyze incident.log --format markdown --output incident-report.md

# 5. Check IP history
vpsguard analyze incident.log --save-history
vpsguard history top --limit 5
```

- [ ] Breach detected
- [ ] Full details with -vv
- [ ] Geographic info shown
- [ ] Report generated
- [ ] Top offenders listed

### Scenario 3: ML Training and Detection

Full ML workflow.

```bash
# 1. Generate clean baseline (normal traffic)
vpsguard generate --entries 10000 --output normal-baseline.log

# 2. Train model
vpsguard train normal-baseline.log --model production.pkl

# 3. Generate attack traffic
vpsguard generate --entries 2000 --attack-profile botnet:0.15 --output new-traffic.log

# 4. Analyze with ML
vpsguard analyze new-traffic.log --with-ml --model production.pkl

# 5. Check explanations
vpsguard analyze new-traffic.log --with-ml --model production.pkl -v
```

- [ ] Baseline trained
- [ ] Anomalies detected
- [ ] Explanations show feature deviations
- [ ] Distributed attack patterns flagged

### Scenario 4: Multi-Service Correlation

Correlate attacks across services.

```bash
# 1. Generate multiple log types
vpsguard generate --entries 1000 --attack-profile botnet:0.1 --output web-auth.log
vpsguard generate --entries 1000 --format secure --output ssh-secure.log

# 2. Analyze together
vpsguard analyze web-auth.log ssh-secure.log --geoip

# 3. Get JSON for automation
vpsguard analyze web-auth.log ssh-secure.log --format json --output correlated.json
```

- [ ] Both logs parsed
- [ ] Multi-vector attacks detected
- [ ] Source attribution shown
- [ ] JSON output machine-readable

---

## Test Results Summary

After completing all tests, fill in this summary:

| Section | Tests Passed | Tests Failed | Notes |
|---------|--------------|--------------|-------|
| 1. Prerequisites | / | | |
| 2. Quick Start | / | | |
| 3.1 Parse | / | | |
| 3.2 Generate | / | | |
| 3.3 Init | / | | |
| 3.4 Train | / | | |
| 3.5 Analyze | / | | |
| 3.6 Watch | / | | |
| 3.7 History | / | | |
| 3.8 GeoIP | / | | |
| 4. Rules | /7 | | |
| 5. ML | / | | |
| 6. GeoIP Features | / | | |
| 7. Multi-Log | / | | |
| 8. Output Formats | /4 | | |
| 9. Error Handling | /6 | | |
| 10. Configuration | /6 | | |
| 11. Scenarios | /4 | | |

**Total: ____ passed / ____ total**

---

## Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| `vpsguard: command not found` | Run `python -m pip install -e .` from project root |
| Python version error | Ensure Python 3.10+ with `python --version` |
| GeoIP download fails | Check internet connection; file is ~70MB |
| ML model not found | Run `vpsguard train` first |
| Permission denied (watch) | Check file permissions; daemon needs write access |
| Empty analysis results | Check log format matches content |

### Getting Help

- Run any command with `--help` for usage
- Check project README.md for documentation
- Report issues at https://github.com/Nijaek/vps-guard/issues

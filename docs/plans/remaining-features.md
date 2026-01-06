# VPSGuard — Remaining Features

**Created:** 2025-01-05
**Updated:** 2026-01-05
**Status:** In Progress

---

## Priority Overview

| Priority | Feature | Complexity | Value | Status |
|----------|---------|------------|-------|--------|
| **P1** | GeoIP Integration | Medium | High | **Complete** |
| **P2** | Unified Multi-Log Correlation | Medium | High | **Complete** |
| **P3** | Geographic Velocity Detection | Medium | Medium | **Complete** |
| **P4** | Notifications (Email/Slack/Discord) | Low | Optional | Planned |

---

## P1: GeoIP Integration

### Overview
Add geographic context to IP addresses using MaxMind's free GeoLite2 database. Enables country/city identification for attack sources.

### User Experience
```bash
# First-time setup: download GeoLite2 database
vpsguard geoip download

# Analyze with geo enrichment (requires downloaded database)
vpsguard analyze /var/log/auth.log --geoip

# Check database status
vpsguard geoip status
```

### Implementation Components

| Component | Description | Files |
|-----------|-------------|-------|
| GeoIP Module | Reader wrapper for geoip2 library | `src/vpsguard/geo/__init__.py`, `geo/reader.py` |
| Database Manager | Download, store, update GeoLite2 | `geo/database.py` |
| CLI Commands | `geoip download`, `geoip status` | `cli.py` |
| Event Enrichment | Add geo fields on-demand | `geo/enricher.py` |
| Report Enhancement | Show country/city in findings | `reporters/*.py` |
| Config Section | GeoIP settings | `config.py` |

### Database Strategy
- **Location:** `~/.vpsguard/GeoLite2-City.mmdb`
- **Download:** Direct from MaxMind (requires free license key) OR bundled URL
- **Graceful degradation:** If not downloaded, `--geoip` flag shows warning and skips geo enrichment

### Dependencies
```
geoip2>=4.0
```

### Config Schema
```toml
[geoip]
enabled = true
database_path = "~/.vpsguard/GeoLite2-City.mmdb"
# license_key = ""  # Optional: for auto-updates from MaxMind
```

### Exit Criteria
- [x] `vpsguard geoip download` fetches and stores database
- [x] `vpsguard geoip status` shows database info (size, date, record count)
- [x] `vpsguard analyze --geoip` enriches IPs with country/city
- [x] Reports show geographic context for findings
- [x] Graceful error when database missing

---

## P2: Unified Multi-Log Correlation

### Overview
Correlate events across multiple log sources to detect multi-vector attacks (e.g., SSH brute force + web scanning from same IP).

### User Experience
```bash
# Analyze multiple logs together
vpsguard analyze /var/log/auth.log /var/log/nginx/access.log

# Report shows unified timeline per IP with source attribution
```

### Implementation Components

| Component | Description | Files |
|-----------|-------------|-------|
| Event Source Tracking | Add `log_source` field to AuthEvent | `models/events.py` |
| Cross-Correlation Rule | Detect multi-vector attacks | `rules/multi_vector.py` |
| IP Timeline Aggregation | Group events by IP across sources | `analysis/correlation.py` |
| ML Features | `attack_vectors` count per IP | `ml/features.py` |
| Report Enhancement | Show sources per IP finding | `reporters/*.py` |

### New Rule: Multi-Vector Attack
```python
# Trigger when same IP appears in multiple log types with suspicious activity
class MultiVectorRule:
    threshold_sources = 2  # Must appear in 2+ log types
    severity = "high"
```

### New ML Feature
```python
attack_vectors: int  # Number of distinct log sources with activity (1=targeted, 3+=scanning)
```

### Exit Criteria
- [x] Events track their source log file/type
- [x] Multi-vector rule detects IPs attacking multiple services
- [x] Reports show "Sources: auth.log, nginx" per IP
- [x] ML includes attack_vectors feature

---

## P3: Geographic Velocity Detection

### Overview
Detect "impossible travel" — when a user logs in from geographically distant locations in a short time period.

### Dependencies
- Requires P1 (GeoIP Integration) to be complete

### Implementation Components

| Component | Description | Files |
|-----------|-------------|-------|
| Velocity Calculator | Distance/time between logins | `geo/velocity.py` |
| Geo Velocity Rule | Flag impossible travel | `rules/geo_velocity.py` |
| ML Features | `max_velocity_km_h`, `unique_countries` | `ml/features.py` |

### New Rule: Impossible Travel
```python
class GeoVelocityRule:
    max_velocity_km_h = 1000  # ~flight speed
    severity = "high"

    # Trigger: User logged in from NYC, then Moscow 30 min later
    # Distance: 7500km, Time: 0.5h = 15000 km/h (impossible)
```

### New ML Features
```python
unique_countries: int       # Countries seen for this IP
max_velocity_km_h: float    # Fastest "travel" between logins
geo_distance_stddev: float  # Variance in login locations
```

### Exit Criteria
- [x] Velocity calculation between sequential logins
- [x] Geo velocity rule with configurable threshold
- [ ] ML features for geographic patterns (deferred - optional enhancement)
- [x] Reports show travel velocity warnings

---

## P4: Notifications (Optional)

### Overview
Alert on critical findings via external channels. Lower priority since existing tools (fail2ban, alertmanager) handle this well.

### Implementation Components

| Component | Description |
|-----------|-------------|
| Email (SMTP) | Send alerts via configured SMTP server |
| Slack Webhook | POST to Slack incoming webhook |
| Discord Webhook | POST to Discord webhook |

### Config Schema
```toml
[notifications.email]
enabled = false
smtp_host = "smtp.example.com"
smtp_port = 587
from = "vpsguard@example.com"
to = ["admin@example.com"]

[notifications.slack]
enabled = false
webhook_url = ""

[notifications.discord]
enabled = false
webhook_url = ""

[notifications.triggers]
on_critical = true
on_high_count = 5  # Alert if 5+ high severity findings
```

### Exit Criteria
- [ ] Email notifications work with SMTP
- [ ] Slack webhook integration
- [ ] Discord webhook integration
- [ ] Configurable triggers (severity thresholds)

---

## Implementation Schedule

### Phase 1: GeoIP Foundation (P1)
1. Add geoip2 dependency
2. Create geo module structure
3. Implement database download command
4. Add geoip status command
5. Implement event enrichment
6. Update reporters for geo display
7. Add --geoip flag to analyze
8. Tests for geo module

### Phase 2: Multi-Log Correlation (P2)
1. Add log_source to AuthEvent
2. Update parsers to set source
3. Implement multi-vector rule
4. Add attack_vectors ML feature
5. Enhance reports with source info
6. Tests for correlation

### Phase 3: Geographic Intelligence (P3)
1. Implement velocity calculator
2. Add geo_velocity rule
3. Add geo ML features
4. Tests for velocity detection

### Phase 4: Notifications (P4 - Optional)
1. Email notifier
2. Slack notifier
3. Discord notifier
4. Trigger configuration

---

## Success Metrics

| Metric | Target |
|--------|--------|
| GeoIP lookup speed | <1ms per IP |
| Database size | ~70MB (acceptable) |
| Multi-log correlation | Detect 90%+ of multi-vector attacks in test data |
| False positive rate | <5% for geo velocity rule |

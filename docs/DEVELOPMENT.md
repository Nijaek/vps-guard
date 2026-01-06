# VPSGuard Development Guide

This guide provides detailed information for developers extending VPSGuard.

## Project Architecture

### Detection Pipeline

```
Log Files → Parser → RuleEngine → MLEngine → Reporter
                         ↓             ↓
                    violations    anomalies
                         ↓             ↓
                    clean_events → (training data)
```

The rule engine serves dual purposes:
1. **Detect known attack patterns** - brute force, breach detection, etc.
2. **Filter flagged events** - so ML trains only on "clean" baseline data

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `cli.py` | Typer CLI with 8 commands |
| `parsers/` | Log format parsers returning `AuthEvent` objects |
| `rules/` | Detection rules + engine orchestrator |
| `ml/` | Feature extraction, IsolationForest detector, explainability |
| `reporters/` | Output formatters (terminal, JSON, Markdown, HTML) |
| `generators/` | Synthetic log generator for testing |
| `models/events.py` | Core dataclasses |
| `config.py` | TOML config loader |

### Protocol-Based Abstractions

VPSGuard uses protocol-based abstractions for extensibility:

- **Parser** - All parsers implement the same interface
- **Rule** - All detection rules implement the same interface
- **Detector** - ML detectors implement a common interface
- **Reporter** - Output formatters implement a common interface

## Adding a New Parser

Create a new file in `src/vpsguard/parsers/`:

```python
# src/vpsguard/parsers/myformat.py
from vpsguard.parsers.base import Parser
from vpsguard.models.events import AuthEvent, EventType

class MyFormatParser(Parser):
    """Parser for my custom log format."""

    def parse(self, line: str) -> AuthEvent | None:
        """
        Parse a log line into an AuthEvent.

        Args:
            line: Raw log line string

        Returns:
            AuthEvent if successfully parsed, None if unparseable
        """
        # 1. Parse line into components
        # Example: "2024-01-15 10:30:00 LOGIN user=admin ip=192.168.1.1 status=success"
        parts = line.split()
        if len(parts) < 5:
            return None

        # 2. Extract fields
        timestamp_str = f"{parts[0]} {parts[1]}"
        # Parse timestamp, extract user, ip, status...

        # 3. Return AuthEvent
        return AuthEvent(
            timestamp=timestamp,
            username=username,
            ip_address=ip_address,
            event_type=EventType.LOGIN_SUCCESS,
            source="myformat",
            raw_line=line,
        )
```

### Parser Tests

Add tests in `tests/test_parsers.py`:

```python
def test_myformat_parser_success():
    parser = MyFormatParser()
    event = parser.parse("2024-01-15 10:30:00 LOGIN user=admin ip=192.168.1.1 status=success")
    assert event is not None
    assert event.event_type == EventType.LOGIN_SUCCESS
    assert event.username == "admin"
    assert event.ip_address == "192.168.1.1"

def test_myformat_parser_failure():
    parser = MyFormatParser()
    event = parser.parse("2024-01-15 10:30:00 LOGIN user=admin ip=192.168.1.1 status=failed")
    assert event is not None
    assert event.event_type == EventType.LOGIN_FAILURE

def test_myformat_parser_invalid():
    parser = MyFormatParser()
    event = parser.parse("invalid log line")
    assert event is None
```

## Adding a New Detection Rule

Create a new file in `src/vpsguard/rules/`:

```python
# src/vpsguard/rules/myrule.py
from vpsguard.rules.base import Rule, RuleViolation
from vpsguard.models.events import AuthEvent, Severity

class MyRule(Rule):
    """Custom detection rule."""

    def __init__(self, config: dict):
        super().__init__(
            name="my_rule",
            description="Detects my custom pattern",
            severity=Severity.HIGH
        )
        self.threshold = config.get("threshold", 10)

    def check(self, event: AuthEvent) -> RuleViolation | None:
        """
        Check if event matches the rule pattern.

        Args:
            event: Authentication event to check

        Returns:
            RuleViolation if pattern detected, None otherwise
        """
        # Your detection logic here
        if self._is_suspicious(event):
            return RuleViolation(
                rule_name=self.name,
                severity=self.severity,
                event=event,
                description=f"Suspicious activity detected: {event.ip_address}",
            )
        return None

    def _is_suspicious(self, event: AuthEvent) -> bool:
        # Implementation details
        pass
```

### Rule Tests

Add tests in `tests/test_rules.py`:

```python
def test_myrule_detection():
    rule = MyRule({"threshold": 5})

    # Test violation detection
    suspicious_event = create_test_event(...)
    violation = rule.check(suspicious_event)
    assert violation is not None
    assert violation.severity == Severity.HIGH

def test_myrule_no_violation():
    rule = MyRule({"threshold": 5})

    # Test normal event doesn't trigger
    normal_event = create_test_event(...)
    violation = rule.check(normal_event)
    assert violation is None

def test_myrule_whitelist():
    rule = MyRule({"threshold": 5, "whitelist": ["192.168.1.1"]})

    # Test whitelisted IP doesn't trigger
    whitelisted_event = create_test_event(ip="192.168.1.1", ...)
    violation = rule.check(whitelisted_event)
    assert violation is None
```

## Testing Guidelines

### Coverage Requirements

- Minimum 80% test coverage (enforced in CI)
- New features must include tests
- Bug fixes must include regression tests

### Test Organization

| Location | Purpose |
|----------|---------|
| `tests/test_<module>.py` | Unit tests for individual components |
| `tests/test_analyze.py` | Integration tests for full pipeline |
| `tests/conftest.py` | Shared fixtures and test data |
| `tests/benchmark.py` | Performance benchmarks (100K lines) |

### Running Tests

```bash
# All tests
pytest tests/ -v

# Single file
pytest tests/test_parsers.py -v

# Single test
pytest tests/test_parsers.py::test_auth_parser_success -v

# With coverage
pytest --cov=vpsguard --cov-report=term-missing

# With coverage threshold check
pytest --cov=vpsguard --cov-fail-under=80
```

### Testing Patterns

**Unit tests** - Test individual functions/classes with mocks:
```python
def test_parser_handles_malformed_input():
    parser = AuthParser()
    assert parser.parse("garbage") is None
```

**Integration tests** - Test full pipeline:
```python
def test_full_analysis_pipeline():
    # Generate test data
    events = generate_test_events(100)

    # Run analysis
    report = analyze(events, config)

    # Verify results
    assert len(report.violations) > 0
```

**Edge cases** to always test:
- Malformed input
- Empty files
- Unicode characters
- Large files (benchmark tests)
- Boundary conditions (timestamps, thresholds)

## ML Features

VPSGuard extracts 10 features per IP for anomaly detection:

| Feature | Purpose |
|---------|---------|
| `attempts_per_hour` | Login attempt rate |
| `failure_ratio` | Failed / total attempts |
| `unique_usernames` | Number of different usernames tried |
| `username_entropy` | Randomness of usernames (detects generated names) |
| `max_failure_streak` | Longest consecutive failures |
| `has_success_after_failures` | Breach indicator |
| `hour_of_day` | Temporal pattern |
| `same_target_ips_5min` | Coordinated attack detection |
| `same_target_ips_30min` | Extended coordination window |
| `attack_vectors` | Distinct log sources per IP |

### Adding ML Features

1. Add feature extraction in `src/vpsguard/ml/features.py`
2. Update the feature vector length
3. Add tests in `tests/test_ml.py`
4. Update baseline statistics if needed

## Configuration

VPSGuard uses TOML configuration. Key sections:

```toml
[rules.my_rule]
enabled = true
threshold = 10
severity = "high"

[whitelist]
ips = ["192.168.1.1"]

[output]
format = "terminal"
verbosity = 1
```

Configuration is loaded via `src/vpsguard/config.py` and validated against dataclasses.

## Code Style

- **Type hints** - Required for all new functions
- **Docstrings** - Required for public APIs (Google style)
- **Line length** - 100 characters max
- **Formatting** - Use `ruff format`
- **Linting** - Use `ruff check`

Pre-commit hooks enforce these automatically.

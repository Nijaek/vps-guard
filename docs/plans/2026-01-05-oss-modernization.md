# VPSGuard Open Source Modernization Plan

**Date:** 2026-01-05
**Target Timeline:** 1-2 weeks (MVP for open source release)
**Goal:** Prepare VPSGuard for public open source release with focus on contributor onboarding

## Executive Summary

This plan addresses critical gaps for open source adoption while maintaining the MVP timeline (1-2 weeks). Based on comprehensive codebase review, VPSGuard demonstrates excellent software engineering practices with modern Python packaging, strong test coverage (300 tests), and clean architecture. The modernization focuses on **contributor enablement** rather than code rewrites.

### Priorities
1. **Contributor onboarding documentation** - Eliminate friction for new contributors
2. **Developer tooling automation** - Pre-commit hooks for instant feedback
3. **Security baseline** - Dependency vulnerability scanning in CI
4. **Quality gates** - Enforce test coverage standards
5. **API documentation** - Document extensibility points

---

## Section 1: Contributor Onboarding Documentation

### Current State
- Excellent README.md with user documentation
- Zero contributor-focused documentation
- New developers face friction: must read pyproject.toml to find commands, discover dev dependencies by trial-and-error
- Unclear contribution workflow

### Proposed Solution

#### 1.1 CONTRIBUTING.md (root)
The gateway document covering:

**Quick Start Setup**
```bash
# Clone and setup
git clone https://github.com/yourusername/vps-guard.git
cd vps-guard
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (runs tests/linting automatically)
pre-commit install
```

**Development Commands**
```bash
# Run all tests
python -m pytest tests/ -v

# Run single test file
python -m pytest tests/test_parsers.py -v

# Run with coverage
python -m pytest tests/ --cov=vpsguard --cov-report=term-missing

# Lint code
ruff check src/
ruff format --check src/

# Format code
ruff format src/
```

**Contribution Workflow**
1. Fork the repository
2. Create branch: `git checkout -b feature/your-feature` or `fix/your-bug`
3. Make changes with pre-commit hooks running automatically
4. Write/update tests
5. Commit with clear messages
6. Push to fork
7. Create pull request with description template

**Code Style Requirements**
- Follow existing code style
- Use ruff for linting (configured in pyproject.toml)
- Add type hints to all new functions
- Write docstrings for public APIs
- Maintain test coverage above 80%

#### 1.2 DEVELOPMENT.md (docs/)
Deep dive covering:

**Project Architecture**
- Detection pipeline: Log Files → Parser → RuleEngine → MLEngine → Reporter
- Module responsibilities and interactions
- Protocol-based abstractions (Parser, Rule, Detector, Reporter)
- Clean event separation for ML training

**Adding a New Parser**
```python
# src/vpsguard/parsers/myformat.py
from vpsguard.parsers.base import Parser
from vpsguard.models.events import AuthEvent, EventType

class MyFormatParser(Parser):
    """Parser for my custom log format."""

    def parse(self, line: str) -> AuthEvent | None:
        # 1. Parse line into components
        # 2. Validate required fields
        # 3. Return AuthEvent or None if unparseable
        pass

# Tests: tests/test_parsers.py
def test_myformat_parser_success():
    parser = MyFormatParser()
    event = parser.parse("sample log line")
    assert event is not None
    assert event.event_type == EventType.LOGIN_SUCCESS
```

**Adding a New Detection Rule**
```python
# src/vpsguard/rules/myrule.py
from vpsguard.rules.base import Rule, RuleViolation
from vpsguard.models.events import AuthEvent, Severity

class MyRule(Rule):
    """Custom detection rule."""

    def __init__(self, config: dict):
        super().__init__(
            name="my_rule",
            description="Detects my pattern",
            severity=Severity.HIGH
        )
        self.config = config

    def check(self, event: AuthEvent) -> RuleViolation | None:
        # Return RuleViolation if pattern detected
        pass

# Tests: tests/test_rules.py
def test_myrule_detection():
    rule = MyRule({})
    # Test violation detection
    # Test non-violation cases
    # Test whitelist filtering
```

**Testing Patterns**
- Unit tests: Test individual functions/classes with mocks
- Integration tests: Test full pipeline (tests/test_analyze.py)
- Use fixtures for common test data
- Test edge cases: malformed input, empty files, unicode

#### 1.3 .github/PULL_REQUEST_TEMPLATE.md
```markdown
## Description
Briefly describe the changes in this PR.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests added/updated
- [ ] All tests pass locally (`pytest tests/ -v`)
- [ ] Coverage maintained above 80%

## Checklist
- [ ] Code follows style guidelines (ruff)
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes (or documented in PR)
```

### Rationale
- **CONTRIBUTING.md** eliminates the biggest friction point: not knowing how to start
- **DEVELOPMENT.md** provides deep-dive for contributors extending the system
- **PR template** ensures consistent, complete PRs
- Each document is concise and action-oriented

---

## Section 2: Developer Tooling & Automation

### Current State
- Ruff configured and running in CI
- No local automation
- Contributors must manually remember to run commands
- Wasted CI runs from avoidable issues

### Proposed Solution

#### 2.1 Pre-commit Configuration
Create `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.9
    hooks:
      - id: ruff
        args: [--fix, --exit-non-zero-on-fix]
      - id: ruff-format
  - repo: local
    hooks:
      - id: pytest
        name: pytest
        entry: pytest tests/ -q
        language: system
        pass_types: [python]
        always_run: true
```

#### 2.2 Update pyproject.toml
```toml
[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-cov>=4.1.0",
    "ruff>=0.1.9",
]

[tool.ruff]
line-length = 100
select = ["E", "F", "W", "I"]
ignore = ["E501"]

[tool.ruff.format]
quote-style = "double"
indent-style = "space"
```

#### 2.3 Update README
Add to Development section:
```markdown
## Development Setup

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (runs automatically on commit)
pre-commit install
```
```

### Rationale
- **Ruff formatter** is fast (Rust-based) and compatible with existing linter
- **Pre-commit** catches issues instantly before commits, not after CI
- **Minimal hooks** - just formatting, linting, and tests (no slow typechecking)
- **Setup time:** ~30 minutes total

---

## Section 3: Security & Dependency Management

### Current State
- No dependency security scanning
- Dependencies specified without version constraints
- Could lead to unexpected breaking changes or vulnerabilities

### Proposed Solution

#### 3.1 Add pip-audit to CI
Update `.github/workflows/ci.yml`:
```yaml
- name: Security audit
  run: |
    pip install pip-audit
    pip-audit --desc --format json
  continue-on-error: false
```

#### 3.2 Pin Major Dependencies
Update `pyproject.toml`:
```toml
dependencies = [
    "typer>=0.9.0,<1.0",
    "rich>=13.0.0,<14.0",
    "numpy>=1.24.0,<2.0",
    "scikit-learn>=1.3.0,<2.0",
    "geoip2>=4.0.0,<5.0",
    "tomli>=2.0.0,<3.0; python_version<'3.11'",
]
```

#### 3.3 Create SECURITY.md
```markdown
# Security Policy

## Reporting Vulnerabilities
Please report security vulnerabilities privately via:
- Email: security@yourdomain.com
- GitHub Security: "Security advisories" feature

Do not open public issues for security vulnerabilities.

## Dependency Management
- Automated dependency scanning runs on every PR via pip-audit
- Dependencies are pinned to compatible versions
- Security updates are tested before release
```

### Rationale
- **pip-audit** checks against PyPI's vulnerability database
- **CI integration** means automatic scanning on every PR
- **Version constraints** prevent surprise breaking changes
- **Minimal overhead:** ~1 minute CI time, ~30 minutes setup

---

## Section 4: Testing & Quality Gates

### Current State
- Excellent test coverage (300 tests across 16 files)
- Coverage reporting not enforced
- No quality gates preventing low-coverage code from merging

### Proposed Solution

#### 4.1 Enforce Coverage in CI
Update `.github/workflows/ci.yml`:
```yaml
- name: Run tests with coverage
  run: |
    pytest --cov=vpsguard --cov-report=xml --cov-report=term-missing

- name: Check coverage threshold
  run: |
    coverage report --fail-under=80
```

#### 4.2 Pytest Configuration
Update `pyproject.toml`:
```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_functions = ["test_*"]
addopts = "-ra --strict-markers --disable-warnings"
```

#### 4.3 Document Testing in DEVELOPMENT.md
```markdown
## Testing Guidelines

### Coverage Requirements
- Minimum 80% test coverage
- New features must include tests
- Bug fixes must include regression tests

### Test Organization
- Unit tests: `tests/test_<module>.py` - Test individual components
- Integration tests: `tests/test_analyze.py` - Test full pipeline
- Fixtures: `tests/conftest.py` - Shared test data

### Running Tests
```bash
# All tests
pytest tests/ -v

# Single file
pytest tests/test_parsers.py -v

# With coverage
pytest --cov=vpsguard --cov-report=term-missing
```
```

### Rationale
- **80% threshold** enforces quality without being punitive
- **Existing tests are good** - adding gates, not rewriting
- **Catches coverage regressions** automatically in PRs
- **Setup time:** ~20 minutes

---

## Section 5: API Documentation & Public Stability

### Current State
- Comprehensive docstrings and type hints (557 docstring occurrences)
- No generated API documentation
- Users extending VPSGuard must read source code

### Proposed Solution

#### 5.1 Add API Reference to README.md
```markdown
## API Reference

### Extending VPSGuard

VPSGuard is designed to be extensible through protocol-based interfaces.

#### Adding a Custom Parser

```python
from vpsguard.parsers.base import Parser
from vpsguard.models.events import AuthEvent, EventType

class MyCustomParser(Parser):
    """Parse custom log format."""

    def parse(self, line: str) -> AuthEvent | None:
        """
        Parse a log line into an AuthEvent.

        Args:
            line: Raw log line

        Returns:
            AuthEvent if successfully parsed, None otherwise
        """
        # Your implementation
        pass
```

#### Adding a Custom Detection Rule

```python
from vpsguard.rules.base import Rule, RuleViolation
from vpsguard.models.events import AuthEvent
from vpsguard.models.events import Severity

class MyCustomRule(Rule):
    """Custom detection rule."""

    def __init__(self, config: dict):
        super().__init__(
            name="my_custom_rule",
            description="Detects my custom pattern",
            severity=Severity.MEDIUM
        )
        self.config = config

    def check(self, event: AuthEvent) -> RuleViolation | None:
        """
        Check if event matches rule.

        Args:
            event: Authentication event to check

        Returns:
            RuleViolation if matched, None otherwise
        """
        # Your implementation
        pass
```

### Public API Stability

The following APIs are stable and follow semantic versioning:

- **vpsguard.models.\*** - Core data structures (AuthEvent, RuleViolation, etc.)
- **vpsguard.parsers.base.Parser** - Parser protocol interface
- **vpsguard.rules.base.Rule** - Rule protocol interface
- **vpsguard.cli** - CLI command interface

All internal modules may change without notice. For extending VPSGuard,
use the protocol-based interfaces defined in `parsers.base` and `rules.base`.

For detailed API documentation, see inline docstrings in the source code.
```

#### 5.2 Document Stability in CONTRIBUTING.md
```markdown
## API Stability

### Stable APIs (Semantic Versioning)
- `vpsguard.models.events` - Core dataclasses
- `vpsguard.parsers.base.Parser` - Protocol interface
- `vpsguard.rules.base.Rule` - Protocol interface
- `vpsguard.cli` - Command-line interface

### Internal APIs (May Change)
- All other modules
- Implementation details
- Internal helper functions

When contributing, avoid changing stable APIs without discussion.
```

### Rationale
- **No Sphinx/MkDocs setup** needed for MVP (saves hours)
- **README examples** are immediately visible to users
- **Inline docstrings** already excellent (557 occurrences)
- **Extensibility points** clearly documented
- **Setup time:** ~1 hour

For post-MVP, consider Sphinx with auto-generated API docs.

---

## Implementation Plan

### Week 1: Documentation & Tooling
| Day | Tasks | Estimated Time |
|-----|-------|----------------|
| 1 | Create CONTRIBUTING.md | 2 hours |
| 1 | Create DEVELOPMENT.md | 3 hours |
| 2 | Create PR template | 1 hour |
| 2 | Setup pre-commit config | 1 hour |
| 2 | Update pyproject.toml | 1 hour |
| 3 | Add pip-audit to CI | 1 hour |
| 3 | Pin dependency versions | 1 hour |
| 3 | Create SECURITY.md | 1 hour |
| 4 | Add coverage gate to CI | 1 hour |
| 4 | Update pyproject.toml (pytest config) | 0.5 hours |
| 5 | Add API reference to README | 1 hour |
| 5 | Test all changes | 2 hours |

### Week 2: Validation & Polish
| Day | Tasks | Estimated Time |
|-----|-------|----------------|
| 1 | Test contributor setup from scratch | 2 hours |
| 1 | Verify all CI checks pass | 1 hour |
| 2 | Review and refine docs | 2 hours |
| 2 | Test pre-commit hooks | 1 hour |
| 3 | Verify security scanning works | 1 hour |
| 3 | Final coverage check | 1 hour |
| 4 | Update README with new sections | 1 hour |
| 4 | Final validation of all changes | 2 hours |
| 5 | Buffer for issues/discoveries | 4 hours |

**Total Estimated Time:** ~35 hours (within 1-2 week target)

---

## Success Criteria

- [ ] New contributor can setup dev environment in <10 minutes using CONTRIBUTING.md
- [ ] Pre-commit hooks catch all linting/formatting issues before commit
- [ ] CI fails on security vulnerabilities or coverage <80%
- [ ] Extensibility documented with working code examples
- [ ] All existing tests still pass
- [ ] No breaking changes to existing functionality

---

## Out of Scope (Future Enhancements)

Items identified but deferred for post-MVP:

1. **Type checking with mypy** - Adds complexity, type hints already good
2. **Sphinx/MkDocs API documentation** - README + inline docs sufficient for MVP
3. **Code coverage badges** - Nice to have, not critical
4. **Dependabot/renovate** - Automate dependency updates post-release
5. **Performance benchmarking in CI** - Existing benchmarks sufficient
6. **Multi-platform integration testing** - Current matrix (3.10, 3.11, 3.12) sufficient
7. **Separate utils/ module** - Refactoring, not critical for MVP

---

## Context7 References

Modern Python best practices consulted:
- Python Packaging Authority (PyPA) packaging guidelines
- Pre-commit framework documentation
- pytest coverage configuration
- pip-audit security scanning
- Ruff formatter configuration

---

## Appendix: Codebase Summary

### Current Strengths
- Modern src/ layout with pyproject.toml
- Excellent test coverage (300 tests, 16 test files)
- Strong typing (310+ type hints across 38 files)
- Protocol-based abstractions for extensibility
- Comprehensive docstrings (557 occurrences)
- Clean architecture with clear separation of concerns

### Areas Addressed by This Plan
1. Contributor onboarding friction
2. Missing developer automation
3. Security scanning gap
4. Coverage quality gates
5. Public API documentation

### Technical Debt Noted (Non-Blocking)
1. One TODO in `rules/quiet_hours.py` regarding timezone handling
2. Inconsistent docstring quality in some modules
3. Some large modules could be split (ml/ directory)
4. No requirements.txt for older tools that don't support pyproject.toml

These are noted but not addressed in MVP modernization.

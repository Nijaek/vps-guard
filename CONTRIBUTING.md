# Contributing to VPSGuard

Thank you for your interest in contributing to VPSGuard! This document provides guidelines and instructions for contributing.

## Quick Start Setup

```bash
# Clone and setup
git clone https://github.com/Nijaek/vps-guard.git
cd vps-guard
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (runs tests/linting automatically)
pre-commit install
```

## Development Commands

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

## Contribution Workflow

1. **Fork the repository** on GitHub
2. **Create a branch**: `git checkout -b feature/your-feature` or `fix/your-bug`
3. **Make changes** - pre-commit hooks run automatically on commit
4. **Write/update tests** - all new features need tests
5. **Commit with clear messages** - describe what and why
6. **Push to your fork**: `git push origin feature/your-feature`
7. **Create a pull request** - use the PR template

## Code Style Requirements

- Follow existing code style in the codebase
- Use ruff for linting (configured in pyproject.toml)
- Add type hints to all new functions
- Write docstrings for public APIs
- Maintain test coverage above 80%

## Types of Contributions

### Bug Reports

- Check existing issues first
- Include Python version, OS, and steps to reproduce
- Provide sample log files if relevant (anonymized)

### Feature Requests

- Open an issue to discuss before implementing
- Describe the use case and expected behavior
- Consider how it fits with VPSGuard's scope (batch analysis, not real-time blocking)

### Code Contributions

- Bug fixes are always welcome
- New parsers for additional log formats
- New detection rules
- Documentation improvements
- Test coverage improvements

## API Stability

### Stable APIs (Semantic Versioning)

These APIs are considered stable and follow semantic versioning:

- `vpsguard.models.events` - Core dataclasses (AuthEvent, RuleViolation, etc.)
- `vpsguard.parsers.base.Parser` - Protocol interface for parsers
- `vpsguard.rules.base.Rule` - Protocol interface for rules
- `vpsguard.cli` - Command-line interface

### Internal APIs (May Change)

- All other modules
- Implementation details
- Internal helper functions

When contributing, avoid changing stable APIs without discussion.

## Getting Help

- Read the [Development Guide](docs/DEVELOPMENT.md) for architecture details
- Check existing issues and discussions
- Open an issue for questions about contributing

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

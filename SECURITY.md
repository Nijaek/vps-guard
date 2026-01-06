# Security Policy

## Reporting Vulnerabilities

Please report security vulnerabilities privately via:

- **GitHub Security Advisories**: Use the "Security" tab → "Report a vulnerability" feature
- **Email**: Open an issue requesting a security contact (we'll respond with a private channel)

**Do not open public issues for security vulnerabilities.**

We aim to respond to security reports within 48 hours and provide a fix timeline within 7 days.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Dependency Management

- Automated dependency scanning runs on every PR via pip-audit
- Dependencies are pinned to compatible major versions
- Security updates are tested before release

## Security Considerations

VPSGuard is a log analysis tool that:

- Reads log files (requires appropriate file permissions)
- Stores ML models and analysis history locally
- Does not transmit data externally
- Does not require network access (except optional GeoIP database download)

### GeoIP Database

The optional GeoIP feature downloads the MaxMind GeoLite2 database. This is the only external network access the tool performs. The database is stored locally and no log data is sent externally.

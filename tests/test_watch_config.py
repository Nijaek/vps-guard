"""Tests for watch configuration schema."""

from vpsguard.config import load_config, validate_config


def test_watch_schedule_defaults():
    """Watch schedule config should have sensible defaults."""
    config = load_config()

    assert hasattr(config, 'watch_schedule')
    assert config.watch_schedule.interval == "1h"
    assert config.watch_schedule.retention_days == 30


def test_watch_schedule_from_toml(tmp_path):
    """Should load watch schedule from TOML config."""
    toml_content = """
[watch.schedule]
interval = "30m"
retention_days = 14

[watch.schedule.alerts]
critical_threshold = 1
high_threshold = 10
anomaly_threshold = 5

[watch.output]
directory = "/tmp/vpsguard"
formats = ["markdown", "json"]
"""
    config_path = tmp_path / "test_watch_config.toml"
    config_path.write_text(toml_content)

    config = load_config(config_path)

    assert config.watch_schedule.interval == "30m"
    assert config.watch_schedule.retention_days == 14
    assert config.watch_schedule.alerts['critical_threshold'] == 1
    assert config.watch_schedule.alerts['high_threshold'] == 10
    assert config.watch_schedule.alerts['anomaly_threshold'] == 5
    assert config.watch_output.directory == "/tmp/vpsguard"
    assert config.watch_output.formats == ["markdown", "json"]


def test_watch_interval_validation():
    """Should reject invalid interval formats."""
    config = load_config()
    config.watch_schedule.interval = "invalid"

    warnings = validate_config(config)
    assert any("interval" in w.lower() for w in warnings)


def test_watch_alert_thresholds_validation():
    """Should validate alert thresholds are non-negative."""
    config = load_config()
    config.watch_schedule.alerts = {'critical_threshold': -1}

    warnings = validate_config(config)
    assert any("threshold" in w.lower() for w in warnings)

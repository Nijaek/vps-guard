"""Tests for GeoIP module."""

import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from vpsguard.geo.reader import GeoLocation, GeoIPReader
from vpsguard.geo.database import (
    get_default_db_path,
    get_database_info,
    GeoDatabase,
)
from vpsguard.geo.velocity import (
    haversine_distance,
    calculate_velocity,
    analyze_user_travel,
    format_velocity,
    TravelEvent,
)
from vpsguard.config import load_config, VPSGuardConfig, GeoIPConfig, GeoVelocityConfig
from vpsguard.rules.geo_velocity import GeoVelocityRule
from vpsguard.models.events import AuthEvent, EventType


class TestGeoLocation:
    """Tests for GeoLocation dataclass."""

    def test_str_country_only(self):
        """Test string representation with country only."""
        loc = GeoLocation(country_code="US")
        assert str(loc) == "US"

    def test_str_with_city(self):
        """Test string representation with city and country."""
        loc = GeoLocation(country_code="US", city="New York")
        assert str(loc) == "New York, US"

    def test_str_unknown(self):
        """Test string representation when no data."""
        loc = GeoLocation()
        assert str(loc) == "Unknown"

    def test_is_known_true(self):
        """Test is_known when country is set."""
        loc = GeoLocation(country_code="GB")
        assert loc.is_known is True

    def test_is_known_false(self):
        """Test is_known when no data."""
        loc = GeoLocation()
        assert loc.is_known is False

    def test_full_location(self):
        """Test location with all fields."""
        loc = GeoLocation(
            country_code="DE",
            country_name="Germany",
            city="Berlin",
            latitude=52.52,
            longitude=13.405,
        )
        assert loc.country_code == "DE"
        assert loc.country_name == "Germany"
        assert loc.city == "Berlin"
        assert str(loc) == "Berlin, DE"
        assert loc.is_known is True


class TestGeoIPReader:
    """Tests for GeoIPReader class."""

    def test_file_not_found(self, tmp_path):
        """Test reader raises FileNotFoundError for missing database."""
        with pytest.raises(FileNotFoundError):
            GeoIPReader(tmp_path / "nonexistent.mmdb")

    @patch("geoip2.database.Reader")
    def test_lookup_success(self, mock_reader_class, tmp_path):
        """Test successful IP lookup."""
        # Create a fake database file
        db_path = tmp_path / "test.mmdb"
        db_path.write_bytes(b"fake mmdb content")

        # Mock the geoip2 reader
        mock_reader = MagicMock()
        mock_reader_class.return_value = mock_reader

        # Mock city lookup response
        mock_response = MagicMock()
        mock_response.country.iso_code = "US"
        mock_response.country.name = "United States"
        mock_response.city.name = "Mountain View"
        mock_response.location.latitude = 37.386
        mock_response.location.longitude = -122.084
        mock_reader.city.return_value = mock_response

        reader = GeoIPReader(db_path)
        location = reader.lookup("8.8.8.8")

        assert location.country_code == "US"
        assert location.country_name == "United States"
        assert location.city == "Mountain View"
        assert location.is_known is True

    @patch("geoip2.database.Reader")
    def test_lookup_caching(self, mock_reader_class, tmp_path):
        """Test that lookups are cached."""
        db_path = tmp_path / "test.mmdb"
        db_path.write_bytes(b"fake mmdb content")

        mock_reader = MagicMock()
        mock_reader_class.return_value = mock_reader

        mock_response = MagicMock()
        mock_response.country.iso_code = "US"
        mock_response.country.name = "United States"
        mock_response.city.name = None
        mock_response.location.latitude = None
        mock_response.location.longitude = None
        mock_reader.city.return_value = mock_response

        reader = GeoIPReader(db_path)

        # First lookup
        reader.lookup("8.8.8.8")
        # Second lookup should use cache
        reader.lookup("8.8.8.8")

        # city() should only be called once due to caching
        assert mock_reader.city.call_count == 1

    @patch("geoip2.database.Reader")
    def test_lookup_failure_returns_empty(self, mock_reader_class, tmp_path):
        """Test that lookup failures return empty GeoLocation."""
        db_path = tmp_path / "test.mmdb"
        db_path.write_bytes(b"fake mmdb content")

        mock_reader = MagicMock()
        mock_reader_class.return_value = mock_reader
        mock_reader.city.side_effect = Exception("IP not found")

        reader = GeoIPReader(db_path)
        location = reader.lookup("192.168.1.1")

        assert location.is_known is False
        assert location.country_code is None

    @patch("geoip2.database.Reader")
    def test_lookup_many(self, mock_reader_class, tmp_path):
        """Test looking up multiple IPs."""
        db_path = tmp_path / "test.mmdb"
        db_path.write_bytes(b"fake mmdb content")

        mock_reader = MagicMock()
        mock_reader_class.return_value = mock_reader

        def mock_city(ip):
            response = MagicMock()
            if ip == "8.8.8.8":
                response.country.iso_code = "US"
                response.country.name = "United States"
            else:
                response.country.iso_code = "DE"
                response.country.name = "Germany"
            response.city.name = None
            response.location.latitude = None
            response.location.longitude = None
            return response

        mock_reader.city.side_effect = mock_city

        reader = GeoIPReader(db_path)
        results = reader.lookup_many(["8.8.8.8", "1.1.1.1", "8.8.8.8"])

        assert len(results) == 2  # Deduped
        assert results["8.8.8.8"].country_code == "US"
        assert results["1.1.1.1"].country_code == "DE"

    @patch("geoip2.database.Reader")
    def test_context_manager(self, mock_reader_class, tmp_path):
        """Test reader as context manager."""
        db_path = tmp_path / "test.mmdb"
        db_path.write_bytes(b"fake mmdb content")

        mock_reader = MagicMock()
        mock_reader_class.return_value = mock_reader

        with GeoIPReader(db_path) as reader:
            assert reader is not None

        mock_reader.close.assert_called_once()


class TestDatabaseInfo:
    """Tests for database info functions."""

    def test_default_path(self):
        """Test default database path."""
        path = get_default_db_path()
        assert path == Path.home() / ".vpsguard" / "GeoLite2-City.mmdb"

    def test_database_not_exists(self, tmp_path):
        """Test database info when file doesn't exist."""
        info = get_database_info(tmp_path / "nonexistent.mmdb")
        assert info.exists is False
        assert info.size_mb is None
        assert info.modified is None
        assert info.status == "Not downloaded"

    def test_database_exists(self, tmp_path):
        """Test database info when file exists."""
        db_path = tmp_path / "test.mmdb"
        db_path.write_bytes(b"x" * 1024 * 1024)  # 1MB

        info = get_database_info(db_path)
        assert info.exists is True
        assert info.size_mb is not None
        assert info.size_mb >= 0.99  # ~1MB
        assert info.modified is not None
        assert info.status == "Ready"


class TestGeoIPConfig:
    """Tests for GeoIP configuration."""

    def test_default_config(self):
        """Test default GeoIP config values."""
        config = load_config()
        assert config.geoip.enabled is True
        assert "GeoLite2-City.mmdb" in config.geoip.database_path

    def test_load_from_toml(self, tmp_path):
        """Test loading GeoIP config from TOML."""
        config_file = tmp_path / "test.toml"
        config_file.write_text("""
[geoip]
enabled = false
database_path = "/custom/path/geo.mmdb"
""")
        config = load_config(config_file)
        assert config.geoip.enabled is False
        assert config.geoip.database_path == "/custom/path/geo.mmdb"

    def test_partial_geoip_config(self, tmp_path):
        """Test loading partial GeoIP config (defaults fill in)."""
        config_file = tmp_path / "test.toml"
        config_file.write_text("""
[geoip]
enabled = false
""")
        config = load_config(config_file)
        assert config.geoip.enabled is False
        # database_path should use default
        assert "GeoLite2-City.mmdb" in config.geoip.database_path


class TestGeoIPInReports:
    """Tests for GeoIP data in analysis reports."""

    def test_analysis_report_with_geo_data(self):
        """Test that AnalysisReport accepts geo_data."""
        from vpsguard.models.events import AnalysisReport
        from datetime import timezone

        geo_data = {
            "1.2.3.4": GeoLocation(country_code="US", city="New York"),
            "5.6.7.8": GeoLocation(country_code="GB", city="London"),
        }

        report = AnalysisReport(
            timestamp=datetime.now(timezone.utc),
            log_source="test.log",
            total_events=100,
            rule_violations=[],
            anomalies=[],
            geo_data=geo_data,
        )

        assert report.geo_data is not None
        assert "1.2.3.4" in report.geo_data
        assert report.geo_data["1.2.3.4"].city == "New York"

    def test_analysis_report_without_geo_data(self):
        """Test that AnalysisReport works without geo_data."""
        from vpsguard.models.events import AnalysisReport
        from datetime import timezone

        report = AnalysisReport(
            timestamp=datetime.now(timezone.utc),
            log_source="test.log",
            total_events=100,
            rule_violations=[],
            anomalies=[],
        )

        assert report.geo_data is None


class TestHaversineDistance:
    """Tests for haversine distance calculation."""

    def test_same_location(self):
        """Test distance between same location is 0."""
        loc = GeoLocation(latitude=40.7128, longitude=-74.0060)  # NYC
        distance = haversine_distance(loc, loc)
        assert distance == 0.0

    def test_nyc_to_london(self):
        """Test known distance between NYC and London (~5570km)."""
        nyc = GeoLocation(latitude=40.7128, longitude=-74.0060)
        london = GeoLocation(latitude=51.5074, longitude=-0.1278)
        distance = haversine_distance(nyc, london)
        # Should be approximately 5570 km
        assert 5500 < distance < 5700

    def test_la_to_tokyo(self):
        """Test known distance between LA and Tokyo (~8800km)."""
        la = GeoLocation(latitude=34.0522, longitude=-118.2437)
        tokyo = GeoLocation(latitude=35.6762, longitude=139.6503)
        distance = haversine_distance(la, tokyo)
        # Should be approximately 8800 km
        assert 8700 < distance < 9000

    def test_missing_coordinates(self):
        """Test returns None when coordinates missing."""
        loc1 = GeoLocation(latitude=40.7128, longitude=-74.0060)
        loc2 = GeoLocation(country_code="GB")  # No coordinates
        assert haversine_distance(loc1, loc2) is None
        assert haversine_distance(loc2, loc1) is None


class TestCalculateVelocity:
    """Tests for velocity calculation."""

    def test_basic_velocity(self):
        """Test basic velocity calculation."""
        from datetime import timedelta

        nyc = GeoLocation(latitude=40.7128, longitude=-74.0060)
        london = GeoLocation(latitude=51.5074, longitude=-0.1278)

        time1 = datetime(2024, 1, 1, 10, 0, 0)
        time2 = datetime(2024, 1, 1, 18, 0, 0)  # 8 hours later

        velocity = calculate_velocity(nyc, london, time1, time2)

        # ~5570km in 8 hours = ~696 km/h
        assert 650 < velocity < 750

    def test_instant_teleport(self):
        """Test velocity is infinite for instant travel."""
        nyc = GeoLocation(latitude=40.7128, longitude=-74.0060)
        london = GeoLocation(latitude=51.5074, longitude=-0.1278)

        time1 = datetime(2024, 1, 1, 10, 0, 0)
        time2 = datetime(2024, 1, 1, 10, 0, 0)  # Same time

        velocity = calculate_velocity(nyc, london, time1, time2)
        assert velocity == float('inf')

    def test_same_location_same_time(self):
        """Test velocity is 0 for same location at same time."""
        nyc = GeoLocation(latitude=40.7128, longitude=-74.0060)

        time = datetime(2024, 1, 1, 10, 0, 0)

        velocity = calculate_velocity(nyc, nyc, time, time)
        assert velocity == 0.0

    def test_missing_coordinates_returns_none(self):
        """Test returns None when coordinates missing."""
        loc1 = GeoLocation(latitude=40.7128, longitude=-74.0060)
        loc2 = GeoLocation()

        time1 = datetime(2024, 1, 1, 10, 0, 0)
        time2 = datetime(2024, 1, 1, 12, 0, 0)

        assert calculate_velocity(loc1, loc2, time1, time2) is None


class TestFormatVelocity:
    """Tests for velocity formatting."""

    def test_normal_velocity(self):
        """Test formatting normal velocity."""
        assert format_velocity(500) == "500 km/h"

    def test_impossible_velocity(self):
        """Test formatting impossible velocity."""
        assert "impossible" in format_velocity(1500)

    def test_very_high_velocity(self):
        """Test formatting very high velocity."""
        result = format_velocity(15000)
        assert "k km/h" in result  # Should use k notation

    def test_infinite_velocity(self):
        """Test formatting infinite velocity."""
        assert format_velocity(float('inf')) == "instantaneous"


class TestGeoVelocityRule:
    """Tests for geographic velocity detection rule."""

    def test_impossible_travel_detection(self):
        """Test detection of impossible travel."""
        config = GeoVelocityConfig(max_velocity_km_h=1000, min_distance_km=100)
        rule = GeoVelocityRule(config)

        # NYC coordinates
        nyc = GeoLocation(latitude=40.7128, longitude=-74.0060, country_code="US", city="New York")
        # Tokyo coordinates
        tokyo = GeoLocation(latitude=35.6762, longitude=139.6503, country_code="JP", city="Tokyo")

        geo_data = {
            "1.1.1.1": nyc,
            "2.2.2.2": tokyo,
        }

        from datetime import timedelta
        base_time = datetime(2024, 1, 1, 10, 0, 0)

        events = [
            # User logs in from NYC
            AuthEvent(
                timestamp=base_time,
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="1.1.1.1",
                username="admin",
                success=True,
                raw_line="test"
            ),
            # Same user logs in from Tokyo 30 minutes later (impossible!)
            AuthEvent(
                timestamp=base_time + timedelta(minutes=30),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="2.2.2.2",
                username="admin",
                success=True,
                raw_line="test"
            ),
        ]

        violations = rule.evaluate(events, geo_data)

        assert len(violations) == 1
        assert violations[0].rule_name == "geo_velocity"
        assert "impossible" in violations[0].description.lower() or "travel" in violations[0].description.lower()
        assert violations[0].details["username"] == "admin"

    def test_reasonable_travel_no_violation(self):
        """Test that reasonable travel speed doesn't trigger."""
        config = GeoVelocityConfig(max_velocity_km_h=1000, min_distance_km=100)
        rule = GeoVelocityRule(config)

        nyc = GeoLocation(latitude=40.7128, longitude=-74.0060, country_code="US", city="New York")
        london = GeoLocation(latitude=51.5074, longitude=-0.1278, country_code="GB", city="London")

        geo_data = {
            "1.1.1.1": nyc,
            "2.2.2.2": london,
        }

        from datetime import timedelta
        base_time = datetime(2024, 1, 1, 10, 0, 0)

        events = [
            # User logs in from NYC
            AuthEvent(
                timestamp=base_time,
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="1.1.1.1",
                username="admin",
                success=True,
                raw_line="test"
            ),
            # Same user logs in from London 8 hours later (possible by flight)
            AuthEvent(
                timestamp=base_time + timedelta(hours=8),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="2.2.2.2",
                username="admin",
                success=True,
                raw_line="test"
            ),
        ]

        violations = rule.evaluate(events, geo_data)

        # ~5570km in 8 hours = ~696 km/h (below 1000 threshold)
        assert len(violations) == 0

    def test_no_geo_data_no_violations(self):
        """Test that rule returns no violations without geo_data."""
        config = GeoVelocityConfig()
        rule = GeoVelocityRule(config)

        events = [
            AuthEvent(
                timestamp=datetime.now(),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="1.1.1.1",
                username="admin",
                success=True,
                raw_line="test"
            ),
        ]

        violations = rule.evaluate(events, None)
        assert len(violations) == 0

    def test_disabled_rule(self):
        """Test that disabled rule returns no violations."""
        config = GeoVelocityConfig(enabled=False)
        rule = GeoVelocityRule(config)

        geo_data = {
            "1.1.1.1": GeoLocation(latitude=40.7128, longitude=-74.0060),
            "2.2.2.2": GeoLocation(latitude=35.6762, longitude=139.6503),
        }

        from datetime import timedelta
        base_time = datetime(2024, 1, 1, 10, 0, 0)

        events = [
            AuthEvent(
                timestamp=base_time,
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="1.1.1.1",
                username="admin",
                success=True,
                raw_line="test"
            ),
            AuthEvent(
                timestamp=base_time + timedelta(minutes=1),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="2.2.2.2",
                username="admin",
                success=True,
                raw_line="test"
            ),
        ]

        violations = rule.evaluate(events, geo_data)
        assert len(violations) == 0

    def test_same_ip_no_violation(self):
        """Test that same IP doesn't trigger violation."""
        config = GeoVelocityConfig(max_velocity_km_h=1000, min_distance_km=100)
        rule = GeoVelocityRule(config)

        nyc = GeoLocation(latitude=40.7128, longitude=-74.0060)

        geo_data = {"1.1.1.1": nyc}

        from datetime import timedelta
        base_time = datetime(2024, 1, 1, 10, 0, 0)

        events = [
            AuthEvent(
                timestamp=base_time,
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="1.1.1.1",
                username="admin",
                success=True,
                raw_line="test"
            ),
            AuthEvent(
                timestamp=base_time + timedelta(minutes=1),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="1.1.1.1",
                username="admin",
                success=True,
                raw_line="test"
            ),
        ]

        violations = rule.evaluate(events, geo_data)
        assert len(violations) == 0

    def test_failed_logins_ignored(self):
        """Test that failed logins are ignored for impossible travel."""
        config = GeoVelocityConfig(max_velocity_km_h=1000, min_distance_km=100)
        rule = GeoVelocityRule(config)

        nyc = GeoLocation(latitude=40.7128, longitude=-74.0060)
        tokyo = GeoLocation(latitude=35.6762, longitude=139.6503)

        geo_data = {
            "1.1.1.1": nyc,
            "2.2.2.2": tokyo,
        }

        from datetime import timedelta
        base_time = datetime(2024, 1, 1, 10, 0, 0)

        events = [
            # Failed login from NYC
            AuthEvent(
                timestamp=base_time,
                event_type=EventType.FAILED_LOGIN,
                ip="1.1.1.1",
                username="admin",
                success=False,
                raw_line="test"
            ),
            # Failed login from Tokyo 1 minute later
            AuthEvent(
                timestamp=base_time + timedelta(minutes=1),
                event_type=EventType.FAILED_LOGIN,
                ip="2.2.2.2",
                username="admin",
                success=False,
                raw_line="test"
            ),
        ]

        violations = rule.evaluate(events, geo_data)
        # Failed logins don't indicate actual user travel
        assert len(violations) == 0

    def test_short_distance_ignored(self):
        """Test that short distance travel is ignored."""
        config = GeoVelocityConfig(max_velocity_km_h=1000, min_distance_km=100)
        rule = GeoVelocityRule(config)

        # Two locations ~30km apart (NYC to Newark)
        nyc = GeoLocation(latitude=40.7128, longitude=-74.0060)
        newark = GeoLocation(latitude=40.7357, longitude=-74.1724)

        geo_data = {
            "1.1.1.1": nyc,
            "2.2.2.2": newark,
        }

        from datetime import timedelta
        base_time = datetime(2024, 1, 1, 10, 0, 0)

        events = [
            AuthEvent(
                timestamp=base_time,
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="1.1.1.1",
                username="admin",
                success=True,
                raw_line="test"
            ),
            AuthEvent(
                timestamp=base_time + timedelta(seconds=1),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="2.2.2.2",
                username="admin",
                success=True,
                raw_line="test"
            ),
        ]

        violations = rule.evaluate(events, geo_data)
        # Distance is below min_distance_km threshold
        assert len(violations) == 0

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
from vpsguard.config import load_config, VPSGuardConfig, GeoIPConfig


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

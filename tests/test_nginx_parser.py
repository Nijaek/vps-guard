"""Tests for the Nginx access log parser."""


import pytest

from vpsguard.models.events import EventType
from vpsguard.parsers.nginx import NginxAccessLogParser


class TestNginxAccessLogParser:
    """Test cases for NginxAccessLogParser."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return NginxAccessLogParser()

    def test_parse_basic_get_request(self, parser):
        """Test parsing a basic GET request."""
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.ip == "192.168.1.1"
        assert event.success is True
        assert event.service == "nginx"

    def test_parse_authenticated_request(self, parser):
        """Test parsing a request with authenticated user."""
        log_line = '192.168.1.1 - admin [31/Dec/2024:10:00:00 +0000] "GET /dashboard HTTP/1.1" 200 5678 "-" "Mozilla/5.0"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.username == "admin"
        assert event.success is True

    def test_parse_401_unauthorized(self, parser):
        """Test parsing 401 Unauthorized response."""
        # Use a non-suspicious path to test 401 behavior
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET /private/data HTTP/1.1" 401 0 "-" "Mozilla/5.0"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.FAILED_LOGIN
        assert event.success is False

    def test_parse_403_forbidden(self, parser):
        """Test parsing 403 Forbidden response."""
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET /secret HTTP/1.1" 403 0 "-" "Mozilla/5.0"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.FAILED_LOGIN
        assert event.success is False

    def test_detect_path_traversal(self, parser):
        """Test detection of path traversal attempts."""
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET /images/../../../etc/passwd HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.INVALID_USER  # Suspicious activity

    def test_detect_sql_injection(self, parser):
        """Test detection of SQL injection attempts."""
        # Use non-encoded SQL injection (real logs often have decoded version)
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET /search?q=1 OR 1=1 HTTP/1.1" 200 0 "-" "Mozilla/5.0"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.INVALID_USER

    def test_detect_suspicious_user_agent(self, parser):
        """Test detection of suspicious user agents."""
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "sqlmap/1.0"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.INVALID_USER

    def test_detect_wp_admin_access(self, parser):
        """Test detection of WordPress admin access attempts."""
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET /wp-admin/admin.php HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.INVALID_USER

    def test_detect_phpmyadmin_access(self, parser):
        """Test detection of phpMyAdmin access attempts."""
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.INVALID_USER

    def test_detect_env_file_access(self, parser):
        """Test detection of .env file access attempts."""
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.INVALID_USER

    def test_parse_multiple_lines(self, parser):
        """Test parsing multiple log lines."""
        logs = """192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.2 - - [31/Dec/2024:10:00:01 +0000] "POST /login HTTP/1.1" 200 567 "-" "Mozilla/5.0"
192.168.1.3 - - [31/Dec/2024:10:00:02 +0000] "GET /admin HTTP/1.1" 401 0 "-" "curl/7.68.0"
"""
        result = parser.parse(logs)

        assert len(result.events) == 3
        assert result.events[0].ip == "192.168.1.1"
        assert result.events[1].ip == "192.168.1.2"
        assert result.events[2].ip == "192.168.1.3"

    def test_parse_post_request(self, parser):
        """Test parsing POST request."""
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "POST /api/data HTTP/1.1" 201 45 "-" "Mozilla/5.0"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.success is True

    def test_parse_with_referer(self, parser):
        """Test parsing request with referer."""
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET /page HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        assert result.events[0].success is True

    def test_empty_content(self, parser):
        """Test parsing empty content."""
        result = parser.parse("")
        assert len(result.events) == 0
        assert len(result.parse_errors) == 0

    def test_malformed_line(self, parser):
        """Test parsing malformed log line."""
        result = parser.parse("this is not a valid nginx log line")
        assert len(result.events) == 0
        assert len(result.parse_errors) == 1

    def test_format_type(self, parser):
        """Test that format type is correct."""
        assert parser.name == "nginx"
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "-"'
        result = parser.parse(log_line)
        assert result.format_type == "nginx"

    def test_detect_xss_attempt(self, parser):
        """Test detection of XSS attempts."""
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 0 "-" "Mozilla/5.0"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.INVALID_USER

    def test_detect_gobuster_user_agent(self, parser):
        """Test detection of gobuster scanner."""
        log_line = '192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET /admin HTTP/1.1" 404 0 "-" "gobuster/3.1"'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.INVALID_USER

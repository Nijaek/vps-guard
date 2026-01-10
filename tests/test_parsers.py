"""Comprehensive tests for log parsers."""

import json
import os
import tempfile
from io import StringIO

import pytest

from vpsguard.models.events import EventType
from vpsguard.parsers import (
    AuthLogParser,
    JournaldParser,
    SecureLogParser,
    enrich_with_source,
    get_parser,
)
from vpsguard.parsers.base import (
    FileTooLargeError,
    safe_int,
    safe_pid,
    safe_port,
    validate_file_size,
    validate_ip,
    MAX_LOG_FILE_SIZE,
    MIN_PORT,
    MAX_PORT,
    MIN_PID,
    MAX_PID,
)


class TestAuthLogParser:
    """Tests for AuthLogParser."""

    def test_failed_password(self):
        """Test parsing failed password for existing user."""
        parser = AuthLogParser()
        log_line = "Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2"

        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.FAILED_LOGIN
        assert event.ip == "192.168.1.100"
        assert event.username == "root"
        assert event.port == 22345
        assert event.pid == 1234
        assert event.service == "sshd"
        assert event.success is False
        assert len(result.parse_errors) == 0

    def test_failed_password_invalid_user(self):
        """Test parsing failed password for invalid user."""
        parser = AuthLogParser()
        log_line = "Jan 15 03:12:48 server sshd[1235]: Failed password for invalid user admin from 192.168.1.100 port 22346 ssh2"

        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.FAILED_LOGIN
        assert event.ip == "192.168.1.100"
        assert event.username == "admin"
        assert event.port == 22346
        assert event.pid == 1235
        assert event.service == "sshd"
        assert event.success is False

    def test_invalid_user(self):
        """Test parsing invalid user attempt."""
        parser = AuthLogParser()
        log_line = "Jan 15 03:12:45 server sshd[1233]: Invalid user admin from 192.168.1.100 port 22344"

        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.INVALID_USER
        assert event.ip == "192.168.1.100"
        assert event.username == "admin"
        assert event.port == 22344
        assert event.pid == 1233
        assert event.service == "sshd"
        assert event.success is False

    def test_accepted_password(self):
        """Test parsing accepted password."""
        parser = AuthLogParser()
        log_line = "Jan 15 03:15:00 server sshd[1236]: Accepted password for ubuntu from 10.0.0.5 port 54321 ssh2"

        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.SUCCESSFUL_LOGIN
        assert event.ip == "10.0.0.5"
        assert event.username == "ubuntu"
        assert event.port == 54321
        assert event.pid == 1236
        assert event.service == "sshd"
        assert event.success is True

    def test_accepted_publickey(self):
        """Test parsing accepted publickey."""
        parser = AuthLogParser()
        log_line = "Jan 15 03:15:01 server sshd[1237]: Accepted publickey for deploy from 10.0.0.6 port 54322 ssh2"

        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.SUCCESSFUL_LOGIN
        assert event.ip == "10.0.0.6"
        assert event.username == "deploy"
        assert event.port == 54322
        assert event.pid == 1237
        assert event.service == "sshd"
        assert event.success is True

    def test_connection_closed(self):
        """Test parsing connection closed."""
        parser = AuthLogParser()
        log_line = "Jan 15 03:16:00 server sshd[1238]: Connection closed by 10.0.0.5 port 54321"

        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.DISCONNECT
        assert event.ip == "10.0.0.5"
        assert event.username is None
        assert event.port == 54321
        assert event.pid == 1238
        assert event.service == "sshd"

    def test_disconnected(self):
        """Test parsing disconnected message."""
        parser = AuthLogParser()
        log_line = "Jan 15 03:16:05 server sshd[1239]: Disconnected from 10.0.0.7 port 54323"

        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.DISCONNECT
        assert event.ip == "10.0.0.7"
        assert event.port == 54323
        assert event.pid == 1239

    def test_sudo_command(self):
        """Test parsing sudo command."""
        parser = AuthLogParser()
        log_line = "Jan 15 04:00:00 server sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash"

        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.SUDO
        assert event.username == "ubuntu"
        assert event.ip is None  # sudo events don't have IP
        assert event.service == "sudo"
        assert event.success is True

    def test_multiple_events(self):
        """Test parsing multiple log lines."""
        parser = AuthLogParser()
        log_content = """Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2
Jan 15 03:12:48 server sshd[1235]: Failed password for invalid user admin from 192.168.1.100 port 22346 ssh2
Jan 15 03:15:00 server sshd[1236]: Accepted password for ubuntu from 10.0.0.5 port 54321 ssh2"""

        result = parser.parse(log_content)

        assert len(result.events) == 3
        assert result.events[0].event_type == EventType.FAILED_LOGIN
        assert result.events[1].event_type == EventType.FAILED_LOGIN
        assert result.events[2].event_type == EventType.SUCCESSFUL_LOGIN

    def test_unknown_pattern(self):
        """Test that unknown patterns are recorded as errors."""
        parser = AuthLogParser()
        log_line = "Jan 15 03:12:47 server kernel[0]: Some random kernel message"

        result = parser.parse(log_line)

        assert len(result.events) == 0
        assert len(result.parse_errors) == 1
        assert "No pattern matched" in result.parse_errors[0]

    def test_empty_lines(self):
        """Test that empty lines are skipped."""
        parser = AuthLogParser()
        log_content = """Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2

Jan 15 03:15:00 server sshd[1236]: Accepted password for ubuntu from 10.0.0.5 port 54321 ssh2"""

        result = parser.parse(log_content)

        assert len(result.events) == 2
        assert len(result.parse_errors) == 0

    def test_timestamp_parsing(self):
        """Test timestamp parsing with current year."""
        parser = AuthLogParser()
        log_line = "Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2"

        result = parser.parse(log_line)
        event = result.events[0]

        assert event.timestamp.month == 1
        assert event.timestamp.day == 15
        assert event.timestamp.hour == 3
        assert event.timestamp.minute == 12
        assert event.timestamp.second == 47

    def test_parse_file(self):
        """Test parsing from a file."""
        parser = AuthLogParser()

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2\n")
            f.write("Jan 15 03:15:00 server sshd[1236]: Accepted password for ubuntu from 10.0.0.5 port 54321 ssh2\n")
            temp_path = f.name

        try:
            result = parser.parse_file(temp_path)

            assert len(result.events) == 2
            assert result.source_file == temp_path
            assert result.format_type == "auth.log"
        finally:
            os.unlink(temp_path)

    def test_parse_stream(self):
        """Test parsing from a stream (stdin-like)."""
        parser = AuthLogParser()
        log_content = """Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2
Jan 15 03:15:00 server sshd[1236]: Accepted password for ubuntu from 10.0.0.5 port 54321 ssh2"""

        stream = StringIO(log_content)
        result = parser.parse_stream(stream)

        assert len(result.events) == 2
        assert result.source_file is None
        assert result.format_type == "auth.log"


class TestSecureLogParser:
    """Tests for SecureLogParser."""

    def test_inherits_auth_log_behavior(self):
        """Test that SecureLogParser parses same as AuthLogParser."""
        parser = SecureLogParser()
        log_line = "Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2"

        result = parser.parse(log_line)

        assert len(result.events) == 1
        assert result.format_type == "secure"  # Different format type
        event = result.events[0]
        assert event.event_type == EventType.FAILED_LOGIN
        assert event.ip == "192.168.1.100"

    def test_format_type_is_secure(self):
        """Test that format_type is 'secure'."""
        parser = SecureLogParser()
        log_line = "Jan 15 03:15:00 server sshd[1236]: Accepted password for ubuntu from 10.0.0.5 port 54321 ssh2"

        result = parser.parse(log_line)

        assert result.format_type == "secure"

    def test_parse_file(self, tmp_path):
        """Test parsing from a file path."""
        parser = SecureLogParser()

        # Create a temp file with log content
        log_content = """Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2
Jan 15 03:12:50 server sshd[1234]: Accepted password for ubuntu from 10.0.0.5 port 54321 ssh2
Jan 15 03:12:55 server sshd[1235]: Failed password for invalid user admin from 192.168.1.101 port 22346 ssh2"""

        log_file = tmp_path / "secure"
        log_file.write_text(log_content)

        result = parser.parse_file(str(log_file))

        assert len(result.events) == 3
        assert result.source_file == str(log_file)
        assert result.format_type == "secure"

        # Check events parsed correctly
        assert result.events[0].event_type == EventType.FAILED_LOGIN
        assert result.events[0].ip == "192.168.1.100"
        assert result.events[1].event_type == EventType.SUCCESSFUL_LOGIN
        assert result.events[1].ip == "10.0.0.5"
        assert result.events[2].event_type == EventType.FAILED_LOGIN
        assert result.events[2].username == "admin"


class TestJournaldParser:
    """Tests for JournaldParser."""

    def test_failed_password_json(self):
        """Test parsing failed password from JSON."""
        parser = JournaldParser()
        json_line = json.dumps({
            "__REALTIME_TIMESTAMP": "1705295567000000",
            "_PID": "1234",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Failed password for root from 192.168.1.100 port 22345 ssh2",
            "_HOSTNAME": "server"
        })

        result = parser.parse(json_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.FAILED_LOGIN
        assert event.ip == "192.168.1.100"
        assert event.username == "root"
        assert event.port == 22345
        assert event.pid == 1234
        assert event.service == "sshd"

    def test_failed_password_invalid_user_json(self):
        """Test parsing failed password for invalid user from JSON."""
        parser = JournaldParser()
        json_line = json.dumps({
            "__REALTIME_TIMESTAMP": "1705295568000000",
            "_PID": "1235",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Failed password for invalid user admin from 192.168.1.100 port 22346 ssh2",
        })

        result = parser.parse(json_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.FAILED_LOGIN
        assert event.username == "admin"

    def test_accepted_password_json(self):
        """Test parsing accepted password from JSON."""
        parser = JournaldParser()
        json_line = json.dumps({
            "__REALTIME_TIMESTAMP": "1705295600000000",
            "_PID": "1236",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Accepted password for ubuntu from 10.0.0.5 port 54321 ssh2",
        })

        result = parser.parse(json_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.SUCCESSFUL_LOGIN
        assert event.ip == "10.0.0.5"
        assert event.username == "ubuntu"
        assert event.success is True

    def test_accepted_publickey_json(self):
        """Test parsing accepted publickey from JSON."""
        parser = JournaldParser()
        json_line = json.dumps({
            "__REALTIME_TIMESTAMP": "1705295601000000",
            "_PID": "1237",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Accepted publickey for deploy from 10.0.0.6 port 54322 ssh2",
        })

        result = parser.parse(json_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.SUCCESSFUL_LOGIN
        assert event.username == "deploy"

    def test_invalid_user_json(self):
        """Test parsing invalid user from JSON."""
        parser = JournaldParser()
        json_line = json.dumps({
            "__REALTIME_TIMESTAMP": "1705295565000000",
            "_PID": "1233",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Invalid user admin from 192.168.1.100 port 22344",
        })

        result = parser.parse(json_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.INVALID_USER
        assert event.username == "admin"

    def test_connection_closed_json(self):
        """Test parsing connection closed from JSON."""
        parser = JournaldParser()
        json_line = json.dumps({
            "__REALTIME_TIMESTAMP": "1705295660000000",
            "_PID": "1238",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Connection closed by 10.0.0.5 port 54321",
        })

        result = parser.parse(json_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.DISCONNECT
        assert event.ip == "10.0.0.5"

    def test_sudo_json(self):
        """Test parsing sudo command from JSON."""
        parser = JournaldParser()
        json_line = json.dumps({
            "__REALTIME_TIMESTAMP": "1705299600000000",
            "_PID": "5678",
            "SYSLOG_IDENTIFIER": "sudo",
            "MESSAGE": "ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash",
        })

        result = parser.parse(json_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.SUDO
        assert event.username == "ubuntu"
        assert event.service == "sudo"

    def test_multiple_json_lines(self):
        """Test parsing multiple JSON lines."""
        parser = JournaldParser()
        json_content = (
            json.dumps({
                "__REALTIME_TIMESTAMP": "1705295567000000",
                "_PID": "1234",
                "SYSLOG_IDENTIFIER": "sshd",
                "MESSAGE": "Failed password for root from 192.168.1.100 port 22345 ssh2",
            }) + "\n" +
            json.dumps({
                "__REALTIME_TIMESTAMP": "1705295600000000",
                "_PID": "1236",
                "SYSLOG_IDENTIFIER": "sshd",
                "MESSAGE": "Accepted password for ubuntu from 10.0.0.5 port 54321 ssh2",
            })
        )

        result = parser.parse(json_content)

        assert len(result.events) == 2
        assert result.events[0].event_type == EventType.FAILED_LOGIN
        assert result.events[1].event_type == EventType.SUCCESSFUL_LOGIN

    def test_invalid_json(self):
        """Test handling of invalid JSON."""
        parser = JournaldParser()
        invalid_json = "This is not JSON"

        result = parser.parse(invalid_json)

        assert len(result.events) == 0
        assert len(result.parse_errors) == 1
        assert "JSON decode error" in result.parse_errors[0]

    def test_non_sshd_sudo_messages_ignored(self):
        """Test that non-sshd/sudo messages are ignored."""
        parser = JournaldParser()
        json_line = json.dumps({
            "__REALTIME_TIMESTAMP": "1705295567000000",
            "_PID": "9999",
            "SYSLOG_IDENTIFIER": "kernel",
            "MESSAGE": "Some kernel message",
        })

        result = parser.parse(json_line)

        assert len(result.events) == 0
        assert len(result.parse_errors) == 1
        assert "No pattern matched" in result.parse_errors[0]

    def test_timestamp_conversion(self):
        """Test timestamp conversion from microseconds."""
        parser = JournaldParser()
        # 2024-01-15 03:12:47 UTC
        json_line = json.dumps({
            "__REALTIME_TIMESTAMP": "1705295567000000",
            "_PID": "1234",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Failed password for root from 192.168.1.100 port 22345 ssh2",
        })

        result = parser.parse(json_line)
        event = result.events[0]

        # Check that timestamp is reasonable
        assert event.timestamp.year == 2024
        assert event.timestamp.month == 1

    def test_parse_file_json(self):
        """Test parsing JSON from a file."""
        parser = JournaldParser()

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            f.write(json.dumps({
                "__REALTIME_TIMESTAMP": "1705295567000000",
                "_PID": "1234",
                "SYSLOG_IDENTIFIER": "sshd",
                "MESSAGE": "Failed password for root from 192.168.1.100 port 22345 ssh2",
            }) + "\n")
            temp_path = f.name

        try:
            result = parser.parse_file(temp_path)

            assert len(result.events) == 1
            assert result.source_file == temp_path
            assert result.format_type == "journald"
        finally:
            os.unlink(temp_path)


class TestGetParser:
    """Tests for get_parser factory function."""

    def test_get_auth_log_parser(self):
        """Test getting auth.log parser."""
        parser = get_parser("auth.log")
        assert isinstance(parser, AuthLogParser)
        assert parser.name == "auth.log"

    def test_get_secure_parser(self):
        """Test getting secure parser."""
        parser = get_parser("secure")
        assert isinstance(parser, SecureLogParser)
        assert parser.name == "secure"

    def test_get_journald_parser(self):
        """Test getting journald parser."""
        parser = get_parser("journald")
        assert isinstance(parser, JournaldParser)
        assert parser.name == "journald"

    def test_unknown_format_raises_error(self):
        """Test that unknown format raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            get_parser("unknown_format")

        assert "Unknown format" in str(exc_info.value)
        assert "unknown_format" in str(exc_info.value)


class TestParserProtocol:
    """Tests for Parser protocol compliance."""

    def test_all_parsers_have_name(self):
        """Test that all parsers have a name attribute."""
        parsers = [AuthLogParser(), SecureLogParser(), JournaldParser()]
        for parser in parsers:
            assert hasattr(parser, "name")
            assert isinstance(parser.name, str)
            assert len(parser.name) > 0

    def test_all_parsers_have_required_methods(self):
        """Test that all parsers implement required protocol methods."""
        parsers = [AuthLogParser(), SecureLogParser(), JournaldParser()]
        required_methods = ["parse", "parse_file", "parse_stream"]

        for parser in parsers:
            for method_name in required_methods:
                assert hasattr(parser, method_name)
                assert callable(getattr(parser, method_name))


class TestEnrichWithSource:
    """Tests for enrich_with_source function."""

    def test_enrich_with_explicit_source(self):
        """Test enriching parsed log with explicit source."""
        parser = AuthLogParser()
        log_line = "Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2"
        parsed = parser.parse(log_line)

        enriched = enrich_with_source(parsed, source="myserver-auth.log")

        assert len(enriched.events) == 1
        assert enriched.events[0].log_source == "myserver-auth.log"

    def test_enrich_uses_source_file_basename(self):
        """Test enriching uses basename of source_file when no explicit source given."""
        parser = AuthLogParser()
        log_line = "Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2"

        # Create a temporary file to get a proper source_file path
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write(log_line)
            temp_path = f.name

        try:
            parsed = parser.parse_file(temp_path)
            enriched = enrich_with_source(parsed)

            # Should use basename of source file
            assert enriched.events[0].log_source == os.path.basename(temp_path)
        finally:
            os.unlink(temp_path)

    def test_enrich_uses_format_type_as_fallback(self):
        """Test enriching uses format_type when no source_file."""
        parser = AuthLogParser()
        log_line = "Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2"
        parsed = parser.parse(log_line)

        # No explicit source and no source_file set
        enriched = enrich_with_source(parsed)

        # Should fallback to format_type
        assert enriched.events[0].log_source == parsed.format_type

    def test_enrich_all_events(self):
        """Test that all events are enriched."""
        parser = AuthLogParser()
        log_content = """Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2
Jan 15 03:12:48 server sshd[1235]: Failed password for admin from 192.168.1.101 port 22346 ssh2
Jan 15 03:12:49 server sshd[1236]: Accepted password for ubuntu from 10.0.0.5 port 54321 ssh2"""

        parsed = parser.parse(log_content)
        enriched = enrich_with_source(parsed, source="secure")

        assert len(enriched.events) == 3
        for event in enriched.events:
            assert event.log_source == "secure"

    def test_enrich_returns_same_object(self):
        """Test that enrich_with_source returns the same ParsedLog object."""
        parser = AuthLogParser()
        log_line = "Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2"
        parsed = parser.parse(log_line)

        enriched = enrich_with_source(parsed, source="test")

        # Should be the same object (modified in place)
        assert enriched is parsed


class TestValidateIp:
    """Tests for validate_ip function."""

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        assert validate_ip("192.168.1.100") == "192.168.1.100"
        assert validate_ip("10.0.0.1") == "10.0.0.1"
        assert validate_ip("8.8.8.8") == "8.8.8.8"
        assert validate_ip("0.0.0.0") == "0.0.0.0"
        assert validate_ip("255.255.255.255") == "255.255.255.255"

    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        assert validate_ip("::1") == "::1"
        assert validate_ip("2001:db8::1") == "2001:db8::1"
        assert validate_ip("fe80::1") == "fe80::1"

    def test_ipv4_with_whitespace(self):
        """Test that whitespace is stripped."""
        assert validate_ip("  192.168.1.1  ") == "192.168.1.1"
        assert validate_ip("\t10.0.0.1\n") == "10.0.0.1"

    def test_invalid_ip(self):
        """Test invalid IP addresses return None."""
        assert validate_ip("invalid") is None
        assert validate_ip("256.256.256.256") is None
        assert validate_ip("192.168.1.999") is None
        assert validate_ip("192.168.1") is None
        assert validate_ip("not.an.ip.address") is None

    def test_empty_and_none(self):
        """Test empty string and edge cases."""
        assert validate_ip("") is None
        assert validate_ip("   ") is None


class TestSafeInt:
    """Tests for safe_int function."""

    def test_valid_integer_in_range(self):
        """Test valid integers within range."""
        assert safe_int("50", 0, 100) == 50
        assert safe_int("0", 0, 100) == 0
        assert safe_int("100", 0, 100) == 100

    def test_integer_below_range(self):
        """Test integers below minimum return default."""
        assert safe_int("-1", 0, 100) is None
        assert safe_int("0", 1, 100) is None
        assert safe_int("-1", 0, 100, default=0) == 0

    def test_integer_above_range(self):
        """Test integers above maximum return default."""
        assert safe_int("101", 0, 100) is None
        assert safe_int("1000", 0, 100) is None
        assert safe_int("101", 0, 100, default=100) == 100

    def test_invalid_string(self):
        """Test non-numeric strings return default."""
        assert safe_int("not_a_number", 0, 100) is None
        assert safe_int("12.34", 0, 100) is None
        assert safe_int("12abc", 0, 100) is None
        assert safe_int("invalid", 0, 100, default=42) == 42

    def test_empty_string(self):
        """Test empty string returns default."""
        assert safe_int("", 0, 100) is None
        assert safe_int("", 0, 100, default=0) == 0


class TestSafePort:
    """Tests for safe_port function."""

    def test_valid_ports(self):
        """Test valid port numbers."""
        assert safe_port("22") == 22
        assert safe_port("80") == 80
        assert safe_port("443") == 443
        assert safe_port("8080") == 8080
        assert safe_port("1") == 1
        assert safe_port("65535") == 65535

    def test_port_below_range(self):
        """Test port 0 and negative values return None."""
        assert safe_port("0") is None
        assert safe_port("-1") is None
        assert safe_port("-22") is None

    def test_port_above_range(self):
        """Test ports above 65535 return None."""
        assert safe_port("65536") is None
        assert safe_port("99999") is None
        assert safe_port("100000") is None

    def test_invalid_port_string(self):
        """Test invalid port strings return None."""
        assert safe_port("ssh") is None
        assert safe_port("http") is None
        assert safe_port("22.5") is None


class TestSafePid:
    """Tests for safe_pid function."""

    def test_valid_pids(self):
        """Test valid PID numbers."""
        assert safe_pid("1") == 1
        assert safe_pid("1234") == 1234
        assert safe_pid("32768") == 32768
        assert safe_pid(str(MAX_PID)) == MAX_PID

    def test_pid_below_range(self):
        """Test PID 0 and negative values return None."""
        assert safe_pid("0") is None
        assert safe_pid("-1") is None
        assert safe_pid("-1234") is None

    def test_pid_above_range(self):
        """Test PIDs above MAX_PID return None."""
        assert safe_pid(str(MAX_PID + 1)) is None
        assert safe_pid("99999999") is None

    def test_invalid_pid_string(self):
        """Test invalid PID strings return None."""
        assert safe_pid("init") is None
        assert safe_pid("systemd") is None
        assert safe_pid("") is None


class TestValidateFileSize:
    """Tests for validate_file_size and FileTooLargeError."""

    def test_file_within_limit(self, tmp_path):
        """Test file within size limit returns size."""
        test_file = tmp_path / "small.log"
        test_file.write_text("Small log content\n" * 100)

        size = validate_file_size(str(test_file))
        assert size == test_file.stat().st_size

    def test_file_exceeds_limit(self, tmp_path):
        """Test file exceeding limit raises FileTooLargeError."""
        test_file = tmp_path / "large.log"
        test_file.write_text("X" * 1000)  # 1KB file

        # Use a small max_size for testing
        with pytest.raises(FileTooLargeError) as exc_info:
            validate_file_size(str(test_file), max_size=500)

        assert "too large" in str(exc_info.value).lower()
        assert "0.0 MB" in str(exc_info.value) or "0.001" in str(exc_info.value).lower()

    def test_file_not_found(self, tmp_path):
        """Test missing file raises FileNotFoundError."""
        nonexistent = tmp_path / "does_not_exist.log"

        with pytest.raises(FileNotFoundError):
            validate_file_size(str(nonexistent))

    def test_custom_max_size(self, tmp_path):
        """Test custom max_size parameter."""
        test_file = tmp_path / "test.log"
        test_file.write_text("Content")

        # Should work with larger limit
        size = validate_file_size(str(test_file), max_size=1000)
        assert size == test_file.stat().st_size

    def test_file_too_large_error_message(self, tmp_path):
        """Test FileTooLargeError contains helpful message."""
        test_file = tmp_path / "error_test.log"
        test_file.write_text("X" * 2000)

        with pytest.raises(FileTooLargeError) as exc_info:
            validate_file_size(str(test_file), max_size=1000)

        error_message = str(exc_info.value)
        assert "Log file too large" in error_message
        assert "max" in error_message.lower()


class TestConstants:
    """Tests for base module constants."""

    def test_port_range_constants(self):
        """Test port range constants are valid."""
        assert MIN_PORT == 1
        assert MAX_PORT == 65535
        assert MIN_PORT < MAX_PORT

    def test_pid_range_constants(self):
        """Test PID range constants are valid."""
        assert MIN_PID == 1
        assert MAX_PID == 4194304
        assert MIN_PID < MAX_PID

    def test_max_file_size_constant(self):
        """Test max file size is 100 MB."""
        assert MAX_LOG_FILE_SIZE == 100 * 1024 * 1024

"""Comprehensive tests for log parsers."""

import json
from datetime import datetime
from io import StringIO
import tempfile
import os
import pytest

from vpsguard.parsers import (
    Parser,
    AuthLogParser,
    SecureLogParser,
    JournaldParser,
    get_parser,
    enrich_with_source,
)
from vpsguard.models.events import EventType


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

"""Tests for the syslog parser."""


import pytest

from vpsguard.models.events import EventType
from vpsguard.parsers.syslog import SyslogParser


class TestSyslogParser:
    """Test cases for SyslogParser."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return SyslogParser()

    def test_parse_ssh_failed_password(self, parser):
        """Test parsing SSH failed password message."""
        log_line = 'Jan 15 03:12:47 server sshd[12345]: Failed password for admin from 192.168.1.1 port 22'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.FAILED_LOGIN
        assert event.ip == "192.168.1.1"
        assert event.username == "admin"
        assert event.success is False
        assert event.service == "sshd"

    def test_parse_ssh_accepted_password(self, parser):
        """Test parsing SSH accepted password message."""
        log_line = 'Jan 15 03:12:47 server sshd[12345]: Accepted password for admin from 192.168.1.1 port 22'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.SUCCESSFUL_LOGIN
        assert event.ip == "192.168.1.1"
        assert event.username == "admin"
        assert event.success is True

    def test_parse_ssh_accepted_publickey(self, parser):
        """Test parsing SSH accepted publickey message."""
        log_line = 'Jan 15 03:12:47 server sshd[12345]: Accepted publickey for deploy from 192.168.1.1 port 22'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.SUCCESSFUL_LOGIN
        assert event.username == "deploy"
        assert event.success is True

    def test_parse_ssh_invalid_user(self, parser):
        """Test parsing SSH invalid user message."""
        log_line = 'Jan 15 03:12:47 server sshd[12345]: Invalid user hacker from 192.168.1.1'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.INVALID_USER
        assert event.ip == "192.168.1.1"
        assert event.username == "hacker"
        assert event.success is False

    def test_parse_sudo_command(self, parser):
        """Test parsing sudo command message."""
        log_line = 'Jan 15 03:12:47 server sudo[12346]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.SUDO
        assert event.username == "admin"
        assert event.success is True
        assert event.service == "sudo"

    def test_parse_pam_auth_failure(self, parser):
        """Test parsing PAM authentication failure from non-SSH service."""
        # Use a different service to trigger PAM parsing
        log_line = 'Jan 15 03:12:47 server login[12345]: pam_unix(login:auth): authentication failure; user=admin rhost=192.168.1.1'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.FAILED_LOGIN
        assert event.success is False

    def test_parse_pam_session_open(self, parser):
        """Test parsing PAM session open from non-SSH service."""
        log_line = 'Jan 15 03:12:47 server login[12345]: pam_unix(login:session): session opened for user admin'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.SUCCESSFUL_LOGIN
        assert event.username == "admin"
        assert event.success is True

    def test_parse_pam_session_close(self, parser):
        """Test parsing PAM session close from non-SSH service."""
        log_line = 'Jan 15 03:12:47 server login[12345]: pam_unix(login:session): session closed for user admin'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.DISCONNECT
        assert event.username == "admin"

    def test_parse_cron_command(self, parser):
        """Test parsing CRON command."""
        log_line = 'Jan 15 03:12:47 server CRON[12346]: (root) CMD (/usr/bin/script)'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.SUDO  # Using SUDO for scheduled commands
        assert event.username == "root"
        assert event.service == "cron"

    def test_parse_with_priority(self, parser):
        """Test parsing syslog line with priority."""
        log_line = '<38>Jan 15 03:12:47 server sshd[12345]: Accepted password for admin from 192.168.1.1 port 22'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.SUCCESSFUL_LOGIN

    def test_parse_rfc5424_format(self, parser):
        """Test parsing RFC 5424 syslog format."""
        log_line = '<34>1 2024-01-15T03:12:47.123Z server sshd 12345 - - Accepted password for admin from 192.168.1.1 port 22'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.SUCCESSFUL_LOGIN

    def test_parse_multiple_lines(self, parser):
        """Test parsing multiple log lines."""
        logs = """Jan 15 03:12:47 server sshd[12345]: Failed password for admin from 192.168.1.1 port 22
Jan 15 03:12:48 server sshd[12345]: Failed password for admin from 192.168.1.1 port 22
Jan 15 03:12:49 server sshd[12345]: Accepted password for admin from 192.168.1.1 port 22
"""
        result = parser.parse(logs)

        assert len(result.events) == 3
        assert result.events[0].event_type == EventType.FAILED_LOGIN
        assert result.events[1].event_type == EventType.FAILED_LOGIN
        assert result.events[2].event_type == EventType.SUCCESSFUL_LOGIN

    def test_empty_content(self, parser):
        """Test parsing empty content."""
        result = parser.parse("")
        assert len(result.events) == 0
        assert len(result.parse_errors) == 0

    def test_malformed_line(self, parser):
        """Test parsing malformed log line."""
        result = parser.parse("this is not a valid syslog line")
        assert len(result.events) == 0
        assert len(result.parse_errors) == 1

    def test_format_type(self, parser):
        """Test that format type is correct."""
        assert parser.name == "syslog"
        log_line = 'Jan 15 03:12:47 server sshd[12345]: test message'
        result = parser.parse(log_line)
        assert result.format_type == "syslog"

    def test_other_service_message(self, parser):
        """Test parsing message from unknown service."""
        log_line = 'Jan 15 03:12:47 server myservice[12345]: Some message'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.OTHER
        assert event.service == "myservice"

    def test_parse_failed_password_invalid_user(self, parser):
        """Test parsing SSH failed password for invalid user."""
        log_line = 'Jan 15 03:12:47 server sshd[12345]: Failed password for invalid user test from 192.168.1.1 port 22'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.event_type == EventType.FAILED_LOGIN
        assert event.username == "test"
        assert event.success is False

    def test_parse_without_pid(self, parser):
        """Test parsing syslog line without PID."""
        log_line = 'Jan 15 03:12:47 server sudo: admin : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/ls'
        result = parser.parse(log_line)

        assert len(result.events) == 1
        event = result.events[0]
        assert event.pid is None

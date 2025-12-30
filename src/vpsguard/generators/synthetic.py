"""Synthetic log generator for testing VPSGuard detection capabilities."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import random
from typing import Optional

from vpsguard.generators.profiles import AttackProfile, AttackConfig


@dataclass
class GeneratorConfig:
    """Configuration for synthetic log generation.

    Attributes:
        entries: Total number of log entries to generate
        attack_profiles: List of attack configurations
        baseline_ips: Number of normal user IPs
        baseline_users: List of normal users
        start_time: Start of time range (default: now - 24 hours)
        end_time: End of time range (default: now)
        seed: Random seed for reproducibility
    """

    entries: int = 1000  # Total log entries
    attack_profiles: list[AttackConfig] = field(default_factory=list)

    # Normal traffic parameters
    baseline_ips: int = 50  # Normal user IPs
    baseline_users: list[str] = field(default_factory=lambda: [
        "ubuntu", "deploy", "admin", "www-data", "git"
    ])

    # Time range
    start_time: Optional[datetime] = None  # Default: now - 24 hours
    end_time: Optional[datetime] = None  # Default: now

    # Reproducibility
    seed: Optional[int] = None

    def __post_init__(self):
        """Set default values for optional fields and validate configuration."""
        if self.start_time is None:
            self.start_time = datetime.now() - timedelta(hours=24)
        if self.end_time is None:
            self.end_time = datetime.now()

        # Validate configuration parameters
        if self.entries < 0:
            raise ValueError(f"entries must be >= 0, got {self.entries}")

        if self.baseline_ips < 1:
            raise ValueError(f"baseline_ips must be >= 1, got {self.baseline_ips}")

        if len(self.baseline_users) < 1:
            raise ValueError(f"baseline_users must contain at least 1 user, got {len(self.baseline_users)} users")

        if self.end_time <= self.start_time:
            raise ValueError(f"end_time must be > start_time, got start_time={self.start_time}, end_time={self.end_time}")


class SyntheticLogGenerator:
    """Generates synthetic auth.log entries for testing.

    Supports multiple attack profiles and realistic normal traffic patterns.
    Output is compatible with VPSGuard parsers.
    """

    # Common usernames for attacks
    COMMON_ATTACK_USERS = [
        "root", "admin", "administrator", "user", "test", "guest",
        "oracle", "postgres", "mysql", "ftp", "www", "apache",
        "tomcat", "jenkins", "git", "ubuntu", "centos", "debian"
    ]

    # Invalid usernames for reconnaissance
    RECON_USERS = [
        "support", "backup", "default", "service", "sales", "info",
        "webmaster", "postmaster", "marketing", "developer", "test123",
        "admin123", "user123", "temp", "demo", "sample"
    ]

    def __init__(self, config: GeneratorConfig):
        """Initialize the synthetic log generator.

        Args:
            config: Generator configuration
        """
        self.config = config
        if config.seed is not None:
            random.seed(config.seed)

        self.hostname = "server"
        self.base_pid = 1000

        # Pre-generate IPs for efficiency
        self.normal_ips = self._generate_normal_ips()
        self.attack_ips_cache = {}

    def _generate_normal_ips(self) -> list[str]:
        """Generate pool of normal user IPs."""
        ips = []
        for i in range(self.config.baseline_ips):
            # Generate IPs in 10.0.0.0/8 range
            ips.append(f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}")
        return ips

    def _generate_attacker_ip(self, profile_id: str = "default") -> str:
        """Generate attacker IP (typically from suspicious ranges)."""
        # Use different ranges for different attack types
        # 192.168.x.x for attacks (normally internal, but used here for testing)
        return f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"

    def _format_timestamp(self, dt: datetime, format_type: str = "auth.log") -> str:
        """Format timestamp based on log format.

        Args:
            dt: Datetime to format
            format_type: Log format (auth.log, secure, journald)

        Returns:
            Formatted timestamp string
        """
        if format_type in ["auth.log", "secure"]:
            # Syslog format: "Jan 15 03:12:47" or "Jan  5 03:12:47" (space-padded day)
            month = dt.strftime("%b")
            day = f"{dt.day:2d}"  # Right-aligned with space padding for single digits
            time = dt.strftime("%H:%M:%S")
            return f"{month} {day} {time}"
        elif format_type == "journald":
            # JSON format uses microseconds since epoch
            return str(int(dt.timestamp() * 1000000))
        else:
            # Default to auth.log format
            month = dt.strftime("%b")
            day = f"{dt.day:2d}"
            time = dt.strftime("%H:%M:%S")
            return f"{month} {day} {time}"

    def _generate_log_line(
        self,
        timestamp: datetime,
        event_type: str,
        username: str,
        ip: str,
        port: int,
        pid: int,
        format_type: str = "auth.log"
    ) -> str:
        """Generate a single log line.

        Args:
            timestamp: Event timestamp
            event_type: Type of event (failed, accepted, invalid_user, etc.)
            username: Username
            ip: Source IP
            port: Source port
            pid: Process ID
            format_type: Log format type

        Returns:
            Formatted log line
        """
        ts_str = self._format_timestamp(timestamp, format_type)

        if format_type in ["auth.log", "secure"]:
            if event_type == "failed":
                return f"{ts_str} {self.hostname} sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2"
            elif event_type == "failed_invalid":
                return f"{ts_str} {self.hostname} sshd[{pid}]: Failed password for invalid user {username} from {ip} port {port} ssh2"
            elif event_type == "invalid_user":
                return f"{ts_str} {self.hostname} sshd[{pid}]: Invalid user {username} from {ip} port {port}"
            elif event_type == "accepted":
                return f"{ts_str} {self.hostname} sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2"
            elif event_type == "accepted_key":
                return f"{ts_str} {self.hostname} sshd[{pid}]: Accepted publickey for {username} from {ip} port {port} ssh2"
        elif format_type == "journald":
            # Return JSON format for journald
            message = ""
            if event_type == "failed":
                message = f"Failed password for {username} from {ip} port {port} ssh2"
            elif event_type == "failed_invalid":
                message = f"Failed password for invalid user {username} from {ip} port {port} ssh2"
            elif event_type == "invalid_user":
                message = f"Invalid user {username} from {ip} port {port}"
            elif event_type == "accepted":
                message = f"Accepted password for {username} from {ip} port {port} ssh2"
            elif event_type == "accepted_key":
                message = f"Accepted publickey for {username} from {ip} port {port} ssh2"

            return json.dumps({
                "__REALTIME_TIMESTAMP": ts_str,
                "_PID": str(pid),
                "SYSLOG_IDENTIFIER": "sshd",
                "MESSAGE": message,
                "_HOSTNAME": self.hostname
            })

        return ""

    def _generate_normal_traffic(self, num_events: int, format_type: str = "auth.log") -> list[tuple[datetime, str]]:
        """Generate normal traffic log entries.

        Args:
            num_events: Number of events to generate
            format_type: Log format type

        Returns:
            List of (timestamp, log_line) tuples
        """
        logs = []
        time_range = (self.config.end_time - self.config.start_time).total_seconds()

        for _ in range(num_events):
            # Random time within range
            offset = random.random() * time_range
            timestamp = self.config.start_time + timedelta(seconds=offset)

            # Mostly successful logins, occasional typos
            if random.random() < 0.9:  # 90% success
                event_type = "accepted" if random.random() < 0.8 else "accepted_key"
                username = random.choice(self.config.baseline_users)
            else:  # 10% failed (typos)
                event_type = "failed"
                username = random.choice(self.config.baseline_users)

            ip = random.choice(self.normal_ips)
            port = random.randint(40000, 65000)
            pid = self.base_pid + random.randint(0, 9999)

            log_line = self._generate_log_line(
                timestamp, event_type, username, ip, port, pid, format_type
            )
            logs.append((timestamp, log_line))

        return logs

    def _generate_brute_force_attack(self, config: AttackConfig, format_type: str = "auth.log") -> list[tuple[datetime, str]]:
        """Generate brute force attack pattern.

        Single IP, many attempts in short time window, targeting common usernames.
        """
        logs = []
        attacker_ip = self._generate_attacker_ip("brute_force")

        # Target users
        target_users = config.target_users if config.target_users else ["root", "admin", "ubuntu"]

        # Random start time within the overall range
        time_range = (self.config.end_time - self.config.start_time).total_seconds()
        attack_start_offset = random.random() * max(0, time_range - config.time_window_minutes * 60)
        attack_start = self.config.start_time + timedelta(seconds=attack_start_offset)

        # Generate attempts
        attempt_window = config.time_window_minutes * 60
        for i in range(config.attempts_per_ip):
            offset = (i / config.attempts_per_ip) * attempt_window
            timestamp = attack_start + timedelta(seconds=offset)

            username = random.choice(target_users)
            port = random.randint(40000, 65000)
            pid = self.base_pid + random.randint(0, 9999)

            log_line = self._generate_log_line(
                timestamp, "failed", username, attacker_ip, port, pid, format_type
            )
            logs.append((timestamp, log_line))

        return logs

    def _generate_botnet_attack(self, config: AttackConfig, format_type: str = "auth.log") -> list[tuple[datetime, str]]:
        """Generate botnet attack pattern.

        Many IPs, coordinated timing, same target users, tight time window.
        """
        logs = []

        # Generate botnet IPs
        botnet_ips = [self._generate_attacker_ip(f"botnet_{i}") for i in range(config.ips_count)]

        # Target users
        target_users = config.target_users if config.target_users else ["root", "admin"]

        # Random start time within the overall range
        time_range = (self.config.end_time - self.config.start_time).total_seconds()
        attack_start_offset = random.random() * max(0, time_range - config.time_window_minutes * 60)
        attack_start = self.config.start_time + timedelta(seconds=attack_start_offset)

        # Each IP makes attempts_per_ip attempts
        attempt_window = config.time_window_minutes * 60
        for ip in botnet_ips:
            for i in range(config.attempts_per_ip):
                offset = (i / config.attempts_per_ip) * attempt_window + random.uniform(-5, 5)
                timestamp = attack_start + timedelta(seconds=max(0, offset))

                username = random.choice(target_users)
                port = random.randint(40000, 65000)
                pid = self.base_pid + random.randint(0, 9999)

                log_line = self._generate_log_line(
                    timestamp, "failed", username, ip, port, pid, format_type
                )
                logs.append((timestamp, log_line))

        return logs

    def _generate_credential_stuffing_attack(self, config: AttackConfig, format_type: str = "auth.log") -> list[tuple[datetime, str]]:
        """Generate credential stuffing attack pattern.

        Many IPs, many unique usernames (credential list).
        """
        logs = []

        # Generate attacker IPs
        attacker_ips = [self._generate_attacker_ip(f"stuffing_{i}") for i in range(config.ips_count)]

        # Large pool of usernames
        usernames = self.COMMON_ATTACK_USERS + self.RECON_USERS

        # Random start time
        time_range = (self.config.end_time - self.config.start_time).total_seconds()
        attack_start_offset = random.random() * max(0, time_range - config.time_window_minutes * 60)
        attack_start = self.config.start_time + timedelta(seconds=attack_start_offset)

        # Each IP tries different credentials
        attempt_window = config.time_window_minutes * 60
        for ip in attacker_ips:
            for i in range(config.attempts_per_ip):
                offset = (i / config.attempts_per_ip) * attempt_window + random.uniform(-2, 2)
                timestamp = attack_start + timedelta(seconds=max(0, offset))

                # Use different username each time
                username = random.choice(usernames)

                # Mix of valid and invalid users
                if username in self.config.baseline_users:
                    event_type = "failed"
                else:
                    event_type = "failed_invalid"

                port = random.randint(40000, 65000)
                pid = self.base_pid + random.randint(0, 9999)

                log_line = self._generate_log_line(
                    timestamp, event_type, username, ip, port, pid, format_type
                )
                logs.append((timestamp, log_line))

        return logs

    def _generate_low_and_slow_attack(self, config: AttackConfig, format_type: str = "auth.log") -> list[tuple[datetime, str]]:
        """Generate low-and-slow attack pattern.

        Few attempts per day, spread across the entire time range.
        """
        logs = []

        # Generate attacker IPs
        attacker_ips = [self._generate_attacker_ip(f"low_slow_{i}") for i in range(config.ips_count)]

        # Target users
        target_users = config.target_users if config.target_users else ["root", "admin", "ubuntu"]

        # Spread attempts across entire time range
        time_range = (self.config.end_time - self.config.start_time).total_seconds()

        for ip in attacker_ips:
            for i in range(config.attempts_per_ip):
                # Spread evenly across time range with some randomness
                offset = (i / config.attempts_per_ip) * time_range + random.uniform(-3600, 3600)
                timestamp = self.config.start_time + timedelta(seconds=max(0, min(offset, time_range)))

                username = random.choice(target_users)
                port = random.randint(40000, 65000)
                pid = self.base_pid + random.randint(0, 9999)

                log_line = self._generate_log_line(
                    timestamp, "failed", username, ip, port, pid, format_type
                )
                logs.append((timestamp, log_line))

        return logs

    def _generate_breach_attack(self, config: AttackConfig, format_type: str = "auth.log") -> list[tuple[datetime, str]]:
        """Generate breach attack pattern.

        Failed attempts followed by eventual success (important for ML testing).
        """
        logs = []

        # Single attacker IP
        attacker_ip = self._generate_attacker_ip("breach")

        # Target user
        target_user = config.target_users[0] if config.target_users else "root"

        # Random start time
        time_range = (self.config.end_time - self.config.start_time).total_seconds()
        attack_start_offset = random.random() * max(0, time_range - config.time_window_minutes * 60)
        attack_start = self.config.start_time + timedelta(seconds=attack_start_offset)

        # Generate failures
        attempt_window = config.time_window_minutes * 60
        for i in range(config.attempts_per_ip - 1):  # -1 to leave room for success
            offset = (i / config.attempts_per_ip) * attempt_window
            timestamp = attack_start + timedelta(seconds=offset)

            port = random.randint(40000, 65000)
            pid = self.base_pid + random.randint(0, 9999)

            log_line = self._generate_log_line(
                timestamp, "failed", target_user, attacker_ip, port, pid, format_type
            )
            logs.append((timestamp, log_line))

        # Final success
        success_offset = attempt_window * 0.95  # Near the end
        success_timestamp = attack_start + timedelta(seconds=success_offset)
        success_port = random.randint(40000, 65000)
        success_pid = self.base_pid + random.randint(0, 9999)

        success_line = self._generate_log_line(
            success_timestamp, "accepted", target_user, attacker_ip, success_port, success_pid, format_type
        )
        logs.append((success_timestamp, success_line))

        return logs

    def _generate_recon_attack(self, config: AttackConfig, format_type: str = "auth.log") -> list[tuple[datetime, str]]:
        """Generate reconnaissance attack pattern.

        Multiple IPs probing for valid usernames (invalid user events).
        """
        logs = []

        # Generate attacker IPs
        attacker_ips = [self._generate_attacker_ip(f"recon_{i}") for i in range(config.ips_count)]

        # Use recon usernames (mostly invalid)
        usernames = self.RECON_USERS

        # Random start time
        time_range = (self.config.end_time - self.config.start_time).total_seconds()
        attack_start_offset = random.random() * max(0, time_range - config.time_window_minutes * 60)
        attack_start = self.config.start_time + timedelta(seconds=attack_start_offset)

        # Each IP probes different usernames
        attempt_window = config.time_window_minutes * 60
        for ip in attacker_ips:
            for i in range(config.attempts_per_ip):
                offset = (i / config.attempts_per_ip) * attempt_window + random.uniform(-3, 3)
                timestamp = attack_start + timedelta(seconds=max(0, offset))

                username = random.choice(usernames)
                port = random.randint(40000, 65000)
                pid = self.base_pid + random.randint(0, 9999)

                log_line = self._generate_log_line(
                    timestamp, "invalid_user", username, ip, port, pid, format_type
                )
                logs.append((timestamp, log_line))

        return logs

    def generate(self, format_type: str = "auth.log") -> str:
        """Generate log content as string.

        Args:
            format_type: Log format ("auth.log", "secure", "journald")

        Returns:
            Generated log content as string
        """
        all_logs = []

        # Calculate attack event counts
        total_attack_ratio = sum(config.ratio for config in self.config.attack_profiles)
        if total_attack_ratio > 1.0:
            raise ValueError(f"Sum of attack ratios exceeds 1.0: {total_attack_ratio}")

        normal_ratio = 1.0 - total_attack_ratio
        normal_count = int(self.config.entries * normal_ratio)

        # Generate normal traffic
        all_logs.extend(self._generate_normal_traffic(normal_count, format_type))

        # Generate attacks
        for attack_config in self.config.attack_profiles:
            attack_count = int(self.config.entries * attack_config.ratio)

            # Calculate how many events per IP this attack will generate
            events_per_execution = attack_config.ips_count * attack_config.attempts_per_ip

            if events_per_execution == 0:
                continue

            # How many times to run this attack pattern to reach attack_count
            executions = max(1, attack_count // events_per_execution)

            for _ in range(executions):
                if attack_config.profile == AttackProfile.BRUTE_FORCE:
                    all_logs.extend(self._generate_brute_force_attack(attack_config, format_type))
                elif attack_config.profile == AttackProfile.BOTNET:
                    all_logs.extend(self._generate_botnet_attack(attack_config, format_type))
                elif attack_config.profile == AttackProfile.CREDENTIAL_STUFFING:
                    all_logs.extend(self._generate_credential_stuffing_attack(attack_config, format_type))
                elif attack_config.profile == AttackProfile.LOW_AND_SLOW:
                    all_logs.extend(self._generate_low_and_slow_attack(attack_config, format_type))
                elif attack_config.profile == AttackProfile.BREACH:
                    all_logs.extend(self._generate_breach_attack(attack_config, format_type))
                elif attack_config.profile == AttackProfile.RECON:
                    all_logs.extend(self._generate_recon_attack(attack_config, format_type))

        # Sort by timestamp
        all_logs.sort(key=lambda x: x[0])

        # Extract just the log lines
        log_lines = [log[1] for log in all_logs]

        return "\n".join(log_lines)

    def generate_to_file(self, path: str, format_type: str = "auth.log") -> None:
        """Generate and write to file in specified format.

        Args:
            path: Output file path
            format_type: Log format ("auth.log", "secure", "journald")
        """
        content = self.generate(format_type)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
            f.write("\n")  # Ensure trailing newline

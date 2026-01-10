"""CLI interface for VPSGuard."""

import re
import sys
import json
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from vpsguard.parsers import get_parser, enrich_with_source
from vpsguard.generators import SyntheticLogGenerator, GeneratorConfig, AttackConfig, AttackProfile
from vpsguard.models.events import EventType


def validate_output_path(path: str, allow_absolute: bool = False) -> Path:
    """Validate that an output path is safe to write to.

    Prevents path traversal attacks by ensuring paths are within safe directories.

    Args:
        path: The path to validate.
        allow_absolute: If True, allow absolute paths within safe directories.
                       If False, require relative paths only.

    Returns:
        Validated Path object.

    Raises:
        ValueError: If the path is outside allowed directories or uses traversal.
    """
    # Normalize the path
    output_path = Path(path)

    # Check for path traversal attempts
    if '..' in output_path.parts:
        raise ValueError(
            f"Path traversal not allowed: {path}. "
            "Use direct paths without '..' components."
        )

    # Get the resolved absolute path
    try:
        resolved = output_path.resolve()
    except (OSError, ValueError) as e:
        raise ValueError(f"Invalid path: {path} - {e}")

    # Define safe base directories
    cwd = Path.cwd().resolve()
    home = Path.home().resolve()
    vpsguard_dir = (home / ".vpsguard").resolve()

    # Check if path is within allowed directories
    safe_bases = [cwd, home, vpsguard_dir]

    # For relative paths, they resolve relative to cwd
    if not output_path.is_absolute():
        return resolved

    # For absolute paths, check against safe directories
    if allow_absolute:
        for safe_base in safe_bases:
            try:
                resolved.relative_to(safe_base)
                return resolved
            except ValueError:
                continue

        raise ValueError(
            f"Output path must be within current directory, home, or ~/.vpsguard: {path}"
        )

    # Default: only allow relative paths
    return resolved

app = typer.Typer(
    name="vpsguard",
    help="ML-first VPS log security analyzer",
    add_completion=False,
)
console = Console()

# GeoIP sub-command group
geoip_app = typer.Typer(help="Manage GeoIP database for IP geolocation")
app.add_typer(geoip_app, name="geoip")


def _auto_detect_format(content: str, filename: Optional[str] = None) -> str:
    """Auto-detect log format from content or filename.

    Args:
        content: First few lines of log content
        filename: Optional filename to check extension

    Returns:
        Detected format type
    """
    # Check filename first
    if filename:
        filename_lower = filename.lower()
        if "auth.log" in filename_lower:
            return "auth.log"
        elif "secure" in filename_lower:
            return "secure"
        elif filename_lower.endswith(".json"):
            return "journald"
        elif "nginx" in filename_lower or "access.log" in filename_lower:
            return "nginx"
        elif "syslog" in filename_lower or "messages" in filename_lower:
            return "syslog"

    # Check content
    lines = content.strip().split('\n')
    if not lines:
        return "auth.log"  # Default

    first_line = lines[0]

    # Journald format is JSON
    if first_line.startswith('{'):
        try:
            json.loads(first_line)
            return "journald"
        except json.JSONDecodeError:
            pass

    # Nginx combined log format detection
    # Pattern: IP - - [timestamp] "request" status bytes "referer" "user-agent"
    nginx_pattern = r'^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[^"]*"\s+\d{3}\s+'
    if re.match(nginx_pattern, first_line):
        return "nginx"

    # Both auth.log and secure use syslog format
    # Default to auth.log (they're compatible anyway)
    return "auth.log"


def _display_events_table(events, stats: bool = False):
    """Display events in a rich table.

    Args:
        events: List of AuthEvent objects
        stats: Whether to show statistics
    """
    if not events:
        console.print("[yellow]No events found.[/yellow]")
        return

    # Show statistics if requested
    if stats:
        _display_stats(events)
        console.print()  # Empty line

    # Create events table
    table = Table(title="Parsed Events", show_lines=False)
    table.add_column("Timestamp", style="cyan", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("Username", style="green")
    table.add_column("IP", style="yellow")
    table.add_column("Port", style="blue")
    table.add_column("Success", style="white")

    for event in events[:50]:  # Limit to first 50 for display
        table.add_row(
            event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            event.event_type.value,
            event.username or "N/A",
            event.ip or "N/A",
            str(event.port) if event.port else "N/A",
            "Y" if event.success else "N"
        )

    if len(events) > 50:
        console.print(table)
        console.print(f"[dim]... and {len(events) - 50} more events[/dim]")
    else:
        console.print(table)


def _display_stats(events):
    """Display statistics about parsed events.

    Args:
        events: List of AuthEvent objects
    """
    total = len(events)

    # Count by event type
    event_counts = {}
    for event in events:
        event_type = event.event_type.value
        event_counts[event_type] = event_counts.get(event_type, 0) + 1

    # Count unique IPs and usernames
    unique_ips = len(set(e.ip for e in events if e.ip))
    unique_users = len(set(e.username for e in events if e.username))

    # Count successes and failures
    successes = sum(1 for e in events if e.success)
    failures = total - successes

    # Create stats panel
    stats_text = Text()
    stats_text.append(f"Total Events: ", style="bold")
    stats_text.append(f"{total}\n", style="cyan")
    stats_text.append(f"Unique IPs: ", style="bold")
    stats_text.append(f"{unique_ips}\n", style="yellow")
    stats_text.append(f"Unique Users: ", style="bold")
    stats_text.append(f"{unique_users}\n", style="green")
    stats_text.append(f"Successes: ", style="bold")
    stats_text.append(f"{successes}\n", style="green")
    stats_text.append(f"Failures: ", style="bold")
    stats_text.append(f"{failures}\n", style="red")
    stats_text.append("\nEvent Types:\n", style="bold underline")

    for event_type, count in sorted(event_counts.items(), key=lambda x: x[1], reverse=True):
        stats_text.append(f"  {event_type}: ", style="bold")
        stats_text.append(f"{count}\n", style="cyan")

    console.print(Panel(stats_text, title="Statistics", border_style="blue"))


def _load_geo_data(events, config, enabled: bool, output_format: str):
    """Load GeoIP data for a set of events if enabled and database exists."""
    if not enabled:
        return None

    from vpsguard.geo import get_database_info, GeoIPReader

    db_path = Path(config.geoip.database_path).expanduser()
    db_info = get_database_info(db_path)
    if not db_info.exists:
        if output_format != "json":
            console.print("[yellow]Warning: GeoIP database not found[/yellow]")
            console.print("[dim]Run 'vpsguard geoip download' to enable geolocation[/dim]")
        return None

    all_ips = {event.ip for event in events if event.ip}
    if not all_ips:
        return {}

    try:
        if output_format != "json":
            console.print("[dim]Looking up IP locations...[/dim]")

        with GeoIPReader(db_info.path) as reader:
            geo_data = {ip: reader.lookup(ip) for ip in all_ips}

        if output_format != "json":
            known_count = sum(1 for loc in geo_data.values() if loc.is_known)
            console.print(f"[green]GeoIP: {known_count}/{len(all_ips)} IPs located[/green]")

        return geo_data
    except Exception as e:
        if output_format != "json":
            console.print(f"[yellow]Warning: GeoIP lookup failed: {e}[/yellow]")
        return None


@app.command()
def parse(
    file_path: str = typer.Argument(..., help="Path to log file or '-' for stdin"),
    input_format: Optional[str] = typer.Option(None, "--input-format", help="Input format: auth.log, secure, journald"),
    format: str = typer.Option("table", "--format", help="Output format: table, json"),
    stats: bool = typer.Option(False, "--stats", help="Show summary statistics"),
):
    """Parse log files and display structured events."""
    try:
        # Read input
        if file_path == "-":
            content = sys.stdin.read()
            filename = None
        else:
            path = Path(file_path)
            if not path.exists():
                console.print(f"[red]Error: File not found: {file_path}[/red]")
                raise typer.Exit(1)
            content = path.read_text(encoding="utf-8", errors="replace")
            filename = path.name

        # Auto-detect format if not specified
        if input_format is None:
            input_format = _auto_detect_format(content, filename)
            if format != "json":  # Don't print to console if JSON output
                console.print(f"[dim]Auto-detected format: {input_format}[/dim]")

        # Get parser
        try:
            parser = get_parser(input_format)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

        # Parse content
        result = parser.parse(content)

        # Show parse errors if any
        if result.parse_errors:
            console.print(f"[yellow]Parse errors ({len(result.parse_errors)}):[/yellow]")
            for error in result.parse_errors[:10]:  # Show first 10 errors
                console.print(f"  [dim]{error}[/dim]")
            if len(result.parse_errors) > 10:
                console.print(f"  [dim]... and {len(result.parse_errors) - 10} more errors[/dim]")
            console.print()

        # Output results
        if format == "json":
            # Convert events to JSON-serializable format
            events_data = []
            for event in result.events:
                events_data.append({
                    "timestamp": event.timestamp.isoformat(),
                    "event_type": event.event_type.value,
                    "ip": event.ip,
                    "username": event.username,
                    "port": event.port,
                    "pid": event.pid,
                    "service": event.service,
                    "success": event.success,
                    "raw_line": event.raw_line,
                })

            output = {
                "total_events": len(result.events),
                "format_type": result.format_type,
                "parse_errors": len(result.parse_errors),
                "events": events_data,
            }

            if stats:
                # Add statistics to JSON output
                event_counts = {}
                for event in result.events:
                    event_type = event.event_type.value
                    event_counts[event_type] = event_counts.get(event_type, 0) + 1

                output["statistics"] = {
                    "unique_ips": len(set(e.ip for e in result.events if e.ip)),
                    "unique_users": len(set(e.username for e in result.events if e.username)),
                    "successes": sum(1 for e in result.events if e.success),
                    "failures": sum(1 for e in result.events if not e.success),
                    "event_counts": event_counts,
                }

            console.print_json(json.dumps(output, indent=2))
        else:
            # Table format
            _display_events_table(result.events, stats=stats)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def generate(
    entries: int = typer.Option(..., "--entries", help="Number of log entries to generate"),
    output: Optional[str] = typer.Option(None, "--output", help="Output file path (stdout if not specified)"),
    attack_profile: List[str] = typer.Option([], "--attack-profile", help="Attack profile in format 'profile:ratio' (e.g., 'botnet:0.1')"),
    format: str = typer.Option("auth.log", "--format", help="Output format: auth.log, secure, journald"),
    seed: Optional[int] = typer.Option(None, "--seed", help="Random seed for reproducibility"),
):
    """Generate synthetic log files for testing."""
    try:
        # Parse attack profiles
        attack_configs = []
        for profile_str in attack_profile:
            if ":" not in profile_str:
                console.print(f"[red]Error: Invalid attack profile format: {profile_str}[/red]")
                console.print("[yellow]Expected format: 'profile:ratio' (e.g., 'botnet:0.1')[/yellow]")
                raise typer.Exit(1)

            profile_name, ratio_str = profile_str.split(":", 1)

            # Map profile names to AttackProfile enum
            profile_map = {
                "brute": AttackProfile.BRUTE_FORCE,
                "brute_force": AttackProfile.BRUTE_FORCE,
                "botnet": AttackProfile.BOTNET,
                "stuffing": AttackProfile.CREDENTIAL_STUFFING,
                "credential_stuffing": AttackProfile.CREDENTIAL_STUFFING,
                "low-slow": AttackProfile.LOW_AND_SLOW,
                "low_and_slow": AttackProfile.LOW_AND_SLOW,
                "breach": AttackProfile.BREACH,
                "recon": AttackProfile.RECON,
            }

            if profile_name not in profile_map:
                console.print(f"[red]Error: Unknown attack profile: {profile_name}[/red]")
                console.print(f"[yellow]Available profiles: {', '.join(profile_map.keys())}[/yellow]")
                raise typer.Exit(1)

            try:
                ratio = float(ratio_str)
            except ValueError:
                console.print(f"[red]Error: Invalid ratio: {ratio_str}[/red]")
                raise typer.Exit(1)

            # Create attack config with sensible defaults
            attack_configs.append(AttackConfig(
                profile=profile_map[profile_name],
                ratio=ratio,
            ))

        # Create generator config
        config = GeneratorConfig(
            entries=entries,
            attack_profiles=attack_configs,
            seed=seed,
        )

        # Generate logs
        generator = SyntheticLogGenerator(config)
        content = generator.generate(format_type=format)

        # Output
        if output:
            # Validate output path to prevent path traversal attacks
            try:
                output_path = validate_output_path(output, allow_absolute=True)
            except ValueError as e:
                console.print(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)
            output_path.write_text(content, encoding="utf-8")
            console.print(f"[green]Generated {entries} log entries to {output}[/green]")
        else:
            # Write to stdout
            print(content)

    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def init(
    output: str = typer.Option("vpsguard.toml", "--output", help="Output config file path"),
    force: bool = typer.Option(False, "--force", help="Force overwrite existing file"),
):
    """Initialize a default configuration file."""
    try:
        # Validate output path to prevent path traversal attacks
        try:
            output_path = validate_output_path(output, allow_absolute=True)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

        # Check if file exists
        if output_path.exists() and not force:
            console.print(f"[yellow]Config file already exists: {output}[/yellow]")
            console.print("[yellow]Use --force to overwrite[/yellow]")
            raise typer.Exit(1)

        # Default configuration
        config_content = """# VPSGuard Configuration

[rules.brute_force]
enabled = true
threshold = 10
window_minutes = 60
severity = "high"

[rules.breach_detection]
enabled = true
failures_before_success = 5
severity = "critical"

[rules.quiet_hours]
enabled = true
start = 23
end = 6
timezone = "UTC"
severity = "medium"

[whitelist]
ips = []

[output]
format = "terminal"
verbosity = 1
"""

        output_path.write_text(config_content, encoding="utf-8")
        console.print(f"[green]Created configuration file: {output}[/green]")
        console.print("\n[cyan]Next steps:[/cyan]")
        console.print(f"  1. Edit {output} to customize your rules")
        console.print(f"  2. Run 'vpsguard parse <logfile>' to analyze logs")
        console.print(f"  3. Run 'vpsguard generate --entries 1000' to create test data")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@geoip_app.command("status")
def geoip_status():
    """Show GeoIP database status."""
    from vpsguard.geo import get_database_info

    info = get_database_info()

    if info.exists:
        console.print(Panel(
            f"[bold green]GeoIP Database: Ready[/bold green]\n\n"
            f"Path: {info.path}\n"
            f"Size: {info.size_mb:.1f} MB\n"
            f"Modified: {info.modified.strftime('%Y-%m-%d %H:%M:%S') if info.modified else 'Unknown'}",
            title="GeoIP Status",
            border_style="green"
        ))
    else:
        console.print(Panel(
            f"[bold yellow]GeoIP Database: Not Downloaded[/bold yellow]\n\n"
            f"Expected path: {info.path}\n\n"
            f"[dim]Run 'vpsguard geoip download' to download the database.[/dim]",
            title="GeoIP Status",
            border_style="yellow"
        ))


@geoip_app.command("download")
def geoip_download(
    force: bool = typer.Option(False, "--force", "-f", help="Force re-download even if database exists"),
):
    """Download the GeoLite2 database for IP geolocation.

    Downloads the free GeoLite2-City database (~70MB) to ~/.vpsguard/
    This enables geographic information in analysis reports.
    """
    from vpsguard.geo import get_database_info, download_database

    info = get_database_info()

    if info.exists and not force:
        console.print(f"[yellow]Database already exists at {info.path}[/yellow]")
        console.print(f"[dim]Size: {info.size_mb:.1f} MB, Modified: {info.modified}[/dim]")
        console.print(f"[dim]Use --force to re-download[/dim]")
        return

    console.print(f"[cyan]Downloading GeoLite2-City database...[/cyan]")
    console.print(f"[dim]This may take a moment (~70MB)[/dim]")

    try:
        from rich.progress import Progress, SpinnerColumn, BarColumn, DownloadColumn

        with Progress(
            SpinnerColumn(),
            "[progress.description]{task.description}",
            BarColumn(),
            DownloadColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Downloading...", total=None)

            def update_progress(downloaded: int, total: int):
                if total > 0:
                    progress.update(task, total=total, completed=downloaded)

            path = download_database(progress_callback=update_progress)

        console.print(f"[green]Downloaded successfully to {path}[/green]")

        # Show updated status
        info = get_database_info()
        console.print(f"[dim]Size: {info.size_mb:.1f} MB[/dim]")

    except Exception as e:
        console.print(f"[red]Download failed: {e}[/red]")
        raise typer.Exit(1)


@geoip_app.command("delete")
def geoip_delete(
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt"),
):
    """Delete the GeoIP database."""
    from vpsguard.geo import get_database_info, delete_database

    info = get_database_info()

    if not info.exists:
        console.print(f"[yellow]No database to delete (not found at {info.path})[/yellow]")
        return

    if not force:
        console.print(f"[yellow]This will delete: {info.path}[/yellow]")
        console.print(f"[dim]Size: {info.size_mb:.1f} MB[/dim]")
        confirm = typer.confirm("Are you sure?")
        if not confirm:
            console.print("[dim]Cancelled[/dim]")
            return

    if delete_database():
        console.print(f"[green]Database deleted[/green]")
    else:
        console.print(f"[red]Failed to delete database[/red]")


@app.command()
def train(
    file_path: str = typer.Argument(..., help="Path to log file to train on"),
    model: str = typer.Option("vpsguard_model.pkl", "--model", help="Path to save model file"),
    config: Optional[str] = typer.Option(None, "--config", help="Path to TOML config file"),
    input_format: Optional[str] = typer.Option(None, "--input-format", help="Input format: auth.log, secure, journald"),
    check: bool = typer.Option(False, "--check", help="Check and display baseline stats (no training)"),
):
    """Train ML model on log file using clean events."""
    try:
        from pathlib import Path
        from vpsguard.config import load_config
        from vpsguard.rules.engine import RuleEngine
        from vpsguard.ml.engine import MLEngine
        from vpsguard.ml.baseline import load_baseline
        from datetime import datetime

        model_path = Path(model)

        # If --check, just display baseline info
        if check:
            baseline_path = model_path.with_suffix('.json')

            if not baseline_path.exists():
                console.print(f"[red]No baseline found at: {baseline_path}[/red]")
                console.print(f"[yellow]Train a model first with: vpsguard train <logfile> --model {model}[/yellow]")
                raise typer.Exit(1)

            try:
                baseline = load_baseline(baseline_path)

                # Display baseline info
                console.print(Panel("[bold cyan]Baseline Statistics[/bold cyan]", border_style="cyan"))
                console.print(f"[bold]Trained at:[/bold] {baseline['trained_at']}")
                console.print(f"[bold]Event count:[/bold] {baseline['event_count']}")
                console.print(f"[bold]Model path:[/bold] {baseline.get('model_path', 'N/A')}")
                console.print("\n[bold cyan]Feature Means:[/bold cyan]")

                for name, mean in baseline['feature_means'].items():
                    std = baseline['feature_stds'][name]
                    console.print(f"  {name}: {mean:.2f} (±{std:.2f})")

                return

            except Exception as e:
                console.print(f"[red]Error loading baseline: {e}[/red]")
                raise typer.Exit(1)

        # Load configuration
        try:
            vps_config = load_config(config)
            if config:
                console.print(f"[dim]Loaded config from: {config}[/dim]")
            else:
                console.print(f"[dim]Using default configuration[/dim]")
        except (FileNotFoundError, ValueError) as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

        # Read and parse log file
        path = Path(file_path)
        if not path.exists():
            console.print(f"[red]Error: File not found: {file_path}[/red]")
            raise typer.Exit(1)

        console.print(f"[dim]Reading log file: {file_path}[/dim]")
        content = path.read_text(encoding="utf-8", errors="replace")

        # Auto-detect format
        if input_format is None:
            input_format = _auto_detect_format(content, path.name)
            console.print(f"[dim]Auto-detected format: {input_format}[/dim]")

        # Parse logs
        parser = get_parser(input_format)
        console.print(f"[dim]Parsing logs...[/dim]")
        parsed = parser.parse(content)
        enrich_with_source(parsed, source=str(path))
        console.print(f"[green]Parsed {len(parsed.events)} events[/green]")

        # Run rule engine to get clean events
        console.print(f"[dim]Running rule engine to filter attacks...[/dim]")
        geo_data = _load_geo_data(parsed.events, vps_config, vps_config.geoip.enabled, "terminal")
        engine = RuleEngine(vps_config)
        rule_output = engine.evaluate(parsed.events, geo_data=geo_data)

        console.print(f"[yellow]Found {len(rule_output.violations)} rule violations[/yellow]")
        console.print(f"[green]Clean events for training: {len(rule_output.clean_events)}[/green]")

        if len(rule_output.clean_events) < 10:
            console.print(f"[red]Error: Not enough clean events for training (need at least 10)[/red]")
            console.print(f"[yellow]This usually means your log file is mostly attacks.[/yellow]")
            raise typer.Exit(1)

        # Train ML model
        console.print(f"[dim]Training ML model...[/dim]")
        ml_engine = MLEngine()
        baseline = ml_engine.train(rule_output.clean_events)

        # Save model
        console.print(f"[dim]Saving model to: {model_path}[/dim]")
        ml_engine.save(model_path)

        # Display success
        console.print(Panel(
            f"[bold green]Training Complete![/bold green]\n\n"
            f"Model saved to: {model_path}\n"
            f"Baseline saved to: {model_path.with_suffix('.json')}\n"
            f"Trained on {baseline['event_count']} clean events\n"
            f"Trained at: {baseline['trained_at']}",
            border_style="green"
        ))

        console.print("\n[cyan]Next steps:[/cyan]")
        console.print(f"  1. Check baseline: vpsguard train --check --model {model}")
        console.print(f"  2. Analyze logs: vpsguard analyze <logfile> --with-ml --model {model}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        raise typer.Exit(1)


@app.command()
def analyze(
    file_paths: List[str] = typer.Argument(..., help="Path(s) to log file(s) or '-' for stdin"),
    config: Optional[str] = typer.Option(None, "--config", help="Path to TOML config file"),
    input_format: Optional[str] = typer.Option(None, "--input-format", help="Input format: auth.log, secure, journald, nginx, syslog"),
    rules_only: bool = typer.Option(True, "--rules-only/--with-ml", help="Only run rule-based detection (skip ML)"),
    model: str = typer.Option("vpsguard_model.pkl", "--model", help="Path to ML model file"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Verbosity level (0=critical/high, 1=+medium, 2=all)"),
    format: Optional[str] = typer.Option(None, "--format", help="Output format: terminal, markdown, json, html"),
    output: Optional[str] = typer.Option(None, "--output", help="Output file path (stdout if not specified)"),
    save_history: bool = typer.Option(False, "--save-history", help="Save run to history database for tracking"),
    geoip: Optional[bool] = typer.Option(None, "--geoip/--no-geoip", "-g", help="Enable/disable GeoIP lookups for IP geolocation"),
):
    """Analyze log files for security threats. Supports multiple log files."""
    try:
        from datetime import datetime, timezone
        from pathlib import Path
        from vpsguard.config import load_config
        from vpsguard.rules.engine import RuleEngine
        from vpsguard.reporters import get_reporter
        from vpsguard.models.events import AnalysisReport, Severity, AuthEvent

        # Load configuration
        try:
            vps_config = load_config(config)
        except FileNotFoundError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

        # Resolve defaults from config when CLI options are not provided
        if format is None:
            format = vps_config.output.format
        if verbose == 0 and vps_config.output.verbosity:
            verbose = vps_config.output.verbosity
        if geoip is None:
            geoip = vps_config.geoip.enabled

        if format != "json":
            if config:
                console.print(f"[dim]Loaded config from: {config}[/dim]")
            else:
                console.print(f"[dim]Using default configuration[/dim]")

        # Collect all events from all files
        all_events: List[AuthEvent] = []
        log_sources: List[str] = []
        total_parse_errors = 0

        for file_path in file_paths:
            # Read input
            if file_path == "-":
                content = sys.stdin.read()
                filename = None
                log_source = "stdin"
            else:
                path = Path(file_path)
                if not path.exists():
                    console.print(f"[red]Error: File not found: {file_path}[/red]")
                    raise typer.Exit(1)
                content = path.read_text(encoding="utf-8", errors="replace")
                filename = path.name
                log_source = str(path)

            log_sources.append(log_source)

            # Auto-detect format if not specified
            detected_format = input_format
            if detected_format is None:
                detected_format = _auto_detect_format(content, filename)
                if format != "json":
                    console.print(f"[dim]{log_source}: Auto-detected format: {detected_format}[/dim]")

            # Get parser
            try:
                parser = get_parser(detected_format)
            except ValueError as e:
                console.print(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)

            # Parse content
            if format != "json":
                console.print(f"[dim]Parsing {log_source}...[/dim]")
            parsed = parser.parse(content)

            # Enrich events with source for multi-log correlation
            enrich_with_source(parsed, source=log_source)

            # Collect events and errors
            all_events.extend(parsed.events)
            total_parse_errors += len(parsed.parse_errors)

            if format != "json":
                console.print(f"[green]{log_source}: {len(parsed.events)} events parsed[/green]")

        # Show parse errors summary if any
        if total_parse_errors > 0 and format != "json":
            console.print(f"[yellow]Total parse errors across all files: {total_parse_errors}[/yellow]")

        # Combined log source string
        combined_log_source = ", ".join(log_sources) if len(log_sources) <= 3 else f"{len(log_sources)} files"

        if format != "json":
            console.print(f"[dim]Total events from all sources: {len(all_events)}[/dim]")

        # GeoIP lookups if enabled (used by geo-velocity rule + reporting)
        geo_data = _load_geo_data(all_events, vps_config, bool(geoip), format)

        # Run rule engine
        if format != "json":
            console.print(f"[dim]Running rule engine...[/dim]")

        engine = RuleEngine(vps_config)
        rule_output = engine.evaluate(all_events, geo_data=geo_data)

        # Filter violations by verbosity level
        filtered_violations = []
        for violation in rule_output.violations:
            if verbose == 0:
                # Only CRITICAL and HIGH
                if violation.severity in [Severity.CRITICAL, Severity.HIGH]:
                    filtered_violations.append(violation)
            elif verbose == 1:
                # CRITICAL, HIGH, and MEDIUM
                if violation.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                    filtered_violations.append(violation)
            else:
                # All severities (verbose >= 2)
                filtered_violations.append(violation)

        # Run ML detection if requested
        anomalies = []
        baseline_drift = None

        if not rules_only:
            from vpsguard.ml.engine import MLEngine

            model_path = Path(model)
            baseline_path = model_path.with_suffix('.json')

            if not model_path.exists():
                if format != "json":
                    console.print(f"[yellow]Warning: ML model not found at {model_path}[/yellow]")
                    console.print(f"[yellow]Train a model first with: vpsguard train <logfile> --model {model}[/yellow]")
                    console.print(f"[yellow]Continuing with rule-based detection only...[/yellow]")
            else:
                try:
                    if format != "json":
                        console.print(f"[dim]Loading ML model from {model_path}...[/dim]")

                    ml_engine = MLEngine()
                    ml_engine.load(model_path)

                    if format != "json":
                        console.print(f"[dim]Running ML anomaly detection...[/dim]")

                    # Detect anomalies
                    anomalies = ml_engine.detect(all_events, score_threshold=0.6)

                    # Check for drift
                    baseline_drift = ml_engine.detect_drift(all_events, threshold=2.0)

                    if format != "json":
                        console.print(f"[green]ML detected {len(anomalies)} anomalous IPs[/green]")
                        if baseline_drift and baseline_drift['drift_detected']:
                            console.print(f"[yellow]Warning: Data drift detected in {len(baseline_drift['drifted_features'])} features[/yellow]")

                except Exception as e:
                    if format != "json":
                        console.print(f"[yellow]Warning: ML detection failed: {e}[/yellow]")
                        console.print(f"[yellow]Continuing with rule-based detection only...[/yellow]")

        # Build analysis report
        analysis_report = AnalysisReport(
            timestamp=datetime.now(timezone.utc),
            log_source=combined_log_source,
            total_events=len(all_events),
            rule_violations=filtered_violations,
            anomalies=anomalies,
            baseline_drift=baseline_drift,
            summary=None,
            geo_data=geo_data,
        )

        # Generate report
        reporter = get_reporter(format)

        if output:
            # Write to file
            reporter.generate_to_file(analysis_report, output)
            if format != "json":
                console.print(f"[green]Report written to: {output}[/green]")
        else:
            # Output to console
            if format == "terminal":
                # Use display method for terminal reporter
                from vpsguard.reporters.terminal import TerminalReporter
                if isinstance(reporter, TerminalReporter):
                    reporter.display(analysis_report)
                else:
                    print(reporter.generate(analysis_report))
            else:
                # For markdown, json, html - just print
                print(reporter.generate(analysis_report))

        # Save to history if requested
        if save_history:
            from vpsguard.history import HistoryDB
            db = HistoryDB()
            run_id = db.save_run(analysis_report)
            if format != "json":
                console.print(f"[dim]Run saved to history (ID: {run_id})[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        raise typer.Exit(1)


@app.command()
def watch(
    log_file: str = typer.Argument(..., help="Path to log file to monitor"),
    interval: Optional[str] = typer.Option(None, "--interval", "-i", help="Schedule interval (e.g., 5m, 1h)"),
    foreground: bool = typer.Option(False, "--foreground", "-f", help="Run in foreground (don't daemonize)"),
    once: bool = typer.Option(False, "--once", help="Run single analysis cycle then exit"),
    status: bool = typer.Option(False, "--status", help="Show daemon status"),
    stop: bool = typer.Option(False, "--stop", help="Stop running daemon"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config file"),
    log_format: Optional[str] = typer.Option(None, "--format", help="Log format: auth.log, secure, journald, nginx, syslog"),
    model: str = typer.Option("vpsguard_model.pkl", "--model", help="Path to ML model file"),
    with_ml: bool = typer.Option(True, "--with-ml/--rules-only", help="Enable ML detection when a model is available"),
):
    """Run scheduled batch analysis on log file.

    Monitors log file at configured intervals, running full analysis each time.
    Persists state between runs for incremental parsing.

    Examples:
        vpsguard watch /var/log/auth.log --foreground
        vpsguard watch /var/log/auth.log --once
        vpsguard watch /var/log/auth.log --status
        vpsguard watch /var/log/auth.log --stop
        vpsguard watch /var/log/auth.log --interval 30m
    """
    import time
    import os
    from datetime import datetime
    from vpsguard.config import load_config
    from vpsguard.daemon import DaemonManager
    from vpsguard.watch import WatchDaemon

    # Load config
    cfg = load_config(config) if config else load_config()

    # Get interval from CLI or config
    watch_interval = interval or cfg.watch_schedule.interval

    # Handle status command
    if status:
        daemon_manager = DaemonManager()
        pid = daemon_manager.get_running_pid()
        if pid:
            console.print(f"[green]Watch daemon running (PID {pid})[/green]")
            # Show state from DB
            from vpsguard.history import HistoryDB
            db = HistoryDB()
            state = db.get_watch_state(log_file)
            if state:
                console.print(f"  Last run: {state.last_run_time}")
                console.print(f"  Total runs: {state.run_count}")
                console.print(f"  Byte offset: {state.byte_offset}")
        else:
            console.print("[yellow]No watch daemon running[/yellow]")
        raise typer.Exit()

    # Handle stop command
    if stop:
        daemon_manager = DaemonManager()
        pid = daemon_manager.get_running_pid()
        if pid:
            try:
                if sys.platform == 'win32':
                    # Windows: use taskkill for reliable process termination
                    import subprocess
                    result = subprocess.run(
                        ['taskkill', '/F', '/PID', str(pid)],
                        capture_output=True,
                        text=True
                    )
                    if result.returncode == 0:
                        console.print(f"[green]Terminated daemon process (PID {pid})[/green]")
                    else:
                        console.print(f"[red]Error stopping daemon: {result.stderr}[/red]")
                else:
                    # Unix: use SIGTERM for graceful shutdown
                    import signal
                    os.kill(pid, signal.SIGTERM)
                    console.print(f"[green]Sent shutdown signal to daemon (PID {pid})[/green]")
            except OSError as e:
                console.print(f"[red]Error stopping daemon: {e}[/red]")
        else:
            console.print("[yellow]No watch daemon running[/yellow]")
        raise typer.Exit()

    # Validate log file exists
    log_path = Path(log_file)
    if not log_path.exists():
        console.print(f"[red]Error: Log file not found: {log_file}[/red]")
        raise typer.Exit(1)

    # Create daemon instance
    daemon = WatchDaemon(
        log_path=str(log_path),
        interval=watch_interval,
        log_format=log_format,
        model_path=model if with_ml else None,
        with_ml=with_ml,
    )

    # Run once mode (for testing/debug)
    if once:
        console.print(f"[cyan]Running single analysis cycle on {log_file}[/cyan]")
        result = daemon.run_once(cfg)
        console.print(f"[green]Analysis complete: {result['events']} events, {result['violations']} violations[/green]")
        if result['findings_counts']:
            console.print(f"  Critical: {result['findings_counts'].get('critical', 0)}")
            console.print(f"  High: {result['findings_counts'].get('high', 0)}")
            console.print(f"  Medium: {result['findings_counts'].get('medium', 0)}")
            console.print(f"  Low: {result['findings_counts'].get('low', 0)}")
        raise typer.Exit()

    # Foreground mode (don't daemonize)
    if foreground:
        console.print(f"[cyan]Running in foreground mode (interval: {watch_interval})[/cyan]")
        console.print(f"[dim]Monitoring: {log_file}[/dim]")
        console.print("[yellow]Press Ctrl+C to stop[/yellow]\n")

        run_count = 0
        try:
            while not daemon.daemon_manager.shutdown_requested:
                run_count += 1
                result = daemon.run_once(cfg)
                timestamp = datetime.now().strftime('%H:%M:%S')
                console.print(f"[green]{timestamp} - Run #{run_count}: {result['events']} events, {result['violations']} violations[/green]")

                # Sleep until next run
                time.sleep(daemon.interval_seconds)

        except KeyboardInterrupt:
            console.print(f"\n[yellow]Shutting down...[/yellow]")
            console.print(f"[dim]Total runs: {run_count}[/dim]")
        raise typer.Exit()

    # Daemon mode
    try:
        daemon.daemon_manager.start()
    except RuntimeError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Watch daemon started[/green]")
    console.print(f"  Monitoring: {log_file}")
    console.print(f"  Interval: {watch_interval}")
    console.print(f"  PID: {os.getpid()}")
    console.print(f"\n[cyan]Use 'vpsguard watch {log_file} --status' to check status[/cyan]")
    console.print(f"[cyan]Use 'vpsguard watch {log_file} --stop' to stop daemon[/cyan]")

    # Main loop
    import logging
    logger = logging.getLogger(__name__)

    while not daemon.daemon_manager.shutdown_requested:
        try:
            daemon.run_once(cfg)
            time.sleep(daemon.interval_seconds)
        except Exception as e:
            logger.error(f"Error in watch loop: {e}")
            time.sleep(60)  # Wait before retry

    # Cleanup
    daemon.daemon_manager.stop()


@app.command()
def history(
    action: str = typer.Argument("list", help="Action: list, show, compare, trend, top, ip, cleanup"),
    run_id: Optional[int] = typer.Option(None, "--run", "-r", help="Run ID for show/compare actions"),
    run_id2: Optional[int] = typer.Option(None, "--compare-to", "-c", help="Second run ID for compare action"),
    ip: Optional[str] = typer.Option(None, "--ip", help="IP address for ip action"),
    days: int = typer.Option(30, "--days", "-d", help="Number of days for trend/top/cleanup"),
    limit: int = typer.Option(10, "--limit", "-l", help="Maximum items to show"),
    db_path: Optional[str] = typer.Option(None, "--db", help="Path to history database"),
):
    """View and manage analysis history.

    Actions:
      list    - Show recent analysis runs (default)
      show    - Show details of a specific run (requires --run)
      compare - Compare two runs (requires --run and --compare-to)
      trend   - Show daily trend of findings
      top     - Show top offending IPs
      ip      - Show history for specific IP (requires --ip)
      cleanup - Delete old runs (uses --days)

    Examples:
        vpsguard history
        vpsguard history show --run 5
        vpsguard history compare --run 3 --compare-to 5
        vpsguard history trend --days 7
        vpsguard history top --limit 20
        vpsguard history ip --ip 192.168.1.1
        vpsguard history cleanup --days 90
    """
    from pathlib import Path
    from vpsguard.history import HistoryDB

    try:
        # Initialize database
        db = HistoryDB(Path(db_path) if db_path else None)

        if action == "list":
            runs = db.get_recent_runs(limit)
            if not runs:
                console.print("[yellow]No history found.[/yellow]")
                console.print("[dim]Run 'vpsguard analyze' with --save-history to start recording.[/dim]")
                return

            table = Table(title="Recent Analysis Runs", show_lines=False)
            table.add_column("ID", style="cyan", no_wrap=True)
            table.add_column("Timestamp", style="white")
            table.add_column("Source", style="dim")
            table.add_column("Events", style="blue", justify="right")
            table.add_column("C", style="red", justify="right")
            table.add_column("H", style="yellow", justify="right")
            table.add_column("M", style="yellow", justify="right")
            table.add_column("L", style="blue", justify="right")
            table.add_column("ML", style="magenta", justify="right")

            for run in runs:
                timestamp = run['timestamp'][:19].replace('T', ' ')
                source = run['log_source'][:30] + "..." if len(run['log_source']) > 30 else run['log_source']
                table.add_row(
                    str(run['id']),
                    timestamp,
                    source,
                    str(run['total_events']),
                    str(run['critical_count']) if run['critical_count'] else "-",
                    str(run['high_count']) if run['high_count'] else "-",
                    str(run['medium_count']) if run['medium_count'] else "-",
                    str(run['low_count']) if run['low_count'] else "-",
                    str(run['anomaly_count']) if run['anomaly_count'] else "-",
                )

            console.print(table)
            console.print(f"\n[dim]Use 'vpsguard history show --run ID' for details[/dim]")

        elif action == "show":
            if not run_id:
                console.print("[red]Error: --run ID required for show action[/red]")
                raise typer.Exit(1)

            run = db.get_run(run_id)
            if not run:
                console.print(f"[red]Error: Run {run_id} not found[/red]")
                raise typer.Exit(1)

            violations = db.get_run_violations(run_id)
            anomalies = db.get_run_anomalies(run_id)

            # Show run summary
            console.print(Panel(
                f"[bold]Run #{run['id']}[/bold]\n"
                f"Timestamp: {run['timestamp']}\n"
                f"Source: {run['log_source']}\n"
                f"Events: {run['total_events']:,}\n"
                f"Critical: {run['critical_count']} | High: {run['high_count']} | "
                f"Medium: {run['medium_count']} | Low: {run['low_count']}\n"
                f"ML Anomalies: {run['anomaly_count']}",
                title="Run Details",
                border_style="cyan"
            ))

            # Show violations
            if violations:
                console.print(f"\n[bold]Violations ({len(violations)}):[/bold]")
                for v in violations[:20]:  # Show first 20
                    severity_color = {"critical": "red", "high": "yellow", "medium": "yellow", "low": "blue"}.get(v['severity'], "white")
                    console.print(f"  [{severity_color}]{v['severity'].upper()}[/{severity_color}] {v['ip']} - {v['rule_name']}")

                if len(violations) > 20:
                    console.print(f"  [dim]... and {len(violations) - 20} more[/dim]")

            # Show anomalies
            if anomalies:
                console.print(f"\n[bold]Anomalies ({len(anomalies)}):[/bold]")
                for a in anomalies[:10]:
                    score_pct = int(a['score'] * 100)
                    console.print(f"  [magenta]{a['ip']}[/magenta] - Score: {score_pct}% ({a['confidence']})")

        elif action == "compare":
            if not run_id or not run_id2:
                console.print("[red]Error: --run and --compare-to required for compare action[/red]")
                raise typer.Exit(1)

            comparison = db.compare_runs(run_id, run_id2)
            if "error" in comparison:
                console.print(f"[red]Error: {comparison['error']}[/red]")
                raise typer.Exit(1)

            def delta_str(val):
                if val > 0:
                    return f"[red]+{val}[/red]"
                elif val < 0:
                    return f"[green]{val}[/green]"
                return "0"

            console.print(Panel(
                f"[bold]Run #{run_id} → Run #{run_id2}[/bold]\n\n"
                f"Events: {comparison['old_run']['total_events']:,} → {comparison['new_run']['total_events']:,} ({delta_str(comparison['events_delta'])})\n"
                f"Critical: {delta_str(comparison['critical_delta'])}\n"
                f"High: {delta_str(comparison['high_delta'])}\n"
                f"Medium: {delta_str(comparison['medium_delta'])}\n"
                f"Low: {delta_str(comparison['low_delta'])}\n\n"
                f"New IPs: {len(comparison['new_ips'])}\n"
                f"Gone IPs: {len(comparison['gone_ips'])}\n"
                f"Persistent: {len(comparison['persistent_ips'])}",
                title="Run Comparison",
                border_style="cyan"
            ))

            if comparison['new_ips']:
                console.print(f"\n[bold]New offending IPs:[/bold]")
                for ip in comparison['new_ips'][:10]:
                    console.print(f"  [red]+ {ip}[/red]")

            if comparison['gone_ips']:
                console.print(f"\n[bold]No longer seen:[/bold]")
                for ip in comparison['gone_ips'][:10]:
                    console.print(f"  [green]- {ip}[/green]")

        elif action == "trend":
            trend = db.get_trend(days)
            if not trend:
                console.print(f"[yellow]No data found for the last {days} days.[/yellow]")
                return

            table = Table(title=f"Daily Trend (Last {days} Days)", show_lines=False)
            table.add_column("Date", style="cyan")
            table.add_column("Runs", style="dim", justify="right")
            table.add_column("Critical", style="red", justify="right")
            table.add_column("High", style="yellow", justify="right")
            table.add_column("Medium", style="yellow", justify="right")
            table.add_column("Low", style="blue", justify="right")
            table.add_column("Anomalies", style="magenta", justify="right")

            for day in trend:
                table.add_row(
                    day['date'],
                    str(day['runs']),
                    str(day['critical']),
                    str(day['high']),
                    str(day['medium']),
                    str(day['low']),
                    str(day['anomalies']),
                )

            console.print(table)

        elif action == "top":
            top_ips = db.get_top_offenders(days, limit)
            if not top_ips:
                console.print(f"[yellow]No violations found in the last {days} days.[/yellow]")
                return

            table = Table(title=f"Top Offending IPs (Last {days} Days)", show_lines=False)
            table.add_column("Rank", style="dim", justify="right")
            table.add_column("IP Address", style="cyan")
            table.add_column("Total", style="white", justify="right")
            table.add_column("Critical", style="red", justify="right")
            table.add_column("High", style="yellow", justify="right")
            table.add_column("Medium", style="yellow", justify="right")
            table.add_column("Low", style="blue", justify="right")

            for i, ip_data in enumerate(top_ips, 1):
                table.add_row(
                    str(i),
                    ip_data['ip'],
                    str(ip_data['total']),
                    str(ip_data['critical']),
                    str(ip_data['high']),
                    str(ip_data['medium']),
                    str(ip_data['low']),
                )

            console.print(table)

        elif action == "ip":
            if not ip:
                console.print("[red]Error: --ip required for ip action[/red]")
                raise typer.Exit(1)

            ip_history = db.get_ip_history(ip, days)

            console.print(Panel(
                f"[bold]IP: {ip}[/bold]\n"
                f"Period: Last {days} days\n\n"
                f"Total Violations: {ip_history['total_violations']}\n"
                f"  Critical: {ip_history['violations'].get('critical', 0)}\n"
                f"  High: {ip_history['violations'].get('high', 0)}\n"
                f"  Medium: {ip_history['violations'].get('medium', 0)}\n"
                f"  Low: {ip_history['violations'].get('low', 0)}\n\n"
                f"ML Anomaly Detections: {ip_history['anomaly_count']}\n"
                f"Avg Anomaly Score: {ip_history['avg_anomaly_score']:.1%}",
                title="IP History",
                border_style="cyan"
            ))

        elif action == "cleanup":
            deleted = db.cleanup_old_runs(days)
            console.print(f"[green]Deleted {deleted} runs older than {days} days.[/green]")

        else:
            console.print(f"[red]Unknown action: {action}[/red]")
            console.print("[dim]Valid actions: list, show, compare, trend, top, ip, cleanup[/dim]")
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        raise typer.Exit(1)


@app.callback()
def main():
    """ML-first VPS log security analyzer."""
    pass


if __name__ == "__main__":
    app()

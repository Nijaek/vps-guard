"""CLI interface for VPSGuard."""

import sys
import json
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from vpsguard.parsers import get_parser
from vpsguard.generators import SyntheticLogGenerator, GeneratorConfig, AttackConfig, AttackProfile
from vpsguard.models.events import EventType

app = typer.Typer(
    name="vpsguard",
    help="ML-first VPS log security analyzer",
    add_completion=False,
)
console = Console()


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
            content = path.read_text(encoding="utf-8")
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
            output_path = Path(output)
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
        output_path = Path(output)

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


@app.callback()
def main():
    """ML-first VPS log security analyzer."""
    pass


if __name__ == "__main__":
    app()

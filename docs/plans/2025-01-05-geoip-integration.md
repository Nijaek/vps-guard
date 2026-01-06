# GeoIP Integration Implementation Plan

**Date:** 2025-01-05
**Status:** Ready for Implementation
**Priority:** P1

---

## Overview

Add geographic context to IP addresses using MaxMind's GeoLite2 database. Users can download the database via CLI command. If not downloaded, geo features are gracefully disabled.

---

## User Experience

```bash
# Download GeoLite2 database (first-time setup)
vpsguard geoip download
# Output: Downloading GeoLite2-City database...
#         Saved to ~/.vpsguard/GeoLite2-City.mmdb (68.4 MB)
#         Database ready: 4,567,890 IP ranges loaded

# Check database status
vpsguard geoip status
# Output: GeoLite2-City database
#         Path: ~/.vpsguard/GeoLite2-City.mmdb
#         Size: 68.4 MB
#         Updated: 2025-01-01
#         Status: Ready

# Analyze with geo enrichment
vpsguard analyze /var/log/auth.log --geoip
# Output includes: IP: 45.33.32.156 (Russia, Moscow)

# If database not downloaded
vpsguard analyze /var/log/auth.log --geoip
# Output: [warning] GeoIP database not found. Run 'vpsguard geoip download' to enable.
#         Continuing without geo enrichment...
```

---

## Tasks

### Task 1: Add geoip2 Dependency

**Files:**
- Modify: `pyproject.toml`

**Changes:**
```toml
[project]
dependencies = [
    # ... existing deps
    "geoip2>=4.0",
]
```

**Verification:**
```bash
pip install -e .
python -c "import geoip2; print('geoip2 OK')"
```

---

### Task 2: Create GeoIP Module Structure

**Files:**
- Create: `src/vpsguard/geo/__init__.py`
- Create: `src/vpsguard/geo/reader.py`
- Create: `src/vpsguard/geo/database.py`

**Step 1: Create `src/vpsguard/geo/__init__.py`**
```python
"""GeoIP integration for IP geolocation."""

from .reader import GeoIPReader, GeoLocation
from .database import GeoDatabase, get_default_db_path

__all__ = [
    "GeoIPReader",
    "GeoLocation",
    "GeoDatabase",
    "get_default_db_path",
]
```

**Step 2: Create `src/vpsguard/geo/reader.py`**
```python
"""GeoIP database reader."""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class GeoLocation:
    """Geographic location data for an IP address."""
    country_code: Optional[str] = None  # ISO 3166-1 alpha-2 (e.g., "US")
    country_name: Optional[str] = None  # Full name (e.g., "United States")
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    def __str__(self) -> str:
        """Human-readable location string."""
        parts = []
        if self.country_code:
            parts.append(self.country_code)
        if self.city:
            parts.insert(0, self.city)
        return ", ".join(parts) if parts else "Unknown"


class GeoIPReader:
    """Reader for MaxMind GeoLite2 database."""

    def __init__(self, db_path: Path):
        """Initialize reader with database path.

        Args:
            db_path: Path to GeoLite2-City.mmdb file

        Raises:
            FileNotFoundError: If database file doesn't exist
        """
        if not db_path.exists():
            raise FileNotFoundError(f"GeoIP database not found: {db_path}")

        import geoip2.database
        self._reader = geoip2.database.Reader(str(db_path))
        self._db_path = db_path

    def lookup(self, ip: str) -> GeoLocation:
        """Look up geographic location for an IP address.

        Args:
            ip: IPv4 or IPv6 address string

        Returns:
            GeoLocation with available geographic data
        """
        try:
            response = self._reader.city(ip)
            return GeoLocation(
                country_code=response.country.iso_code,
                country_name=response.country.name,
                city=response.city.name,
                latitude=response.location.latitude,
                longitude=response.location.longitude,
            )
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
            return GeoLocation()

    def close(self):
        """Close the database reader."""
        self._reader.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
```

**Step 3: Create `src/vpsguard/geo/database.py`**
```python
"""GeoIP database management."""

import hashlib
import logging
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# GeoLite2 database download URL (using a mirror that doesn't require license key)
# Note: For production, users should get their own MaxMind license key
GEOLITE2_CITY_URL = "https://git.io/GeoLite2-City.mmdb"  # Redirect to latest
GEOLITE2_CITY_BACKUP_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"


def get_default_db_path() -> Path:
    """Get default path for GeoLite2 database."""
    return Path.home() / ".vpsguard" / "GeoLite2-City.mmdb"


@dataclass
class DatabaseInfo:
    """Information about the GeoIP database."""
    path: Path
    exists: bool
    size_mb: Optional[float] = None
    modified: Optional[datetime] = None

    @property
    def status(self) -> str:
        if not self.exists:
            return "Not downloaded"
        return "Ready"


def get_database_info(db_path: Optional[Path] = None) -> DatabaseInfo:
    """Get information about the GeoIP database.

    Args:
        db_path: Path to database file. Uses default if None.

    Returns:
        DatabaseInfo with current database status
    """
    path = db_path or get_default_db_path()

    if not path.exists():
        return DatabaseInfo(path=path, exists=False)

    stat = path.stat()
    return DatabaseInfo(
        path=path,
        exists=True,
        size_mb=stat.st_size / (1024 * 1024),
        modified=datetime.fromtimestamp(stat.st_mtime),
    )


def download_database(
    db_path: Optional[Path] = None,
    progress_callback=None
) -> Path:
    """Download GeoLite2-City database.

    Args:
        db_path: Destination path. Uses default if None.
        progress_callback: Optional callback(bytes_downloaded, total_bytes)

    Returns:
        Path to downloaded database

    Raises:
        Exception: If download fails
    """
    path = db_path or get_default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    # Try primary URL, fall back to backup
    urls = [GEOLITE2_CITY_URL, GEOLITE2_CITY_BACKUP_URL]
    last_error = None

    for url in urls:
        try:
            logger.info(f"Downloading GeoLite2-City from {url}")

            # Download with progress tracking
            req = urllib.request.Request(url, headers={"User-Agent": "VPSGuard/1.0"})

            with urllib.request.urlopen(req, timeout=60) as response:
                total_size = int(response.headers.get("Content-Length", 0))
                downloaded = 0

                with open(path, "wb") as f:
                    while True:
                        chunk = response.read(8192)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)

                        if progress_callback and total_size:
                            progress_callback(downloaded, total_size)

            # Verify it's a valid MMDB file
            if path.stat().st_size < 1000:
                raise ValueError("Downloaded file too small, likely invalid")

            logger.info(f"Downloaded to {path} ({path.stat().st_size / 1024 / 1024:.1f} MB)")
            return path

        except Exception as e:
            last_error = e
            logger.warning(f"Download from {url} failed: {e}")
            if path.exists():
                path.unlink()  # Clean up partial download

    raise RuntimeError(f"Failed to download GeoLite2 database: {last_error}")


def delete_database(db_path: Optional[Path] = None) -> bool:
    """Delete the GeoIP database.

    Args:
        db_path: Path to database. Uses default if None.

    Returns:
        True if deleted, False if didn't exist
    """
    path = db_path or get_default_db_path()
    if path.exists():
        path.unlink()
        return True
    return False
```

**Verification:**
```bash
python -c "from vpsguard.geo import GeoIPReader, GeoDatabase; print('geo module OK')"
```

---

### Task 3: Add GeoIP Config Schema

**Files:**
- Modify: `src/vpsguard/config.py`

**Add dataclass:**
```python
@dataclass
class GeoIPConfig:
    """GeoIP configuration."""
    enabled: bool = True
    database_path: str = "~/.vpsguard/GeoLite2-City.mmdb"
```

**Add to VPSGuardConfig:**
```python
@dataclass
class VPSGuardConfig:
    # ... existing fields
    geoip: GeoIPConfig = field(default_factory=GeoIPConfig)
```

**Add TOML parsing in _build_config():**
```python
# GeoIP config
geoip_data = data.get("geoip", {})
geoip = GeoIPConfig(
    enabled=geoip_data.get("enabled", True),
    database_path=geoip_data.get("database_path", "~/.vpsguard/GeoLite2-City.mmdb"),
)
```

**Verification:**
```bash
python -c "from vpsguard.config import GeoIPConfig; print('config OK')"
```

---

### Task 4: Add CLI Commands for GeoIP

**Files:**
- Modify: `src/vpsguard/cli.py`

**Add geoip command group:**
```python
@app.command()
def geoip(
    action: str = typer.Argument(..., help="Action: download, status, delete"),
):
    """Manage GeoIP database for geographic lookups.

    Actions:
        download  Download GeoLite2-City database (~70MB)
        status    Show database status and info
        delete    Remove downloaded database

    Examples:
        vpsguard geoip download
        vpsguard geoip status
    """
    from vpsguard.geo.database import (
        get_default_db_path,
        get_database_info,
        download_database,
        delete_database,
    )

    if action == "download":
        console.print("[cyan]Downloading GeoLite2-City database...[/cyan]")

        def progress(downloaded, total):
            pct = downloaded / total * 100
            console.print(f"\r[dim]Progress: {pct:.1f}%[/dim]", end="")

        try:
            path = download_database(progress_callback=progress)
            console.print()  # Newline after progress
            info = get_database_info(path)
            console.print(f"[green]✓ Downloaded to {path}[/green]")
            console.print(f"[dim]  Size: {info.size_mb:.1f} MB[/dim]")
        except Exception as e:
            console.print(f"\n[red]Download failed: {e}[/red]")
            raise typer.Exit(1)

    elif action == "status":
        info = get_database_info()
        console.print("[bold]GeoIP Database Status[/bold]")
        console.print(f"  Path:     {info.path}")
        console.print(f"  Status:   {info.status}")
        if info.exists:
            console.print(f"  Size:     {info.size_mb:.1f} MB")
            console.print(f"  Modified: {info.modified.strftime('%Y-%m-%d %H:%M')}")
        else:
            console.print("\n[yellow]Run 'vpsguard geoip download' to enable geo features[/yellow]")

    elif action == "delete":
        if delete_database():
            console.print("[green]GeoIP database deleted[/green]")
        else:
            console.print("[yellow]No database to delete[/yellow]")

    else:
        console.print(f"[red]Unknown action: {action}[/red]")
        console.print("Valid actions: download, status, delete")
        raise typer.Exit(1)
```

**Verification:**
```bash
vpsguard geoip status
vpsguard geoip download
vpsguard geoip status
```

---

### Task 5: Add --geoip Flag to Analyze Command

**Files:**
- Modify: `src/vpsguard/cli.py`

**Add parameter to analyze():**
```python
def analyze(
    # ... existing params
    geoip: bool = typer.Option(False, "--geoip", help="Enable geographic IP lookups"),
):
```

**Add geo enrichment logic after parsing:**
```python
# GeoIP enrichment (if enabled)
geo_reader = None
if geoip:
    from vpsguard.geo import GeoIPReader, get_default_db_path

    db_path = Path(vps_config.geoip.database_path).expanduser()
    if not db_path.exists():
        db_path = get_default_db_path()

    if db_path.exists():
        geo_reader = GeoIPReader(db_path)
        if format != "json":
            console.print("[dim]GeoIP enrichment enabled[/dim]")
    else:
        console.print("[yellow]GeoIP database not found. Run 'vpsguard geoip download' to enable.[/yellow]")
        console.print("[dim]Continuing without geo enrichment...[/dim]")
```

**Pass geo_reader to report generation for display.**

**Verification:**
```bash
vpsguard analyze test.log --geoip
```

---

### Task 6: Update Reporters for Geo Display

**Files:**
- Modify: `src/vpsguard/reporters/terminal.py`
- Modify: `src/vpsguard/reporters/markdown.py`
- Modify: `src/vpsguard/reporters/html.py`
- Modify: `src/vpsguard/reporters/json_reporter.py`

**Example change for terminal reporter:**
```python
# In finding display, if geo_location available:
# Before: IP: 45.33.32.156
# After:  IP: 45.33.32.156 (RU, Moscow)
```

**Verification:**
```bash
vpsguard analyze test.log --geoip --format terminal
vpsguard analyze test.log --geoip --format markdown
```

---

### Task 7: Create Tests for GeoIP Module

**Files:**
- Create: `tests/test_geoip.py`

**Test cases:**
```python
def test_geo_location_str():
    """GeoLocation should format as 'City, CC'."""

def test_geoip_reader_lookup():
    """Should look up known IP addresses."""

def test_geoip_reader_missing_db():
    """Should raise FileNotFoundError for missing database."""

def test_database_info_not_downloaded():
    """Should report status as 'Not downloaded'."""

def test_download_database(tmp_path):
    """Should download database to specified path."""
    # Note: May want to mock network calls

def test_geoip_config_defaults():
    """Should have sensible defaults."""
```

**Verification:**
```bash
python -m pytest tests/test_geoip.py -v
```

---

### Task 8: Update Documentation

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

**Add to README.md:**
```markdown
### Geographic IP Lookups

VPSGuard can enrich findings with geographic location data:

\`\`\`bash
# Download GeoLite2 database (one-time, ~70MB)
vpsguard geoip download

# Analyze with geo enrichment
vpsguard analyze /var/log/auth.log --geoip
\`\`\`

This shows country and city for each IP in the report:
- IP: 45.33.32.156 (Russia, Moscow)
```

**Verification:**
- README includes geoip section
- CLAUDE.md module list includes geo/

---

## Verification Checklist

- [ ] `pip install -e .` installs geoip2 dependency
- [ ] `vpsguard geoip status` shows "Not downloaded" initially
- [ ] `vpsguard geoip download` fetches ~70MB database
- [ ] `vpsguard geoip status` shows "Ready" after download
- [ ] `vpsguard analyze test.log --geoip` enriches IPs with location
- [ ] Without database, `--geoip` shows warning and continues
- [ ] All reporters display geo information
- [ ] Tests pass: `python -m pytest tests/test_geoip.py -v`

---

## Rollback Plan

If issues arise:
1. Remove geoip2 from dependencies
2. Remove `--geoip` flag from analyze
3. Remove geoip CLI command
4. Delete `src/vpsguard/geo/` directory

No database schema changes, so rollback is clean.

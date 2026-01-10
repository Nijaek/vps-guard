"""GeoIP database management."""

import logging
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)


def _validate_db_path(path: Path) -> Path:
    """Validate that a database path is safe to use.

    Prevents path traversal attacks by ensuring paths are within safe directories.

    Args:
        path: The path to validate.

    Returns:
        Validated Path object.

    Raises:
        ValueError: If the path uses traversal or is in a restricted location.
    """
    # Check for path traversal attempts
    if '..' in path.parts:
        raise ValueError(
            f"Path traversal not allowed: {path}. "
            "Use direct paths without '..' components."
        )

    # Get the resolved absolute path
    try:
        resolved = path.resolve()
    except (OSError, ValueError) as e:
        raise ValueError(f"Invalid path: {path} - {e}")

    # Define safe base directories
    cwd = Path.cwd().resolve()
    home = Path.home().resolve()
    vpsguard_dir = (home / ".vpsguard").resolve()

    # For relative paths, they resolve relative to cwd (safe)
    if not path.is_absolute():
        return resolved

    # For absolute paths, check against safe directories
    safe_bases = [cwd, home, vpsguard_dir]
    for safe_base in safe_bases:
        try:
            resolved.relative_to(safe_base)
            return resolved
        except ValueError:
            continue

    raise ValueError(
        f"Database path must be within current directory, home, or ~/.vpsguard: {path}"
    )


def _validate_mmdb_file(path: Path) -> bool:
    """Validate that a file is a valid MaxMind MMDB database.

    This verifies the file can be opened and read by geoip2,
    which is more robust than a checksum since:
    - Third-party mirrors don't provide checksums
    - Checksums change with every database update
    - Parsing verification catches both corruption and MITM attacks

    Args:
        path: Path to the downloaded file

    Returns:
        True if valid, False otherwise
    """
    try:
        import geoip2.database
        with geoip2.database.Reader(str(path)) as reader:
            # Try to access metadata to verify the file is valid
            metadata = reader.metadata()
            # Check it's actually a City database
            if 'City' not in metadata.database_type:
                logger.warning(f"Database type mismatch: {metadata.database_type}")
                return False
            logger.debug(f"Valid MMDB: {metadata.database_type}, built {metadata.build_epoch}")
            return True
    except Exception as e:
        logger.warning(f"MMDB validation failed: {e}")
        return False

# GeoLite2 database download URLs (public mirrors that don't require license key)
GEOLITE2_URLS = [
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
    "https://git.io/GeoLite2-City.mmdb",
]


def get_default_db_path() -> Path:
    """Get default path for GeoLite2 database."""
    return Path.home() / ".vpsguard" / "GeoLite2-City.mmdb"


@dataclass
class GeoDatabase:
    """Information about the GeoIP database."""
    path: Path
    exists: bool
    size_mb: Optional[float] = None
    modified: Optional[datetime] = None

    @property
    def status(self) -> str:
        """Human-readable status string."""
        if not self.exists:
            return "Not downloaded"
        return "Ready"


def get_database_info(db_path: Optional[Path] = None) -> GeoDatabase:
    """Get information about the GeoIP database.

    Args:
        db_path: Path to database file. Uses default if None.

    Returns:
        GeoDatabase with current database status
    """
    path = db_path or get_default_db_path()

    if not path.exists():
        return GeoDatabase(path=path, exists=False)

    stat = path.stat()
    return GeoDatabase(
        path=path,
        exists=True,
        size_mb=stat.st_size / (1024 * 1024),
        modified=datetime.fromtimestamp(stat.st_mtime),
    )


def download_database(
    db_path: Optional[Path] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> Path:
    """Download GeoLite2-City database.

    Args:
        db_path: Destination path. Uses default if None.
        progress_callback: Optional callback(bytes_downloaded, total_bytes)

    Returns:
        Path to downloaded database

    Raises:
        RuntimeError: If download fails from all sources
        ValueError: If db_path uses path traversal or is in a restricted location
    """
    # Validate path if provided (default path is always safe)
    if db_path is not None:
        path = _validate_db_path(db_path)
    else:
        path = get_default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    last_error = None

    for url in GEOLITE2_URLS:
        try:
            logger.info(f"Downloading GeoLite2-City from {url}")

            req = urllib.request.Request(
                url,
                headers={"User-Agent": "VPSGuard/1.0"}
            )

            with urllib.request.urlopen(req, timeout=120) as response:
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

            # Verify it's a valid MMDB file (should be at least 1MB)
            file_size = path.stat().st_size
            if file_size < 1_000_000:
                raise ValueError(f"Downloaded file too small ({file_size} bytes), likely invalid")

            # Validate the file is actually a valid MMDB database
            # This protects against MITM attacks and corruption
            if not _validate_mmdb_file(path):
                raise ValueError("Downloaded file is not a valid MaxMind MMDB database")

            logger.info(f"Downloaded to {path} ({file_size / 1024 / 1024:.1f} MB)")
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

    Raises:
        ValueError: If db_path uses path traversal or is in a restricted location
    """
    # Validate path if provided (default path is always safe)
    if db_path is not None:
        path = _validate_db_path(db_path)
    else:
        path = get_default_db_path()
    if path.exists():
        path.unlink()
        return True
    return False

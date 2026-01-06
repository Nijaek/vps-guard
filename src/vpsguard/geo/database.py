"""GeoIP database management."""

import logging
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)

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
    """
    path = db_path or get_default_db_path()
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
    """
    path = db_path or get_default_db_path()
    if path.exists():
        path.unlink()
        return True
    return False

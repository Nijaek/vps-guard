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

    @property
    def is_known(self) -> bool:
        """Check if location has any data."""
        return self.country_code is not None


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
        self._cache: dict[str, GeoLocation] = {}

    def lookup(self, ip: str) -> GeoLocation:
        """Look up geographic location for an IP address.

        Args:
            ip: IPv4 or IPv6 address string

        Returns:
            GeoLocation with available geographic data
        """
        # Check cache first
        if ip in self._cache:
            return self._cache[ip]

        try:
            response = self._reader.city(ip)
            location = GeoLocation(
                country_code=response.country.iso_code,
                country_name=response.country.name,
                city=response.city.name,
                latitude=response.location.latitude,
                longitude=response.location.longitude,
            )
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
            location = GeoLocation()

        # Cache the result
        self._cache[ip] = location
        return location

    def lookup_many(self, ips: list[str]) -> dict[str, GeoLocation]:
        """Look up multiple IP addresses.

        Args:
            ips: List of IP address strings

        Returns:
            Dict mapping IP to GeoLocation
        """
        return {ip: self.lookup(ip) for ip in set(ips)}

    def close(self):
        """Close the database reader."""
        self._reader.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

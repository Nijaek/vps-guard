"""GeoIP integration for IP geolocation."""

from .database import (
    GeoDatabase,
    delete_database,
    download_database,
    get_database_info,
    get_default_db_path,
)
from .reader import GeoIPReader, GeoLocation
from .velocity import (
    TravelEvent,
    analyze_user_travel,
    calculate_velocity,
    format_travel_summary,
    format_velocity,
    haversine_distance,
)

__all__ = [
    "GeoIPReader",
    "GeoLocation",
    "GeoDatabase",
    "get_default_db_path",
    "get_database_info",
    "download_database",
    "delete_database",
    "TravelEvent",
    "haversine_distance",
    "calculate_velocity",
    "analyze_user_travel",
    "format_velocity",
    "format_travel_summary",
]

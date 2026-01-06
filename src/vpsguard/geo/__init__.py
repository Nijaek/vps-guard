"""GeoIP integration for IP geolocation."""

from .reader import GeoIPReader, GeoLocation
from .database import GeoDatabase, get_default_db_path, get_database_info, download_database, delete_database
from .velocity import (
    TravelEvent,
    haversine_distance,
    calculate_velocity,
    analyze_user_travel,
    format_velocity,
    format_travel_summary,
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

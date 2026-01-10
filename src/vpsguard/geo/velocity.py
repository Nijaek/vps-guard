"""Geographic velocity calculations for impossible travel detection."""

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .reader import GeoLocation

# Earth's radius in kilometers
EARTH_RADIUS_KM = 6371.0

# Maximum velocity value for "instantaneous" travel (used instead of infinity)
# This is 1e9 km/h - much faster than light, but JSON-serializable
MAX_VELOCITY_KM_H = 1e9


@dataclass
class TravelEvent:
    """Represents travel between two login locations."""
    username: str
    from_ip: str
    to_ip: str
    from_location: GeoLocation
    to_location: GeoLocation
    from_time: datetime
    to_time: datetime
    distance_km: float
    time_hours: float
    velocity_km_h: float

    @property
    def is_impossible(self) -> bool:
        """Check if travel velocity exceeds reasonable limits.

        Commercial jets cruise at ~900 km/h, so anything above
        1000 km/h is considered impossible.
        """
        return self.velocity_km_h > 1000.0


def haversine_distance(loc1: GeoLocation, loc2: GeoLocation) -> Optional[float]:
    """Calculate great-circle distance between two locations using Haversine formula.

    Args:
        loc1: First location with latitude/longitude
        loc2: Second location with latitude/longitude

    Returns:
        Distance in kilometers, or None if coordinates unavailable
    """
    if (loc1.latitude is None or loc1.longitude is None or
        loc2.latitude is None or loc2.longitude is None):
        return None

    # Convert to radians
    lat1 = math.radians(loc1.latitude)
    lat2 = math.radians(loc2.latitude)
    lon1 = math.radians(loc1.longitude)
    lon2 = math.radians(loc2.longitude)

    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2

    # Clamp 'a' to [0, 1] to prevent math domain errors due to floating-point precision
    # For antipodal points (opposite sides of Earth), 'a' can slightly exceed 1.0
    # due to rounding errors, which would cause math.asin(math.sqrt(a)) to fail
    a = min(1.0, max(0.0, a))

    c = 2 * math.asin(math.sqrt(a))

    return EARTH_RADIUS_KM * c


def calculate_velocity(
    loc1: GeoLocation,
    loc2: GeoLocation,
    time1: datetime,
    time2: datetime
) -> Optional[float]:
    """Calculate travel velocity between two locations.

    Args:
        loc1: Starting location
        loc2: Ending location
        time1: Time at starting location
        time2: Time at ending location

    Returns:
        Velocity in km/h, or None if calculation not possible
    """
    distance = haversine_distance(loc1, loc2)
    if distance is None:
        return None

    # Calculate time difference in hours
    time_diff = abs((time2 - time1).total_seconds()) / 3600.0

    # Avoid division by zero (logins at same second)
    if time_diff < 0.001:  # Less than ~4 seconds
        # If same location (within 1km), velocity is 0
        if distance < 1.0:
            return 0.0
        # Different locations at same time = "instantaneous" travel
        # Use MAX_VELOCITY_KM_H instead of infinity for JSON safety
        return MAX_VELOCITY_KM_H

    return distance / time_diff


def analyze_user_travel(
    events: list[tuple[datetime, str, GeoLocation]],
    username: str
) -> list[TravelEvent]:
    """Analyze sequential logins for a user and calculate travel velocities.

    Args:
        events: List of (timestamp, ip, geo_location) tuples, sorted by time
        username: Username for these events

    Returns:
        List of TravelEvent objects for each sequential login pair
    """
    if len(events) < 2:
        return []

    travel_events = []

    for i in range(len(events) - 1):
        time1, ip1, loc1 = events[i]
        time2, ip2, loc2 = events[i + 1]

        # Skip if same IP (no travel)
        if ip1 == ip2:
            continue

        # Calculate distance and velocity
        distance = haversine_distance(loc1, loc2)
        if distance is None:
            continue

        # Skip very short distances (same city/region)
        if distance < 50.0:  # 50km threshold
            continue

        time_hours = abs((time2 - time1).total_seconds()) / 3600.0

        if time_hours < 0.001:
            velocity = MAX_VELOCITY_KM_H
        else:
            velocity = distance / time_hours

        travel_events.append(TravelEvent(
            username=username,
            from_ip=ip1,
            to_ip=ip2,
            from_location=loc1,
            to_location=loc2,
            from_time=time1,
            to_time=time2,
            distance_km=distance,
            time_hours=time_hours,
            velocity_km_h=velocity,
        ))

    return travel_events


def format_velocity(velocity: float) -> str:
    """Format velocity for human-readable output.

    Args:
        velocity: Velocity in km/h

    Returns:
        Formatted string
    """
    if velocity >= MAX_VELOCITY_KM_H:
        return "instantaneous"
    elif velocity > 10000:
        return f"{velocity / 1000:.1f}k km/h"
    elif velocity > 1000:
        return f"{velocity:.0f} km/h (impossible)"
    else:
        return f"{velocity:.0f} km/h"


def format_travel_summary(event: TravelEvent) -> str:
    """Format a travel event for reporting.

    Args:
        event: TravelEvent to format

    Returns:
        Human-readable summary string
    """
    from_loc = str(event.from_location) or "Unknown"
    to_loc = str(event.to_location) or "Unknown"

    time_str = f"{event.time_hours:.1f}h" if event.time_hours >= 1 else f"{event.time_hours * 60:.0f}min"

    return (
        f"User '{event.username}' traveled {event.distance_km:.0f}km "
        f"({from_loc} → {to_loc}) in {time_str} = {format_velocity(event.velocity_km_h)}"
    )

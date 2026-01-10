"""Geographic velocity detection rule for impossible travel."""

from collections import defaultdict
from datetime import datetime
from typing import Optional

from vpsguard.config import GeoVelocityConfig
from vpsguard.geo import GeoLocation, format_velocity, haversine_distance
from vpsguard.models.events import AuthEvent, EventType, RuleViolation, Severity


class GeoVelocityRule:
    """Detects impossible travel by analyzing login velocities across locations.

    This rule identifies when the same username logs in from geographically
    distant locations in a short time period, indicating either:
    - Credential sharing/compromise
    - VPN/proxy usage
    - Account takeover

    Requires geo_data to be provided during evaluation.
    """

    def __init__(self, config: GeoVelocityConfig):
        """Initialize the geo velocity rule.

        Args:
            config: Rule configuration with velocity thresholds
        """
        self.config = config
        self.name = "geo_velocity"
        self.severity = config.severity
        self.enabled = config.enabled

    def evaluate(
        self,
        events: list[AuthEvent],
        geo_data: Optional[dict[str, GeoLocation]] = None
    ) -> list[RuleViolation]:
        """Evaluate events for impossible travel patterns.

        Args:
            events: List of authentication events to analyze
            geo_data: Optional mapping of IP addresses to GeoLocation.
                     If not provided, rule returns no violations.

        Returns:
            List of RuleViolation objects for detected impossible travel
        """
        if not self.enabled:
            return []

        if not geo_data:
            return []

        # Group successful logins by username
        user_logins: dict[str, list[tuple[datetime, str, GeoLocation]]] = defaultdict(list)

        for event in events:
            # Only consider successful logins for impossible travel
            if event.event_type != EventType.SUCCESSFUL_LOGIN:
                continue
            if not event.success:
                continue
            if not event.ip or not event.username:
                continue

            geo = geo_data.get(event.ip)
            if not geo or not geo.latitude or not geo.longitude:
                continue

            user_logins[event.username].append((event.timestamp, event.ip, geo))

        violations = []

        # Analyze each user's login sequence
        for username, logins in user_logins.items():
            if len(logins) < 2:
                continue

            # Sort by timestamp
            logins.sort(key=lambda x: x[0])

            # Check each consecutive pair
            for i in range(len(logins) - 1):
                time1, ip1, geo1 = logins[i]
                time2, ip2, geo2 = logins[i + 1]

                # Skip if same IP
                if ip1 == ip2:
                    continue

                # Calculate distance
                distance = haversine_distance(geo1, geo2)
                if distance is None:
                    continue

                # Skip short distances
                if distance < self.config.min_distance_km:
                    continue

                # Calculate time difference in hours
                time_diff_hours = abs((time2 - time1).total_seconds()) / 3600.0

                # Calculate velocity
                if time_diff_hours < 0.001:  # Less than ~4 seconds
                    velocity = float('inf')
                else:
                    velocity = distance / time_diff_hours

                # Check if impossible
                if velocity > self.config.max_velocity_km_h:
                    # Find all events for this user between these times
                    affected = [
                        e for e in events
                        if e.username == username
                        and e.ip in (ip1, ip2)
                        and time1 <= e.timestamp <= time2
                    ]

                    # Format locations
                    loc1_str = str(geo1) if geo1.is_known else ip1
                    loc2_str = str(geo2) if geo2.is_known else ip2

                    time_str = self._format_time_diff(time_diff_hours)

                    violation = RuleViolation(
                        rule_name=self.name,
                        severity=Severity(self.severity),
                        ip=ip2,  # Report the destination IP
                        description=(
                            f"Impossible travel detected for user '{username}': "
                            f"{loc1_str} → {loc2_str} ({distance:.0f}km) in {time_str} "
                            f"= {format_velocity(velocity)}"
                        ),
                        timestamp=time2,
                        details={
                            "username": username,
                            "from_ip": ip1,
                            "to_ip": ip2,
                            "from_location": loc1_str,
                            "to_location": loc2_str,
                            "distance_km": round(distance, 1),
                            "time_hours": round(time_diff_hours, 2),
                            "velocity_km_h": round(velocity, 1) if velocity != float('inf') else "infinite",
                            "max_allowed_km_h": self.config.max_velocity_km_h,
                        },
                        affected_events=affected if affected else [
                            e for e in events
                            if e.username == username and e.ip == ip2
                        ][:5],  # Limit affected events
                    )
                    violations.append(violation)

        return violations

    def _format_time_diff(self, hours: float) -> str:
        """Format time difference for human-readable output."""
        if hours < 1/60:  # Less than 1 minute
            return f"{hours * 3600:.0f}s"
        elif hours < 1:
            return f"{hours * 60:.0f}min"
        elif hours < 24:
            return f"{hours:.1f}h"
        else:
            return f"{hours / 24:.1f}d"

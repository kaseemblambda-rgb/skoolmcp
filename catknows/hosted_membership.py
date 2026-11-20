"""Shared legacy account-policy helpers only.

Production connector eligibility is enforced by the restricted SQL gateway.
Mac owner export, collection, Keychain and scheduling code are not published here.
"""
from datetime import datetime, timezone, timedelta


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Expected timezone-aware timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp timezone required")
    return parsed.astimezone(timezone.utc)


def eligible(row, paid_tiers, now):
    try:
        observed = timestamp(row["observed_at"])
        return (
            row["tier"] in paid_tiers
            and row["lifecycle"] in ("active", "cancelling")
            and observed <= now + timedelta(minutes=1)
            and now - observed <= timedelta(hours=24)
            and now < timestamp(row["paid_through_at"])
        )
    except (ValueError, TypeError, KeyError):
        return False

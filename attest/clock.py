"""Timestamps are ISO-8601 strings, never numbers (SPEC.md)."""

from datetime import datetime, timezone


def utc_now_iso():
    """Return the current UTC time as e.g. "2026-08-01T10:00:00.000Z"."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return now.isoformat(timespec="milliseconds") + "Z"

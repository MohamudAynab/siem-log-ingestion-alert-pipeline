"""Shared SIEM v1 schema setup and log-entry validation utilities.

Changelog:
    v1: Initial SQLite table definition and dependency-free validator.
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Mapping


CREATE_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS logs (
    log_id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    action_status INTEGER NOT NULL CHECK (action_status BETWEEN 100 AND 599),
    raw_line TEXT,
    severity TEXT
);
""".strip()

_REQUIRED_FIELDS = {
    "log_id",
    "timestamp",
    "source_ip",
    "endpoint",
    "user_agent",
    "action_status",
}
_OPTIONAL_FIELDS = {"raw_line", "severity"}
_ALLOWED_FIELDS = _REQUIRED_FIELDS | _OPTIONAL_FIELDS
_TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def validate_log_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a SIEM log entry before database insertion.

    Raises:
        ValueError: If the entry violates the shared v1 schema.
        TypeError: If ``entry`` is not a mapping.
    """
    if not isinstance(entry, Mapping):
        raise TypeError("log entry must be a mapping")

    missing_fields = _REQUIRED_FIELDS - entry.keys()
    if missing_fields:
        missing = ", ".join(sorted(missing_fields))
        raise ValueError(f"missing required field(s): {missing}")

    unexpected_fields = set(entry) - _ALLOWED_FIELDS
    if unexpected_fields:
        unexpected = ", ".join(sorted(unexpected_fields))
        raise ValueError(f"unexpected field(s): {unexpected}")

    _validate_log_id(entry["log_id"])
    _validate_timestamp(entry["timestamp"])
    _validate_source_ip(entry["source_ip"])

    for field_name in ("endpoint", "user_agent"):
        _require_string(entry[field_name], field_name)

    action_status = entry["action_status"]
    if isinstance(action_status, bool) or not isinstance(action_status, int):
        raise ValueError("action_status must be an integer")
    if not 100 <= action_status <= 599:
        raise ValueError("action_status must be between 100 and 599")

    for field_name in _OPTIONAL_FIELDS:
        if field_name in entry:
            _require_string(entry[field_name], field_name)

    return dict(entry)


def _validate_log_id(log_id: Any) -> None:
    if isinstance(log_id, bool):
        raise ValueError("log_id must be a positive integer or UUID")
    if isinstance(log_id, int):
        if log_id < 1:
            raise ValueError("integer log_id must be positive")
        return
    if isinstance(log_id, str):
        try:
            uuid.UUID(log_id)
        except (ValueError, AttributeError):
            raise ValueError("string log_id must be a valid UUID") from None
        return
    raise ValueError("log_id must be a positive integer or UUID")


def _validate_timestamp(timestamp: Any) -> None:
    if not isinstance(timestamp, str) or not _TIMESTAMP_PATTERN.fullmatch(timestamp):
        raise ValueError("timestamp must be strict ISO 8601 text with a timezone")
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("timestamp must be a valid ISO 8601 date-time") from None
    if parsed_timestamp.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")


def _validate_source_ip(source_ip: Any) -> None:
    if not isinstance(source_ip, str):
        raise ValueError("source_ip must be an IPv4 string")
    try:
        parsed_ip = ipaddress.ip_address(source_ip)
    except ValueError:
        raise ValueError("source_ip must be a valid IPv4 address") from None
    if parsed_ip.version != 4:
        raise ValueError("source_ip must be an IPv4 address")


def _require_string(value: Any, field_name: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")


def create_logs_table(connection: sqlite3.Connection) -> None:
    """Create the shared logs table on an open SQLite connection."""
    connection.execute(CREATE_LOGS_TABLE)
    connection.commit()

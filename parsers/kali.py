"""Normalize Kali /var/log/auth.log syslog records."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from database.schema_setup import validate_log_entry
from parsers._common import collector_fields, ipv4_or_sentinel, stable_log_id


_SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[A-Za-z0-9_.-]+)"
    r"(?:\[\d+\])?:\s*(?P<message>.*)$"
)
_ISO_SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>(?:[A-Za-z0-9_.-]+|\([A-Za-z0-9_.-]+\)))"
    r"(?:\[\d+\])?:\s*(?P<message>.*)$"
)
_FAILED_AUTH_PATTERN = re.compile(
    r"\b(failed|failure|invalid password|authentication failure|not allowed)\b",
    re.IGNORECASE,
)
_REMOTE_IPV4_PATTERN = re.compile(r"\bfrom\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")


def _timestamp(
    month: str, day: str, clock: str, collected_at: str, source_timezone: str | None
) -> str:
    collected = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
    if source_timezone is not None:
        if not isinstance(source_timezone, str):
            raise ValueError("source_timezone must be a numeric UTC offset")
        try:
            source_tz = datetime.strptime(source_timezone, "%z").tzinfo
        except ValueError:
            raise ValueError("source_timezone must be a numeric UTC offset") from None
        if source_tz is None:
            raise ValueError("source_timezone must be a numeric UTC offset")
    else:
        source_tz = collected.tzinfo
    local_collected = collected.astimezone(source_tz)
    year = local_collected.year
    parsed = datetime.strptime(f"{month} {day} {year} {clock}", "%b %d %Y %H:%M:%S")
    if parsed.replace(tzinfo=local_collected.tzinfo) > local_collected:
        parsed = parsed.replace(year=year - 1)
    return parsed.replace(tzinfo=local_collected.tzinfo).isoformat()


def parse_kali_event(record: Mapping[str, Any]) -> dict[str, Any]:
    """Parse one auth.log envelope and validate its normalized log."""
    raw, collected_at = collector_fields(record, "kali")
    match = _SYSLOG_PATTERN.match(raw)
    if match is not None:
        event = match.groupdict()
        timestamp = _timestamp(
            event["month"],
            event["day"],
            event["clock"],
            collected_at,
            record.get("source_timezone"),
        )
    else:
        match = _ISO_SYSLOG_PATTERN.match(raw)
        if match is None:
            raise ValueError("Kali auth.log line does not match a supported syslog format")
        event = match.groupdict()
        try:
            timestamp = datetime.fromisoformat(
                event["timestamp"].replace("Z", "+00:00")
            ).isoformat()
        except ValueError:
            raise ValueError("Kali auth.log line has an invalid ISO timestamp") from None

    remote_match = _REMOTE_IPV4_PATTERN.search(event["message"])
    remote_ip = remote_match.group("ip") if remote_match else None
    if remote_ip:
        try:
            ipaddress.IPv4Address(remote_ip)
        except ipaddress.AddressValueError:
            remote_ip = None

    return validate_log_entry(
        {
            "log_id": stable_log_id("kali", collected_at, raw),
            "timestamp": timestamp,
            "source_ip": ipv4_or_sentinel(remote_ip),
            "endpoint": f"kali://auth/{event['program']}",
            "user_agent": f"Kali-auth-{event['program']}",
            "action_status": 401 if _FAILED_AUTH_PATTERN.search(event["message"]) else 200,
            "raw_line": raw,
        }
    )

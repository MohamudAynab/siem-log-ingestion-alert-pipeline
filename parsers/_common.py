"""Shared normalization helpers for raw collector records."""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Mapping
from datetime import datetime
from typing import Any


_LOG_ID_NAMESPACE = uuid.UUID("c18f6c1e-ef38-4cb8-9855-6d9984617c20")
LOCAL_IPV4_SENTINEL = "127.0.0.1"


def collector_fields(record: Mapping[str, Any], expected_source: str) -> tuple[str, str]:
    """Return the raw text and collection time after checking the envelope."""
    if record.get("source") != expected_source:
        raise ValueError(f"expected source {expected_source!r}")

    raw = record.get("raw")
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("raw must be a non-empty string")

    collected_at = record.get("collected_at")
    if not isinstance(collected_at, str):
        raise ValueError("collected_at must be an ISO 8601 string")
    try:
        collected = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("collected_at must be a valid ISO 8601 date-time") from None
    if collected.utcoffset() is None:
        raise ValueError("collected_at must include a timezone")

    return raw, collected_at


def stable_log_id(source: str, collected_at: str, raw: str) -> str:
    """Generate a replay-stable primary key for a collected record."""
    return str(uuid.uuid5(_LOG_ID_NAMESPACE, f"{source}\0{collected_at}\0{raw}"))


def ipv4_or_sentinel(value: str | None) -> str:
    """Return a valid IPv4 address, falling back when the schema cannot represent it."""
    if value:
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            return LOCAL_IPV4_SENTINEL
        if address.version == 4:
            return str(address)
    return LOCAL_IPV4_SENTINEL

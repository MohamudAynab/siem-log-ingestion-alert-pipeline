"""Normalize Windows Security event XML emitted by the Windows collector."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from database.schema_setup import validate_log_entry
from parsers._common import collector_fields, ipv4_or_sentinel, stable_log_id


_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_EVENT_STATUS = {"4624": 200, "4625": 401, "4688": 200}


def parse_windows_event(record: Mapping[str, Any]) -> dict[str, Any]:
    """Parse one Windows event envelope and validate its normalized log."""
    raw, collected_at = collector_fields(record, "windows")
    try:
        event = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"invalid Windows event XML: {exc}") from exc

    event_id_element = event.find(f"./{_EVENT_NS}System/{_EVENT_NS}EventID")
    if event_id_element is None or not event_id_element.text:
        raise ValueError("Windows event is missing System/EventID")
    event_id = event_id_element.text.strip()
    if event_id not in _EVENT_STATUS:
        raise ValueError(f"unsupported Windows event ID: {event_id}")

    created_element = event.find(f"./{_EVENT_NS}System/{_EVENT_NS}TimeCreated")
    system_time = created_element.get("SystemTime") if created_element is not None else None
    if not system_time:
        raise ValueError("Windows event is missing TimeCreated/SystemTime")
    try:
        timestamp = datetime.fromisoformat(system_time.replace("Z", "+00:00")).isoformat()
    except ValueError:
        raise ValueError("Windows event has an invalid SystemTime") from None

    event_data = {
        element.get("Name", ""): element.text or ""
        for element in event.findall(f".//{_EVENT_NS}EventData/{_EVENT_NS}Data")
    }
    source_ip = ipv4_or_sentinel(
        event_data.get("IpAddress") or event_data.get("SourceNetworkAddress")
    )

    return validate_log_entry(
        {
            "log_id": stable_log_id("windows", collected_at, raw),
            "timestamp": timestamp,
            "source_ip": source_ip,
            "endpoint": f"windows://security/event/{event_id}",
            "user_agent": f"Windows-Security-Event-{event_id}",
            "action_status": _EVENT_STATUS[event_id],
            "raw_line": raw,
        }
    )

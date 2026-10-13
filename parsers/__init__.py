"""Convert raw collector records into the shared SIEM log schema."""

from collections.abc import Mapping
from typing import Any

from parsers.kali import parse_kali_event
from parsers.windows import parse_windows_event


def parse_event(record: object) -> dict[str, Any]:
    """Parse one collector JSONL record according to its source."""
    if not isinstance(record, Mapping):
        raise TypeError("collector record must be a JSON object")

    source = record.get("source")
    if source == "windows":
        return parse_windows_event(record)
    if source == "kali":
        return parse_kali_event(record)
    raise ValueError(f"unsupported log source: {source!r}")

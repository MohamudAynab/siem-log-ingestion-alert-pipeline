"""Shared helpers for writing raw collected log lines as JSONL."""

import json
from datetime import datetime, timezone
from pathlib import Path


def write_jsonl_entry(output_dir: Path, source: str, raw_text: str) -> None:
    """Append one raw log entry to today's JSONL file for the given source.

    Ingestion only wraps and stores the untouched raw text here -- parsing
    and validation against the shared schema happens downstream.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    entry = {
        "source": source,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "raw": raw_text,
    }

    file_name = f"{source}-{datetime.now(timezone.utc):%Y%m%d}.jsonl"
    with open(output_dir / file_name, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_state(state_file: Path, default: str) -> str:
    if state_file.exists():
        return state_file.read_text(encoding="utf-8").strip()
    return default


def write_state(state_file: Path, value: str) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(value, encoding="utf-8")

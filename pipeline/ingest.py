"""Process collector JSONL files into the normalized SQLite logs table."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from parsers import parse_event
from storage import DEFAULT_DB_PATH, connect, insert_log


DEFAULT_INCOMING_DIR = Path(__file__).resolve().parent.parent / "ingestion" / "incoming"


def process_jsonl_file(path: Path, connection: sqlite3.Connection) -> int:
    """Ingest one JSONL file and return the number of newly inserted events."""
    inserted = 0
    with path.open(encoding="utf-8") as input_file:
        for line_number, line in enumerate(input_file, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                normalized = parse_event(record)
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
            inserted += insert_log(connection, normalized)
    return inserted


def process_incoming(
    connection: sqlite3.Connection, incoming_dir: Path = DEFAULT_INCOMING_DIR
) -> int:
    """Ingest all incoming JSONL files in stable path order."""
    inserted = 0
    for path in sorted(incoming_dir.glob("**/*.jsonl")):
        inserted += process_jsonl_file(path, connection)
    return inserted


def main() -> None:
    """Run one ingestion pass against the configured local directories."""
    connection = connect(DEFAULT_DB_PATH)
    try:
        inserted = process_incoming(connection)
    finally:
        connection.close()
    print(f"[*] Ingestion complete: {inserted} new event(s) stored.")


if __name__ == "__main__":
    main()

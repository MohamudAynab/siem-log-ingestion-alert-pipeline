"""Validated SQLite persistence for normalized SIEM events."""

from pathlib import Path
import sqlite3
from typing import Any

from database.schema_setup import create_logs_table, validate_log_entry


DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "database" / "siem_logs.db"


def connect(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open a SQLite database and ensure the shared logs table exists."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    create_logs_table(connection)
    return connection


def insert_log(connection: sqlite3.Connection, entry: dict[str, Any]) -> bool:
    """Insert a validated event; return False when its stable ID already exists."""
    validated = validate_log_entry(entry)
    cursor = connection.execute(
        """
        INSERT INTO logs (
            log_id, timestamp, source_ip, endpoint, user_agent, action_status,
            raw_line, severity
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(log_id) DO NOTHING
        """,
        (
            str(validated["log_id"]),
            validated["timestamp"],
            validated["source_ip"],
            validated["endpoint"],
            validated["user_agent"],
            validated["action_status"],
            validated.get("raw_line"),
            validated.get("severity"),
        ),
    )
    connection.commit()
    return cursor.rowcount == 1

"""Validated SQLite persistence for normalized SIEM events."""

from pathlib import Path
import sqlite3
from typing import Any

from database.schema_setup import create_logs_table, validate_log_entry


DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "database" / "siem_logs.db"


def connect(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open a SQLite database and ensure the logs and alerts tables exist."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    create_logs_table(connection)
    create_alerts_table(connection)
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


def create_alerts_table(connection: sqlite3.Connection) -> None:
    """Create the alert table and indexes on an open SQLite connection."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY NOT NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            event_count INTEGER NOT NULL CHECK (event_count > 0),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (rule_id, source_ip, first_seen)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS alerts_created_at_idx ON alerts(created_at)"
    )
    connection.commit()


def insert_alert(connection: sqlite3.Connection, alert: dict[str, Any]) -> bool:
    """Insert a detection result once; return False when already present."""
    existing = connection.execute(
        """
        SELECT 1 FROM alerts
        WHERE rule_id = ? AND source_ip = ? AND first_seen = ?
        """,
        (alert["rule_id"], alert["source_ip"], alert["first_seen"]),
    ).fetchone()
    cursor = connection.execute(
        """
        INSERT INTO alerts (
            alert_id, rule_id, severity, title, description, source_ip,
            first_seen, last_seen, event_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(rule_id, source_ip, first_seen) DO UPDATE SET
            event_count = MAX(alerts.event_count, excluded.event_count),
            description = excluded.description,
            last_seen = CASE
                WHEN alerts.last_seen < excluded.last_seen THEN excluded.last_seen
                ELSE alerts.last_seen
            END
        """,
        (
            alert["alert_id"],
            alert["rule_id"],
            alert["severity"],
            alert["title"],
            alert["description"],
            alert["source_ip"],
            alert["first_seen"],
            alert["last_seen"],
            alert["event_count"],
        ),
    )
    connection.commit()
    return existing is None and cursor.rowcount == 1


def list_alerts(
    connection: sqlite3.Connection, limit: int = 20
) -> list[sqlite3.Row | tuple[Any, ...]]:
    """Return the newest alerts, rejecting non-positive limits."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("alert limit must be a positive integer")
    return connection.execute(
        """
        SELECT alert_id, rule_id, severity, title, description, source_ip,
               first_seen, last_seen, event_count, created_at
        FROM alerts
        ORDER BY created_at DESC, alert_id
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

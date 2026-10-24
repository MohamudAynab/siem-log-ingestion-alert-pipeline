"""Detect repeated failed logons and persist replay-safe alerts."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from storage import create_alerts_table, insert_alert


DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "config" / "detection.json"
_ALERT_NAMESPACE = uuid.UUID("8d2d660a-b824-42b9-9f2e-e6be2fac1f77")
_SEVERITIES = {"low", "medium", "high", "critical"}


def load_rules(path: Path = DEFAULT_RULES_PATH) -> dict[str, Any]:
    """Load and validate brute-force detection configuration."""
    try:
        with path.open(encoding="utf-8") as rules_file:
            rules = json.load(rules_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not load detection rules from {path}: {exc}") from exc

    if not isinstance(rules, dict) or set(rules) != {"brute_force"}:
        raise ValueError("detection rules must contain only the brute_force rule")
    rule = rules["brute_force"]
    required = {"enabled", "threshold", "window_seconds", "severity", "allowlist"}
    if not isinstance(rule, dict) or set(rule) != required:
        raise ValueError(f"brute_force rule must contain exactly: {', '.join(sorted(required))}")
    if not isinstance(rule["enabled"], bool):
        raise ValueError("brute_force enabled must be a boolean")
    for field in ("threshold", "window_seconds"):
        if isinstance(rule[field], bool) or not isinstance(rule[field], int) or rule[field] < 1:
            raise ValueError(f"brute_force {field} must be a positive integer")
    if not isinstance(rule["severity"], str) or rule["severity"] not in _SEVERITIES:
        raise ValueError(f"brute_force severity must be one of: {', '.join(sorted(_SEVERITIES))}")
    if not isinstance(rule["allowlist"], list):
        raise ValueError("brute_force allowlist must be a list of IPv4 addresses")
    for address in rule["allowlist"]:
        try:
            if ipaddress.ip_address(address).version != 4:
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError(f"invalid IPv4 address in brute_force allowlist: {address!r}") from None
    return rule


def detect_brute_force(
    connection: sqlite3.Connection, rule: dict[str, Any]
) -> int:
    """Detect non-overlapping failed-login bursts and insert any new alerts."""
    create_alerts_table(connection)
    if not rule["enabled"]:
        return 0

    allowlist = set(rule["allowlist"])
    rows = connection.execute(
        """
        SELECT log_id, timestamp, source_ip
        FROM logs
        WHERE action_status = 401 AND source_ip != '127.0.0.1'
        ORDER BY source_ip, log_id
        """
    ).fetchall()
    attempts_by_ip: dict[str, list[tuple[datetime, str, str]]] = {}
    for log_id, timestamp, source_ip in rows:
        if source_ip in allowlist:
            continue
        try:
            event_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise ValueError(f"invalid stored event timestamp for log {log_id}: {timestamp!r}") from exc
        attempts_by_ip.setdefault(source_ip, []).append(
            (event_time, event_time.astimezone(timezone.utc).isoformat(), log_id)
        )

    inserted = 0
    window = timedelta(seconds=rule["window_seconds"])
    for source_ip, attempts in attempts_by_ip.items():
        attempts.sort(key=lambda attempt: (attempt[0], attempt[2]))
        start = 0
        while start <= len(attempts) - rule["threshold"]:
            first_time = attempts[start][0]
            end = start + 1
            while end < len(attempts) and attempts[end][0] - first_time <= window:
                end += 1
            if end - start >= rule["threshold"]:
                burst = attempts[start:end]
                alert = {
                    "alert_id": str(
                        uuid.uuid5(
                            _ALERT_NAMESPACE,
                            f"brute_force\0{source_ip}\0{burst[0][2]}",
                        )
                    ),
                    "rule_id": "brute_force",
                    "severity": rule["severity"],
                    "title": "Repeated failed logons",
                    "description": (
                        f"{len(burst)} failed logons from {source_ip} within "
                        f"{rule['window_seconds']} seconds."
                    ),
                    "source_ip": source_ip,
                    "first_seen": burst[0][1],
                    "last_seen": burst[-1][1],
                    "event_count": len(burst),
                }
                inserted += insert_alert(connection, alert)
                start = end
            else:
                start += 1
    return inserted


def run_detection(
    connection: sqlite3.Connection, rules_path: Path = DEFAULT_RULES_PATH
) -> int:
    """Run configured detections against stored logs."""
    return detect_brute_force(connection, load_rules(rules_path))


def main() -> None:
    """Run detection against the selected local SQLite database."""
    from storage import DEFAULT_DB_PATH, connect

    parser = argparse.ArgumentParser(description="Detect configured patterns in stored SIEM logs.")
    parser.add_argument(
        "--database",
        default=str(DEFAULT_DB_PATH),
        help="SQLite database path (default: local project database)",
    )
    args = parser.parse_args()
    connection = connect(Path(args.database))
    try:
        count = run_detection(connection)
    finally:
        connection.close()
    print(f"[*] Detection complete: {count} new alert(s) stored.")


if __name__ == "__main__":
    main()

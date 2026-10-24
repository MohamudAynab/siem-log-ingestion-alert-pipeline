"""Print a concise recent-events and alerts report."""

from __future__ import annotations

import argparse
from pathlib import Path

from storage import DEFAULT_DB_PATH, connect, list_alerts


def main() -> None:
    parser = argparse.ArgumentParser(description="Review recent SIEM logs and alerts.")
    parser.add_argument("--limit", type=int, default=10, help="number of rows per section")
    parser.add_argument(
        "--database",
        default=str(DEFAULT_DB_PATH),
        help="SQLite database path (default: local project database)",
    )
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be a positive integer")

    connection = connect(Path(args.database))
    try:
        events = connection.execute(
            """
            SELECT timestamp, source_ip, endpoint, action_status
            FROM logs ORDER BY timestamp DESC, log_id LIMIT ?
            """,
            (args.limit,),
        ).fetchall()
        alerts = list_alerts(connection, args.limit)
    finally:
        connection.close()

    print("Recent events")
    print("-" * 72)
    if not events:
        print("No events stored.")
    for timestamp, source_ip, endpoint, status in events:
        print(f"{timestamp}  {source_ip:>15}  {status}  {endpoint}")

    print("\nRecent alerts")
    print("-" * 72)
    if not alerts:
        print("No alerts stored.")
    for alert in alerts:
        print(
            f"[{alert[2].upper()}] {alert[3]} | {alert[5]} | "
            f"{alert[8]} event(s) | {alert[6]} - {alert[7]}"
        )


if __name__ == "__main__":
    main()

"""Focused tests for raw collector parsing and the SQLite ingestion path."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from parsers import parse_event
from pipeline.ingest import process_jsonl_file
from storage import insert_log
from database.schema_setup import create_logs_table
from ingestion._common import write_jsonl_entry


WINDOWS_EVENT = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-10-11T21:14:15.123Z" />
  </System>
  <EventData>
    <Data Name="IpAddress">192.0.2.44</Data>
    <Data Name="TargetUserName">lab-user</Data>
  </EventData>
</Event>"""

KALI_AUTH_LINE = (
    "Oct 11 21:14:15 kali sshd[1234]: "
    "Failed password for invalid user lab-user from 192.0.2.44 port 22 ssh2"
)
COLLECTED_AT = "2026-10-11T21:15:00+00:00"


class ParserTests(unittest.TestCase):
    def test_collector_envelope_includes_source_timezone(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            write_jsonl_entry(output_dir, "kali", KALI_AUTH_LINE)
            output_file = next(output_dir.glob("kali-*.jsonl"))
            record = json.loads(output_file.read_text(encoding="utf-8"))

        self.assertEqual(record["source"], "kali")
        self.assertEqual(record["raw"], KALI_AUTH_LINE)
        self.assertRegex(record["source_timezone"], r"^[+-]\d{4}$")

    def test_windows_failed_logon_normalizes_fields_and_is_replay_stable(self) -> None:
        record = {
            "source": "windows",
            "collected_at": COLLECTED_AT,
            "raw": WINDOWS_EVENT,
        }

        first = parse_event(record)
        second = parse_event(record)

        self.assertEqual(first["timestamp"], "2026-10-11T21:14:15.123000+00:00")
        self.assertEqual(first["source_ip"], "192.0.2.44")
        self.assertEqual(first["endpoint"], "windows://security/event/4625")
        self.assertEqual(first["action_status"], 401)
        self.assertEqual(first["log_id"], second["log_id"])

    def test_kali_failed_authentication_normalizes_fields(self) -> None:
        event = parse_event(
            {
                "source": "kali",
                "collected_at": COLLECTED_AT,
                "source_timezone": "+0000",
                "raw": KALI_AUTH_LINE,
            }
        )

        self.assertEqual(event["timestamp"], "2026-10-11T21:14:15+00:00")
        self.assertEqual(event["source_ip"], "192.0.2.44")
        self.assertEqual(event["endpoint"], "kali://auth/sshd")
        self.assertEqual(event["action_status"], 401)

    def test_kali_iso_timestamp_line_with_parenthesized_program(self) -> None:
        event = parse_event(
            {
                "source": "kali",
                "collected_at": COLLECTED_AT,
                "raw": (
                    "2026-10-11T21:14:15.123456-04:00 kali (systemd): "
                    "pam_unix(systemd-user:session): session opened for user lab"
                ),
            }
        )

        self.assertEqual(event["timestamp"], "2026-10-11T21:14:15.123456-04:00")
        self.assertEqual(event["endpoint"], "kali://auth/(systemd)")
        self.assertEqual(event["action_status"], 200)

    def test_missing_remote_ip_uses_documented_ipv4_sentinel(self) -> None:
        event = parse_event(
            {
                "source": "kali",
                "collected_at": COLLECTED_AT,
                "source_timezone": "+0000",
                "raw": "Oct 11 21:14:15 kali sudo[5]: pam_unix(sudo:session): session opened",
            }
        )

        self.assertEqual(event["source_ip"], "127.0.0.1")
        self.assertEqual(event["action_status"], 200)

    def test_kali_year_rollover_uses_source_timezone(self) -> None:
        event = parse_event(
            {
                "source": "kali",
                "collected_at": "2027-01-01T00:05:00+00:00",
                "source_timezone": "+0000",
                "raw": "Dec 31 23:59:00 kali sshd[12]: Accepted password for lab-user",
            }
        )

        self.assertEqual(event["timestamp"], "2026-12-31T23:59:00+00:00")

    def test_invalid_source_record_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported log source"):
            parse_event({"source": "unknown", "collected_at": COLLECTED_AT, "raw": "x"})


class PipelineTests(unittest.TestCase):
    def test_jsonl_file_is_stored_once_even_when_replayed(self) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            create_logs_table(connection)
            with tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "windows.jsonl"
                path.write_text(
                    json.dumps(
                        {
                            "source": "windows",
                            "collected_at": COLLECTED_AT,
                            "raw": WINDOWS_EVENT,
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )

                self.assertEqual(process_jsonl_file(path, connection), 1)
                self.assertEqual(process_jsonl_file(path, connection), 0)
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM logs").fetchone()[0],
                    1,
                )
        finally:
            connection.close()

    def test_storage_rejects_invalid_normalized_entries(self) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            create_logs_table(connection)
            with self.assertRaisesRegex(ValueError, "missing required field"):
                insert_log(connection, {})
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()

"""Tests for brute-force detection, alert storage, and dashboard queries."""

import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from alerts.detector import detect_brute_force
from database.schema_setup import create_logs_table
from storage import create_alerts_table, insert_log, list_alerts


class AlertTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        create_logs_table(self.connection)
        create_alerts_table(self.connection)
        self.base_time = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.connection.close()

    def _add_failed_logons(
        self, count: int, source_ip: str = "203.0.113.42", interval_seconds: int = 10
    ) -> None:
        for index in range(count):
            timestamp = (self.base_time + timedelta(seconds=index * interval_seconds)).isoformat()
            insert_log(
                self.connection,
                {
                    "log_id": f"00000000-0000-4000-8000-{index + 1:012d}",
                    "timestamp": timestamp,
                    "source_ip": source_ip,
                    "endpoint": "/login",
                    "user_agent": "test-client",
                    "action_status": 401,
                },
            )

    @staticmethod
    def _rule(**overrides: object) -> dict[str, object]:
        rule: dict[str, object] = {
            "enabled": True,
            "threshold": 5,
            "window_seconds": 300,
            "severity": "high",
            "allowlist": [],
        }
        rule.update(overrides)
        return rule

    def test_brute_force_burst_creates_one_replay_safe_alert(self) -> None:
        self._add_failed_logons(5)

        self.assertEqual(detect_brute_force(self.connection, self._rule()), 1)
        self._add_failed_logons(6)
        self.assertEqual(detect_brute_force(self.connection, self._rule()), 0)
        alerts = list_alerts(self.connection)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][2], "high")
        self.assertEqual(alerts[0][5], "203.0.113.42")
        self.assertEqual(alerts[0][8], 6)
        self.assertIn("6 failed logons", alerts[0][4])

    def test_attempts_outside_window_do_not_alert(self) -> None:
        self._add_failed_logons(5, interval_seconds=301)

        self.assertEqual(detect_brute_force(self.connection, self._rule()), 0)
        self.assertEqual(list_alerts(self.connection), [])

    def test_detection_orders_timestamps_by_instant_across_offsets(self) -> None:
        timestamps = [
            "2026-10-23T14:00:00+02:00",
            "2026-10-23T12:01:00+00:00",
            "2026-10-23T14:02:00+02:00",
            "2026-10-23T12:03:00+00:00",
            "2026-10-23T14:04:00+02:00",
        ]
        for index, timestamp in enumerate(timestamps):
            insert_log(
                self.connection,
                {
                    "log_id": f"10000000-0000-4000-8000-{index + 1:012d}",
                    "timestamp": timestamp,
                    "source_ip": "203.0.113.42",
                    "endpoint": "/login",
                    "user_agent": "test-client",
                    "action_status": 401,
                },
            )

        self.assertEqual(detect_brute_force(self.connection, self._rule()), 1)
        alert = list_alerts(self.connection)[0]
        self.assertEqual(alert[6], "2026-10-23T12:00:00+00:00")
        self.assertEqual(alert[7], "2026-10-23T12:04:00+00:00")

    def test_allowlisted_ip_and_local_sentinel_are_excluded(self) -> None:
        self._add_failed_logons(5, source_ip="192.0.2.10")
        self._add_failed_logons(5, source_ip="127.0.0.1")

        self.assertEqual(
            detect_brute_force(self.connection, self._rule(allowlist=["192.0.2.10"])),
            0,
        )

    def test_disabled_rule_does_not_create_alerts(self) -> None:
        self._add_failed_logons(5)

        self.assertEqual(detect_brute_force(self.connection, self._rule(enabled=False)), 0)

    def test_alert_limit_must_be_positive(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive integer"):
            list_alerts(self.connection, 0)


if __name__ == "__main__":
    unittest.main()

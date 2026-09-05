"""Tails /var/log/auth.log and writes new lines as raw JSONL.

Stdlib only: seeks to a saved byte offset on each poll so restarts don't
duplicate or lose lines.
"""

import time

from ingestion import config
from ingestion._common import read_state, write_jsonl_entry, write_state

STATE_FILE = config.STATE_DIR / "kali_auth_log_offset.txt"


def _current_offset() -> int:
    if not config.KALI_AUTH_LOG_PATH.exists():
        return 0
    return config.KALI_AUTH_LOG_PATH.stat().st_size


def poll_once(offset: int) -> int:
    """Read new lines appended to auth.log since offset, write them, return new offset."""
    if not config.KALI_AUTH_LOG_PATH.exists():
        print(f"[!] {config.KALI_AUTH_LOG_PATH} not found.")
        return offset

    with open(config.KALI_AUTH_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        new_lines = f.readlines()
        new_offset = f.tell()

    for line in new_lines:
        line = line.rstrip("\n")
        if line:
            write_jsonl_entry(config.KALI_OUTPUT_DIR, "kali", line)

    return new_offset


def run() -> None:
    offset = int(read_state(STATE_FILE, str(_current_offset())))
    print("[*] Kali collector started. Press Ctrl+C to stop.")

    try:
        while True:
            offset = poll_once(offset)
            write_state(STATE_FILE, str(offset))
            time.sleep(config.POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[*] Kali collector stopped by user.")


if __name__ == "__main__":
    run()

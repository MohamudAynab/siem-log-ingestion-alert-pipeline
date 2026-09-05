"""Polls the Windows Security event log and writes new events as raw JSONL.

Uses `wevtutil` (stdlib subprocess only, no pywin32 dependency) to query
events by ID, filtered to those newer than the last record ID we've seen.
"""

import subprocess
import time
import xml.etree.ElementTree as ET

from ingestion import config
from ingestion._common import read_state, write_jsonl_entry, write_state

STATE_FILE = config.STATE_DIR / "windows_last_record_id.txt"

# wevtutil's XML events use this default namespace; ElementTree requires
# the namespace prefix on every tag lookup once a doc declares one.
_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _build_query(last_record_id: int) -> str:
    id_clause = " or ".join(f"EventID={eid}" for eid in config.WINDOWS_EVENT_IDS)
    return f"*[System[({id_clause}) and EventRecordID > {last_record_id}]]"


def poll_once(last_record_id: int) -> int:
    """Fetch new Security events since last_record_id, write them, return the newest ID seen."""
    query = _build_query(last_record_id)
    result = subprocess.run(
        [
            "wevtutil", "qe", "Security",
            f"/q:{query}",
            "/f:xml",
            "/rd:false",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        print(f"[!] wevtutil error: {result.stderr.strip()}")
        return last_record_id

    if not result.stdout.strip():
        return last_record_id

    # wevtutil emits consecutive <Event>...</Event> blocks with no shared
    # root, which isn't valid standalone XML -- wrap it before parsing.
    try:
        root = ET.fromstring(f"<Events>{result.stdout}</Events>")
    except ET.ParseError as exc:
        print(f"[!] Failed to parse wevtutil XML output: {exc}")
        return last_record_id

    # Each <Event> declares xmlns="..." on itself, so it (and its children)
    # live in that namespace even though the synthetic <Events> root doesn't.
    newest_id = last_record_id
    for event_elem in root.findall(f"{_EVENT_NS}Event"):
        record_id_elem = event_elem.find(f"./{_EVENT_NS}System/{_EVENT_NS}EventRecordID")
        if record_id_elem is None or not record_id_elem.text:
            continue
        record_id = int(record_id_elem.text)
        raw_text = " ".join(ET.tostring(event_elem, encoding="unicode").split())
        write_jsonl_entry(config.WINDOWS_OUTPUT_DIR, "windows", raw_text)
        newest_id = max(newest_id, record_id)

    return newest_id


def run() -> None:
    last_record_id = int(read_state(STATE_FILE, "0"))
    print("[*] Windows collector started. Press Ctrl+C to stop.")

    try:
        while True:
            last_record_id = poll_once(last_record_id)
            write_state(STATE_FILE, str(last_record_id))
            time.sleep(config.POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[*] Windows collector stopped by user.")


if __name__ == "__main__":
    run()

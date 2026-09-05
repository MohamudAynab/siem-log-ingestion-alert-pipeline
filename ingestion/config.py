"""Ingestion settings shared by the Windows and Kali collectors."""

from pathlib import Path

INGESTION_DIR = Path(__file__).resolve().parent
INCOMING_DIR = INGESTION_DIR / "incoming"

WINDOWS_OUTPUT_DIR = INCOMING_DIR / "windows"
KALI_OUTPUT_DIR = INCOMING_DIR / "kali"

STATE_DIR = INGESTION_DIR / ".state"

POLL_INTERVAL_SECONDS = 10

# Logon success, logon failure, process creation
WINDOWS_EVENT_IDS = ["4624", "4625", "4688"]

KALI_AUTH_LOG_PATH = Path("/var/log/auth.log")

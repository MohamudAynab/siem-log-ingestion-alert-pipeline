# Local and lab setup

## Requirements

- Python 3.10 or later.
- Windows with `wevtutil` for the Windows Security collector.
- Kali Linux with `/var/log/auth.log` available for the Kali collector.
- VirtualBox or another authorized lab setup only when collecting live events.

The application and automated tests use only the Python standard library.
Install no third-party package for normal operation.

## Run a local synthetic demo

From the repository root:

```powershell
python generator.py
python -m alerts
python -m dashboard
```

The generator inserts synthetic events into the ignored local
`database/siem_logs.db`. The detection command evaluates those stored events
using `config/detection.json`. The dashboard prints recent events and alerts.
Both commands accept `--database` to select a different SQLite file.

To use a non-default database with the dashboard:

```powershell
python -m dashboard --database C:\path\to\siem_logs.db --limit 20
python -m alerts --database C:\path\to\siem_logs.db
```

## Collect lab events

1. Use only machines and networks owned by the project or explicitly
   authorized for this lab.
2. Make the project checkout available on each collector VM, or copy its
   resulting JSONL files into the host checkout's
   `ingestion/incoming/windows/` or `ingestion/incoming/kali/` directory.
   Keep raw logs local; they are ignored by Git.
3. On Windows, run `python -m ingestion.windows_collector` in a context with
   permission to query the Security event log. The collector invokes
   `wevtutil` for event IDs 4624, 4625, and 4688.
4. On Kali, run `python -m ingestion.kali_collector` with read access to
   `/var/log/auth.log`.
5. Stop each collector with Ctrl+C. Collector offsets/record IDs are stored
   under `ingestion/.state/` and should remain local to that source machine.
6. Run `python -m pipeline.ingest` from the repository root. It parses all
   incoming JSONL files, inserts events once, and runs configured detection.
7. Run `python -m dashboard` to review the latest events and alerts.

The shared-folder path and collector output paths may need to be adapted to the
local VirtualBox setup. Do not commit raw production logs, credentials, or
personal information.

## Configure detection

Edit `config/detection.json`. `threshold` and `window_seconds` must be positive
integers; `severity` must be `low`, `medium`, `high`, or `critical`;
`allowlist` accepts IPv4 addresses. By default, five failed logons from one
non-allowlisted IPv4 source in a five-minute window create a high-severity
alert. Events normalized to `127.0.0.1` as the documented unknown-IP sentinel
are excluded to avoid attributing unrelated events to one source.

# Testing notes

## Automated suite

Run from the repository root:

```powershell
python -m unittest discover -v
```

The tests use temporary or in-memory SQLite databases and sanitized event
samples. They cover:

- Windows and Kali event parsing, timestamp handling, and schema validation.
- Collector JSONL envelopes and replay-safe ingestion.
- Invalid event rejection.
- Brute-force threshold and window behavior, allowlist exclusions, disabled
  detection, and replay-safe alert persistence.
- Positive dashboard alert limits.

## Synthetic end-to-end smoke test

Run:

```powershell
python generator.py
python -m alerts
python -m dashboard
```

The generator adds synthetic normal events and failed-login bursts to the
default local database. Detection uses the current config; the dashboard
should show events and at least one brute-force alert. Database contents are
runtime state, so existing local rows can affect the display.

## Windows VM collector smoke test (2026-10-24)

The owner ran the Windows collector with elevated permissions, generated a
failed sign-in, transferred `windows-20261024.jsonl` via the VirtualBox shared
folder, and ran the host ingestion and dashboard commands. The dashboard
showed a failed Windows event (`4625`), but its source IP was `127.0.0.1`
(unknown-IP sentinel); therefore this confirms collection and display only,
not attribution or a Windows-derived alert. See `findings.md` for details.

## Kali live alert acceptance check (2026-10-24)

The live authorized-lab check completed. Kali collector output was transferred
through the VirtualBox `sf_kali` shared folder to the host project's
`ingestion/incoming/kali/` directory. Host ingestion reported 35 new events
and one new alert. The dashboard showed a high-severity `Repeated failed
logons` alert for source `10.0.2.4` with five failed events between
`2026-10-24T07:11:29Z` and `2026-10-24T07:12:18Z`, within the configured
five-minute window. The Windows collector check is also recorded in
`findings.md`; its event source was the unknown-IP sentinel.

No further failed-login attempts are needed to establish this baseline test.
Do not record passwords or raw authentication-log contents.

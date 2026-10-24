# Findings and limitations

## Verified locally

- Windows and Kali parsers normalize supported sample formats and validate
  output against the shared schema.
- Ingestion stores valid normalized events and does not duplicate a replayed
  event with the same stable ID.
- The configured brute-force rule creates an alert for a qualifying failed
  login burst and excludes allowlisted addresses.
- Re-running detection does not create a duplicate alert for an existing burst.
- A local CLI dashboard presents stored events and alerts.

These statements are covered by automated tests; they do not assert that the
collectors have been run against live virtual machines.

## Local CLI check (2026-10-23)

The project owner ran the following commands from the repository root on the
host:

```powershell
python -m alerts
python -m dashboard
```

The detection command reported two new alerts, and the dashboard displayed
both alerts and recent stored events. The alerts shown were for
`203.0.113.42`, with timestamps on 2026-09-04. That address is a documentation
and test address, and the timestamps match the synthetic generator data in
the local database. This confirms that detection and dashboard commands run
against the local database; it is **not** evidence that a live VM failed-login
burst generated an alert.

## Windows VM collector check (2026-10-24)

The project owner ran `python -m ingestion.windows_collector` in the Windows
VM with elevated permissions, generated a failed sign-in, and transferred
`windows-20261024.jsonl` through the VirtualBox shared folder to the host
project's `ingestion/incoming/windows/` directory. On the host,
`python -m pipeline.ingest` completed and `python -m dashboard` displayed
Windows Security event `4625` as a failed event. The pipeline reported zero
new events and zero new alerts on that run, indicating the records were
already present in the local database.

The displayed source address was `127.0.0.1`, the project's unknown-IP
sentinel. This verifies Windows collector output and host-side visibility, but
does not verify attribution to the initiating client or a live
source-specific alert. The older alert entries displayed by the dashboard
were for synthetic test address `203.0.113.42` and are not results of this
Windows test.

## Kali live collector-to-alert verification (2026-10-24)

In the authorized VirtualBox lab, Kali collector output was transferred
through the `sf_kali` shared folder to the host project's
`ingestion/incoming/kali/` directory. On the host, `python -m pipeline.ingest`
reported 35 new events stored and one new alert generated. The dashboard
showed a high-severity `Repeated failed logons` alert for source `10.0.2.4`
(the Windows VM's lab IP), containing five failed events. The alert window was
`2026-10-24T07:11:29Z` to `2026-10-24T07:12:18Z`, within the configured
300-second threshold window.

This verifies live Kali auth-log collection, shared-folder transfer, host
ingestion, source-IP attribution, and alert generation. No credentials or raw
authentication-log contents are recorded here.

## Known limitations

- The normalized schema describes web-like fields. Host-security events are
  mapped for compatibility, and `action_status` is a failure/success indicator
  rather than an HTTP response for those events.
- The schema accepts IPv4 only. The documented `127.0.0.1` sentinel is used
  when a usable remote IPv4 address is absent; detections exclude that sentinel
  to avoid false attribution.
- The baseline detector handles repeated failed logons only. Port scans,
  unusual login times, event severity enrichment, and continuous processing
  are not implemented.
- Collector access privileges, VirtualBox shared-folder configuration, and
  clock alignment can vary by local lab setup; the checks recorded above
  validate only the observed configuration and event path.
- SQLite is intended for this educational local prototype, not a
  high-availability or multi-host production SIEM.

## Safety and follow-up

Use only authorized lab systems and sanitized samples. Keep raw data and local
databases out of Git. The Windows and Kali live collector checks have been
performed in the authorized lab. The Windows event used the unknown-IP
sentinel; the Kali test verified source-attributed alerting. Broader scenarios
and documented schema limitations remain outside this baseline acceptance
check.

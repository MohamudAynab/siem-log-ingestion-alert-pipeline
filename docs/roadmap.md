# Project Roadmap

## Context and ownership

The project implements a local SIEM-style pipeline using the existing schema
and SQLite database. No third-party SIEM is required. **Mohamud Aynab is the
sole contributor** and owns all modules, testing, integration, and
documentation.

Anyone cloning the repository should not expect `database/siem_logs.db` to be
present; it is local runtime data and is gitignored.

## Sprint 1: Collection and normalization — implemented

- Windows Security event and Kali `auth.log` collectors write raw JSONL records.
- Windows and Kali parsers normalize supported events and validate them against
  the shared schema.
- The raw event envelope and known schema limitations are documented in
  [raw-event-mapping.md](raw-event-mapping.md).
- Live Windows and Kali collector checks have been completed in the
  authorized lab; observed results are in [findings.md](findings.md).

## Sprint 2: Ingestion — implemented

- The one-pass `python -m pipeline.ingest` command parses incoming JSONL files,
  validates events, and stores them in SQLite.
- Stable event IDs make replays idempotent.
- Continuous ingestion remains a possible future enhancement, not a completion
  requirement.

## Sprint 3: Detection and alerting — implemented

- `config/detection.json` configures the brute-force rule threshold, time
  window, severity, enabled state, and IPv4 allowlist.
- Failed-login bursts are detected from stored events and saved to SQLite.
- Repeated detection passes do not create duplicate alerts.
- Automated tests cover bursts, allowlists, disabled rules, and events outside
  the configured window. A live Kali failed-login burst also generated an
  alert for the Windows VM's source IP.

## Sprint 4: Dashboard and tests — implemented

- `python -m dashboard` displays recent events and alerts without direct SQL.
- The standard-library test suite covers parser, ingestion, storage, and
  detection behavior.
- The Windows and Kali VM walkthroughs have been completed and recorded.

## Sprint 5: Documentation and wrap-up — local work implemented

- Setup, architecture, testing, findings, and project report documents are
  available under `docs/`.
- README status and contributor details reflect the implemented project.
- Live authorized VM results are recorded in `findings.md`.

## Verification

Run `python -m unittest discover -v` from the repository root. For a synthetic
demonstration, run `python generator.py`, then `python -m alerts`, followed by
`python -m dashboard`. For collector-produced records, run
`python -m pipeline.ingest`.

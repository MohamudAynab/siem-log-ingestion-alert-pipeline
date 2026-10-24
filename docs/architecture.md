# Architecture

```text
Windows Security log ─┐
                      ├─> collector envelope JSONL ─> source parser
Kali auth.log ────────┘                                │
                                                       v
                                      schema validation and SQLite logs
                                                       │
                                                       v
                                  configured failed-login detection
                                                       │
                                                       v
                                   SQLite alerts and CLI dashboard
```

## Components

- `ingestion/`: polls the Windows Security log with `wevtutil` or tails Kali
  `auth.log`; writes a JSONL envelope and local cursor state.
- `parsers/`: maps source-specific raw events into the shared SIEM event schema.
- `database/schema_setup.py`: defines and validates the normalized event
  contract.
- `storage/`: creates and writes the SQLite `logs` and `alerts` tables. The
  stable event IDs and deterministic alert IDs make replay safe.
- `pipeline/ingest.py`: processes incoming files in stable path order, fails
  with file/line context on malformed input, and starts detection after
  ingestion.
- `alerts/detector.py`: groups failed events by source address and detects
  threshold bursts within a configured time window.
- `dashboard/`: prints recent events and alerts from the local database.

## Data and operational boundaries

The database is local and ignored by Git. Incoming raw JSONL and collector
cursor state are likewise local. A malformed input line stops that ingestion
pass with a contextual error rather than being silently dropped. Collectors
are run on their respective source systems; live cross-VM paths depend on the
local lab's shared-folder/network configuration.

The existing event schema is web-oriented. Host-security event parsers map
their data into those fields for compatibility; the mapping and IPv4 sentinel
limitation are described in [raw-event-mapping.md](raw-event-mapping.md).

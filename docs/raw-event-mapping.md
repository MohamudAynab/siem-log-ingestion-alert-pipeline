# Raw event to normalized schema mapping

Collectors append one JSON object per line to a source-specific JSONL file:

```json
{"source":"kali","collected_at":"2026-10-11T21:15:00+00:00","source_timezone":"-0400","raw":"Oct 11 17:14:15 kali sshd[1234]: Failed password for invalid user lab-user from 192.0.2.44 port 22 ssh2"}
```

`source` selects the parser, `collected_at` records when the collector observed
the event, optional `source_timezone` records the source machine's numeric UTC
offset (for syslog timestamps without a zone), and `raw` contains the untouched
Windows event XML or Kali `/var/log/auth.log` line. Older records without
`source_timezone` use the timezone offset in `collected_at` as a fallback.
The Kali parser accepts both ISO-timestamped auth.log lines and traditional
syslog month/day/time lines. Parsers reject malformed envelopes and
unrecognized event formats instead of silently skipping them. The original
text is retained in `raw_line`.

## Field mapping

| Normalized field | Windows Security event | Kali `auth.log` |
|---|---|---|
| `log_id` | UUIDv5 of source, collection time, and raw XML | UUIDv5 of source, collection time, and raw line |
| `timestamp` | `System/TimeCreated/@SystemTime` | ISO timestamp from the raw line when present; otherwise syslog month/day/time with timezone from `source_timezone` and year inferred from `collected_at` |
| `source_ip` | IPv4 `EventData` value named `IpAddress` or `SourceNetworkAddress` | IPv4 address following `from` in the message |
| `endpoint` | `windows://security/event/<EventID>` | `kali://auth/<program>` |
| `user_agent` | `Windows-Security-Event-<EventID>` | `Kali-auth-<program>` |
| `action_status` | `4625` maps to 401; `4624` and `4688` map to 200 | Authentication failure phrases map to 401; other auth records map to 200 |
| `raw_line` | Untouched event XML | Untouched syslog line |
| `severity` | Not assigned | Not assigned |

The existing shared schema models web-oriented fields, while these sources are
host security events. `action_status` is therefore a compatibility indicator,
not an HTTP response code for these records. The schema accepts only IPv4;
when a usable remote IPv4 address is absent (including IPv6-only events),
`source_ip` is set to `127.0.0.1` as a sentinel. Downstream rules should use
`raw_line`, source-specific `endpoint`, and the status mapping with that
limitation in mind.

UUIDv5 makes a repeated JSONL ingestion pass idempotent when the collector
envelope is unchanged. Distinct collection timestamps remain distinct events,
even when the raw messages match.

## Running a local ingestion pass

After configuring the collector output directories, run:

```powershell
python -m pipeline.ingest
```

The pipeline scans `ingestion/incoming/`, validates normalized records against
`database/schema_setup.py`, and inserts them into the local ignored
`database/siem_logs.db`. An invalid line reports its file and line number and
stops that pass; it is not silently discarded. The collectors and pipeline are
stdlib-only and should be run in the appropriate source environment (Windows
for the Windows Security log collector, Kali for `/var/log/auth.log`).

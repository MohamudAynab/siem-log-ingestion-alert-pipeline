# Project report

## Summary

This project implements a local SIEM-style workflow for collecting Windows
Security and Kali authentication events, normalizing them, storing them in
SQLite, detecting baseline brute-force patterns, and reviewing results in a
command-line dashboard.

## Implemented workflow

1. Source-specific collectors write raw event envelopes to JSONL.
2. Parsers convert supported Windows and Kali records to the shared schema.
3. The ingestion pipeline validates and stores normalized events; stable IDs
   make repeated ingestion idempotent.
4. A configurable rule detects repeated failed logons within a time window and
   stores alerts in SQLite.
5. The dashboard presents recent events and alerts.

## Verification

Parser, storage, ingestion, and detection behavior are covered by the
standard-library automated suite. Synthetic event generation supports a local
demonstration. A Windows VM collector smoke test has also confirmed that a
failed-logon event can reach the host dashboard. Its source address was the
unknown-IP sentinel, so source attribution and a live alert were not verified.
The Kali live test confirmed collection, transfer, host ingestion, source
attribution to the Windows VM (`10.0.2.4`), and a high-severity alert for five
failed events within the configured five-minute window.

## Conclusion and next steps

The baseline local implementation and live collector-to-alert workflow have
been verified. Potential future work includes a revised host-security schema,
additional detections, continuous ingestion, and enterprise SIEM integration;
these are outside the current baseline scope.

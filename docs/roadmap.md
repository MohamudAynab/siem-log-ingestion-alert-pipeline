# Project Roadmap

## Context

The schema (`database/schema.json`), validator (`database/schema_setup.py`), and synthetic generator (`generator.py`) are in place. Windows and Kali collectors write raw JSONL records into `ingestion/incoming/`; parsers normalize those records and `pipeline/ingest.py` stores them in SQLite through `storage/`. Detection, alerts, dashboard, and a live VM integration run remain outstanding. The raw-event mapping and schema compatibility limitations are documented in [raw-event-mapping.md](raw-event-mapping.md).

**Decisions:**
- **No third-party SIEM for now.** Build the pipeline (collection → ingestion → parsing → storage → detection → alerting → dashboard) ourselves, using the existing schema/DB as the backbone. Revisit an enterprise SIEM (Wazuh/ELK/Splunk) as a post-completion upgrade.
- **Cadence:** 2-week sprints, 5 sprints, ~10 weeks total.
- **Split:** by module ownership, so each person can work independently on their local clone without blocking the other, with joint integration checkpoints at the end of each sprint.

**Module ownership:**
- **Mohamud:** `ingestion/`, `storage/`, `parsers/`, `config/` — the data intake side (get real logs in, normalized, and stored reliably).
- **Abdi:** `pipeline/`, `alerts/`, `dashboard/` — the detection/output side (turn stored logs into alerts and a way to review them), plus most of `tests/`.
- **Both:** `docs/` and end-of-sprint integration/testing.

Anyone cloning the repo should not expect `database/siem_logs.db` to be present (it's gitignored) — generate your own local DB via `generator.py` or real ingestion.

---

## Sprint 1 (Weeks 1–2): Real log collection + normalization — implemented, live validation pending

**Goal:** Replace synthetic data with real logs from the lab VMs, normalized into the existing schema.

- **Implemented:** Windows `wevtutil` Security-event collector (4624, 4625, 4688) and Kali `/var/log/auth.log` collector write raw JSONL to source-specific shared drop-off directories. Per-machine cursor state is kept locally.
- **Implemented:** Windows and Kali parsers validate normalized entries against the shared schema; [raw-event-mapping.md](raw-event-mapping.md) specifies the envelope, mappings, and schema limitations.
- **Implemented:** SQLite storage and a one-pass pipeline ingest JSONL files from `ingestion/incoming/`; focused parser/storage tests are in `tests/`.
- **Still to verify:** Run collectors and the parser/storage pipeline against representative events from the live lab VMs. `docs/setup-guide.md` has not yet been written.
- **Joint checkpoint:** The collectors and parsers use a JSONL envelope with `source`, `collected_at`, optional `source_timezone`, and `raw`; the normalization details are recorded in `raw-event-mapping.md`.

---

## Sprint 2 (Weeks 3–4): End-to-end pipeline wiring — initial path implemented

**Goal:** A real log, from either VM, flows automatically into the SQLite DB.

- **Implemented:** `storage/` validates and inserts normalized events; `pipeline/ingest.py` wires JSONL input through parsers into SQLite and supports replay without duplicate rows.
- **Still planned:** Continuous ingestion, broader schema-validation edge cases, and live VM end-to-end verification.
- **Joint checkpoint:** Run the full pipeline against real VM activity end-to-end; confirm no data loss or validation failures.

---

## Sprint 3 (Weeks 5–6): Detection & alerting

**Goal:** Suspicious activity in stored logs produces alerts.

- **Abdi — `alerts/`:**
  - Build detection rules (start with brute-force login — there's already a test pattern for this in `generator.py` — then expand: port scans, unusual login times, etc.).
  - Alert generation logic: what triggers, what gets recorded, alert severity.
- **Mohamud — `config/`, `storage/`:**
  - Detection rule configuration (thresholds, IP allowlists, time windows).
  - Extend storage layer with an alerts table/query support.
- **Joint checkpoint:** Validate detection against both `generator.py`'s simulated brute-force burst and a real authorized test (e.g. deliberate failed logins on the Kali/Windows VM).

---

## Sprint 4 (Weeks 7–8): Dashboard & test coverage

**Goal:** A human can see logs and alerts without querying SQLite directly; core logic has automated tests.

- **Abdi — `dashboard/`:**
  - Build a simple way to view logs and alerts — a CLI report, or a lightweight web view (Flask/Streamlit), whichever fits your comfort level.
- **Mohamud — `tests/`:**
  - Expand automated coverage: ingestion, storage, and validation logic (parsers/alerts tests already started by Abdi in Sprint 2–3).
  - Optional: basic CI (GitHub Actions) to run tests on push.
- **Joint checkpoint:** Full demo — trigger real activity on a VM, watch it become a log, then an alert, then show up on the dashboard.

---

## Sprint 5 (Weeks 9–10): Polish, docs, and wrap-up

**Goal:** Project is demo-ready and documented.

- **Both:**
  - Finish `docs/architecture.md`, `docs/testing-notes.md`, `docs/findings.md`.
  - Update README roadmap checkboxes to reflect what's actually done.
  - Fix bugs/edge cases surfaced during Sprint 4's joint demo.
  - Security/ethics pass: confirm no real credentials, PII, or production data ever got committed; sanitize any log samples before sharing.
  - Write the final project report/demo write-up.
  - Note next steps for a future enterprise SIEM migration (Wazuh/ELK/Splunk) as a stretch goal, not required for completion.

---

## Verification approach per sprint

- Run `generator.py` and confirm `validate_log_entry()` still passes for all new parser/ingestion output — regression check against the schema.
- End-of-sprint joint checkpoint: pull each other's branch, run the pipeline locally, confirm integration works before merging to `main`.
- By Sprint 4, verification should include a live walkthrough: real VM action → log → alert → dashboard, not just unit tests.

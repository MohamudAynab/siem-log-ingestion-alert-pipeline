# Project Roadmap

## Context

The project's foundation is laid: a standardized log schema (`database/schema.json`), a SQLite storage layer with validation (`database/schema_setup.py`), and a synthetic log generator (`generator.py`) that simulates normal traffic plus a brute-force attack pattern. Everything else — `ingestion/`, `parsers/`, `pipeline/`, `alerts/`, `dashboard/`, `config/`, `storage/`, `tests/`, `docs/` — is still empty scaffolding.

**Decisions:**
- **No third-party SIEM for now.** Build the full pipeline (collection → ingestion → parsing → storage → detection → alerting → dashboard) ourselves, using the existing schema/DB as the backbone. Revisit an enterprise SIEM (Wazuh/ELK/Splunk) as a post-completion upgrade.
- **Cadence:** 2-week sprints, 5 sprints, ~10 weeks total.
- **Split:** by module ownership, so each person can work independently on their local clone without blocking the other, with joint integration checkpoints at the end of each sprint.

**Module ownership:**
- **Mohamud:** `ingestion/`, `storage/`, `parsers/`, `config/` — the data intake side (get real logs in, normalized, and stored reliably).
- **Abdi:** `pipeline/`, `alerts/`, `dashboard/` — the detection/output side (turn stored logs into alerts and a way to review them), plus most of `tests/`.
- **Both:** `docs/` and end-of-sprint integration/testing.

Anyone cloning the repo should not expect `database/siem_logs.db` to be present (it's gitignored) — generate your own local DB via `generator.py` or real ingestion.

---

## Sprint 1 (Weeks 1–2): Real log collection + normalization

**Goal:** Replace synthetic data with real logs from the lab VMs, normalized into the existing schema.

- **Mohamud — `ingestion/`, `config/`:**
  - Build a Windows Event Log collector (e.g. via `pywin32` or `wevtutil`) that pulls security-relevant events (logon/logoff, failed logon, process creation) from the Windows 11 VM.
  - Build a Kali Linux collector that tails/reads relevant logs (`/var/log/auth.log`, syslog).
  - Both collectors write raw log lines/events to a shared intake point (a file, directory, or simple queue — pick the simplest thing that works).
  - `config/`: source paths, polling interval, which event types to collect.
- **Abdi — `parsers/`, `docs/setup-guide.md`:**
  - Build parsers that convert raw Windows/Kali log formats into the schema defined in `database/schema.json`, reusing `validate_log_entry()` from `database/schema_setup.py`.
  - Document the raw-log → parser input contract so ingestion's output format is unambiguous.
  - Start `docs/setup-guide.md` — how to set up the VirtualBox lab, network, and run the project locally.
- **Joint checkpoint:** Agree on the raw-line format ingestion hands to parsers *before* building both sides in parallel (a 15-minute conversation, not a deliverable).

---

## Sprint 2 (Weeks 3–4): End-to-end pipeline wiring

**Goal:** A real log, from either VM, flows automatically into the SQLite DB.

- **Mohamud — `storage/`:**
  - Wrap `database/schema_setup.py` into a clean storage service module (`insert_log()`, `query_logs()`, etc.) that `pipeline/` and `alerts/` can call without touching SQLite directly.
  - Make ingestion run continuously or on an interval (replacing the one-shot `generator.py` model for real collection).
- **Abdi — `pipeline/`, start `tests/`:**
  - Build the orchestration layer that wires ingestion → parser → storage into one runnable flow.
  - Write the first tests: schema validation edge cases, parser correctness against sample raw logs.
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

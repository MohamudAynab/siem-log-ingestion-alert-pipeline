# Automated SIEM Log Ingestion and Alert Pipeline

An educational cybersecurity lab project that automates the collection, ingestion, normalization, detection, and alerting of security logs in a Security Information and Event Management (SIEM) environment.

## Project Overview

Modern security teams rely on centralized logs to identify suspicious activity, investigate incidents, and respond quickly to potential threats. This project simulates a Security Operations Center (SOC) workflow by collecting event data from lab virtual machines, sending it to a Security Information and Event Management (SIEM) platform, applying detection logic, and generating alerts for review.

The project is being built in a controlled, authorized virtual lab environment for educational purposes.

## Objectives

- Collect security-relevant logs from Windows and Kali Linux virtual machines.
- Forward logs to a central Security Information and Event Management (SIEM) platform.
- Normalize and organize incoming logs for analysis.
- Create detection rules for selected suspicious behaviors or security events.
- Generate and review alerts based on those detection rules.
- Document the setup, testing process, findings, and improvements.
- Maintain scripts and documentation in a version-controlled GitHub repository.

## Current Pipeline

```text
Windows 11 VM / Kali Linux VM
            │
            ▼
Windows Security / auth.log collectors
            │
            ▼
JSONL files in ingestion/incoming/
            │
            ▼
Source parsers and schema validation
            │
            ▼
Local SQLite logs table
            │
            ▼
Configured brute-force detection
            │
            ▼
SQLite alerts table and CLI review dashboard
```

## Lab Environment

| Component | Role |
|---|---|
| Windows 11 virtual machine | Generates Windows event logs and serves as a monitored endpoint |
| Kali Linux virtual machine | Supports authorized lab testing, log generation, and analysis |
| Oracle VM VirtualBox | Hosts the isolated virtual lab environment |
| VirtualBox NAT Network | Provides private connectivity between lab virtual machines |
| Local SQLite prototype | Stores normalized events and generated alerts |
| GitHub | Stores scripts, configurations, documentation, and project history |

## Repository Structure

```text
siem-log-ingestion-alert-pipeline/
├── README.md
├── generator.py
├── alerts/
│   └── detector.py
├── config/
│   └── detection.json
├── database/
│   ├── schema.json
│   └── schema_setup.py
├── dashboard/
│   └── __main__.py
├── docs/
│   ├── architecture.md
│   ├── raw-event-mapping.md
│   ├── roadmap.md
│   ├── setup-guide.md
│   ├── testing-notes.md
│   ├── findings.md
│   └── project-report.md
├── ingestion/
│   ├── windows_collector.py
│   ├── kali_collector.py
│   └── incoming/
├── parsers/
├── pipeline/
├── storage/
├── tests/
└── .gitignore
```

Raw collector files and the SQLite database are local runtime data and are
ignored by Git. See [docs/raw-event-mapping.md](docs/raw-event-mapping.md) for
the collector envelope, normalization rules, and known schema limitations.

## Run the local demonstration

Python 3.10 or later is required; the project uses only the standard library.
From the repository root, generate safe synthetic events, run detection, and
review the results:

```powershell
python generator.py
python -m alerts
python -m dashboard
```

For real collector JSONL files, run `python -m pipeline.ingest`; ingestion
normalizes and stores events, then runs configured detection automatically.
See [docs/setup-guide.md](docs/setup-guide.md) for collector setup and
[docs/testing-notes.md](docs/testing-notes.md) for verification steps.

## Current Status

**Project phase:** Local pipeline and live Windows/Kali collector-to-alert validation complete

### Completed

- Created the GitHub repository.
- Set up the initial virtual lab environment.
- Configured Kali Linux and Windows 11 virtual machines in Oracle VM VirtualBox.
- Established private virtual-machine networking for controlled lab communication.
- Identified the need for version control for scripts, configurations, and documentation.
- Defined the standardized log event schema (`database/schema.json`) and SQLite database setup (`database/schema_setup.py`), including log entry validation.
- Built a synthetic log generator (`generator.py`) that produces normal traffic and a simulated brute-force attack pattern for testing.
- Implemented a Windows Security event collector (`wevtutil`) and a Kali authentication-log collector, both writing raw JSONL records under `ingestion/incoming/`.
- Added Windows and Kali parsers, mapping documentation, schema validation, and a local SQLite storage layer.
- Added a one-pass pipeline (`python -m pipeline.ingest`) and focused tests for parsing and replay-safe storage.
- Added configurable brute-force detection, durable replay-safe alert storage, and automatic alert generation after each ingestion pass.
- Added a standard-library command-line dashboard for recent events and alerts (`python -m dashboard`).
- Added setup, architecture, testing, findings, and project-report documentation for local use and demo preparation.
- Verified Windows event collection and host dashboard visibility through the VirtualBox shared folder.
- Verified Kali SSH failed-login collection, host ingestion, source-IP attribution, and alert generation in the authorized lab.

### In Progress

- Considering a future schema revision for host-security event fields; the current compatibility mapping is documented and tested.

### Planned

- Add continuous ingestion only if required by a future lab workflow.
- Expand detection beyond the baseline brute-force rule after validating additional use cases.
- Consider a future enterprise SIEM integration as a separate project phase.

The project currently uses its own SQLite-backed pipeline; integrating a
third-party SIEM is not part of the current implementation plan.

## Collaboration Workflow

1. Before starting work, pull the latest repository changes:

   ```bash
   git pull origin main
   ```

2. Create a separate branch for a focused change:

   ```bash
   git checkout -b feature/short-description
   ```

3. Make changes only within the appropriate folders, such as `scripts/`, `configs/`, or `docs/`.

4. Review changes before committing:

   ```bash
   git status
   git diff
   ```

5. Commit with a clear message:

   ```bash
   git add .
   git commit -m "Add Windows log collection notes"
   ```

6. Push the branch and open a pull request for review:

   ```bash
   git push -u origin feature/short-description
   ```

## Security and Ethics

- Perform all testing only on systems, virtual machines, and networks that the project team owns or has explicit permission to use.
- Keep testing activity inside the authorized lab environment.
- Do not upload credentials, passwords, private keys, application programming interface (API) tokens, personally identifiable information, or real production logs.
- Use sanitized log samples when sharing examples in this repository.
- Store sensitive local configuration values in ignored files, such as `.env`, rather than committing them to GitHub.

## Contributors

- **Mohamud Aynab** — Sole project contributor; virtual lab setup, log collection, ingestion, detection, alerting, dashboard, testing, and documentation.

## Roadmap

See [docs/roadmap.md](docs/roadmap.md) for project status and completed validation.

- [x] Configure Windows event-log collection.
- [x] Configure Kali Linux log collection.
- [x] Build the initial raw-log parsing and SQLite ingestion path.
- [x] Create configurable baseline brute-force detection rules.
- [x] Generate and validate test alerts using synthetic lab events.
- [x] Document test cases, findings, architecture, setup, and limitations.
- [x] Prepare the project report and demonstration instructions.
- [x] Verify Windows and Kali collector workflows in the authorized lab.

## License

This project is for educational and authorized lab use. A formal license will be added if the repository is shared publicly.

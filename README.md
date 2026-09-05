# Automated SIEM Log Ingestion and Alert Pipeline

A collaborative cybersecurity lab project that automates the collection, ingestion, normalization, detection, and alerting of security logs in a Security Information and Event Management (SIEM) environment.

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
- Maintain scripts and documentation through a shared GitHub workflow.

## Planned Pipeline

```text
Windows 11 VM / Kali Linux VM
            │
            ▼
     Log Collection Agent
            │
            ▼
   Log Forwarding / Ingestion
            │
            ▼
Security Information and Event Management (SIEM)
            │
            ▼
 Parsing, Normalization, and Detection Rules
            │
            ▼
      Alerts and Investigation Notes
```

## Lab Environment

| Component | Planned role |
|---|---|
| Windows 11 virtual machine | Generates Windows event logs and serves as a monitored endpoint |
| Kali Linux virtual machine | Supports authorized lab testing, log generation, and analysis |
| Oracle VM VirtualBox | Hosts the isolated virtual lab environment |
| VirtualBox NAT Network | Provides private connectivity between lab virtual machines |
| Security Information and Event Management (SIEM) platform | Centralizes logs, applies detections, and displays alerts |
| GitHub | Stores scripts, configurations, documentation, and project history |

## Repository Structure

```text
siem-log-ingestion-alert-pipeline/
├── README.md
├── generator.py
├── database/
│   ├── schema.json
│   ├── schema_setup.py
│   └── siem_logs.db
├── alerts/
├── config/
├── dashboard/
├── docs/
├── ingestion/
├── parsers/
├── pipeline/
├── storage/
├── tests/
└── .gitignore
```

> Most module folders (`alerts/`, `config/`, `dashboard/`, `ingestion/`, `parsers/`, `pipeline/`, `storage/`, `tests/`) are currently placeholders and will be filled in as the project develops.

## Current Status

**Project phase:** Initial setup and planning

### Completed

- Created the collaborative GitHub repository.
- Set up the initial virtual lab environment.
- Configured Kali Linux and Windows 11 virtual machines in Oracle VM VirtualBox.
- Established private virtual-machine networking for controlled lab communication.
- Identified the need for version control for scripts, configurations, and documentation.
- Defined the standardized log event schema (`database/schema.json`) and SQLite database setup (`database/schema_setup.py`), including log entry validation.
- Built a synthetic log generator (`generator.py`) that produces normal traffic and a simulated brute-force attack pattern for testing.

### In Progress

- Selecting and configuring the Security Information and Event Management (SIEM) platform.
- Choosing log sources and log collection methods.
- Building initial ingestion and detection workflows (`ingestion/`, `parsers/`, `pipeline/`).
- Defining test scenarios and expected alert outcomes.

### Planned

- Collect Windows event logs.
- Collect relevant Kali Linux system and authentication logs.
- Configure log forwarding into the Security Information and Event Management (SIEM) platform.
- Develop initial detection rules and alerting logic (`alerts/`).
- Build out a dashboard for reviewing logs and alerts (`dashboard/`).
- Add automated test coverage (`tests/`).
- Test alert generation with safe, authorized lab activity.
- Document results, limitations, and next steps.

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

- **Mohamud Aynab** — Virtual lab setup, documentation, and project development
- **Abdi Aynab** — Log collection, Security Information and Event Management (SIEM) configuration, detection development, and testing

> Update these roles as work is assigned.

## Roadmap

See [docs/roadmap.md](docs/roadmap.md) for the full sprint-by-sprint plan and task ownership split between contributors.

- [ ] Select a Security Information and Event Management (SIEM) platform.
- [ ] Configure Windows event-log collection.
- [ ] Configure Kali Linux log collection.
- [ ] Build the initial log-ingestion pipeline.
- [ ] Create baseline detection rules.
- [ ] Generate and validate test alerts.
- [ ] Document test cases and findings.
- [ ] Finalize the project demonstration and report.

## License

This project is for educational and authorized lab use. A formal license will be added if the repository is shared publicly.

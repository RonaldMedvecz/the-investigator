# The Investigator

**An AI security analyst that levels up every week.**

CYBER 402 — AI-powered security & network analyst.

## What it can do so far

- **Week 1:** Answer security questions in a clear, analyst voice (`investigator-instructions.md`)
- **Week 2:** Triage suspicious emails for phishing and BEC — check headers (SPF/DKIM/DMARC, Reply-To), flag urgency/secrecy/authority, and recommend out-of-band verification (`bec-triage.md`)
- **Week 3:** Audit server logs for brute-force attacks (built with help from `audit.py`)
- **Week 4:** Hunt beaconing in network traffic and reconstruct a ransomware incident timeline — spot C2 patterns with `hunt.py`, merge auth and file events with `timeline.py` (logs in `evidence/`, reports in `reports/`), identify patient zero and dwell time, and recommend contain / eradicate / recover / report actions
- **Week 5:** Auto-triage pipeline — `triage.py` sends `evidence/` logs and `ir_runbook.md` to a local Llama 3.2 model (Ollama) for a Markdown incident report (summary, timeline, MITRE ATT&CK, runbook compliance); GitHub Actions (`.github/workflows/triage.yml`) runs triage on every `evidence/` push and commits timestamped reports to `reports/`
- **Week 6:** Streamlit SOC Copilot (`app.py`) — correlates four telemetry sources (firewall, Sysmon, Windows Event, Suricata) via Groq and returns a triaged report with MITRE mapping, severity, and response plan; verify Copilot output against `samples/` logs and `ir_runbook.md` before trusting it

More skills coming each week.

## Repo

[github.com/RonaldMedvecz/the-investigator](https://github.com/RonaldMedvecz/the-investigator)

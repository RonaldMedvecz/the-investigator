# The Investigator

**An AI security analyst that levels up every week.**

CYBER 402 — AI-powered security & network analyst.

## Live app

**[the-investigator.streamlit.app](https://the-investigator.streamlit.app)**

### What it does

- **Correlate & Triage:** Upload multiple log files; Groq (Llama 3.3 70B) correlates them into one incident report with MITRE ATT&CK mapping, severity, investigation plan, and response steps.
- **Ask the Investigator:** Chat with a SOC analyst persona for follow-up questions on cases or security topics (always verify against your evidence).
- **Case Files:** Browse timestamped pipeline reports from `reports/` (Week 5 auto-triage), newest first. No AI call — display only.
- **Autonomous Investigation:** Run the tool-using agent against `evidence/` — it chooses `list_evidence`, `read_log`, and `lookup_mitre` on its own, streams its reasoning trail, and delivers a final verdict (same loop as `agent.py` / Docker).

### Weeks 1–8

- **Week 1:** Answer security questions in a clear, analyst voice (`investigator-instructions.md`)
- **Week 2:** Triage suspicious emails for phishing and BEC — check headers (SPF/DKIM/DMARC, Reply-To), flag urgency/secrecy/authority, and recommend out-of-band verification (`bec-triage.md`)
- **Week 3:** Audit server logs for brute-force attacks (built with help from `audit.py`)
- **Week 4:** Hunt beaconing in network traffic and reconstruct a ransomware incident timeline — spot C2 patterns with `hunt.py`, merge auth and file events with `timeline.py` (logs in `evidence/`, reports in `reports/`), identify patient zero and dwell time, and recommend contain / eradicate / recover / report actions
- **Week 5:** Auto-triage pipeline — `triage.py` sends `evidence/` logs and `ir_runbook.md` to a local Llama 3.2 model (Ollama) for a Markdown incident report (summary, timeline, MITRE ATT&CK, runbook compliance); GitHub Actions (`.github/workflows/triage.yml`) runs triage on every `evidence/` push and commits timestamped reports to `reports/`
- **Week 6:** Streamlit SOC Copilot (`app.py`) — correlates four telemetry sources (firewall, Sysmon, Windows Event, Suricata) via Groq and returns a triaged report with MITRE mapping, severity, and response plan; verify Copilot output against `samples/` logs and `ir_runbook.md` before trusting it
- **Week 7:** Deployed Streamlit app with Case Files tab; front end reads pipeline reports from `reports/`, back end is GitHub Actions + `triage.py`
- **Week 8:** Tool-using agent (`agent.py`) — Groq function-calling loop with three tools over `evidence/` logs and a local MITRE lookup table; ships as a Docker container for CLI use and as the **Autonomous Investigation** tab in the deployed app (same loop, different interface: `st.secrets` + `st.write` instead of env vars + `print`)

## Repo

[github.com/RonaldMedvecz/the-investigator](https://github.com/RonaldMedvecz/the-investigator)

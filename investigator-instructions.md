You are The Investigator, an AI security and network analyst. You help a junior analyst examine evidence, explain findings in plain English, and you ALWAYS recommend verifying before taking action. If you are unsure, you say so. You never invent facts.

## Week 6 — SOC Copilot

A Streamlit SOC Copilot (`app.py`) that correlates four telemetry sources — firewall, Sysmon, Windows Event, and Suricata — via Groq (Llama 3.3 70B) and returns a triaged report with MITRE ATT&CK mapping, severity, investigation plan, and response plan.

**Before you trust the report, verify it against the logs:**
- **Correlation:** Do all sources share the same host (e.g., 10.1.1.20 / WIN-FIN-07) and external IP (e.g., 45.137.21.130)? Trace the chain yourself — phishing doc → PowerShell download → new admin account → C2 beacon → lateral movement — and confirm it is one story, not coincidences.
- **MITRE IDs:** Look up every cited technique on [attack.mitre.org](https://attack.mitre.org). Watch for conflation — creating `svc_backup` is **Create Account (T1136)**, not **Valid Accounts (T1078)**; using that account to log on elsewhere is T1078. Check whether lateral movement to other hosts (e.g., WIN-FILE-01, T1021) was identified or missed.
- **Severity:** Point to specific evidence that earns the score, or push back if it is inflated.
- **Runbook:** Compare the response plan to `ir_runbook.md` — evidence preserved before remediation? Network isolation instead of power-off?

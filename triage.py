import os
from datetime import datetime
from pathlib import Path

import ollama

EVIDENCE_DIR = Path("evidence")
RUNBOOK_PATH = Path("ir_runbook.md")
MODEL = "llama3.2:3b"

SYSTEM_PROMPT = (
    "You are a senior SOC analyst. Map findings to MITRE ATT&CK with "
    "technique IDs and cite the runbook."
)

USER_PROMPT_TEMPLATE = """Analyze the evidence logs and IR runbook below.

Produce a Markdown incident report with these sections:
1. **Summary** — one-paragraph overview of the incident
2. **Timeline** — chronological key events across all logs
3. **Root Cause** — initial access and attack chain
4. **MITRE ATT&CK Mapping** — for each finding, list tactic, technique name, and technique ID
5. **Runbook Compliance** — which runbook steps were completed vs. missed (reference step text)
6. **Recommended Next Actions** — prioritized IR actions aligned with the runbook

---

## Evidence Logs

{evidence}

---

## Incident Response Runbook

{runbook}
"""

# Step 1: Read every log file in the evidence/ folder
evidence_parts = []
for log_file in sorted(EVIDENCE_DIR.iterdir()):
    if log_file.is_file():
        evidence_parts.append(f"### {log_file.name}\n\n{log_file.read_text()}")
evidence_text = "\n\n".join(evidence_parts)

# Step 2: Read the incident-response runbook
runbook_text = RUNBOOK_PATH.read_text()

# Step 3: Send evidence and runbook to the local Llama model via Ollama (no API key)
prompt_text = USER_PROMPT_TEMPLATE.format(
    evidence=evidence_text,
    runbook=runbook_text,
)
resp = ollama.chat(
    model=MODEL,
    messages=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt_text},
    ],
)
report = resp.message.content

# Step 4: Create reports/ if needed and write a timestamped report file
os.makedirs("reports", exist_ok=True)
stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
report_path = f"reports/report_{stamp}.md"
with open(report_path, "w", encoding="utf-8") as report_file:
    report_file.write(report)

print(f"Report written to {report_path}")

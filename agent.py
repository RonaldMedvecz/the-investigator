"""
The Investigator — tool-using agent (Week 8)
Three tools: list_evidence(), read_log(filename), lookup_mitre(technique_id).
The loop lets the model choose tools until it delivers a final verdict.
"""

import json
import os
from pathlib import Path

from groq import Groq
from rich.console import Console
from rich.panel import Panel

EVIDENCE_DIR = Path("evidence")
MODEL = "llama-3.3-70b-versatile"
MAX_STEPS = 10

console = Console()

# Common MITRE techniques referenced in course incidents (verify on attack.mitre.org)
MITRE_TABLE = {
    "T1021": "Remote Services",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1136": "Create Account",
    "T1136.001": "Create Account: Local Account",
    "T1486": "Data Encrypted for Impact",
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
}


def list_evidence():
    """List log filenames in evidence/."""
    if not EVIDENCE_DIR.is_dir():
        return []
    return sorted(f.name for f in EVIDENCE_DIR.iterdir() if f.is_file())


def read_log(filename: str):
    """Read one log file from evidence/."""
    path = EVIDENCE_DIR / filename
    if not path.is_file():
        return f"Error: '{filename}' not found in evidence/"
    return path.read_text(encoding="utf-8", errors="ignore")


def lookup_mitre(technique_id: str):
    """Look up a MITRE ATT&CK technique ID."""
    tid = technique_id.strip().upper()
    if not tid.startswith("T"):
        tid = f"T{tid}"
    name = MITRE_TABLE.get(tid)
    if name:
        return {"technique_id": tid, "name": name, "source": "local reference table"}
    return {
        "technique_id": tid,
        "name": "Unknown in local table — verify at https://attack.mitre.org",
        "source": "not found locally",
    }


AVAILABLE = {
    "list_evidence": list_evidence,
    "read_log": read_log,
    "lookup_mitre": lookup_mitre,
}

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_evidence",
            "description": "List all log filenames in the evidence/ folder.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_log",
            "description": "Read the full contents of one evidence log file by filename.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Log filename in evidence/, e.g. auth_events.log",
                    }
                },
                "required": ["filename"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_mitre",
            "description": "Look up a MITRE ATT&CK technique ID (e.g. T1136, T1078).",
            "parameters": {
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "MITRE technique ID, e.g. T1059.001",
                    }
                },
                "required": ["technique_id"],
            },
        },
    },
]

SYSTEM = """You are The Investigator, a senior SOC analyst agent.

Use the tools to examine evidence/ logs before concluding. Typical workflow:
1. list_evidence() to see what logs exist
2. read_log(filename) for each relevant file
3. lookup_mitre(technique_id) to confirm technique names

When you have enough evidence, stop calling tools and deliver a final verdict:
- Summary of the incident
- Timeline / attack chain
- MITRE ATT&CK mapping (tactic, technique name, technique ID)
- Severity with justification
- Recommended next actions aligned with standard IR practice

Cite log evidence. Do not invent events or technique IDs not supported by the logs."""

DEFAULT_GOAL = """Investigate the security incident using the logs in evidence/.
Identify initial access, key IoCs, MITRE techniques, and recommend response steps."""


def run_agent(goal=None, api_key=None, on_step=None):
    """Run the agent loop. Returns final verdict string."""
    goal = goal or DEFAULT_GOAL
    api_key = api_key or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return "⚠️ No GROQ_API_KEY found. Set it in the environment or Streamlit secrets."

    client = Groq(api_key=api_key)
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": goal}]

    for step in range(MAX_STEPS):
        resp = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
        )
        msg = resp.choices[0].message
        messages.append(msg)

        if not msg.tool_calls:
            return msg.content or ""

        for tc in msg.tool_calls:
            args = json.loads(tc.function.arguments or "{}") or {}
            if on_step:
                on_step(f"**Step {step + 1}:** `{tc.function.name}({args})`")
            result = AVAILABLE[tc.function.name](**args)
            preview = str(result)
            if len(preview) > 500:
                preview = preview[:500] + "..."
            if on_step:
                on_step(preview)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": tc.function.name,
                    "content": str(result),
                }
            )

    return "Max steps reached without a final verdict."


if __name__ == "__main__":
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        console.print("[red]Set GROQ_API_KEY first.[/red]")
        console.print('PowerShell: $env:GROQ_API_KEY="your_key_here"')
    else:
        verdict = run_agent(
            api_key=key,
            on_step=lambda text: console.print(f"[cyan]{text}[/cyan]"),
        )
        console.print(Panel(verdict, title="Verdict", border_style="green"))

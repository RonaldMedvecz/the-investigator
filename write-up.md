# Project: The Investigator

**Problem:** Junior analysts and small teams often face too many raw logs and not enough time to correlate them into a clear incident story with correct MITRE ATT&CK labels and actionable response steps. I wanted a tool that speeds up triage while still forcing human verification against real evidence.

**What I built:** A Streamlit SOC Copilot with four modes in one deployed app. Users can upload multiple log sources and get a correlated incident report; chat with an AI analyst for follow-up questions; browse timestamped reports that a GitHub Actions pipeline writes automatically; and run an autonomous agent that reads `evidence/`, calls tools (`list_evidence`, `read_log`, `lookup_mitre`), streams its reasoning trail, and delivers a final verdict. The same agent loop also runs as a Docker container for CLI use.

**Tech:** Python, Streamlit, Groq (Llama 3.3 70B), GitHub Actions, Ollama (Llama 3.2), Docker, MITRE ATT&CK

**The AI check:** When correlating a ransomware scenario, the Copilot sometimes mapped account creation to **T1078 (Valid Accounts)** instead of **T1136 (Create Account)**. I checked each ID on [attack.mitre.org](https://attack.mitre.org) and re-read the Windows Event logs in `samples/` — the attacker created a new local account after initial access, which is T1136, not reuse of an existing valid account. I also verified the response plan against `ir_runbook.md`: the model occasionally suggested powering off hosts; the runbook says isolate on the network and preserve evidence first. Catching those mismatches is why the app prompts analysts to verify before acting.

**Learned:**

1. **The agent is the loop, not the interface** — the same tool-calling logic works in the terminal, in Docker, and in Streamlit; only secrets and output change.
2. **Ground truth beats model confidence** — runbooks, sample logs, and MITRE's site are the checks that keep AI-assisted triage trustworthy.
3. **Pipelines and products belong together** — GitHub Actions + Ollama writes reports in the background while the web app displays them in Case Files; autonomous investigation adds a third path over the same evidence.

**Links:** [Live app](https://5cts8ezvu5r8gqwzytbypy.streamlit.app) · [GitHub](https://github.com/RonaldMedvecz/the-investigator) · [Docker Hub — investigator-agent](https://hub.docker.com/r/ronaldmedvecz/investigator-agent)

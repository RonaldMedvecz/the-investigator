# BEC Triage — Meridian Group wire-transfer email

## Verdict
Spoofed (impersonation). Confidence: high.
(add your reasoning — what in the evidence proves it)

## Red flags found
- Reply-To is a Gmail address, not the company domain
- SPF softfail, DKIM fail, DMARC fail — sender not authorized
- Originating IP (41.223.x.x) is an African ISP, not Singapore
- Urgency (5 PM deadline), secrecy ("don't tell the team"),
  authority (the CEO)
(add any others you spotted)

## Verification checklist (before wiring money)
1. Call the CEO back on a known, trusted number (not from the email)
2. Require a second approver for any new payee or wire
(add the rest — 5–7 steps total)

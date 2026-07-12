# Ransomware Incident Response Runbook

**Ground truth for The Investigator pipeline.** Numbered steps follow NIST SP 800-61 incident response phases (Rev. 2 life cycle; aligned with Rev. 3 Respond/Recover activities) and SANS six-step IR (Prepare, Identify, Contain, Eradicate, Recover, Learn).

**Verified against:** NIST SP 800-61r2/r3 (evidence collection, containment, eradication, recovery from clean backups); SANS Incident Response process. Critical ordering: preserve evidence before remediation, isolate on the network (do not power off), restore from known-good offline backups.

---

## 1. Preparation

- [ ] Maintain an incident response plan, escalation path, and contact list (IR team, legal, leadership, law enforcement, cyber insurance).
- [ ] Identify critical assets and data (file servers, domain controllers, PHI/EMR systems) and document dependencies.
- [ ] Maintain **offline or immutable backups**; test restores regularly and verify backup integrity before an incident.
- [ ] Enable and retain centralized logging (authentication, endpoint, network, file activity).
- [ ] Pre-define isolation procedures (network segmentation, EDR network containment, firewall deny rules).
- [ ] Train responders on evidence handling and chain-of-custody basics.

## 2. Detection & Analysis

- [ ] Detect indicators: mass file renames (e.g., `.locked`), ransom notes, failed-then-successful logins, C2 beaconing to external IPs.
- [ ] Confirm and classify the incident; assign severity, incident lead, and start an incident log.
- [ ] **Preserve evidence before remediation:** collect logs, disk images, and network captures; record timestamps and chain of custody. Do not wipe or rebuild systems yet.
- [ ] Build a timeline from auth, network, and file events; identify initial access (patient zero) and affected scope.
- [ ] Extract and hunt for IoCs (IPs, domains, file hashes, accounts); check for persistence and lateral movement.
- [ ] Notify legal and compliance leadership; begin regulatory/breach assessment (e.g., HIPAA if PHI is involved).

## 3. Containment, Eradication & Recovery

### Containment

- [ ] **Isolate infected hosts on the network** (VLAN quarantine, firewall block, EDR network isolation, disable compromised accounts). **Do not power off** unless life/safety requires it—powering off destroys volatile evidence and may aid the attacker.
- [ ] Block confirmed attacker IoCs at the perimeter without disrupting ongoing evidence collection.
- [ ] Stop spread: disable open shares, pause backups to compromised paths, suspend remote access vectors used in the attack.
- [ ] Document all containment actions and times.

### Eradication

- [ ] Remove malware, ransom payloads, and persistence (scheduled tasks, new accounts, backdoors) from contained systems.
- [ ] Reset compromised credentials; rotate keys and certificates where exposure is suspected.
- [ ] Close the entry vector (patch vulnerabilities, disable exposed services, enforce MFA).
- [ ] Re-scan systems to confirm IoCs and persistence are eliminated before recovery begins.

### Recovery

- [ ] **Restore data and systems from known-good offline (or immutable) backups** predating the compromise; verify backup integrity before restore.
- [ ] Rebuild severely compromised hosts from clean images—do not trust systems that were encrypted in place.
- [ ] Bring systems online incrementally; monitor for re-infection, beaconing, or new encryption.
- [ ] **Do not pay the ransom**—payment does not guarantee decryption and encourages repeat attacks.
- [ ] Validate restored operations and confirm incident closure criteria are met.

## 4. Post-Incident Activity

- [ ] Conduct a post-incident review: root cause, dwell time, control gaps, and timeline accuracy.
- [ ] Complete required breach notifications, stakeholder communications, and regulatory reports.
- [ ] Update the IR plan, detection rules, and backups/containment procedures from lessons learned.
- [ ] Track remediation tasks to closure and feed improvements back into Preparation.

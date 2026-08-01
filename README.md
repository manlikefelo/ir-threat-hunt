# Incident Response & Threat Hunting 🔵

The defender's chair for the whole portfolio. I attacked an Active Directory domain
([ad-attack-chain](https://github.com/manlikefelo/ad-attack-chain)) and two web apps
([webapp-pentest-juiceshop](https://github.com/manlikefelo/webapp-pentest-juiceshop)); I detected those attacks
([detection-engineering](https://github.com/manlikefelo/detection-engineering)); **here I investigate and respond to
them as incidents** — reconstructing timelines from the logs, triaging, and writing the
response the way a SOC lead would actually read it.

> This closes the purple-team loop: **attack → detect → investigate & respond**, all on
> the same events, in one coherent lab.

---

## What's here

```
incidents/    NIST IR-lifecycle reports with reconstructed attack timelines
  INC-001-ad-domain-compromise.md      the AD kill chain (AS-REP → DCSync → BloodHound)
  INC-002-web-application-attack.md     the web SQLi / XSS attack
threat-hunts/ hypothesis-driven hunts
  HUNT-001-kerberoasting.md            hunt for RC4 TGS / roastable service accounts
playbooks/    reusable triage decision tree + escalation criteria
docs/iocs.md  extracted indicators of compromise
```

## The headline artifact — the timeline

Each incident reconstructs the attack as a **timeline built from log evidence** (a
mermaid diagram + an evidence table mapping each step to a timestamp, host, ATT&CK
technique, and the source alert). Timelines are what say *"this person can actually
investigate,"* so they lead each report:

- **[INC-001](incidents/INC-001-ad-domain-compromise.md)** — three DC01 alerts, ~5 hours
  apart, reconstructed into one kill chain on the account `b.otieno`: AS-REP roast →
  DCSync (every hash incl. `krbtgt`) → BloodHound. The ~5h gap = offline cracking.
- **[INC-002](incidents/INC-002-web-application-attack.md)** — an XSS probe escalating to
  a successful UNION SQL injection against the DVWA `users` table.

## How I think under pressure (the part interviewers probe)

Each report shows the **triage reasoning** — *why* each alert is a true positive vs a
false positive — because "walk me through how you'd investigate this" is the question you
*will* be asked. Examples:

- **DCSync is a near-certain TP** because a *non-DC* account exercised replication rights
  — legitimate replication only comes from DC machine accounts / SYSTEM.
- **The enumeration burst is low-confidence alone** but earns its keep *by correlation*
  with the other steps from the same source IP.
- **The web SQLi's HTTP 200 + large response** indicates the injection *succeeded* — a
  blocked attempt would be a 3xx/4xx.

## Reusable outputs

- **[Triage playbook](playbooks/triage-playbook.md)** — a decision tree with escalation
  criteria for every alert type in the lab.
- **[IOCs](docs/iocs.md)** — indicators extracted from both incidents, ready for a
  watchlist.

## Skills demonstrated

Log analysis · timeline reconstruction · NIST IR lifecycle · true/false-positive triage
· hypothesis-driven threat hunting · IOC extraction · playbook design · clear written
communication for a technical-lead audience.

## Read next
- **[`docs/reviewer-path.md`](docs/reviewer-path.md)** — a 3-minute guided tour.

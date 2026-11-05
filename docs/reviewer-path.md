# Reviewer path: a 3-minute tour

The fastest route through this repo, in the order that best shows investigative skill.

### 1. The reconstructed timeline (60 sec)
Open **[INC-001: AD domain compromise](../incidents/INC-001-ad-domain-compromise.md)**
and look at the **attack timeline** (the mermaid diagram + the evidence table). Three
alerts, hours apart, reconstructed into one kill chain on a single account. Reading a
timeline out of scattered log events is the core investigative skill. This is it.

### 2. The triage reasoning (60 sec)
In the same report, read **§2 "Triage, true positive vs false positive."** It shows
*why* DCSync is a near-certain true positive (a non-DC account using replication rights),
and how the low-confidence enumeration alert earns its keep by correlation. This is the
"walk me through how you'd investigate" answer, written down.

### 3. The threat hunt (45 sec)
Open **[HUNT-001: Kerberoasting](../threat-hunts/HUNT-001-kerberoasting.md)**. A
*proactive* hunt: hypothesis → data → query → findings → outcome. Note the shift from
"detect the attack" to "find the exposure *before* the attack" (which service accounts
are roastable at all).

### 4. If you want the reusable outputs
- **[Triage playbook](../playbooks/triage-playbook.md)**: the decision tree + escalation
  criteria a SOC analyst would actually follow.
- **[IOCs](iocs.md)**: the indicators, cleanly extracted.

---

**What this repo proves:** I can take raw SIEM alerts, reconstruct what happened into a
coherent timeline, triage true vs false positives with defensible reasoning, hunt
proactively, and communicate all of it the way a SOC lead needs to read it. Paired with
the attack and detection repos, it completes the purple-team story: I attacked, I
detected, and here I investigate and respond.

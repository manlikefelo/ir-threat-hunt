# INC-001: Active Directory domain compromise

**Severity:** Critical · **Status:** Closed (lab exercise) · **Analyst:** Felix Githure
**Source of truth:** Wazuh SIEM (DC01 agent), custom rules 100011–100013

An investigation, from the defender's chair, of the attack I ran in my
[ad-attack-chain](https://github.com/manlikefelo/ad-attack-chain) repo. Structured on the **NIST SP 800-61
incident-response lifecycle**.

---

## 1. Preparation

The environment was instrumented before the incident: DC01 forwards Security events to
Wazuh, **Directory Service Access auditing + a SACL on the domain root** were enabled
(without them, DCSync/enumeration generate no 4662 events), and custom detection rules
100010–100013 map Kerberos/replication signatures to ATT&CK. This preparation is *why*
the incident was detectable at all: a point worth making, because most "how did we miss
it" post-mortems trace back to telemetry that was never collected.

## 2. Detection & analysis

Three Wazuh alerts fired on DC01, which together tell one story. Reconstructed from the
alert timestamps and `data.win.*` fields:

### Attack timeline

| # | Timestamp (UTC) | Host | Event / rule | ATT&CK | Evidence source |
|---|-----------------|------|--------------|--------|-----------------|
| 1 | 2026-07-30 20:54:09 | DC01 | Rule **100011**: AS-REP roast: 4768, preAuthType 0, RC4, target `b.otieno`, src `10.10.10.40` | T1558.004 | [alert JSON](https://github.com/manlikefelo/ad-attack-chain/blob/main/engagement/02-asrep-roasting/evidence/wazuh_alert_100011.json) |
| 2 | 2026-07-31 02:00:34 | DC01 | Rule **100012**: DCSync: 4662, replication GUID `1131f6aa…`, subject `b.otieno` (non-DC), src `10.10.10.40` | T1003.006 | [alert JSON](https://github.com/manlikefelo/ad-attack-chain/blob/main/engagement/03-dcsync/evidence/wazuh_alert_100012.json) |
| 3 | 2026-07-31 02:01:49 | DC01 | Rule **100013**, enumeration burst: 4662 read spike (BloodHound), src `10.10.10.40` | T1087.002 | [alert JSON](https://github.com/manlikefelo/ad-attack-chain/blob/main/engagement/04-bloodhound/evidence/wazuh_alert_100013.json) |

```mermaid
timeline
    title INC-001 - attack timeline (all from 10.10.10.40)
    2026-07-30 20:54 : AS-REP roast of b.otieno (T1558.004) : no creds needed - harvest crackable hash
    2026-07-31 02:00 : DCSync as b.otieno (T1003.006) : replicate ALL domain hashes incl. krbtgt
    2026-07-31 02:01 : BloodHound enumeration (T1087.002) : map every path to Domain Admin
```

### What the timeline tells us

The three events are **one kill chain on a single account, `b.otieno`**, all from
attacker IP `10.10.10.40`:

1. **AS-REP roasting** harvested `b.otieno`'s crackable hash with *no credentials*:
   the initial foothold.
2. **DCSync** ~5 hours later used `b.otieno`'s replication rights to pull **every**
   domain hash, including `krbtgt`. That's the "game over" moment (Golden Ticket
   capability = persistent domain control).
3. **BloodHound enumeration** mapped the domain graph, confirming `b.otieno`'s paths to
   Domain Admin.

The ~5-hour gap between step 1 and step 2 is consistent with **offline password
cracking** between the roast and its reuse.

### Triage: true positive vs false positive

- **Rule 100012 (DCSync)** is the highest-confidence signal: replication rights
  (`Get-Changes-All`) exercised by `b.otieno`, which is **not a Domain Controller**.
  Legitimate replication comes only from DC machine accounts / SYSTEM, so a *user*
  account here is a true positive with near-certainty. **Confirmed TP.**
- **Rule 100011 (AS-REP)**: `preAuthType 0` means pre-auth is disabled on the account,
  an abnormal configuration; combined with an external source IP, **TP**.
- **Rule 100013 (enumeration)** is the noisiest (a rate signal). On its own it could be
  a busy admin tool; **in the context of steps 1–2 from the same IP**, it corroborates
  the intrusion. TP *by correlation*, which is exactly how a low-confidence signal earns
  its keep.

## 3. Containment

Immediate actions a defender should take:
- **Disable `b.otieno`** and force-expire its sessions/tickets.
- **Isolate** the source host `10.10.10.40` from the domain network.
- Because `krbtgt` was replicated, **the entire domain's Kerberos trust is compromised**:
  treat all TGTs as forgeable.

## 4. Eradication & recovery

- **Rotate the `krbtgt` password twice** (with a replication interval between) to
  invalidate any Golden Tickets.
- Remove `b.otieno` from Domain Admins and **strip its replication rights** (the ACL
  misconfig that enabled DCSync).
- Re-enable Kerberos pre-authentication on `b.otieno`.
- Reset credentials for any account whose hash was exposed by the DCSync (i.e. all of
  them, prioritising privileged accounts).

## 5. Post-incident (lessons learned)

- **Detection gap closed forward:** the ~5h dwell between roast and DCSync is a window a
  faster alert-to-response could have caught. Feeds a detection-improvement to
  [detection-engineering](https://github.com/manlikefelo/detection-engineering): alert on *any* non-DC principal
  using replication rights at **level 12 (page-worthy)**, which rule 100012 already does.
- **Root cause was configuration, not exploitation:** one over-permissioned account
  (`b.otieno`: pre-auth off + replication rights + Domain Admins). The fix is least
  privilege and tiered admin, see the [remediation plan](https://github.com/manlikefelo/ad-attack-chain/blob/main/remediation.md).
- **Preparation paid off:** without the DS-Access auditing + SACL enabled in phase 1,
  steps 2–3 would have been invisible.

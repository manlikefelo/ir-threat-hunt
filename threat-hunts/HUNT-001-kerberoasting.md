# HUNT-001: Hypothesis-driven hunt: Kerberoasting

**Analyst:** Felix Githure · **Data source:** Wazuh SIEM (DC01 Security events)
**Framework:** hypothesis → data → query → findings → outcome (ATT&CK-aligned)

A proactive hunt, not triggered by an alert, but by a *hypothesis*. This is the
difference between waiting for a rule to fire and going looking for the thing before it
does.

---

## Hypothesis

> *"An attacker has performed, or could perform, **Kerberoasting** (T1558.003) against a
> service account in the domain, requesting an RC4-encrypted service ticket to crack
> its password offline."*

Kerberoasting is attractive to attackers because any authenticated user can do it and it
touches no privileged system. If it's happening, it leaves a specific fingerprint.

## Data sources

- **Windows Security Event 4769** (Kerberos service ticket requested), forwarded from
  DC01 to Wazuh via the `windows_eventchannel` decoder.
- Fields of interest: `ticketEncryptionType`, `serviceName`, `targetUserName`,
  `ipAddress`.

## The hunt query

In Wazuh Discover (or the indexer):

```
data.win.system.eventID:4769 AND data.win.eventdata.ticketEncryptionType:0x17
```

Reasoning: **`0x17` = RC4**. Modern accounts negotiate AES (`0x11`/`0x12`); an RC4
service-ticket request is the crackable case Kerberoasting depends on. A cluster of RC4
TGS requests for SPN accounts, especially from one source, is the signature.

Supporting pivots once a hit is found:
- Group by `serviceName`: which service accounts are being targeted.
- Group by `ipAddress` / `targetUserName`: who is doing the requesting.
- Cross-reference SPN accounts with weak-password / RC4-enabled accounts (the actual
  exposure).

## Findings

The hunt surfaced the Kerberoast I ran in Project 1: a 4769 with
`ticketEncryptionType 0x17` for `serviceName: svc_sql`, requested by `a.mokaya` from
`10.10.10.40`. This is exactly what rule **100010** alerts on, so here the hunt
*confirms* the detection's premise and validates the coverage.

More usefully, the hunt also frames the **proactive** question: *which accounts are
roastable even if no one has roasted them yet?* Those are the SPN accounts with RC4
enabled and weak/old passwords, found with:

```powershell
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName, msDS-SupportedEncryptionTypes, PasswordLastSet
```

## Outcome

- **Detection validated:** the RC4-TGS signature is present and rule 100010 covers it.
- **Proactive risk identified:** `svc_sql` (and any other RC4/weak SPN account) is a
  standing Kerberoast target regardless of current activity: a finding to remediate
  (gMSA / long random password / force AES), not just detect.
- **Feeds forward:** this hunt's logic is the same as detection 100010; the hunt's value
  is catching the *exposure* before the *attack*, and confirming the detection isn't
  blind. Mapped to **ATT&CK T1558.003**.

# Indicators of Compromise (IOCs)

Extracted from INC-001 (AD compromise) and INC-002 (web attack). In a real environment
these feed watchlists, SIEM correlation, and threat-intel sharing. Format is deliberately
clean and copy-pasteable.

> **Lab note:** these indicators are from my own isolated lab (`10.10.10.0/24`). They are
> illustrative of *what* to extract and *how* to present it, not real-world threat intel.

## Network

| Type | Indicator | Context |
|------|-----------|---------|
| IP | `10.10.10.40` | Attacker host (Kali), source of all AD attacks in INC-001 |
| IP | `10.10.10.30` | Victim host (UB01) generating the web-attack requests in INC-002 |

## Host / identity

| Type | Indicator | Context |
|------|-----------|---------|
| Account | `b.otieno` | Compromised/abused account: AS-REP roasted, then used for DCSync (INC-001) |
| Account | `svc_sql` | Kerberoast target (SPN service account) |
| Account | `a.mokaya` | Low-priv account used to request the Kerberoast TGS |

## Behavioural / detection signatures

| Type | Indicator | ATT&CK |
|------|-----------|--------|
| Event | 4768 with `preAuthType 0` | T1558.004 AS-REP Roasting |
| Event | 4769 with `ticketEncryptionType 0x17` (RC4) for an SPN | T1558.003 Kerberoasting |
| Event | 4662 with replication GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` or `1131f6ad-…` by a non-DC | T1003.006 DCSync |
| Event | 4661/4662 read burst (>15 / 60s) from one principal | T1087.002 Enumeration |
| HTTP | Request URI containing `UNION SELECT` / `UNION%20SELECT` / `information_schema` | T1190 Web SQLi |
| HTTP | Request URI containing `<script>` / `<iframe` / `javascript:` / `onerror=` | T1190 Web XSS |

## Credential exposure (INC-001 / INC-002)

- **All domain NTLM hashes** (via DCSync), including **`krbtgt`** → assume Golden Ticket
  capability; rotate krbtgt twice.
- **DVWA `users` table** (via UNION SQLi): 5 accounts, unsalted MD5, all cracked
  (`admin`, `gordonb`, `1337`, `pablo`, `smithy`).

## Recommended watchlist actions

- Alert on any 4662 replication-GUID access by a **non-DC** principal (already: rule 100012).
- Alert on 4768 `preAuthType 0` and 4769 RC4 (rules 100011 / 100010).
- WAF/SIEM match on the web SQLi/XSS URI patterns (rules 100014 / 100015).

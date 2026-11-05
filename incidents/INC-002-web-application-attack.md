# INC-002: Web application attack (SQL injection & XSS)

**Severity:** High · **Status:** Closed (lab exercise) · **Analyst:** Felix Githure
**Source of truth:** Wazuh SIEM (UB01 agent, DVWA access log), rules 100014 / 100015

The defender's investigation of the web attacks I ran in my
[webapp-pentest-juiceshop](https://github.com/manlikefelo/webapp-pentest-juiceshop) repo. NIST IR lifecycle.

---

## 1. Preparation

The UB01 Wazuh agent tails the DVWA container's Apache access log (shipped as the docker
JSON log), and rules 100014 (SQLi) / 100015 (XSS) match injection patterns in the request
URI. Critically, the SQLi rule uses a **URL-encoding-aware** pattern: an earlier version
missed the attack because real traffic is encoded (`UNION%20SELECT`). That tuning is what
made this incident detectable.

## 2. Detection & analysis

### Attack timeline

| # | Timestamp (UTC) | Host | Event / rule | ATT&CK | Request |
|---|-----------------|------|--------------|--------|---------|
| 1 | 2026-07-31 16:19:52 | UB01 | Rule **100015**: XSS pattern | T1190 | `GET /vulnerabilities/xss_r/?name=<script>alert(1)</script>` |
| 2 | 2026-07-31 16:23:07 | UB01 | Rule **100014**: SQLi pattern | T1190 | `GET /vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users-- -` |

```mermaid
timeline
    title INC-002 - web attack timeline
    2026-07-31 16:19 : Reflected XSS probe (T1190) : script payload in name param
    2026-07-31 16:23 : UNION SQL injection (T1190) : extract users.password from the DB
```

### What the timeline tells us

An attacker probed the application's input handling (XSS), then escalated to a
**UNION-based SQL injection** that reads the `users` table: the request string itself
(`UNION SELECT user,password FROM users`) is unambiguous intent to exfiltrate
credentials. The HTTP 200 on the SQLi request indicates the injection **succeeded** (a
blocked/redirected attempt would be 3xx/4xx).

### Triage: true positive vs false positive

- **Rule 100014 (SQLi)**: the request contains `UNION SELECT ... FROM users`. This is
  not a string a legitimate user or app generates; **confirmed TP**. The 200 response
  size (5637 bytes vs a normal page) corroborates data was returned.
- **Rule 100015 (XSS)**: a `<script>alert(1)</script>` in a query parameter is a
  textbook probe. **TP.** In production I'd lower its confidence slightly (some params
  legitimately carry markup), see the tuning note.
- **Correlation:** both from the same session against the same host minutes apart: a
  single actor progressing from probe to exploitation.

## 3. Containment

- **Block the source IP** at the WAF / reverse proxy.
- **Take the vulnerable endpoint offline** or put it behind a WAF rule that blocks
  `UNION SELECT` / encoded equivalents until patched.
- Assume the `users` table (and any credentials in it) is **compromised**.

## 4. Eradication & recovery

- **Fix the injection at the code level**: parameterised queries (the only real fix).
- **Reset all credentials** in the exposed `users` table; if hashes were weak/unsalted
  (they were: MD5), force resets and move to bcrypt/argon2.
- Add the missing security headers and set `HttpOnly`/`Secure`/`SameSite` on session
  cookies (closes the XSS→session-theft path, see the pentest's F-05).

## 5. Post-incident (lessons learned)

- **Detection tuning matters more than detection logic:** the SQLi rule was "correct"
  yet initially caught nothing because it matched a literal space, not the encoded
  `%20`. Detections must be validated against **captured real traffic**. This is written
  up as FP-3 in [detection-engineering/docs/tuning-log.md](https://github.com/manlikefelo/detection-engineering/blob/main/docs/tuning-log.md).
- **Log the right layer:** the win here was tailing the Apache access log, where the full
  malicious URI is visible. Application-level logs alone would have shown a DB error at
  best.
- **Chain awareness:** this same injection, in a real app, chains into the broken-access
  and credential-reuse findings from the pentest: one bug rarely stops at one bug.

# Broken Authentication – Session Reuse After Logout

Hands-on security assessment of JWT session invalidation and authentication lifecycle observability in OWASP Juice Shop.

## Quick Summary

| Metric | Value |
| :--- | :--- |
| **Vulnerability** | Broken Authentication (Improper Session Invalidation) |
| **OWASP Category** | A07:2021 – Identification and Authentication Failures |
| **CWE** | CWE-287: Improper Authentication |
| **Severity** | High |
| **Target Endpoints** | `POST /rest/user/login`, `GET /rest/user/whoami`, `POST /rest/user/logout` |
| **Status** | ✅ Remediated & Verified (Closed) |

---

## Lab Documentation

This module tracks the vulnerability lifecycle across four sequential reports:

1. **[01-broken-authentication-report.md](./01-broken-authentication-report.md)**  
   Vulnerability discovery, token replay exploit steps via Burp Repeater, root cause analysis, and baseline logging gaps.

2. **[02-detection-observability-logging.md](./02-detection-observability-logging.md)**  
   Phase 1 hardening: instrumenting authentication lifecycle telemetry (`LOGIN_SUCCESS`, `TOKEN_USED`, `LOGOUT`) to make session abuse observable before applying blocking controls.

3. **[03-prevention-token-revocation.md](./03-prevention-token-revocation.md)**  
   Phase 2 hardening: implementing server-side token revocation (`revokedTokens` set in `insecurity.ts`) and a dedicated backend logout endpoint in `server.ts`.

4. **[04-retest-results.md](./04-retest-results.md)**  
   Retest verification confirming replayed tokens receive `HTTP 401 Unauthorized` (`Session expired`) and trigger `TOKEN_REJECTED` audit logs.

---

## Patches & Evidence

* **`patches/`** – Drop-in replacement source files for Juice Shop:
  * [`insecurity.ts`](./patches/insecurity.ts) – Token revocation store & middleware validation check.
  * [`login.ts`](./patches/login.ts) – Authentication success audit logging.
  * [`server.ts`](./patches/server.ts) – Server-side logout endpoint (`POST /rest/user/logout`).
* **`evidence/`** – Supporting screenshots covering Burp Repeater flows, DevTools cookie storage, and server console telemetry.

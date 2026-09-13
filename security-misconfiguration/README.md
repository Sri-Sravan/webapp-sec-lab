# Security Misconfiguration (OWASP A02:2025 / A05:2021)

Hands-on vulnerability assessment, defensive code remediation, and post-patch validation of **Security Misconfiguration** flaws in OWASP Juice Shop.

## Quick Summary

| Metric | Value |
| :--- | :--- |
| **Vulnerability** | Security Misconfiguration |
| **OWASP Category** | A02:2025 – Security Misconfiguration / A05:2021 – Security Misconfiguration |
| **CWE** | CWE-209 (Verbose Error Disclosure), CWE-548 (Directory Listing), CWE-200 (Exposure of Sensitive Information), CWE-693 (Protection Mechanism Failure) |
| **Severity** | High |
| **Target Endpoints** | `GET /rest/products/search`, `GET /ftp/`, `GET /ftp/:file`, Global HTTP Headers |
| **Status** | ✅ Remediated & Verified (Closed) |

---

## Lab Documentation

This module evaluates three separate misconfiguration vectors across three technical reports:

1. **[01-security-misconfiguration-assessment.md](./01-security-misconfiguration-assessment.md)**  
   Detailed discovery, root cause analysis, and Burp Suite proof-of-concept captures for database error leaking, unrestricted directory indexing, null-byte backup file exposure, and absent security headers.

2. **[02-prevention-security-misconfiguration-hardening.md](./02-prevention-security-misconfiguration-hardening.md)**  
   Engineering remediation: replacing development error handlers with centralized production error-handling middleware, disabling directory browsing on static mounts, strictly sanitizing file downloads, and enforcing modern defensive HTTP headers.

3. **[03-retest-results.md](./03-retest-results.md)**  
   Retest verification demonstrating sanitized `HTTP 500` JSON errors, `HTTP 403 Forbidden` responses for directory indexing and null-byte manipulation, and enforced security headers (`CSP`, `HSTS`, `Referrer-Policy`, `Permissions-Policy`).

---

## Attack Vectors Tested

| Vector | Classification | Target Endpoint / Context | Impact | Root Cause & Defense |
| :--- | :---: | :--- | :--- | :--- |
| **Vector 1: Stack & SQL Error Leak** | Information Disclosure | `GET /rest/products/search?q='))` & `/ftp/invalid` | Internal filesystem paths, database engine versions, and raw SQL queries leaked to client | Dev error handler (`errorhandler()`) active; replaced with sanitized production error middleware |
| **Vector 2: Directory Browsing & Backup Disclosure** | Unrestricted Access / Null Byte Bypass | `GET /ftp/` & `GET /ftp/package.json.bak%2500.md` | Full directory browsing and unauthorized download of sensitive backup files (`package.json.bak`, `coupons_2013.md.bak`) | `serveIndex` enabled and flawed null-byte truncation; fixed by disabling indexing and blocking null bytes/backup extensions |
| **Vector 3: Missing Security Headers** | Protection Mechanism Failure | Global HTTP Response Headers | Lack of browser-side mitigation against XSS, clickjacking, MIME sniffing, and downgrade attacks | Incomplete `helmet` deployment; enforced strict CSP, HSTS, Referrer-Policy, and Permissions-Policy |

---

## Patches & Evidence

* **`patches/`** – Drop-in patched server and route files:
  * [`server.ts`](./patches/server.ts) – Production error-handling middleware, disabled directory browsing, and defensive security headers.
  * [`fileServer.ts`](./patches/fileServer.ts) – Strict file extension enforcement, directory traversal containment, and null-byte rejection.
* **`evidence/`** – Burp Suite Repeater screenshots capturing pre-patch disclosures, exploit PoCs, and post-patch retest confirmations.

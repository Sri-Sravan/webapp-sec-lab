# Cross-Site Scripting (XSS) Security Assessment

Hands-on security assessment, source code remediation, and validation of multiple Cross-Site Scripting (XSS) injection contexts in OWASP Juice Shop.

## Quick Summary

| Metric | Value |
| :--- | :--- |
| **Vulnerability** | Cross-Site Scripting (DOM, Reflected, Stored) |
| **OWASP Category** | A03:2021 – Injection |
| **CWE** | CWE-79: Improper Neutralization of Input During Web Page Generation |
| **Severity** | High |
| **Target Endpoints** | `/search?q=`, `/track-order?id=`, `/api/Feedbacks` |
| **Status** | ✅ Remediated & Verified (Closed) |

---

## Lab Documentation

This assessment covers three distinct XSS attack vectors across three sequential reports:

1. **[01-xss-vulnerability-assessment.md](./01-xss-vulnerability-assessment.md)**  
   Technical breakdown, reproduction steps, and evidence captures for DOM XSS (search), Reflected XSS (tracking), and Stored XSS (feedback).

2. **[02-prevention-xss-hardening.md](./02-prevention-xss-hardening.md)**  
   Code-level remediation: removing Angular `DomSanitizer.bypassSecurityTrustHtml()` sinks, adopting Angular interpolation (`{{ }}`), and sanitizing HTML with `SecurityContext.HTML`.

3. **[03-retest-results.md](./03-retest-results.md)**  
   Post-patch verification confirming all payloads render as inert plain text without executing script or triggering alert dialogs.

---

## Attack Vectors Tested

| Context | Endpoint | Payload Example | Root Cause & Remediation |
| :--- | :--- | :--- | :--- |
| **DOM XSS** | `/search?q=` | `<iframe src="javascript:alert(\`xss\`)">` | Removed `bypassSecurityTrustHtml()`; switched `[innerHTML]` to `{{ searchValue }}` |
| **Reflected XSS** | `/track-order?id=` | `<iframe src="javascript:alert(\`xss\`)">` | Removed sanitizer bypass in `track-result.component.ts` |
| **Stored XSS** | `/api/Feedbacks` | `<<iframe src="javascript:evil"/>iframe src="javascript:alert(\`xss\`)">` | Added explicit `sanitizeFeedback()` using `DomSanitizer.sanitize()` |

---

## Patches & Evidence

* **`patches/`** – Modified Angular components:
  * [`search-result.component.ts`](./patches/search-result.component.ts) & [`html`](./patches/search-result.component.html)
  * [`track-result.component.ts`](./patches/track-result.component.ts)
  * [`administration.component.ts`](./patches/administration.component.ts) & [`html`](./patches/administration.component.html)
* **`evidence/`** – Screenshots documenting payload injection, alert popups, and inert post-patch rendering.

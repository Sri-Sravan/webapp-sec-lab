# Insecure Direct Object References (IDOR / BOLA)

Hands-on security assessment, defensive code remediation, and validation of Broken Object Level Access Control (BOLA) flaws across relational and document datastore tiers in OWASP Juice Shop.

## Quick Summary

| Metric | Value |
| :--- | :--- |
| **Vulnerability** | Insecure Direct Object Reference (IDOR) / BOLA |
| **OWASP Category** | A01:2021 – Broken Access Control |
| **CWE** | CWE-639: Authorization Bypass Through User-Controlled Key |
| **Severity** | High |
| **Target Endpoints** | `GET /rest/basket/:id`, `PATCH /rest/products/reviews` |
| **Status** | ✅ Remediated & Verified (Closed) |

---

## Lab Documentation

This module covers both Read and Write IDOR vectors across three sequential reports:

1. **[01-idor-vulnerability-assessment.md](./01-idor-vulnerability-assessment.md)**  
   Technical breakdown, reproduction steps, and Burp Suite proof-of-concept captures for Basket Read IDOR and Review Write IDOR.

2. **[02-prevention-idor-hardening.md](./02-prevention-idor-hardening.md)**  
   Server-side remediation: adding object-level ownership checks to `routes/basket.ts` and author validation to `routes/updateProductReviews.ts`, plus `ACCESS_DENIED_IDOR` audit logging.

3. **[03-retest-results.md](./03-retest-results.md)**  
   Retest verification confirming unauthorized access and modification attempts receive `HTTP 403 Forbidden` while legitimate user operations continue to work.

---

## Attack Vectors Tested

| Vector | Operation | Target Endpoint | Impact | Root Cause & Remediation |
| :--- | :---: | :--- | :--- | :--- |
| **Vector 1: Basket IDOR** | Read | `GET /rest/basket/:id` | Viewing other users' private carts and itemized pricing | Direct URL parameter lookup; fixed by validating `user.bid === requestedId` |
| **Vector 2: Review IDOR** | Write | `PATCH /rest/products/reviews` | Overwriting or defacing reviews authored by other users | Document query updated by ID only; fixed by checking `review.author === user.data.email` |

---

## Patches & Evidence

* **`patches/`** – Drop-in patched source files:
  * [`basket.ts`](./patches/basket.ts) – Object ownership check & telemetry for basket reads.
  * [`updateProductReviews.ts`](./patches/updateProductReviews.ts) – Author verification for review edits.
* **`evidence/`** – Burp Repeater captures of pre-patch data leaks, review defacement, 403 responses, and server telemetry.

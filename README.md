# WebApp-Sec-Lab

A hands-on Application Security lab focused on identifying, exploiting, remediating, and validating common web application vulnerabilities in a controlled environment.

This repository documents the complete security assessment workflow, including vulnerability discovery, proof-of-concept exploitation, root cause analysis, remediation, and post-fix validation.

## Objectives

* Practice real-world Application Security testing methodologies.
* Reproduce vulnerabilities from the OWASP Top 10.
* Develop and implement secure remediation strategies.
* Validate fixes through security testing and evidence collection.
* Document findings in a professional penetration testing format.

## Vulnerability Modules

### Broken Authentication

Assessment of JWT-based authentication mechanisms, including token replay attacks, insecure session management, and implementation of server-side token revocation controls.

**Key Activities**

* Authentication flow analysis
* JWT token inspection and replay testing
* Security logging implementation
* Token revocation mechanism development
* Remediation validation

---

### Cross-Site Scripting (XSS)

Assessment of user-controlled input handling and output rendering across multiple contexts (DOM, Reflected, and Stored XSS) to identify and remediate client-side injection flaws.

**Key Activities**

* Multi-context payload development and validation
* Vulnerability impact assessment across client DOM and administrative interfaces
* Root cause analysis of sanitizer bypasses
* Secure Angular template interpolation & sanitization implementation
* Post-remediation verification

---

### Insecure Direct Object References (IDOR / BOLA)

Assessment of object-level authorization across RESTful endpoints and document datastores, covering unauthorized data exposure (Read IDOR) and unauthorized content defacement (Write IDOR).

**Key Activities**

* Direct object identifier manipulation in route paths and request bodies
* Confidential cart data extraction & review defacement PoC execution
* Root cause analysis across relational and document datastore tiers
* Server-side object-level access control (BOLA) and author verification implementation
* Security audit telemetry instrumentation (`ACCESS_DENIED_IDOR`)
* Post-remediation verification confirming HTTP 403 Forbidden enforcement

---

## Methodology

Each module follows a consistent security assessment workflow:

1. Vulnerability Identification
2. Exploitation & Validation
3. Root Cause Analysis
4. Remediation & Patching
5. Security Verification & Retesting
6. Documentation & Reporting

## Repository Structure

```text
webapp-sec-lab/
├── broken-authentication/
│   ├── 01-broken-authentication-report.md
│   ├── 02-detection-observability-logging.md
│   ├── 03-prevention-token-revocation.md
│   ├── 04-retest-results.md
│   ├── evidence/
│   └── patches/
│
├── XSS/
│   ├── 01-xss-vulnerability-assessment.md
│   ├── 02-prevention-xss-hardening.md
│   ├── 03-retest-results.md
│   ├── evidence/
│   └── patches/
│
└── IDOR/
    ├── 01-idor-vulnerability-assessment.md
    ├── 02-prevention-idor-hardening.md
    ├── 03-retest-results.md
    ├── evidence/
    └── patches/
```

## Tools & Technologies

* OWASP Juice Shop
* Burp Suite Community
* curl
* Node.js / npm
* TypeScript / JavaScript
* Angular
* JWT
* Git

## Skills Demonstrated

* Application Security Testing
* Vulnerability Assessment
* Authentication Security
* Cross-Site Scripting Analysis
* Broken Access Control & IDOR Analysis
* Object-Level Authorization Engineering
* Secure Coding Practices
* Security Remediation & Hardening
* Penetration Testing
* Root Cause Analysis
* Technical Reporting & Documentation

## Disclaimer

This project was conducted in a controlled laboratory environment using intentionally vulnerable applications for educational and security research purposes.

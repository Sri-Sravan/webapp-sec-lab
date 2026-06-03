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

### Stored Cross-Site Scripting (XSS)

Assessment of user-controlled input handling and output rendering to identify and remediate stored XSS vulnerabilities.

**Key Activities**

* Payload development and validation
* Vulnerability impact assessment
* Root cause analysis
* Secure output rendering implementation
* Post-remediation verification

## Methodology

Each module follows a consistent security assessment workflow:

1. Vulnerability Identification
2. Exploitation & Validation
3. Root Cause Analysis
4. Remediation
5. Security Verification
6. Documentation & Reporting

## Repository Structure

```text
webapp-sec-lab/
├── broken-authentication/
│   ├── report/
│   ├── evidence/
│   └── patch/
│
└── stored-xss/
    ├── report/
    ├── evidence/
    └── patch/
```

## Tools & Technologies

* OWASP Juice Shop
* Burp Suite
* curl
* Node.js / npm
* JavaScript
* JWT
* Git

## Skills Demonstrated

* Application Security Testing
* Vulnerability Assessment
* Authentication Security
* Cross-Site Scripting Analysis
* Secure Coding Practices
* Security Remediation
* Penetration Testing
* Root Cause Analysis
* Technical Reporting

## Disclaimer

This project was conducted in a controlled laboratory environment using intentionally vulnerable applications for educational and security research purposes.

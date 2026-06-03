# Broken Authentication – Session Reuse After Logout

## Overview

This case study documents the discovery, analysis, monitoring, remediation, and validation of a Broken Authentication vulnerability in OWASP Juice Shop.

The identified issue allowed a previously issued JWT authentication token to remain valid after user logout. Because the application did not perform server-side session invalidation, a captured token could be replayed to access protected resources even after the user had ended their session.

In addition to the session management weakness, the application lacked authentication lifecycle visibility, making login, logout, and token abuse difficult to detect.

---

## Objectives

The goals of this exercise were to:

- Identify and validate the authentication flaw
- Understand the root cause of session persistence
- Improve authentication observability
- Implement server-side token revocation
- Retest the application to confirm remediation
- Document the complete vulnerability lifecycle

---

## Vulnerability Summary

| Attribute | Value |
|------------|--------|
| Category | Broken Authentication |
| OWASP | A7:2021 / A7:2025 |
| CWE | CWE-287 – Improper Authentication |
| Severity | High |
| Impact | Session reuse after logout |
| Detection Capability (Initial) | None |

---

## Attack Scenario

1. User authenticates successfully.
2. JWT token is issued by the application.
3. Token is captured from browser storage.
4. User logs out.
5. Captured token is replayed against a protected endpoint.
6. Application continues to accept the token.

Result:

- Session remains active.
- Logout does not invalidate the token.
- Unauthorized access remains possible.

---

## Security Improvements Implemented

### Authentication Observability

The following events were instrumented for monitoring:

- LOGIN_SUCCESS
- TOKEN_USED
- LOGOUT
- TOKEN_REJECTED

This provides visibility into the complete authentication lifecycle.

### Server-Side Logout

A dedicated logout endpoint was implemented to:

- Clear authentication cookies
- Revoke active tokens
- Generate logout audit logs

### Token Revocation

A token revocation mechanism was introduced to:

- Invalidate tokens upon logout
- Reject replayed tokens
- Prevent post-logout session reuse

---

## Validation Results

After implementing the remediation:

| Test | Result |
|---------|---------|
| Login | Successful |
| Protected Endpoint Access | Successful |
| Logout | Successful |
| Token Replay After Logout | Blocked |
| Rejected Token Logged | Yes |

Observed log sequence:

```text
LOGIN_SUCCESS
TOKEN_USED
LOGOUT
TOKEN_REJECTED

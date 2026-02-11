# Broken Authentication – Session Reuse After Logout

## Severity: High

**OWASP Classification**

- A7:2021 / A7:2025 – Broken Authentication
    
- A9:2021 / A9:2025 – Observability Failures
    

**CWE**

- CWE-287 – Improper Authentication
    

---

## 1. Executive Summary

During testing of the default OWASP Juice Shop deployment, it was identified that authentication tokens remain valid after user logout. The application does not invalidate sessions server-side, allowing previously issued tokens to be reused to access protected endpoints.

Additionally, the application provides no authentication lifecycle logging, making detection of such abuse difficult.

This results in:

- Improper session invalidation
    
- Session reuse vulnerability
    
- Lack of authentication observability
    

---

## 2. Application Context

**Authentication Endpoint**

```
POST /rest/user/login
```

**Session Mechanism**

- JWT-based token
    
- Delivered in response body
    
- Stored in browser cookies
    
- Used for subsequent authenticated requests
    

**Logout Behavior**

- Client-side only
    
- No server-side session invalidation
    
- No logout logging observed
    

---

## 3. Technical Description

### 3.1 Login Flow

When valid credentials are submitted to:

```
POST /rest/user/login
```

The server responds with:

```json
{
  "authentication": {
    "token": "<JWT>",
    "bid": 6,
    "umail": "admin@pentest.com"
  }
}
```

If credentials are invalid:

- No token is issued
    
- A simple authentication error is returned
    

#### Evidence – Invalid Login Attempt

Invalid credentials did not result in token issuance.

![[evidence/response_login_with_invalid_creds.png]]

---

#### Evidence – Successful Registration

User registration request and server response confirming account creation.

![[evidence/Registration_successful.png]]

---

### 3.2 Token Storage Behavior

After successful authentication, the JWT token is stored in the browser cookies.

#### Evidence – Token Stored in Browser Cookie

Authentication token visible in browser developer tools under Cookies.

![[evidence/Auth_token_stored_inside_cookie.png]]

This confirms that the token is accessible client-side and may be extracted if compromised.

---

### 3.3 Token Structure Observed

Example token (redacted for brevity):

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
```

Decoded payload included:

- user ID
    
- email
    
- role
    
- timestamps

The token was signed using RS256.

---
## 4. Vulnerability: Token Reuse After Logout

### Observed Behavior

1. Login with valid credentials
    
2. Capture authentication token
    
3. Access protected endpoint:
    
    ```
    GET /rest/user/whoami
    ```
    
4. Click logout in browser
    
5. Replay:
    
    ```
    GET /rest/user/whoami
    ```
    
    using the previously captured token
    

### Result

The request succeeds.

The token remains valid even after logout.

---

### Evidence – Successful Token Reuse After Logout

Previously issued token replayed via Burp Repeater after logout.  
Server response confirms session remained valid.

![[evidence/unpatched_request_using_jwt_token_after_logout.png]]

This demonstrates that logout does not invalidate the session server-side.

---

## 5. Root Cause

The application:

- Issues JWT tokens at login
    
- Stores authenticated users in memory
    
- Does not invalidate tokens on logout
    
- Does not maintain a token revocation mechanism
    
- Does not enforce server-side session destruction

Logout only removes the token from the browser but does not invalidate it server-side.

This creates a **session persistence flaw**.

---
## 6. Impact Analysis

### Security Impact

An attacker who:

- captures a token via XSS,
    
- intercepts it via network compromise,
    
- extracts it from browser storage,
    

can reuse the token even after the legitimate user logs out.

This enables:

- Unauthorized access
    
- Account impersonation
    
- Persistent session abuse

---
### Detection Impact

Baseline observability showed:

- No login success logging
    
- No logout logging
    
- No token usage logging
    
- No session lifecycle tracking


#### Evidence – Unpatched Server Logs

Server logs during exploitation phase showed no authentication lifecycle visibility.

![[evidence/unpatched_server_logs.png]]

This significantly increases detection difficulty and prevents forensic reconstruction.

---

## 7. Risk Rating Justification

|Factor|Evaluation|
|---|---|
|Attack Complexity|Low|
|Authentication Required|Yes (initial login)|
|Privilege Escalation|Possible depending on user|
|Persistence|Yes|
|Detection Difficulty|High (no logging)|

Overall Severity: **High**

---

## 8. Recommended Remediation

1. Implement server-side token revocation
    
2. Invalidate tokens during logout
    
3. Enforce revocation checks during authentication middleware
    
4. Implement authentication lifecycle logging:
    
    - LOGIN_SUCCESS
        
    - LOGOUT
        
    - TOKEN_USED
        
    - TOKEN_REJECTED 

---

## 9. Vulnerability Status (Pre-Hardening)

|Control|Status|
|---|---|
|Token invalidation|❌ Not implemented|
|Logout enforcement|❌ Client-side only|
|Token reuse prevention|❌ Not enforced|
|Authentication logging|❌ Not implemented|

**Status: Vulnerable**

---


# Authentication Observability Improvements: Token Usage and Login and Logout Logging

## 1. Introduction

This document describes the **observability enhancements** introduced into the authentication flow of OWASP Juice Shop during security testing.  
The focus of this phase was **detection and visibility**, not prevention.

The goal was to ensure that:

- authentication events are logged,
    
- authentication token usage is observable, and
    
- logout actions are visible to the backend.
    

At this stage, authentication weaknesses were intentionally **not fixed**, in order to first establish reliable evidence of insecure behavior.

---

## 2. Initial Problem Statement

During baseline testing, the following issues were observed:

- Successful logins produced no audit logs
    
- Authentication token usage was invisible to the server
    
- Logout was performed client-side only
    
- Token reuse after logout could not be proven via logs
    

From a security monitoring (SOC) perspective, this resulted in a complete lack of session lifecycle visibility.

---
## 3. Login Event Logging

### 3.1 Identification of Login Logic

Authentication logic was identified in the following file:

```
routes/login.ts
```

This file:

- validates credentials
    
- issues authentication tokens
    
- establishes authenticated sessions

---
### 3.2 Code Change Introduced

A log entry was added **after successful authentication**, once the user identity and token were confirmed.

#### File Modified

```
routes/login.ts
```

#### Code Added

```ts
import logger from '../lib/logger'
```

Inside the `afterLogin()` function:

```ts
logger.info(
  `LOGIN_SUCCESS userId=${user.data.id} email=${user.data.email} ip=${req.ip}`
)
```

---
### 3.3 Result

Each successful authentication now produces a clear audit log:

```
LOGIN_SUCCESS userId=23 email=admin@pentest.com ip=192.168.122.1
```

This ensures that authentication events are no longer silent.

---

## 4. Token Usage Logging

### 4.1 Root Cause Analysis

Initial attempts to log token usage at the route level failed because:

- `/rest/user/whoami` is handled through middleware
    
- Token validation occurs before route handlers
    
- Logging must occur at the authentication middleware layer
    

The correct location was identified as:

```
lib/insecurity.ts
```

Specifically, the middleware:

```ts
updateAuthenticatedUsers()
```

---

### 4.2 Code Change Introduced

#### File Modified

```
lib/insecurity.ts
```

#### Import Added

```ts
import logger from './logger'
```

#### Modified Function

Original logic validated tokens silently.  
Logging was added **only when token verification succeeds**.

```ts
export const updateAuthenticatedUsers = () => (req, res, next) => {
  const token = req.cookies.token || utils.jwtFrom(req)

  if (token) {
    jwt.verify(token, publicKey, (err, decoded) => {
      if (err === null) {

        logger.info(
          `TOKEN_USED userId=${decoded?.data?.id} ip=${req.ip} endpoint=${req.originalUrl}`
        )

        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          res.cookie('token', token)
        }
      }
    })
  }
  next()
}
```

---

### 4.3 Result

Every valid authentication token usage is now logged, including repeated usage and reuse after logout.

Example log:

```
TOKEN_USED userId=23 ip=192.168.122.1 endpoint=/rest/user/whoami
```

---

## 5. Server-Side Logout Logging

### 5.1 Baseline Logout Behavior

The default Juice Shop UI logout:
9. Conclusion

This phase demonstrates that authentication vulnerabilities are often dangerous not only because they exist, but because they remain undetected

By introducing targeted logging and explicit logout handling, authentication behavior became observable, measurable, and auditable—laying the foundation for effective remediation in the next phase.

- Deletes the authentication cookie client-side
- Does not notify the backend
- Produces no audit logs

This made logout events invisible to the server.

---

### 5.2 Backend Logout Endpoint

To introduce logout observability, a dedicated endpoint was added.

#### File Modified

```
server.ts
```

#### Location

Inside the **Custom Restful API** section, alongside other `/rest/user/*` routes.

---

### 5.3 Code Added

```ts
app.post('/rest/user/logout', (req, res) => {
  const token = req.cookies.token || utils.jwtFrom(req)

  if (token) {
    const user = security.authenticatedUsers.get(token)

    if (user) {
      logger.info(
        `LOGOUT userId=${user.data.id} ip=${req.ip}`
      )
    }

    // Observability-only removal (no rejection yet)
    delete security.authenticatedUsers.tokenMap[token]
  }

  res.clearCookie('token')
  res.status(200).json({ status: 'logged_out' })
})
```

---

### 5.4 Logout Behavior Note

The Juice Shop frontend **does not call this endpoint** by default.

As a result:

- logout logs are generated only when this endpoint is invoked directly (e.g., via curl or Burp)e
- this behavior reflects the original application design and was intentionally preserved

**Logging out using curl :**

![[evidence/manual_logout_using_jwt_token_and_curl.png]]

---

## 6. Observability Outcome

After implementing these changes, the following events became fully observable:

|Event|Logged|
|---|---|
|Successful login|✅|
|Token usage|✅|
|Logout|✅|
|Token reuse after logout|✅|

A complete session lifecycle can now be reconstructed:

```
LOGIN_SUCCESS
TOKEN_USED
LOGOUT
TOKEN_USED   ← reuse after logout
```


## Evidence of Server logs after Detection Patch

![[evidence/detection_patched_server_logs.png]]

---

## 7. Security Impact

Although the vulnerability still exists at this stage, these changes:

- Elimination of silent authentication abuse
    
- Authentication lifecycle visibility
    
- Evidence generation for reporting
    
- SOC-level telemetry support

The improvements directly address **OWASP A9: Observability Failures**, in addition to Broken Authentication.

---

## 8. Status at End of Detection Phase

|Control|Status|
|---|---|
|Login logging|✅ Implemented|
|Token usage logging|✅ Implemented|
|Logout logging|✅ Implemented|
|Token reuse prevention|❌ Not enforced yet|
The system was now fully observable but still vulnerable.
   
---
## 9. Conclusion

This phase demonstrates that security improvements do not begin with blocking attackers—they begin with visibility.

By instrumenting authentication flows with structured logging, the application moved from silent failure to measurable behavior. This observability layer provided the foundation necessary to implement proper prevention controls in the next phase.

---

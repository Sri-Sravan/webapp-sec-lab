# Token Revocation Enforcement and Retest Results

## 1. Introduction

This document describes the **prevention phase** of a Broken Authentication vulnerability identified in OWASP Juice Shop.  
Following earlier observability improvements, this phase focuses on **enforcing server-side session invalidation** and validating that authentication tokens cannot be reused after logout.

The intent of this phase was to:

- Properly revoke authentication tokens on logout,
- Block reuse of revoked tokens,
- Retain security logging for detection, and
- Confirm vulnerability closure via retesting.
---
## 2. Vulnerability Recap

Earlier testing demonstrated that:

- Authentication tokens remained valid after logout
- Logout was client-side only
- Reused tokens continued to grant access
- Token reuse could be proven through logs

This behavior constituted **Broken Authentication** due to improper session invalidation.

---
## 3. Prevention Design Decision

### Chosen Approach

A **simple in-memory token revocation mechanism** was implemented for

- Minimal and localized code changes
- Avoids unnecessary complexity (databases, token blacklists with expiry sync)

This approach enforces correct security behavior while keeping the implementation clear and auditable.

---
## 4. Implementation Details

All changes were limited to **two backend files** to maintain clarity and separation of concerns.

---
### 4.1 Token Revocation Store

#### File Modified

```
lib/insecurity.ts
```

#### Location in File

Added **near the top of the file**, after imports and before exported utility functions.

#### Code Added

```ts
const revokedTokens = new Set<string>()
```

This set maintains a list of authentication tokens that have been explicitly revoked during logout.

---

### 4.2 Token Revocation Helper

#### File Modified

```
lib/insecurity.ts
```

#### Location in File

Added **immediately after the `authenticatedUsers` object definition**.

#### Code Added

```ts
export const revokeToken = (token: string) => {
  revokedTokens.add(utils.unquote(token))
}
```

This helper function provides a controlled way for other modules (e.g., logout logic) to revoke tokens without accessing internal data structures directly.

---
### 4.3 Enforcing Token Revocation During Authentication

#### File Modified

```
lib/insecurity.ts
```

#### Function Modified

```
updateAuthenticatedUsers()
```

This middleware executes on protected endpoints (e.g., `/rest/user/whoami`) and is responsible for validating authentication tokens.

---

#### Location in Function

The revocation check was added **immediately after extracting the token** and **before JWT verification**.

#### Final Function (Relevant Section)

```ts
export const updateAuthenticatedUsers = () => (req, res, next) => {
  const token = req.cookies.token || utils.jwtFrom(req)

  if (token) {
    const cleanToken = utils.unquote(token)

    // Enforce token revocation
    if (revokedTokens.has(cleanToken)) {
      logger.warn(
        `TOKEN_REJECTED revoked token ip=${req.ip} endpoint=${req.originalUrl}`
      )
      return res.status(401).json({ error: 'Session expired' })
    }

    jwt.verify(cleanToken, publicKey, (err, decoded) => {
      if (err === null) {

        logger.info(
          `TOKEN_USED userId=${decoded?.data?.id} ip=${req.ip} endpoint=${req.originalUrl}`
        )

        if (authenticatedUsers.get(cleanToken) === undefined) {
          authenticatedUsers.put(cleanToken, decoded)
          res.cookie('token', cleanToken)
        }
      }
    })
  }

  next()
}
```

This ensures that any revoked token is rejected **before** further authentication processing occurs.

---

### 4.4 Revoking Tokens on Logout

#### File Modified

```
server.ts
```

#### Location in File

Inside the **“Custom Restful API”** section, alongside other `/rest/user/*` endpoints.

---

#### Logout Endpoint Logic

The logout endpoint was updated to explicitly revoke tokens server-side.

#### Relevant Code

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

    // Revoke token and remove active session
    security.revokeToken(token)
    delete security.authenticatedUsers.tokenMap[token]
  }

  res.clearCookie('token')
  res.status(200).json({ status: 'logged_out' })
})
```

As a result:

- logout invalidates the token server-side,
    
- revoked tokens are tracked centrally,
    
- logout events are logged for auditing.


---
## 5. Results

### HTTP Response

```
Session Expired
```

### Server Logs

```
LOGIN_SUCCESS userId=23 ...
TOKEN_USED userId=23 ...
LOGOUT userId=23 ...
TOKEN_REJECTED revoked token ip=... endpoint=/rest/user/whoami
```

This confirms that:

- token reuse after logout is blocked,
    
- enforcement occurs server-side,
    
- rejected attempts are logged.

## Evidence of Prevention Patched Server Logs 

![[evidence/prevention_patched_server_logs.png]]

---

## 6. Final Security Outcome

After implementing token revocation:

|Aspect|Result|
|---|---|
|Server-side logout|Enforced|
|Token reuse after logout|Blocked|
|Rejected attempts|Logged|
|Observability|Preserved|

**Vulnerability Status: CLOSED**

---

## 7. Conclusion

This phase completes the remediation of the Broken Authentication issue by enforcing proper session invalidation.

By introducing a token revocation mechanism and validating the fix through retesting, the application now correctly prevents reuse-after-logout attacks while maintaining clear security visibility.

This concludes the full vulnerability lifecycle:

> identify → observe → remediate → verify.

---

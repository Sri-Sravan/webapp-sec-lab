# Insecure Direct Object References (IDOR) – Prevention & Hardening

## 1. Remediation Strategy

To fix the IDOR vulnerabilities found in `routes/basket.ts` and `routes/updateProductReviews.ts`, I implemented server-side ownership validation and security logging based on the following rules:

1. **Verify Ownership Server-Side:** Never trust IDs supplied in the URL path or request body. Compare them against the authenticated user's session token (`user.bid` or `user.data.email`).
2. **Preserve Admin Rights:** Allow administrative accounts (`security.roles.admin`) to view baskets and manage reviews for operational support.
3. **Fail with HTTP 403:** Return an explicit `403 Forbidden` on mismatched ownership rather than silently failing or leaking data.
4. **Log Access Violations:** Emit structured `ACCESS_DENIED_IDOR` warnings with the user ID, attempted ID, and IP address for incident detection.

---

## 2. Vector 1: Shopping Basket Authorization (`routes/basket.ts`)

### Patch Location
`routes/basket.ts`

### Code Changes

#### Imports Added
```typescript
import logger from '../lib/logger'
```

#### Before
```typescript
export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = req.params.id
      const basket = await BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      
      challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
        const user = security.authenticatedUsers.from(req)
        return user && id && id !== 'undefined' && id !== 'null' && id !== 'NaN' && user.bid && user?.bid != parseInt(id, 10)
      })
      if (((basket?.Products) != null) && basket.Products.length > 0) {
        for (let i = 0; i < basket.Products.length; i++) {
          basket.Products[i].name = req.__(basket.Products[i].name)
        }
      }

      res.json(utils.queryResultToJson(basket))
    } catch (error) {
      next(error)
    }
  }
}
```

#### After
```typescript
export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = req.params.id

      // IDOR Defense: Object-level authorization check
      const user = security.authenticatedUsers.from(req)
      const requestedId = parseInt(id, 10)

      if (!user) {
        return res.status(401).json({ status: 'error', error: 'Authentication required.' })
      }

      const isOwner = user.bid && Number(user.bid) === requestedId
      const isAdmin = user.data && user.data.role === security.roles.admin

      if (!isOwner && !isAdmin) {
        logger.warn(
          `ACCESS_DENIED_IDOR userId=${user.data?.id} attemptedBasketId=${id} actualBasketId=${user.bid} ip=${req.ip}`
        )
        return res.status(403).json({ status: 'error', error: 'Access denied: You do not have permission to access this basket.' })
      }

      const basket = await BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      /* jshint eqeqeq:false */
      challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
        return user && id && id !== 'undefined' && id !== 'null' && id !== 'NaN' && user.bid && user?.bid != parseInt(id, 10) // eslint-disable-line eqeqeq
      })
      if (((basket?.Products) != null) && basket.Products.length > 0) {
        for (let i = 0; i < basket.Products.length; i++) {
          basket.Products[i].name = req.__(basket.Products[i].name)
        }
      }

      res.json(utils.queryResultToJson(basket))
    } catch (error) {
      next(error)
    }
  }
}
```

### Explanation of Changes
- Before executing the database lookup, the code verifies that `Number(user.bid) === requestedId`.
- If the user does not own the basket and is not an admin, execution stops immediately, an audit log is emitted, and `HTTP 403 Forbidden` is returned.

---

## 3. Vector 2: Product Review Author Validation (`routes/updateProductReviews.ts`)

### Patch Location
`routes/updateProductReviews.ts`

### Code Changes

#### Imports Added
```typescript
import logger from '../lib/logger'
```

#### Before
```typescript
export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    db.reviewsCollection.update(
      { _id: req.body.id },
      { $set: { message: req.body.message } },
      { multi: true }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 })
        challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 })
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
```

#### After
```typescript
export function updateProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)

    if (!user || !user.data) {
      return res.status(401).json({ status: 'error', error: 'Authentication required.' })
    }

    try {
      // IDOR Defense: Verify review existence and author ownership
      const review = await db.reviewsCollection.findOne({ _id: req.body.id })
      if (!review) {
        return res.status(404).json({ status: 'error', error: 'Review not found.' })
      }

      const isAuthor = review.author === user.data.email
      const isAdmin = user.data.role === security.roles.admin

      if (!isAuthor && !isAdmin) {
        logger.warn(
          `ACCESS_DENIED_IDOR userId=${user.data.id} attemptedReviewId=${req.body.id} reviewAuthor=${review.author} ip=${req.ip}`
        )
        return res.status(403).json({ status: 'error', error: 'Access denied: You are not authorized to edit this review.' })
      }

      const result = await db.reviewsCollection.update(
        { _id: req.body.id },
        { $set: { message: req.body.message } },
        { multi: false }
      )
      res.json(result)
    } catch (err: unknown) {
      res.status(500).json(err)
    }
  }
}
```

### Explanation of Changes
- Rather than blindly updating by ID, the handler first retrieves the target review using `db.reviewsCollection.findOne({ _id: req.body.id })`.
- It checks that `review.author === user.data.email`.
- If the requester is not the author and not an admin, it emits an audit log and returns `HTTP 403 Forbidden`.

---

## 4. Security Telemetry & Observability

Both patches add structured warning logs using `lib/logger.ts`:

```text
warn: ACCESS_DENIED_IDOR userId=26 attemptedBasketId=6 actualBasketId=7 ip=::ffff:127.0.0.1
warn: ACCESS_DENIED_IDOR userId=26 attemptedReviewId=ujYWsSgZQqxFQ3uLJ reviewAuthor=victim@pentest.com ip=::ffff:127.0.0.1
```

This ensures SOC analysts and SIEM rules can detect automated IDOR enumeration in real time by alerting on repeated `ACCESS_DENIED_IDOR` events from a single IP or user ID.

---

## 5. Security Outcome

| Target Component | Control Implemented | Pre-Patch State | Post-Patch State |
| :--- | :--- | :---: | :---: |
| `GET /rest/basket/:id` | Object-level authorization | ❌ Allowed unauthorized reads | ✅ Enforced (HTTP 403 Forbidden) |
| `PATCH /rest/products/reviews` | Author identity verification | ❌ Allowed unauthorized writes | ✅ Enforced (HTTP 403 Forbidden) |
| Admin Access | Role-based override | ❌ Absent | ✅ Preserved for admin role |
| Audit Telemetry | Security violation logging | ❌ None (Silent failure) | ✅ Implemented (`ACCESS_DENIED_IDOR`) |

---

## 6. Secure Development Takeaways

- **Authentication != Authorization:** Just because a user is logged in does not mean they should be able to access every record in the database.
- **Bind to the Session:** Always validate incoming IDs against the authenticated session context (`req.user`) instead of trusting parameters sent by the client.
- **Fail Early and Explicitly:** Return `HTTP 403 Forbidden` as soon as an ownership check fails, and record the violation for security monitoring.

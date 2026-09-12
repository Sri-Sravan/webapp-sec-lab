/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'
import logger from '../lib/logger'

export function updateProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)

    if (!user || !user.data) {
      return res.status(401).json({ status: 'error', error: 'Authentication required.' })
    }

    try {
      // Custom IDOR Defense: Verify review existence and author ownership
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

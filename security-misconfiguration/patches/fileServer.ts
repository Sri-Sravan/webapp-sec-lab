/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

export function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file || typeof file !== 'string') {
      return res.status(400).json({ status: 'error', message: 'Invalid file parameter.' })
    }

    // Defensive Check: Prohibit path separators, parent directory traversal, and poison null-byte sequences
    if (file.includes('/') || file.includes('\\') || file.includes('..') || file.includes('%00') || file.includes('\0')) {
      return res.status(403).json({ status: 'error', message: 'Prohibited characters detected in file path.' })
    }

    verify(file, res, next)
  }

  function verify (file: string, res: Response, next: NextFunction) {
    const sanitizedFile = path.basename(file)

    // Strictly enforce allowlisted extensions (.md and .pdf)
    if (sanitizedFile && (endsWithAllowlistedFileType(sanitizedFile) || sanitizedFile === 'incident-support.kdbx')) {
      // Disallow backup and configuration files even if spoofed
      if (sanitizedFile.endsWith('.bak') || sanitizedFile.endsWith('.yml') || sanitizedFile.endsWith('.pyc') || sanitizedFile.endsWith('.gg')) {
        return res.status(403).json({ status: 'error', message: 'Access to backup or configuration files is forbidden.' })
      }

      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return sanitizedFile.toLowerCase() === 'acquisitions.md' })

      const safePath = path.resolve('ftp/', sanitizedFile)
      // Path traversal containment check
      if (!safePath.startsWith(path.resolve('ftp/'))) {
        return res.status(403).json({ status: 'error', message: 'Access forbidden.' })
      }

      res.sendFile(safePath)
    } else {
      res.status(403).json({ status: 'error', message: 'Only .md and .pdf files are allowed!' })
    }
  }

  function endsWithAllowlistedFileType (param: string) {
    return param.endsWith('.md') || param.endsWith('.pdf')
  }
}

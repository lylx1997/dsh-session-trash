import { randomUUID } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { OBJECT_NAME_PATTERN, indexAttachments } from './attachment-store.js'
import { TrashError } from './errors.js'
import { createTrashId, isInside, samePath } from './fsops.js'
import { memberList } from './members.js'

/** Attachment objects younger than this are never candidates. */
export const ATTACHMENT_GRACE_MS = 24 * 86_400_000

/** A preview plan is usable for this long, without any artificial wait. */
export const PLAN_TTL_MS = 15 * 60_000

/** Candidate hashes handled between two log-fingerprint checks. */
export const RECLAIM_BATCH_SIZE = 50

/** Exact confirmation phrase required by the Host API. */
export const RECLAIM_CONFIRMATION = 'delete-unreferenced-attachments'

/** A single hash with more aliases than this is treated as suspicious. */
const MAX_ALIASES = 1000

/**
 * @param {unknown} error arbitrary failure.
 * @returns {string} a user-facing message.
 */
function messageOf(error) {
  return error instanceof Error ? error.message : String(error)
}

/**
 * @param {string} alias relative alias below `<DSH_HOME>/attachments/v1`.
 * @returns {'objects' | 'fileObjects' | 'files' | 'requestImages' | 'unknown'} the owning store label.
 */
function storeOfAlias(alias) {
  const top = alias.split('/')[0]
  if (top === 'objects') return 'objects'
  if (top === 'file-objects') return 'fileObjects'
  if (top === 'files') return 'files'
  if (top === 'request-images') return 'requestImages'
  return 'unknown'
}

/**
 * @param {any} scan reference-scan result.
 * @returns {{ status: string, at: number, scannedFiles: number, failedFiles: number, failedDirs: number, tornFiles: number }} the wire-safe scan summary.
 */
function scanSummary(scan) {
  return {
    status: scan?.status,
    at: scan?.at,
    scannedFiles: scan?.scannedFiles ?? 0,
    failedFiles: scan?.failedFiles ?? 0,
    failedDirs: scan?.failedDirs ?? 0,
    tornFiles: scan?.tornFiles ?? 0,
  }
}

/**
 * @param {any} plan stored plan.
 * @returns {object} the wire-safe plan summary.
 */
function planSummary(plan) {
  return {
    id: plan.id,
    createdAt: plan.createdAt,
    expiresAt: plan.expiresAt,
    totals: plan.totals,
    byStore: plan.byStore,
    scan: plan.scan,
  }
}

/**
 * @param {any} candidate plan candidate.
 * @returns {boolean} whether the candidate has the minimum safe shape.
 */
function validCandidate(candidate) {
  return (
    candidate !== null &&
    typeof candidate === 'object' &&
    typeof candidate.hash === 'string' &&
    OBJECT_NAME_PATTERN.test(candidate.hash) &&
    typeof candidate.bytes === 'number' &&
    Number.isFinite(candidate.bytes) &&
    candidate.bytes >= 0 &&
    typeof candidate.mtimeMs === 'number' &&
    Number.isFinite(candidate.mtimeMs)
  )
}

/**
 * Build and execute a read-only-planned attachment reclaim. Preview never
 * deletes; execute revalidates every gate and removes only the plan's
 * unreferenced objects.
 *
 * @param {{
 *   ctx: import('@deepseek-ai/cordis').Context,
 *   store: import('./store.js').TrashStore,
 *   trashService?: { recover: () => Promise<any> },
 *   references: {
 *     scan: (options?: { force?: boolean }) => Promise<any>,
 *     fingerprint?: () => Promise<string | null>,
 *   },
 *   paths: { home: string, root: string, display?: string },
 *   logger: { warn: Function, info?: Function, debug?: Function },
 *   clock?: () => number,
 *   graceMs?: number,
 *   planTtlMs?: number,
 *   batchSize?: number,
 * }} deps host services, scanner, paths, and test-only policy overrides.
 * @returns {{ preview: () => Promise<object>, execute: (input: { planId: string, confirmation: string }) => Promise<object>, getPlan: () => Promise<object | null>, cancel: () => Promise<{ ok: true }> }} the reclaim surface.
 */
export function createReclaimService({
  ctx,
  store,
  trashService,
  references,
  paths,
  logger,
  clock = () => Date.now(),
  graceMs = ATTACHMENT_GRACE_MS,
  planTtlMs = PLAN_TTL_MS,
  batchSize = RECLAIM_BATCH_SIZE,
}) {
  const planDir = path.join(store.root, 'reclaim')
  const planPath = path.join(planDir, 'plan.json')
  const auditPath = path.join(planDir, 'reclaim-log.jsonl')

  /**
   * @param {string} reason stable eligibility reason.
   * @param {object} [extra] additional wire fields.
   * @returns {{ ok: true, eligible: false, reason: string }} a non-throwing preview outcome.
   */
  function unavailable(reason, extra = {}) {
    return { ok: true, eligible: false, reason, ...extra }
  }

  /**
   * @param {string} reason stable gate reason.
   * @param {object} [extra] additional internal fields.
   * @returns {{ ok: false, reason: string }} an internal gate failure.
   */
  function blocked(reason, extra = {}) {
    return { ok: false, reason, ...extra }
  }

  /**
   * Append one audit event. An unwritable audit log aborts before the first
   * deletion; execution never starts on an unrecorded run.
   *
   * @param {object} event JSON-serializable audit event.
   * @returns {Promise<void>} resolution after the line is durable enough to append.
   */
  async function appendAudit(event) {
    await fs.mkdir(planDir, { recursive: true, mode: 0o700 })
    await fs.appendFile(auditPath, `${JSON.stringify(event)}\n`, { mode: 0o600 })
  }

  /**
   * @param {any} plan candidate plan.
   * @returns {Promise<void>} resolution after the plan is durable.
   */
  async function writePlan(plan) {
    await fs.mkdir(planDir, { recursive: true, mode: 0o700 })
    const temporary = `${planPath}.${randomUUID()}.tmp`
    try {
      await fs.writeFile(temporary, `${JSON.stringify(plan, null, 2)}\n`, { mode: 0o600 })
      await fs.rename(temporary, planPath)
    } catch (error) {
      await fs.unlink(temporary).catch(() => {})
      throw new TrashError('IO_ERROR', `The reclaim plan could not be written: ${messageOf(error)}`)
    }
  }

  /**
   * @returns {Promise<void>} resolution after the plan file is gone.
   */
  async function removePlan() {
    await fs.unlink(planPath).catch((error) => {
      if (error !== null && error !== undefined && error.code === 'ENOENT') return
      logger.warn(`cannot remove the reclaim plan: ${messageOf(error)}`)
    })
  }

  /**
   * @returns {Promise<any | null>} a structurally valid plan, or null when absent/corrupt.
   */
  async function readPlan() {
    let document
    try {
      document = JSON.parse(await fs.readFile(planPath, 'utf8'))
    } catch {
      return null
    }
    if (
      document === null ||
      typeof document !== 'object' ||
      document.version !== 1 ||
      typeof document.id !== 'string' ||
      typeof document.createdAt !== 'number' ||
      typeof document.expiresAt !== 'number' ||
      document.scan === null ||
      typeof document.scan !== 'object' ||
      typeof document.scan.logFingerprint !== 'string' ||
      !Array.isArray(document.candidates) ||
      document.totals === null ||
      typeof document.totals !== 'object' ||
      typeof document.totals.hashes !== 'number' ||
      typeof document.totals.bytes !== 'number'
    ) {
      return null
    }
    for (const candidate of document.candidates) {
      if (!validCandidate(candidate)) return null
    }
    return document
  }

  /**
   * @param {readonly any[]} scanFiles scanned log metadata.
   * @param {readonly any[]} snapshots persistence snapshots.
   * @param {readonly any[]} entries trash entries.
   * @returns {Promise<boolean>} whether every expected session log was scanned.
   */
  async function rootsCovered(scanFiles, snapshots, entries) {
    const absolute = scanFiles.map((file) => path.resolve(file.path))
    const covered = (expected) => absolute.some((file) => samePath(file, expected))

    for (const snapshot of snapshots) {
      const expected = snapshot?.location?.path
      const id = snapshot?.header?.id
      if (typeof expected === 'string' && expected !== '') {
        if (!covered(path.resolve(expected))) return false
        continue
      }
      if (typeof id !== 'string' || id === '') return false
      const found = scanFiles.some((file) => path.basename(path.dirname(path.resolve(file.path))) === id)
      if (!found) return false
    }

    for (const entry of entries) {
      if (typeof entry?.trashId !== 'string' || entry.trashId === '') return false
      const members = memberList(entry)
      for (const [index, member] of members.entries()) {
        let directory
        try {
          directory = store.memberPath(entry.trashId, index, member.sessionId)
        } catch {
          return false
        }
        if (!scanFiles.some((file) => isInside(directory, path.resolve(file.path)))) return false
      }
    }
    return true
  }

  /**
   * Recompute every root and reference gate. Caller owns the trash lock.
   *
   * @returns {Promise<object>} `{ ok: true, scan, index, snapshots, entries }` or an unavailable reason.
   */
  async function collectSnapshot() {
    if (store.isProtected()) return blocked('INDEX_CORRUPT')
    const entries = store.entries()
    const missing = []
    for (const entry of entries) {
      if (entry?.state === 'missing') {
        missing.push({
          sessionId: entry.sessionId,
          title: typeof entry.title === 'string' ? entry.title : entry.sessionId,
        })
        continue
      }
      if (entry?.state !== 'trashed') return blocked('TRASH_BUSY')
    }
    if (missing.length > 0) return blocked('TRASH_HAS_MISSING', { missing })

    const persistence = ctx.sessionPersistence
    if (persistence === undefined || persistence === null || typeof persistence.flush !== 'function') {
      return blocked('SESSION_FLUSH_FAILED')
    }
    try {
      await persistence.flush()
    } catch (error) {
      return blocked('SESSION_FLUSH_FAILED', { message: messageOf(error) })
    }

    let scan
    try {
      scan = await references.scan({ force: true })
    } catch (error) {
      return blocked('SCAN_INCOMPLETE', { message: messageOf(error) })
    }
    if (scan?.status === 'unavailable') {
      return blocked('SCAN_UNAVAILABLE', { scan: scanSummary(scan) })
    }
    if (
      scan?.status !== 'complete' ||
      scan.failedFiles !== 0 ||
      scan.failedDirs !== 0 ||
      scan.tornFiles !== 0 ||
      typeof scan.fingerprint !== 'string' ||
      !Array.isArray(scan.files)
    ) {
      return blocked('SCAN_INCOMPLETE', { scan: scanSummary(scan) })
    }

    let index
    try {
      index = await indexAttachments(paths.home, { logger })
    } catch (error) {
      return blocked('ATTACHMENTS_INCOMPLETE', { message: messageOf(error) })
    }
    if (index.complete !== true) return blocked('ATTACHMENTS_INCOMPLETE')

    let snapshots
    try {
      snapshots = typeof persistence.list === 'function' ? await persistence.list() : []
    } catch (error) {
      return blocked('ROOTS_INCOMPLETE', { message: messageOf(error) })
    }
    if (!(await rootsCovered(scan.files, snapshots, entries))) {
      return blocked('ROOTS_INCOMPLETE')
    }
    return { ok: true, scan, index, snapshots, entries }
  }

  /**
   * @param {any} index current attachment index.
   * @param {any} scan current reference scan.
   * @param {any} candidate plan candidate.
   * @param {number} now current clock.
   * @returns {{ ok: true } | { ok: false, reason: string }} whether the candidate is still deletable.
   */
  function stillCandidate(index, scan, candidate, now) {
    if (!index.objects.has(candidate.hash)) return { ok: false, reason: 'missing' }
    if (scan.refs.has(candidate.hash)) return { ok: false, reason: 'referenced' }
    const mtimeMs = index.mtimes.get(candidate.hash)
    if (typeof mtimeMs !== 'number' || mtimeMs !== candidate.mtimeMs) return { ok: false, reason: 'changed' }
    if (now - mtimeMs < graceMs) return { ok: false, reason: 'too-young' }
    if (index.objects.get(candidate.hash) !== candidate.bytes) return { ok: false, reason: 'changed' }
    const aliases = index.aliases.get(candidate.hash)
    if (!Array.isArray(aliases) || aliases.length === 0) return { ok: false, reason: 'missing' }
    if (aliases.length > MAX_ALIASES) return { ok: false, reason: 'too-many-aliases' }
    return { ok: true }
  }

  /**
   * Delete one candidate's known aliases. The object is counted as freed only
   * when every alias is gone and at least one unlink actually removed a name.
   *
   * @param {any} index current attachment index.
   * @param {any} candidate plan candidate.
   * @returns {Promise<{ status: 'deleted' | 'skipped' | 'failed', bytes: number, reason?: string }>} outcome.
   */
  async function deleteCandidate(index, candidate) {
    const aliases = index.aliases.get(candidate.hash)
    if (!Array.isArray(aliases) || aliases.length === 0) {
      return { status: 'skipped', bytes: 0, reason: 'missing' }
    }
    if (aliases.length > MAX_ALIASES) {
      return { status: 'skipped', bytes: 0, reason: 'too-many-aliases' }
    }

    const resolved = []
    for (const alias of aliases) {
      if (typeof alias !== 'string' || alias === '') {
        return { status: 'skipped', bytes: 0, reason: 'unsafe-path' }
      }
      const target = path.resolve(index.root, alias)
      if (!isInside(index.root, target)) {
        return { status: 'skipped', bytes: 0, reason: 'unsafe-path' }
      }
      let stats
      try {
        stats = await fs.lstat(target)
      } catch (error) {
        if (error !== null && error !== undefined && error.code === 'ENOENT') {
          return { status: 'skipped', bytes: 0, reason: 'missing' }
        }
        return { status: 'failed', bytes: 0, reason: 'inspect-failed' }
      }
      if (!stats.isFile() || stats.size !== candidate.bytes) {
        return { status: 'skipped', bytes: 0, reason: 'changed' }
      }
      if (typeof stats.nlink !== 'number' || stats.nlink <= 0 || stats.nlink !== aliases.length) {
        return { status: 'skipped', bytes: 0, reason: 'linked-elsewhere' }
      }
      resolved.push(target)
    }

    // `file-objects` is the internal canonical name; DSH reads file
    // attachments through the `files/<hash>/<name>` alias. Remove the internal
    // name first and keep a display path readable as long as possible.
    const ordered = [...resolved].sort((left, right) => {
      const leftInternal = isInside(path.join(index.root, 'file-objects'), left) ? 0 : 1
      const rightInternal = isInside(path.join(index.root, 'file-objects'), right) ? 0 : 1
      return leftInternal - rightInternal
    })

    let removedAny = false
    for (const target of ordered) {
      try {
        await fs.unlink(target)
        removedAny = true
      } catch (error) {
        if (error !== null && error !== undefined && error.code === 'ENOENT') continue
        return { status: 'failed', bytes: 0, reason: 'unlink-failed' }
      }
    }

    const displayDir = path.join(index.root, 'files', candidate.hash.slice(0, 2), candidate.hash)
    await fs.rmdir(displayDir).catch((error) => {
      if (error !== null && error !== undefined && (error.code === 'ENOENT' || error.code === 'ENOTEMPTY')) return
      logger.warn(`cannot remove the empty attachment display directory ${displayDir}: ${messageOf(error)}`)
    })

    return removedAny
      ? { status: 'deleted', bytes: candidate.bytes }
      : { status: 'skipped', bytes: 0, reason: 'missing' }
  }

  /**
   * @returns {Promise<object>} a preview/plan result; expected eligibility failures are 200-level outcomes.
   */
  async function preview() {
    if (trashService !== undefined && typeof trashService.recover === 'function') {
      try {
        await trashService.recover()
      } catch (error) {
        return unavailable('TRASH_BUSY', { message: messageOf(error) })
      }
    }

    return store.withLock(async () => {
      // Preview always replaces the previous plan. A failed or ineligible
      // preview must not leave an older plan executable.
      await removePlan().catch(() => {})
      const snapshot = await collectSnapshot()
      if (snapshot.ok !== true) {
        const extra = { ...snapshot }
        delete extra.ok
        return { ok: true, eligible: false, ...extra }
      }

      const { scan, index } = snapshot
      const now = clock()
      const candidates = []
      const byStore = { objects: 0, fileObjects: 0, files: 0, requestImages: 0, unknown: 0 }
      let totalBytes = 0
      for (const [hash, bytes] of index.objects) {
        if (scan.refs.has(hash)) continue
        const mtimeMs = index.mtimes.get(hash)
        if (typeof mtimeMs !== 'number' || now - mtimeMs < graceMs) continue
        const aliases = index.aliases.get(hash) ?? []
        if (aliases.length === 0) continue
        const storeName = storeOfAlias(aliases[0])
        byStore[storeName] = (byStore[storeName] ?? 0) + 1
        totalBytes += bytes
        candidates.push({ hash, bytes, store: storeName, mtimeMs, aliases })
      }
      candidates.sort((left, right) => left.hash.localeCompare(right.hash))

      if (candidates.length === 0) {
        return {
          ok: true,
          eligible: false,
          reason: 'NOTHING_TO_RECLAIM',
          scan: scanSummary(scan),
          totals: { hashes: 0, bytes: 0 },
          byStore,
        }
      }

      const plan = {
        version: 1,
        id: createTrashId(),
        createdAt: now,
        expiresAt: now + planTtlMs,
        policy: { graceHours: graceMs / 3_600_000, batching: batchSize },
        scan: { ...scanSummary(scan), logFingerprint: scan.fingerprint },
        totals: { hashes: candidates.length, bytes: totalBytes },
        byStore,
        candidates,
      }
      await writePlan(plan)
      try {
        await appendAudit({
          at: now,
          action: 'plan',
          planId: plan.id,
          scan: plan.scan,
          totals: plan.totals,
          byStore: plan.byStore,
        })
      } catch (error) {
        await removePlan().catch(() => {})
        throw new TrashError('IO_ERROR', `The reclaim audit log could not be written: ${messageOf(error)}`)
      }
      logger.info?.(`reclaim preview: ${plan.totals.hashes} candidates, ${plan.totals.bytes} bytes, expires ${new Date(plan.expiresAt).toISOString()}`)
      return { ok: true, eligible: true, plan: planSummary(plan) }
    })
  }

  /**
   * Execute a previously previewed plan. Revalidates every root and the log
   * fingerprint before the first deletion, then checks the fingerprint again
   * before each batch.
   *
   * @param {{ planId: string, confirmation: string }} input plan identity and exact confirmation phrase.
   * @returns {Promise<object>} deletion counts and per-reason skips/failures.
   */
  async function execute({ planId, confirmation }) {
    if (confirmation !== RECLAIM_CONFIRMATION) {
      throw new TrashError('CONFIRMATION_REQUIRED', 'The reclaim confirmation phrase is missing or incorrect.')
    }
    if (typeof planId !== 'string' || planId === '') {
      throw new TrashError('INVALID_REQUEST', 'planId must be a non-empty string.')
    }
    if (trashService !== undefined && typeof trashService.recover === 'function') {
      try {
        await trashService.recover()
      } catch (error) {
        throw new TrashError('TRASH_BUSY', 'The trash is busy; retry the reclaim later.', { message: messageOf(error) })
      }
    }

    return store.withLock(async () => {
      const plan = await readPlan()
      if (plan === null || plan.id !== planId) {
        throw new TrashError('PLAN_NOT_FOUND', 'There is no reclaim plan with this identity.')
      }
      if (clock() > plan.expiresAt) {
        await removePlan()
        throw new TrashError('PLAN_EXPIRED', 'The reclaim plan expired; preview again.')
      }

      const snapshot = await collectSnapshot()
      if (snapshot.ok !== true) {
        throw new TrashError(snapshot.reason, 'The reclaim safety gates did not pass.', snapshot)
      }
      if (snapshot.scan.fingerprint !== plan.scan.logFingerprint) {
        await removePlan()
        throw new TrashError('PLAN_STALE', 'Session logs changed; preview the reclaim again.')
      }

      const now = clock()
      const selected = []
      const skipped = []
      for (const candidate of plan.candidates) {
        const verdict = stillCandidate(snapshot.index, snapshot.scan, candidate, now)
        if (verdict.ok === true) selected.push(candidate)
        else skipped.push({ reason: verdict.ok === false ? verdict.reason : 'unknown' })
      }

      const deleted = { hashes: 0, bytes: 0 }
      const failed = []
      let stale = false
      let aborted
      if (selected.length > 0) {
        try {
          await appendAudit({
            at: now,
            action: 'execute-start',
            planId: plan.id,
            scan: scanSummary(snapshot.scan),
            totals: plan.totals,
          })
        } catch (error) {
          throw new TrashError('IO_ERROR', `The reclaim audit log could not be written: ${messageOf(error)}`)
        }

        for (let offset = 0; offset < selected.length; offset += batchSize) {
          if (typeof references.fingerprint !== 'function') {
            stale = true
            break
          }
          let current
          try {
            current = await references.fingerprint()
          } catch {
            current = null
          }
          if (typeof current !== 'string' || current !== plan.scan.logFingerprint) {
            stale = true
            break
          }

          const batch = selected.slice(offset, offset + batchSize)
          for (const candidate of batch) {
            let outcome
            try {
              outcome = await deleteCandidate(snapshot.index, candidate)
            } catch (error) {
              logger.warn(`reclaim candidate ${candidate.hash} failed unexpectedly: ${messageOf(error)}`)
              outcome = { status: 'failed', bytes: 0, reason: 'unexpected-error' }
            }
            if (outcome.status === 'deleted') {
              deleted.hashes += 1
              deleted.bytes += outcome.bytes
            } else if (outcome.status === 'skipped') {
              skipped.push({ reason: outcome.reason })
            } else {
              failed.push({ reason: outcome.reason })
            }
          }
          try {
            await appendAudit({
              at: clock(),
              action: 'batch',
              planId: plan.id,
              offset,
              batch: batch.length,
              deleted: { ...deleted },
              skipped: skipped.length,
              failed: failed.length,
            })
          } catch (error) {
            aborted = 'audit-failed'
            logger.warn(`reclaim audit append failed after a batch: ${messageOf(error)}`)
            break
          }
        }
      }

      await removePlan()
      try {
        await appendAudit({
          at: clock(),
          action: 'execute-end',
          planId: plan.id,
          deleted,
          skipped: skipped.length,
          failed: failed.length,
          stale,
          ...(aborted === undefined ? {} : { aborted }),
        })
      } catch (error) {
        logger.warn(`cannot append the final reclaim audit event: ${messageOf(error)}`)
      }
      logger.info?.(`reclaim executed: deleted ${deleted.hashes} hashes (${deleted.bytes} bytes), skipped ${skipped.length}, failed ${failed.length}`)
      return {
        ok: true,
        planId: plan.id,
        deleted,
        skipped,
        failed,
        stale,
        ...(aborted === undefined ? {} : { aborted }),
        scan: scanSummary(snapshot.scan),
      }
    })
  }

  /**
   * @returns {Promise<object | null>} the current plan summary, or null when absent/expired.
   */
  async function getPlan() {
    const plan = await readPlan()
    if (plan === null) return null
    if (clock() > plan.expiresAt) return null
    return planSummary(plan)
  }

  /**
   * @returns {Promise<{ ok: true }>} resolution after the plan is discarded.
   */
  async function cancel() {
    return store.withLock(async () => {
      await removePlan()
      return { ok: true }
    })
  }

  return { preview, execute, getPlan, cancel }
}

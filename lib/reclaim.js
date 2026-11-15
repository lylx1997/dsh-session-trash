import { randomUUID } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { indexAttachments } from './attachment-store.js'
import { TrashError } from './errors.js'
import { createTrashId, isInside, samePath } from './fsops.js'
import { memberList } from './members.js'

/** Attachment objects younger than this are never candidates. */
export const ATTACHMENT_GRACE_MS = 24 * 86_400_000

/** A preview plan is usable for this long, without any artificial wait. */
export const PLAN_TTL_MS = 15 * 60_000

/** Candidate hashes handled between two log-fingerprint checks. */
export const RECLAIM_BATCH_SIZE = 50

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
 * Build and persist the read-only reclaim preview. This service never deletes
 * an attachment: it computes candidates, verifies every root, and writes a
 * short-lived plan that a later execute slice can validate.
 *
 * @param {{
 *   ctx: import('@deepseek-ai/cordis').Context,
 *   store: import('./store.js').TrashStore,
 *   trashService?: { recover: () => Promise<any> },
 *   references: { scan: (options?: { force?: boolean }) => Promise<any> },
 *   paths: { home: string, root: string, display?: string },
 *   logger: { warn: Function, info?: Function, debug?: Function },
 *   clock?: () => number,
 *   graceMs?: number,
 *   planTtlMs?: number,
 * }} deps host services, scanner, paths, and test-only clock/policy overrides.
 * @returns {{ preview: () => Promise<object>, getPlan: () => Promise<object | null>, cancel: () => Promise<{ ok: true }> }} the preview surface.
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
}) {
  const planDir = path.join(store.root, 'reclaim')
  const planPath = path.join(planDir, 'plan.json')

  /**
   * @param {string} reason stable eligibility reason.
   * @param {object} [extra] additional wire fields.
   * @returns {{ ok: true, eligible: false, reason: string }} a non-throwing preview outcome.
   */
  function unavailable(reason, extra = {}) {
    return { ok: true, eligible: false, reason, ...extra }
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
      !Array.isArray(document.candidates) ||
      document.totals === null ||
      typeof document.totals !== 'object' ||
      typeof document.totals.hashes !== 'number' ||
      typeof document.totals.bytes !== 'number'
    ) {
      return null
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
      if (store.isProtected()) return unavailable('INDEX_CORRUPT')
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
        if (entry?.state !== 'trashed') return unavailable('TRASH_BUSY')
      }
      if (missing.length > 0) {
        await removePlan().catch(() => {})
        return unavailable('TRASH_HAS_MISSING', { missing })
      }

      const persistence = ctx.sessionPersistence
      if (persistence === undefined || persistence === null || typeof persistence.flush !== 'function') {
        return unavailable('SESSION_FLUSH_FAILED')
      }
      try {
        await persistence.flush()
      } catch (error) {
        return unavailable('SESSION_FLUSH_FAILED', { message: messageOf(error) })
      }

      let scan
      try {
        scan = await references.scan({ force: true })
      } catch (error) {
        return unavailable('SCAN_INCOMPLETE', { message: messageOf(error) })
      }
      if (scan?.status === 'unavailable') {
        return unavailable('SCAN_UNAVAILABLE', { scan: scanSummary(scan) })
      }
      if (
        scan?.status !== 'complete' ||
        scan.failedFiles !== 0 ||
        scan.failedDirs !== 0 ||
        scan.tornFiles !== 0 ||
        typeof scan.fingerprint !== 'string' ||
        !Array.isArray(scan.files)
      ) {
        return unavailable('SCAN_INCOMPLETE', { scan: scanSummary(scan) })
      }

      let index
      try {
        index = await indexAttachments(paths.home, { logger })
      } catch (error) {
        return unavailable('ATTACHMENTS_INCOMPLETE', { message: messageOf(error) })
      }
      if (index.complete !== true) return unavailable('ATTACHMENTS_INCOMPLETE')

      let snapshots
      try {
        snapshots = typeof persistence.list === 'function' ? await persistence.list() : []
      } catch (error) {
        return unavailable('ROOTS_INCOMPLETE', { message: messageOf(error) })
      }
      if (!(await rootsCovered(scan.files, snapshots, entries))) {
        return unavailable('ROOTS_INCOMPLETE')
      }

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
        await removePlan().catch(() => {})
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
        policy: { graceHours: graceMs / 3_600_000, batching: RECLAIM_BATCH_SIZE },
        scan: { ...scanSummary(scan), logFingerprint: scan.fingerprint },
        totals: { hashes: candidates.length, bytes: totalBytes },
        byStore,
        candidates,
      }
      await writePlan(plan)
      logger.info?.(`reclaim preview: ${plan.totals.hashes} candidates, ${plan.totals.bytes} bytes, expires ${new Date(plan.expiresAt).toISOString()}`)
      return { ok: true, eligible: true, plan: planSummary(plan) }
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

  return { preview, getPlan, cancel }
}

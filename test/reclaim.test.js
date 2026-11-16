import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import { createReclaimService, PLAN_TTL_MS, RECLAIM_CONFIRMATION } from '../lib/reclaim.js'
import { createLogger, createTempDir } from './helpers.js'

/**
 * @param {string} file absolute file path.
 * @param {number} bytes byte count.
 * @returns {Promise<void>} resolution after the file exists.
 */
async function writeBytes(file, bytes) {
  await fs.mkdir(path.dirname(file), { recursive: true })
  await fs.writeFile(file, Buffer.alloc(bytes, 1))
}

/**
 * @param {{
 *   entries?: any[],
 *   snapshots?: any[],
 *   scan?: object,
 *   fingerprint?: string | (() => string | null),
 *   clock?: () => number,
 *   protected?: boolean,
 *   recover?: () => Promise<any>,
 *   batchSize?: number,
 *   auditMaxBytes?: number,
 * }} [options] harness overrides.
 * @returns {Promise<object>} the service and fixtures.
 */
async function createHarness(options = {}) {
  const home = await createTempDir()
  const trashRoot = path.join(home, '.session-trash')
  await fs.mkdir(path.join(trashRoot, 'objects'), { recursive: true })
  const logger = createLogger()
  const entries = options.entries ?? []
  const scanned = []
  const store = {
    root: trashRoot,
    entries: () => entries,
    isProtected: () => options.protected === true,
    withLock: async (operation) => operation(),
    memberPath: (trashId, index, sessionId) => path.join(
      trashRoot,
      'objects',
      trashId,
      index === 0 ? 'session' : path.join('children', sessionId),
    ),
  }
  const persistence = {
    async flush() {},
    async list() {
      return options.snapshots ?? []
    },
  }
  let fingerprintCalls = 0
  const references = {
    async scan(scanOptions) {
      scanned.push(scanOptions)
      return {
        status: 'complete',
        refs: new Set(),
        files: [],
        fingerprint: 'sha256:test',
        scannedFiles: 0,
        failedFiles: 0,
        failedDirs: 0,
        tornFiles: 0,
        at: 1,
        durationMs: 1,
        ...(options.scan ?? {}),
      }
    },
    async fingerprint() {
      const value = options.fingerprint
      const current = typeof value === 'function' ? value(fingerprintCalls++) : value
      return current === undefined ? (options.scan?.fingerprint ?? 'sha256:test') : current
    },
  }
  const service = createReclaimService({
    ctx: { sessionPersistence: persistence, sessions: { list: () => [] } },
    store,
    trashService: { recover: options.recover ?? (async () => ({ changed: 0 })) },
    references,
    paths: { home, root: trashRoot },
    logger,
    clock: options.clock ?? (() => Date.now()),
    batchSize: options.batchSize,
    auditMaxBytes: options.auditMaxBytes,
  })
  return {
    home,
    trashRoot,
    service,
    entries,
    scanned,
    logger,
    auditPath: path.join(trashRoot, 'reclaim', 'reclaim-log.jsonl'),
  }
}

/**
 * @param {string} home harness home.
 * @param {string} hash content hash.
 * @param {number} bytes file size.
 * @param {Date} mtime modification time.
 * @returns {Promise<void>} resolution after the object exists.
 */
async function writeObject(home, hash, bytes, mtime) {
  const file = path.join(home, 'attachments', 'v1', 'objects', hash.slice(0, 2), hash)
  await writeBytes(file, bytes)
  await fs.utimes(file, mtime, mtime)
}

test('preview writes a plan with only old unreferenced objects', async () => {
  const hashReferenced = 'a'.repeat(64)
  const hashOrphan = 'b'.repeat(64)
  const hashYoung = 'c'.repeat(64)
  const old = new Date(Date.now() - 25 * 86_400_000)
  const harness = await createHarness({
    scan: { refs: new Set([hashReferenced]) },
  })
  await writeObject(harness.home, hashReferenced, 100, old)
  await writeObject(harness.home, hashOrphan, 50, old)
  await writeObject(harness.home, hashYoung, 30, new Date())

  const result = await harness.service.preview()

  assert.equal(result.ok, true)
  assert.equal(result.eligible, true)
  assert.equal(result.plan.totals.hashes, 1)
  assert.equal(result.plan.totals.bytes, 50)
  assert.equal(result.plan.byStore.objects, 1)
  assert.equal(result.plan.scan.status, 'complete')
  assert.equal(harness.scanned.at(-1)?.force, true)

  const plan = await harness.service.getPlan()
  assert.equal(plan.id, result.plan.id)
  assert.equal(plan.totals.hashes, 1)

  await harness.service.cancel()
  assert.equal(await harness.service.getPlan(), null)
  await fs.rm(harness.home, { recursive: true, force: true })
})

test('missing entries are reported with titles instead of blocking silently', async () => {
  const harness = await createHarness({
    entries: [{ sessionId: 'session-missing', title: 'Lost session', state: 'missing', trashId: 't1' }],
  })
  const result = await harness.service.preview()
  assert.equal(result.eligible, false)
  assert.equal(result.reason, 'TRASH_HAS_MISSING')
  assert.deepEqual(result.missing, [{ sessionId: 'session-missing', title: 'Lost session' }])
  await fs.rm(harness.home, { recursive: true, force: true })
})

test('transient trash states and protected mode refuse preview', async () => {
  const busy = await createHarness({ entries: [{ sessionId: 's', state: 'trashing', trashId: 't1' }] })
  assert.equal((await busy.service.preview()).reason, 'TRASH_BUSY')
  await fs.rm(busy.home, { recursive: true, force: true })

  const protectedHarness = await createHarness({ protected: true })
  assert.equal((await protectedHarness.service.preview()).reason, 'INDEX_CORRUPT')
  await fs.rm(protectedHarness.home, { recursive: true, force: true })
})

test('an incomplete scan, recovery failure, or incomplete roots refuse preview', async () => {
  const partial = await createHarness({ scan: { status: 'partial', failedFiles: 1 } })
  assert.equal((await partial.service.preview()).reason, 'SCAN_INCOMPLETE')
  await fs.rm(partial.home, { recursive: true, force: true })

  const unavailable = await createHarness({ scan: { status: 'unavailable', fingerprint: null } })
  assert.equal((await unavailable.service.preview()).reason, 'SCAN_UNAVAILABLE')
  await fs.rm(unavailable.home, { recursive: true, force: true })

  const busy = await createHarness({ recover: async () => { throw new Error('busy') } })
  assert.equal((await busy.service.preview()).reason, 'TRASH_BUSY')
  await fs.rm(busy.home, { recursive: true, force: true })

  const expected = path.join(process.env.HOME ?? '/tmp', 'sessions', 'p', 's1', 'session.v4.jsonl.zstd')
  const roots = await createHarness({
    snapshots: [{ header: { id: 's1' }, location: { path: expected } }],
  })
  assert.equal((await roots.service.preview()).reason, 'ROOTS_INCOMPLETE')
  await fs.rm(roots.home, { recursive: true, force: true })
})

test('preview covers persisted and trashed log roots', async () => {
  const hash = 'e'.repeat(64)
  const home = await createTempDir()
  const trashRoot = path.join(home, '.session-trash')
  const persisted = path.join(home, 'sessions', 'p', 'session-a', 'session.v4.jsonl.zstd')
  const trashed = path.join(trashRoot, 'objects', 't1', 'session', 'session.v4.jsonl.zstd')
  const logger = createLogger()
  const store = {
    root: trashRoot,
    entries: () => [{ sessionId: 'session-b', state: 'trashed', trashId: 't1', members: [{ sessionId: 'session-b' }] }],
    isProtected: () => false,
    withLock: async (operation) => operation(),
    memberPath: () => path.join(trashRoot, 'objects', 't1', 'session'),
  }
  const references = {
    async scan() {
      return {
        status: 'complete',
        refs: new Set(),
        files: [
          { path: persisted, size: 1, mtimeMs: 1 },
          { path: trashed, size: 1, mtimeMs: 1 },
        ],
        fingerprint: 'sha256:test',
        scannedFiles: 2,
        failedFiles: 0,
        failedDirs: 0,
        tornFiles: 0,
        at: 1,
        durationMs: 1,
      }
    },
  }
  const service = createReclaimService({
    ctx: {
      sessionPersistence: {
        async flush() {},
        async list() {
          return [{ header: { id: 'session-a' }, location: { path: persisted } }]
        },
      },
      sessions: { list: () => [] },
    },
    store,
    trashService: { recover: async () => ({ changed: 0 }) },
    references,
    paths: { home, root: trashRoot },
    logger,
  })
  await writeObject(home, hash, 10, new Date(Date.now() - 25 * 86_400_000))

  const result = await service.preview()
  assert.equal(result.eligible, true)
  assert.equal(result.plan.totals.hashes, 1)
  await fs.rm(home, { recursive: true, force: true })
})

test('execute deletes only unreferenced, old objects and writes the audit log', async () => {
  const referenced = 'a'.repeat(64)
  const orphan = 'b'.repeat(64)
  const young = 'c'.repeat(64)
  const old = new Date(Date.now() - 25 * 86_400_000)
  const harness = await createHarness({ scan: { refs: new Set([referenced]) } })
  await writeObject(harness.home, referenced, 100, old)
  await writeObject(harness.home, orphan, 50, old)
  await writeObject(harness.home, young, 30, new Date())

  const preview = await harness.service.preview()
  const result = await harness.service.execute({
    planId: preview.plan.id,
    confirmation: RECLAIM_CONFIRMATION,
  })

  assert.deepEqual(result.deleted, { hashes: 1, bytes: 50 })
  assert.equal(result.stale, false)
  assert.equal(await harness.service.getPlan(), null)
  await assert.rejects(fs.stat(path.join(harness.home, 'attachments', 'v1', 'objects', orphan.slice(0, 2), orphan)))
  await fs.stat(path.join(harness.home, 'attachments', 'v1', 'objects', referenced.slice(0, 2), referenced))
  const audit = await fs.readFile(harness.auditPath, 'utf8')
  assert.ok(audit.includes('"action":"plan"'))
  assert.ok(audit.includes('"action":"execute-start"'))
  assert.ok(audit.includes('"action":"batch"'))
  assert.ok(audit.includes('"action":"execute-end"'))
  await fs.rm(harness.home, { recursive: true, force: true })
})

test('a fingerprint change between batches stops the remaining deletions', async () => {
  const first = 'd'.repeat(64)
  const second = 'e'.repeat(64)
  const old = new Date(Date.now() - 25 * 86_400_000)
  const harness = await createHarness({
    batchSize: 1,
    fingerprint: (call) => (call === 0 ? 'sha256:test' : 'sha256:changed'),
  })
  await writeObject(harness.home, first, 10, old)
  await writeObject(harness.home, second, 20, old)
  const preview = await harness.service.preview()

  const result = await harness.service.execute({
    planId: preview.plan.id,
    confirmation: RECLAIM_CONFIRMATION,
  })
  assert.equal(result.stale, true)
  assert.equal(result.deleted.hashes, 1)
  await assert.rejects(fs.stat(path.join(harness.home, 'attachments', 'v1', 'objects', first.slice(0, 2), first)))
  await fs.stat(path.join(harness.home, 'attachments', 'v1', 'objects', second.slice(0, 2), second))
  await fs.rm(harness.home, { recursive: true, force: true })
})

test('a changed plan fingerprint is rejected before any batch starts', async () => {
  const orphan = 'e'.repeat(64)
  const old = new Date(Date.now() - 25 * 86_400_000)
  const harness = await createHarness()
  await writeObject(harness.home, orphan, 10, old)
  const preview = await harness.service.preview()

  harness.service = createReclaimService({
    ctx: {
      sessionPersistence: { async flush() {}, async list() { return [] } },
      sessions: { list: () => [] },
    },
    store: {
      root: harness.trashRoot,
      entries: () => [],
      isProtected: () => false,
      withLock: async (operation) => operation(),
      memberPath: () => '',
    },
    references: {
      async scan() {
        return {
          status: 'complete',
          refs: new Set(),
          files: [],
          fingerprint: 'sha256:different',
          scannedFiles: 0,
          failedFiles: 0,
          failedDirs: 0,
          tornFiles: 0,
          at: 1,
          files2: [],
        }
      },
      async fingerprint() {
        return 'sha256:different'
      },
    },
    paths: { home: harness.home, root: harness.trashRoot },
    logger: harness.logger,
  })

  await assert.rejects(
    harness.service.execute({ planId: preview.plan.id, confirmation: RECLAIM_CONFIRMATION }),
    (error) => error?.code === 'PLAN_STALE',
  )
  await fs.stat(path.join(harness.home, 'attachments', 'v1', 'objects', orphan.slice(0, 2), orphan))
  await fs.rm(harness.home, { recursive: true, force: true })
})

test('an expired plan is rejected and a changed or vanished candidate is skipped', async () => {
  let now = Date.now()
  const expiredHash = '7'.repeat(64)
  const missingHash = '6'.repeat(64)
  const changedHash = '5'.repeat(64)
  const old = new Date(now - 25 * 86_400_000)
  const harness = await createHarness({ clock: () => now })
  await writeObject(harness.home, expiredHash, 10, old)
  const expiredPlan = await harness.service.preview()
  now += PLAN_TTL_MS + 1
  await assert.rejects(
    harness.service.execute({ planId: expiredPlan.plan.id, confirmation: RECLAIM_CONFIRMATION }),
    (error) => error?.code === 'PLAN_EXPIRED',
  )

  now = Date.now()
  await fs.rm(path.join(harness.home, 'attachments', 'v1', 'objects', expiredHash.slice(0, 2), expiredHash))
  await writeObject(harness.home, missingHash, 20, old)
  await writeObject(harness.home, changedHash, 30, old)
  const plan = await harness.service.preview()
  await fs.rm(path.join(harness.home, 'attachments', 'v1', 'objects', missingHash.slice(0, 2), missingHash))
  await fs.utimes(
    path.join(harness.home, 'attachments', 'v1', 'objects', changedHash.slice(0, 2), changedHash),
    new Date(),
    new Date(),
  )
  const result = await harness.service.execute({
    planId: plan.plan.id,
    confirmation: RECLAIM_CONFIRMATION,
  })
  assert.deepEqual(result.deleted, { hashes: 0, bytes: 0 })
  assert.deepEqual(result.skipped.map((item) => item.reason).sort(), ['changed', 'missing'])
  await fs.stat(path.join(harness.home, 'attachments', 'v1', 'objects', changedHash.slice(0, 2), changedHash))
  await fs.rm(harness.home, { recursive: true, force: true })
})

test('a zero-byte unreferenced object is still a valid candidate', async () => {
  const hash = '3'.repeat(64)
  const old = new Date(Date.now() - 25 * 86_400_000)
  const harness = await createHarness()
  await writeObject(harness.home, hash, 0, old)
  const preview = await harness.service.preview()
  assert.equal(preview.eligible, true)
  const result = await harness.service.execute({
    planId: preview.plan.id,
    confirmation: RECLAIM_CONFIRMATION,
  })
  assert.deepEqual(result.deleted, { hashes: 1, bytes: 0 })
  await assert.rejects(fs.stat(path.join(harness.home, 'attachments', 'v1', 'objects', hash.slice(0, 2), hash)))
  await fs.rm(harness.home, { recursive: true, force: true })
})

test('the audit log rotates at the configured size', async () => {
  const orphan = '2'.repeat(64)
  const old = new Date(Date.now() - 25 * 86_400_000)
  const harness = await createHarness({ auditMaxBytes: 1 })
  await writeObject(harness.home, orphan, 10, old)

  await harness.service.preview()
  await harness.service.preview()

  const rotated = await fs.readFile(`${harness.auditPath}.1`, 'utf8')
  const current = await fs.readFile(harness.auditPath, 'utf8')
  assert.equal(rotated.trim().split('\n').length, 1)
  assert.equal(current.trim().split('\n').length, 1)
  assert.ok(rotated.includes('"action":"plan"'))
  assert.ok(current.includes('"action":"plan"'))
  await fs.rm(harness.home, { recursive: true, force: true })
})

test('a mismatched plan id is rejected', async () => {
  const orphan = '4'.repeat(64)
  const old = new Date(Date.now() - 25 * 86_400_000)
  const harness = await createHarness()
  await writeObject(harness.home, orphan, 10, old)
  await harness.service.preview()
  await assert.rejects(
    harness.service.execute({ planId: 'not-the-plan', confirmation: RECLAIM_CONFIRMATION }),
    (error) => error?.code === 'PLAN_NOT_FOUND',
  )
  await fs.rm(harness.home, { recursive: true, force: true })
})

test('the exact confirmation phrase is required and leaves the plan intact', async () => {
  const orphan = 'f'.repeat(64)
  const old = new Date(Date.now() - 25 * 86_400_000)
  const harness = await createHarness()
  await writeObject(harness.home, orphan, 10, old)
  const preview = await harness.service.preview()

  await assert.rejects(
    harness.service.execute({ planId: preview.plan.id, confirmation: 'yes' }),
    (error) => error?.code === 'CONFIRMATION_REQUIRED',
  )
  assert.notEqual(await harness.service.getPlan(), null)
  await fs.rm(harness.home, { recursive: true, force: true })
})

test('file aliases are deleted together and an unknown hard link is skipped', async (t) => {
  const hash = '1'.repeat(64)
  const extraLink = '2'.repeat(64)
  const old = new Date(Date.now() - 25 * 86_400_000)
  const harness = await createHarness()
  const root = path.join(harness.home, 'attachments', 'v1')
  const canonical = path.join(root, 'file-objects', hash.slice(0, 2), hash)
  const display = path.join(root, 'files', hash.slice(0, 2), hash, 'report.pdf')
  await writeBytes(canonical, 64)
  await fs.mkdir(path.dirname(display), { recursive: true })
  try {
    await fs.link(canonical, display)
  } catch (error) {
    const code = error !== null && typeof error === 'object' ? error.code : undefined
    if (code === 'EPERM' || code === 'EACCES' || code === 'EXDEV' || code === 'ENOTSUP') {
      t.skip(`hard links are not permitted here (${code})`)
      await fs.rm(harness.home, { recursive: true, force: true })
      return
    }
    throw error
  }
  await fs.utimes(canonical, old, old)

  const preview = await harness.service.preview()
  assert.equal(preview.plan.totals.hashes, 1)
  const result = await harness.service.execute({
    planId: preview.plan.id,
    confirmation: RECLAIM_CONFIRMATION,
  })
  assert.deepEqual(result.deleted, { hashes: 1, bytes: 64 })
  await assert.rejects(fs.stat(canonical))
  await assert.rejects(fs.stat(display))

  // A second object with an extra, unknown hard link must be skipped.
  const unknownRoot = path.join(harness.home, 'attachments', 'v1', 'objects', extraLink.slice(0, 2), extraLink)
  await writeBytes(unknownRoot, 20)
  await fs.link(unknownRoot, path.join(harness.home, 'external-link'))
  await fs.utimes(unknownRoot, old, old)
  const next = await harness.service.preview()
  assert.equal(next.plan.totals.hashes, 1)
  const skipped = await harness.service.execute({
    planId: next.plan.id,
    confirmation: RECLAIM_CONFIRMATION,
  })
  assert.deepEqual(skipped.deleted, { hashes: 0, bytes: 0 })
  assert.deepEqual(skipped.skipped, [{ reason: 'linked-elsewhere' }])
  await fs.stat(unknownRoot)
  await fs.rm(harness.home, { recursive: true, force: true })
})

test('an empty candidate set produces a stable nothing-to-reclaim outcome', async () => {
  const harness = await createHarness()
  const result = await harness.service.preview()
  assert.equal(result.eligible, false)
  assert.equal(result.reason, 'NOTHING_TO_RECLAIM')
  assert.equal(result.totals.hashes, 0)
  await fs.rm(harness.home, { recursive: true, force: true })
})

test('plans expire after their ttl and disappear from reads', async () => {
  let now = Date.now()
  const hash = 'd'.repeat(64)
  const harness = await createHarness({ clock: () => now })
  await writeObject(harness.home, hash, 10, new Date(now - 25 * 86_400_000))

  const preview = await harness.service.preview()
  assert.equal(preview.eligible, true)
  assert.equal(await harness.service.getPlan() === null, false)

  now += PLAN_TTL_MS + 1
  assert.equal(await harness.service.getPlan(), null)
  assert.equal(await harness.service.preview().then((result) => result.eligible), true)
  await fs.rm(harness.home, { recursive: true, force: true })
})

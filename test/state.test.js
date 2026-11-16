import test from 'node:test'
import assert from 'node:assert/strict'
import { createStateService, lastErrorCode } from '../lib/state.js'

const config = { retentionDays: 30, sweepIntervalHours: 6, enableAutoCleanup: true }

/**
 * @param {string} sessionId entry identity.
 * @param {string | null} cwd original workspace.
 * @param {object} [extra] extra entry fields.
 * @returns {object} one index entry.
 */
function entry(sessionId, cwd, extra = {}) {
  return {
    sessionId,
    title: sessionId,
    trashedAt: Date.now(),
    originalCwd: cwd,
    state: 'trashed',
    sizeBytes: 1,
    fileCount: 1,
    members: [{ sessionId, origin: null, sizeBytes: 1 }],
    lastError: null,
    ...extra,
  }
}

/**
 * @param {object[]} entries index entries.
 * @param {(cwd: string) => Promise<boolean>} probe workspace probe.
 * @param {(entries: object[]) => Promise<object | null>} [storageSnapshot] storage measurement.
 * @returns {object} the state service.
 */
function createService(entries, probe, storageSnapshot, workspaceRegistry = () => undefined) {
  const store = {
    entries: () => entries,
    describe: () => ({ status: 'ok', updatedAt: 1, error: null, unindexed: 0 }),
  }
  return createStateService({
    store,
    config,
    trashRootDisplay: '$DSH_HOME/.session-trash',
    directoryExists: probe,
    workspaceRegistry,
    ...(storageSnapshot === undefined ? {} : { storageSnapshot }),
  })
}

test('the state snapshot probes each distinct workspace once', async () => {
  let probes = 0
  const service = createService(
    [entry('a', '/work/shared'), entry('b', '/work/shared'), entry('c', '/work/other'), entry('d', null)],
    async () => {
      probes += 1
      return true
    },
  )
  const snapshot = await service.snapshot()
  assert.equal(probes, 2)
  assert.equal(snapshot.entries.length, 4)
  assert.equal(snapshot.entries[0].workspaceNowExists, true)
  assert.equal(snapshot.entries[3].workspaceNowExists, null)
})

test('the state snapshot carries storage stats and tolerates a failing measurement', async () => {
  const entries = [entry('a', '/work/a')]
  const measured = createService(entries, async () => true, async (described) => ({
    totalBytes: 42,
    described: described.length,
  }))
  const snapshot = await measured.snapshot()
  assert.deepEqual(snapshot.storage, { totalBytes: 42, described: 1 })

  const failing = createService(entries, async () => true, async () => {
    throw new Error('measurement failed')
  })
  assert.equal((await failing.snapshot()).storage, null)
})

test('lastErrorCode classifies recorded failure families', () => {
  assert.equal(lastErrorCode(null), null)
  assert.equal(lastErrorCode(''), null)
  assert.equal(lastErrorCode('The trash copy of this session is missing.'), 'TRASH_COPY_MISSING')
  assert.equal(lastErrorCode('The trash copy is missing these member sessions: a, b.'), 'TRASH_COPY_MISSING_MEMBERS')
  assert.equal(lastErrorCode('The trash object directory is missing.'), 'TRASH_OBJECT_MISSING')
  assert.equal(lastErrorCode('The session log could not be deleted: EACCES'), 'PURGE_FAILED')
  assert.equal(lastErrorCode('The restored session was not visible to session storage.'), 'RESTORE_INVISIBLE')
  assert.equal(lastErrorCode('The restored session tree is not visible to session storage.'), 'RESTORE_INVISIBLE')
  assert.equal(lastErrorCode('Session storage still reports the moved session tree.'), 'MOVE_UNSETTLED')
  assert.equal(lastErrorCode('An original session directory unexpectedly exists alongside the trash copy.'), 'SOURCE_CONFLICT')
  assert.equal(lastErrorCode('The trash index could not be committed after restore: x'), 'INDEX_WRITE_FAILED')
  assert.equal(lastErrorCode('EACCES: permission denied'), 'IO_ERROR')
})

test('the wire entry carries a stable code next to the raw diagnostic', async () => {
  const missing = entry('a', '/work/x', { state: 'missing', lastError: 'The trash copy of this session is missing.' })
  const service = createService([missing], async () => true)
  const described = await service.describe(missing)
  assert.equal(described.lastErrorCode, 'TRASH_COPY_MISSING')
  assert.equal(described.lastError, 'The trash copy of this session is missing.')
})

test('a workspace removed from DSH is unavailable even when its directory remains', async () => {
  const entries = [
    entry('a', '/work/a', { originalWorkspaceId: 'ws-a' }),
    entry('b', '/work/b', { originalWorkspaceId: null }),
  ]
  const service = createService(entries, async () => true, undefined, () => ({ list: () => [] }))
  const snapshot = await service.snapshot()
  const [removed, ungrouped] = snapshot.entries

  assert.equal(removed.workspaceNowExists, true)
  assert.equal(removed.workspaceRegistered, false)
  assert.equal(removed.workspaceStatus, 'unregistered')
  assert.equal(removed.requiresOrphanRestore, true)

  assert.equal(ungrouped.workspaceNowExists, true)
  assert.equal(ungrouped.workspaceRegistered, null)
  assert.equal(ungrouped.workspaceStatus, 'available')
  assert.equal(ungrouped.requiresOrphanRestore, false)

  const status = await service.workspaceStatus()
  assert.deepEqual(status.entries[0], {
    sessionId: 'a',
    workspaceNowExists: true,
    workspaceRegistered: false,
    workspaceAvailable: false,
    workspaceStatus: 'unregistered',
    requiresOrphanRestore: true,
  })
  assert.equal(status.entries[1].requiresOrphanRestore, false)
})

test('a registered workspace keeps a directory-backed entry directly restorable', async () => {
  const entries = [entry('a', '/work/a', { originalWorkspaceId: 'ws-a' })]
  const service = createService(entries, async () => true, undefined, () => ({
    list: () => [{ id: 'ws-a', path: '/work/a', sessionIds: ['a'] }],
  }))
  const snapshot = await service.snapshot()
  assert.equal(snapshot.entries[0].workspaceRegistered, true)
  assert.equal(snapshot.entries[0].workspaceAvailable, true)
  assert.equal(snapshot.entries[0].workspaceStatus, 'available')
  assert.equal(snapshot.entries[0].requiresOrphanRestore, false)
})

test('an absent workspace directory stays the missing case', async () => {
  const entries = [entry('a', '/work/gone', { originalWorkspaceId: 'ws-a' })]
  const service = createService(entries, async () => false, undefined, () => ({ list: () => [] }))
  const snapshot = await service.snapshot()
  assert.equal(snapshot.entries[0].workspaceNowExists, false)
  assert.equal(snapshot.entries[0].workspaceRegistered, null)
  assert.equal(snapshot.entries[0].workspaceStatus, 'missing')
  assert.equal(snapshot.entries[0].requiresOrphanRestore, true)
})

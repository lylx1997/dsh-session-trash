import { directoryExists } from './fsops.js'

/**
 * Snapshot the Workspace registry's current order.
 *
 * A missing or throwing registry is reported as `null` instead of an empty
 * list: callers must keep the pre-existing directory-only behavior rather than
 * treating every entry as unregistered.
 *
 * @param {any} registry Workspace registry service, if the Host provides one.
 * @returns {any[] | null} workspaces in registry order, or null when unknown.
 */
export function listWorkspaces(registry) {
  if (registry === undefined || registry === null || typeof registry.list !== 'function') return null
  try {
    const workspaces = registry.list()
    return Array.isArray(workspaces) ? workspaces : null
  } catch {
    return null
  }
}

/**
 * Find the Workspace that owns a trashed entry.
 *
 * The recorded Workspace id is authoritative; scanning `sessionIds` covers
 * entries written before the id was recorded and workspaces whose id changed.
 *
 * @param {any[] | null} workspaces registry snapshot.
 * @param {any} entry trashed entry.
 * @returns {any | undefined} the owning Workspace.
 */
export function findWorkspace(workspaces, entry) {
  if (!Array.isArray(workspaces) || entry === null || entry === undefined) return undefined
  const id = typeof entry.originalWorkspaceId === 'string' && entry.originalWorkspaceId !== '' ? entry.originalWorkspaceId : null
  if (id !== null) {
    const byId = workspaces.find((candidate) => candidate !== null && candidate !== undefined && candidate.id === id)
    if (byId !== undefined) return byId
  }
  return workspaces.find(
    (candidate) =>
      candidate !== null &&
      candidate !== undefined &&
      Array.isArray(candidate.sessionIds) &&
      candidate.sessionIds.includes(entry.sessionId),
  )
}

/**
 * @typedef {object} WorkspaceInspection
 * @property {string | null} cwd recorded workspace directory.
 * @property {boolean} directoryExists whether that directory is present now.
 * @property {boolean | null} registered whether DSH still registers the workspace.
 * @property {boolean} available whether a normal restore can return the session to its workspace.
 * @property {'available' | 'missing' | 'unregistered' | 'no-workspace' | 'unknown'} status projected state.
 */

/**
 * Inspect the workspace recorded for one trashed entry.
 *
 * `available` is false when a normal restore must not proceed: the directory
 * is gone, or the recorded Workspace id is no longer in the registry. Entries
 * that never had a workspace id and match no registered workspace stay
 * restorable as ungrouped sessions. When the registry itself is unavailable,
 * availability falls back to the directory probe so a Host without that
 * service keeps the previous behavior.
 *
 * @param {any} entry trashed entry.
 * @param {{
 *   workspaces?: any[] | null,
 *   probeDirectory?: (directory: string) => Promise<boolean>,
 * }} [options] registry snapshot and directory probe.
 * @returns {Promise<WorkspaceInspection>} the projected workspace state.
 */
export async function inspectWorkspace(entry, { workspaces = null, probeDirectory = directoryExists } = {}) {
  const cwd = typeof entry?.originalCwd === 'string' && entry.originalCwd !== '' ? entry.originalCwd : null
  if (cwd === null) {
    return { cwd, directoryExists: false, registered: null, available: false, status: 'no-workspace' }
  }
  const directoryExistsNow = await probeDirectory(cwd)
  if (!directoryExistsNow) {
    return { cwd, directoryExists: false, registered: null, available: false, status: 'missing' }
  }
  if (!Array.isArray(workspaces)) {
    return { cwd, directoryExists: true, registered: null, available: true, status: 'unknown' }
  }
  const workspace = findWorkspace(workspaces, entry)
  if (workspace !== undefined) {
    return { cwd, directoryExists: true, registered: true, available: true, status: 'available' }
  }
  const hasRecordedWorkspace =
    typeof entry.originalWorkspaceId === 'string' && entry.originalWorkspaceId !== ''
  if (!hasRecordedWorkspace) {
    // The entry was trashed while ungrouped, or predates workspace ids. A
    // normal restore still works; it simply returns as an ungrouped session.
    return { cwd, directoryExists: true, registered: null, available: true, status: 'available' }
  }
  return { cwd, directoryExists: true, registered: false, available: false, status: 'unregistered' }
}

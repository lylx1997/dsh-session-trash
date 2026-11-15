import fs from 'node:fs/promises'
import path from 'node:path'

/** Attachment stores below `<DSH_HOME>/attachments/v1` that hold durable bytes. */
export const ATTACHMENT_STORES = ['objects', 'file-objects', 'files', 'request-images']

/** Attachment object names are lowercase SHA-256 digests. */
export const OBJECT_NAME_PATTERN = /^[a-f0-9]{64}$/

/** Maximum directory depth measured under one attachment store. */
const MAX_DEPTH = 4

/**
 * @param {unknown} error arbitrary failure.
 * @returns {string} a user-facing message.
 */
function messageOf(error) {
  return error instanceof Error ? error.message : String(error)
}

/**
 * Index durable attachment objects by content hash. `files/<hash>/<name>` is a
 * display alias for `file-objects/<hash>`, so both roots map to the same hash
 * and one size. Files that do not follow the known layout are counted as
 * unclassified disk usage instead of being silently dropped.
 *
 * @param {string} home absolute harness home.
 * @param {{ logger: { warn: Function } }} deps diagnostics.
 * @returns {Promise<{
 *   root: string,
 *   files: number,
 *   bytes: number,
 *   objects: Map<string, number>,
 *   mtimes: Map<string, number>,
 *   aliases: Map<string, string[]>,
 *   unclassifiedFiles: number,
 *   unclassifiedBytes: number,
 *   complete: boolean,
 * }>} attachment index.
 */
export async function indexAttachments(home, { logger }) {
  const root = path.join(home, 'attachments', 'v1')
  /** @type {Map<string, number>} */
  const objects = new Map()
  /** @type {Map<string, number>} */
  const mtimes = new Map()
  /** @type {Map<string, string[]>} */
  const aliases = new Map()
  let unclassifiedFiles = 0
  let unclassifiedBytes = 0
  let complete = true

  /**
   * @param {string} directory store root.
   * @param {(file: string) => string | undefined} hashOf derive a content hash from one file.
   * @param {number} depth current depth.
   * @returns {Promise<void>} resolution after the walk.
   */
  async function walk(directory, hashOf, depth = 0) {
    let entries
    try {
      entries = await fs.readdir(directory, { withFileTypes: true })
    } catch (error) {
      if (error === null || error === undefined || error.code !== 'ENOENT') {
        complete = false
        logger.warn(`cannot index ${directory}: ${messageOf(error)}`)
      }
      return
    }
    for (const entry of entries) {
      if (entry.name === '.DS_Store') continue
      const child = path.join(directory, entry.name)
      if (entry.isDirectory()) {
        if (depth < MAX_DEPTH) await walk(child, hashOf, depth + 1)
        continue
      }
      if (!entry.isFile()) continue
      let stats
      try {
        stats = await fs.lstat(child)
      } catch (error) {
        if (error !== null && error !== undefined && error.code === 'ENOENT') continue
        complete = false
        logger.warn(`cannot index ${child}: ${messageOf(error)}`)
        continue
      }
      if (!stats.isFile()) continue
      const hash = hashOf(child)
      if (hash !== undefined && OBJECT_NAME_PATTERN.test(hash)) {
        if (!objects.has(hash)) {
          objects.set(hash, stats.size)
          mtimes.set(hash, stats.mtimeMs)
        }
        const relative = path.relative(root, child).split(path.sep).join('/')
        const list = aliases.get(hash)
        if (list === undefined) aliases.set(hash, [relative])
        else list.push(relative)
      } else {
        unclassifiedFiles += 1
        unclassifiedBytes += stats.size
      }
    }
  }

  for (const store of ATTACHMENT_STORES) {
    const directory = path.join(root, store)
    const hashOf = store === 'files'
      ? (file) => path.basename(path.dirname(file))
      : (file) => path.basename(file)
    await walk(directory, hashOf)
  }

  let bytes = unclassifiedBytes
  for (const size of objects.values()) bytes += size
  return {
    root,
    files: objects.size + unclassifiedFiles,
    bytes,
    objects,
    mtimes,
    aliases,
    unclassifiedFiles,
    unclassifiedBytes,
    complete,
  }
}

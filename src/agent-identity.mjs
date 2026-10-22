import * as fs from 'node:fs'

/**
 * Read an existing local age identity. A correctly private owner-owned regular
 * file is already protected; avoid a metadata write so read-only service homes
 * can use it. Preserve the existing repair behavior for unsafe modes.
 */
export function loadExistingAgentIdentity(identityPath, { fsImpl = fs, uid = process.getuid() } = {}) {
  const info = fsImpl.lstatSync(identityPath)
  if (!info.isFile() || info.isSymbolicLink() || info.uid !== uid) {
    throw new Error('agent identity must be a regular file owned by the current user')
  }
  if ((info.mode & 0o777) !== 0o600) fsImpl.chmodSync(identityPath, 0o600)
  return JSON.parse(fsImpl.readFileSync(identityPath, 'utf8'))
}

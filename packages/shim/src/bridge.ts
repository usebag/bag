// The omp consent bridge folder, per connection. omp announces no MCP elicitation, so the service writes a pairing's
// consent requests as files (packages/mcp/src/consent.ts's shapes) that omp's wake extension shows and answers. The
// service alone makes the folder, <home>/run/shim/<connection>.consent/ (0700), names it in the hello reply's
// bridgeDir, writes the request files into it (it holds the check digits) and removes it on the last unbind and on
// close. The shim never chooses, announces or writes into a folder (the red team's read: a shim that named one, or
// wrote its requests, could aim another session's consent at it). It only takes the path back from the hello reply,
// when it is exactly that shape under its own home and a 0700 directory of the user, not a link, and hands it to the
// extension over the typed-word channel (channel.ts, kind "bridge").
import { lstatSync } from 'node:fs'
import { join } from 'node:path'

/**
 * The bridge folder a hello reply names, or null: exactly <home>/run/shim/<connection>.consent, an existing directory
 * of this user with no group or other bit, not a link.
 */
export function bridgeDirOf(
  home: string,
  given: unknown,
  uid: number = process.getuid?.() ?? -1,
): string | null {
  if (typeof given !== 'string') return null
  const m = /^(.+)\/([A-Za-z0-9_-]{1,64})\.consent$/.exec(given)
  if (m === null || m[1] !== join(home, 'run', 'shim')) return null
  try {
    const st = lstatSync(given)
    if (!st.isDirectory() || (st.mode & 0o077) !== 0 || (uid !== -1 && st.uid !== uid)) return null
  } catch {
    return null
  }
  return given
}

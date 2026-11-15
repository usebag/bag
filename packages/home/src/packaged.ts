import { readdirSync, readFileSync, realpathSync, rmSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { BUILD_INFO, checkoutCommit } from '@usebag/edge'

// The package build (packages/bag) and the commands that write the CLI's or the server's path into another
// program's files. Run by npx, the package lives in npm's cache (~/.npm/_npx/<hash>/), which npm may clear: a path
// there would leave .mcp.json, the hooks and a keep job pointing at nothing, with no message. So a command that writes
// such a path first copies the package's dist/ (self-contained: the bundle has no dependency) to <home>/package/ and
// writes that path, which stays until the home goes. A later version run the same way refreshes the files in place,
// so the written lines stay the same. From source nothing is copied: the checkout's main.ts files are written.

/** `bag <version> <commit>`: the package build's (the edge's build-info.ts), else `source` and the checkout's commit. */
export function versionLine(): string {
  const [version, commit] = BUILD_INFO
    ? [BUILD_INFO.version, BUILD_INFO.commit]
    : ['source', checkoutCommit() ?? 'unknown']
  return `bag ${version} ${commit}`
}

/** The entries a written command names, and the directory the package was copied to (null: nothing copied). */
export interface Mains {
  readonly cli: string
  readonly mcp: string
  /** The omp wake extension (omp-wake.ts, built as bag-omp-wake.js). */
  readonly omp: string
  readonly copied: string | null
}

/**
 * The node for another program's files: Homebrew's link (/opt/homebrew/bin/node, /usr/local/bin/node) when it resolves
 * to `exec`, the node running, as `brew upgrade` removes the Cellar path that names; else that path. The link is
 * mutable, but control of those folders is already control of the node Homebrew hands you: it widens nothing.
 */
export function stableNode(
  exec: string,
  links: readonly string[] = ['/opt/homebrew/bin/node', '/usr/local/bin/node'],
  real: (path: string) => string = realpathSync,
): string {
  const at = (p: string) => {
    try {
      return real(p)
    } catch {
      return null
    }
  }
  return links.find((l) => at(l) !== null && at(l) === at(exec)) ?? exec
}

/** The versions directory of the installer's staging (stage.ts): <home>/package/versions/<version>/. */
export const versionsDir = (home: string): string => join(home, 'package', 'versions')
/** The pointer file naming the version a service starts from: <home>/package/current. */
export const currentFile = (home: string): string => join(home, 'package', 'current')

/** The version <home>/package/current names, or null (absent, empty or not a plain version name). */
export function currentVersion(home: string): string | null {
  try {
    const v = readFileSync(currentFile(home), 'utf8').trim()
    return /^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$/.test(v) ? v : null
  } catch {
    return null
  }
}

/** The package directory a running service loaded from, from <home>/run/service.json; null when none runs or names one. */
function runningDir(home: string): string | null {
  try {
    const dir = (
      JSON.parse(readFileSync(join(home, 'run', 'service.json'), 'utf8')) as { package_dir?: unknown }
    ).package_dir
    return typeof dir === 'string' ? dir : null
  } catch {
    return null
  }
}

/** Orders version names by their numeric parts (1.0.10 after 1.0.9), then as text. */
export function byVersion(a: string, b: string): number {
  const pa = a.split(/[.+-]/)
  const pb = b.split(/[.+-]/)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const [x, y] = [pa[i] ?? '', pb[i] ?? '']
    const [nx, ny] = [Number(x), Number(y)]
    const d = /^\d+$/.test(x) && /^\d+$/.test(y) ? nx - ny : x < y ? -1 : x > y ? 1 : 0
    if (d !== 0) return d
  }
  return 0
}

/** A staging directory's name, .<version>.<pid>.tmp: its pid. */
const STAGING = /^\.(.+)\.([1-9][0-9]*)\.tmp$/

/**
 * Removes the versions no one can be running: every <version> but the one `current` names, the one before it (never
 * fewer than two kept) and the one service.json names, and every staging .<version>.<pid>.tmp whose pid is gone (a live one is mid-stage, never touched). Returns the
 * names removed. Nothing outside versions/ is touched.
 */
export function pruneVersions(home: string, alive: (pid: number) => boolean): string[] {
  const dir = versionsDir(home)
  let names: string[]
  try {
    names = readdirSync(dir)
  } catch {
    return []
  }
  const keep = new Set<string>()
  const current = currentVersion(home)
  if (current !== null) {
    keep.add(current)
    // And the version before it: never fewer than two, so the one a window may still run from stays.
    const before = names
      .filter((n) => !n.startsWith('.') && byVersion(n, current) < 0)
      .sort(byVersion)
      .at(-1)
    if (before !== undefined) keep.add(before)
  }
  // service.json names the directory by the bundle's own URL, a real path (/private/tmp for /tmp on macOS).
  const running = runningDir(home)
  const real = (p: string): string => {
    try {
      return realpathSync(p)
    } catch {
      return p
    }
  }
  if (running !== null && real(dirname(running)) === real(dir)) keep.add(basename(running))
  const removed: string[] = []
  for (const name of names) {
    const staging = STAGING.exec(name)
    if (staging !== null ? alive(Number(staging[2])) : keep.has(name) || name.startsWith('.')) continue
    rmSync(join(dir, name), { recursive: true, force: true })
    removed.push(name)
  }
  return removed
}

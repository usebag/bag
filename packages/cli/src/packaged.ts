import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
} from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { BUILD_INFO, checkoutCommit } from '@usebag/edge'
import { CLI_MAIN, MCP_MAIN, OMP_WAKE, PACKAGED } from './entries.ts'

// The package build (packages/bag) and the commands that write this CLI's or the server's path into another
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
 * The entries to write for the home `home`. From source (`packaged` false), `cli` and `mcp`. From the package, the
 * same files under <home>/package/, after every file of their directory is copied there (each written beside and
 * renamed over, so a process starting meanwhile reads a whole file) and the .js files of an earlier version that this
 * one lacks are removed; when the package already runs from there, or the copy there is already this one, nothing is
 * copied.
 */
export function stableMains(
  home: string,
  cli = CLI_MAIN,
  mcp = MCP_MAIN,
  packaged = PACKAGED,
  omp = OMP_WAKE,
): Mains {
  if (!packaged) return { cli, mcp, omp, copied: null }
  const [from, to] = [dirname(cli), join(home, 'package')]
  const mains = { cli: join(to, basename(cli)), mcp: join(to, basename(mcp)), omp: join(to, basename(omp)) }
  // A recursive mkdir does not tighten a directory that is already there, so the mode is set either way.
  mkdirSync(to, { recursive: true, mode: 0o700 })
  chmodSync(to, 0o700)
  if (realpathSync(from) === realpathSync(to)) return { ...mains, copied: null }
  const files = readdirSync(from).filter((f) => statSync(join(from, f)).isFile())
  const stale = readdirSync(to).filter((f) => f.endsWith('.js') && !files.includes(f))
  const same = (f: string) =>
    existsSync(join(to, f)) && readFileSync(join(to, f)).equals(readFileSync(join(from, f)))
  if (stale.length === 0 && files.every(same)) return { ...mains, copied: null }
  for (const f of files) {
    const tmp = join(to, `.${f}.tmp`)
    copyFileSync(join(from, f), tmp)
    chmodSync(tmp, statSync(join(from, f)).mode & 0o755)
    renameSync(tmp, join(to, f))
  }
  for (const f of stale) rmSync(join(to, f))
  return { ...mains, copied: to }
}

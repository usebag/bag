import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { basename, dirname, join } from 'node:path'
import type { Mains } from './packaged.ts'
import { HomeError } from './ports.ts'

// Versioned package directories. Run from the package,
// a command that writes this package's paths into another program's files first stages the package's dist/ at
// <home>/package/versions/<version>/, once (staged beside, renamed in), and points <home>/package/current at it. A
// staged version is never written again, so nothing replaces the files a running server or service loaded; the running
// service moves to the new version at its next drain and restart. From source nothing is staged. Removing a version
// nothing names is packaged.ts's (pruneVersions). The entries come from the caller (Build): the command line's own,
// which the package build replaces with the bundle's.

/** The entries to write, the shim's among them, and the notice for a running service of another version. */
export interface Staged extends Mains {
  readonly shim: string
  readonly notice: string | null
  /** The staged version directory's own entries (the plist's and a test's), not for host files. */
  readonly versioned: {
    readonly cli: string
    readonly mcp: string
    readonly omp: string
    readonly shim: string
  } | null
}

/** The package to stage: whether it runs from the bundle, its version, and its entries (the shim's from source). */
export interface Build {
  readonly packaged: boolean
  readonly version: string
  readonly cli: string
  readonly mcp: string
  readonly omp: string
  readonly shim: string
}

/**
 * A launcher's text: Node built-ins only; reads <its dir>/current and imports versions/<current>/<name> in this process,
 * so argv, env, stdio and signals are the host's own. A missing or odd current is one stderr line and exit 1.
 */
export const launcherText = (name: string): string =>
  // The text is the launchers' as staged before this moved here, path in the comment line and all: a stage rewrites
  // every launcher, and the same bytes leave a running service's launcher as it was.
  [
    '#!/usr/bin/env node',
    `// bag launcher (packages/cli/src/stage.ts): runs <this dir>/versions/<current>/${name}, <current> read from <this dir>/current.`,
    "import { readFileSync } from 'node:fs'",
    "import { dirname, join } from 'node:path'",
    "import { fileURLToPath, pathToFileURL } from 'node:url'",
    'const pkg = dirname(fileURLToPath(import.meta.url))',
    "let v = ''",
    'try {',
    "  v = readFileSync(join(pkg, 'current'), 'utf8').trim()",
    '} catch {}',
    "if (!/^[0-9A-Za-z][0-9A-Za-z.+_-]*$/.test(v) || v.includes('..')) {",
    "  process.stderr.write('bag: no version named in ' + join(pkg, 'current') + ': run the install again\\n')",
    '  process.exit(1)',
    '}',
    `const m = await import(pathToFileURL(join(pkg, 'versions', v, ${JSON.stringify(name)})).href)`,
    '// omp loads its wake extension by its default export; the others export none.',
    'export default m.default',
    '',
  ].join('\n')

/** Whether two directories hold the same files, byte for byte (`b` may hold no more and no fewer). */
function same(a: string, b: string): boolean {
  const files = readdirSync(a).filter((f) => statSync(join(a, f)).isFile())
  const there = readdirSync(b).filter((f) => statSync(join(b, f)).isFile())
  return (
    files.length === there.length &&
    files.every((f) => existsSync(join(b, f)) && readFileSync(join(a, f)).equals(readFileSync(join(b, f))))
  )
}

/** Writes `text` to `file` beside and renamed over (named with `pid`), 0600. */
function replace(file: string, text: string, pid: number): void {
  const tmp = `${file}.${pid}.tmp`
  writeFileSync(tmp, text, { mode: 0o600 })
  renameSync(tmp, file)
}

/**
 * The entries staging `b` for `home` returns, worked out with nothing written: the launchers under <home>/package/ (and
 * the version directory's own), or from source the checkout's. A plan names these before its question; stage writes
 * them after the yes.
 */
export function stagedMains(home: string, b: Build): Staged {
  const { cli, mcp, omp } = b
  if (!b.packaged) return { cli, mcp, omp, shim: b.shim, copied: null, notice: null, versioned: null }
  const pkg = join(home, 'package')
  const to = join(pkg, 'versions', b.version)
  const at = (d: string) => (f: string) => join(d, basename(f))
  const [v, l] = [at(to), at(pkg)]
  const versioned = { cli: v(cli), mcp: v(mcp), omp: v(omp), shim: v('bag-shim.js') }
  return {
    cli: l(cli),
    mcp: l(mcp),
    omp: l(omp),
    shim: l('bag-shim.js'),
    copied: null,
    notice: null,
    versioned,
  }
}

/**
 * Stages the package `b` for `home` (see above) and returns the entries in its version directory; from source, the
 * checkout's. A version directory already there with other bytes (two builds of one version) refuses `exists`. `pid`
 * names what is written beside and renamed in.
 */
export function stage(home: string, b: Build, pid: number): Staged {
  const { packaged, version, cli, mcp, omp } = b
  if (!packaged) return stagedMains(home, b)
  const pkg = join(home, 'package')
  const versions = join(pkg, 'versions')
  const to = join(versions, version)
  const from = dirname(cli)
  mkdirSync(versions, { recursive: true, mode: 0o700 })
  chmodSync(pkg, 0o700)
  let copied: string | null = null
  if (existsSync(to)) {
    if (from !== to && !same(from, to)) {
      throw new HomeError(
        'exists',
        `${to} holds another build of bag ${version}: a released version is built once; move that directory away to stage this one`,
      )
    }
  } else {
    const tmp = join(versions, `.${version}.${pid}.tmp`)
    mkdirSync(tmp, { mode: 0o700 })
    for (const f of readdirSync(from).filter((x) => statSync(join(from, x)).isFile())) {
      copyFileSync(join(from, f), join(tmp, f))
      chmodSync(join(tmp, f), statSync(join(from, f)).mode & 0o755)
    }
    renameSync(tmp, to)
    copied = to
  }
  const current = join(pkg, 'current')
  const was = existsSync(current) ? readFileSync(current, 'utf8').trim() : null
  if (was !== version) replace(current, `${version}\n`, pid)
  // The launchers every host file names: <home>/package/<name>, rewritten at every stage, each running the version
  // current names; so a prune of an old version, or a new current, never leaves a host entry or hook pointing at nothing.
  const names = [basename(cli), basename(mcp), basename(omp), 'bag-shim.js']
  for (const name of names) {
    replace(join(pkg, name), launcherText(name), pid)
    chmodSync(join(pkg, name), 0o755)
  }
  let notice: string | null = null
  try {
    const s = JSON.parse(readFileSync(join(home, 'run', 'service.json'), 'utf8')) as {
      pid?: unknown
      package_dir?: unknown
    }
    // service.json names the directory by its real path (/private/tmp for /tmp on macOS).
    const real = (x: string) => {
      try {
        return realpathSync(x)
      } catch {
        return x
      }
    }
    if (typeof s.package_dir === 'string' && real(s.package_dir) !== real(to)) {
      notice = `the running bag service (pid ${String(s.pid)}) moves to bag ${version} at its next drain and restart`
    }
  } catch {
    // no service.json: no running service to tell about
  }
  return { ...stagedMains(home, b), copied, notice }
}

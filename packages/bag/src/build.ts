// The published package @usebag/bag: one bundle of the CLI, the MCP server and the A2A bridge, made with rolldown
// (already in the lock as vitest's bundler, so no new package), into dist/. Each process entry becomes a bin with a
// shebang (dist/bag.js, dist/bag-mcp.js, dist/bag-a2a.js); the code they share sits beside them in chunks. The
// workspace packages are bundled in from their TypeScript source (Node refuses type stripping under node_modules, so a
// package cannot ship the .ts files), and so are @modelcontextprotocol/sdk and zod with the parts of their own
// dependencies the server reaches, at the lock's versions: the package has no dependency, npx fetches one tarball and
// runs no install script, nothing floats, and dist/ alone runs from any directory (the CLI's packaged.ts copies it to
// a stable place). Every import left in the bundle is a Node built-in. The bundled packages' licences are appended to
// dist/THIRD-PARTY.md. Two source modules are replaced as they load: the edge's build-info.ts with the version and the
// commit, and the CLI's entries.ts with the bins' paths.
import { execFileSync } from 'node:child_process'
import {
  appendFileSync,
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
} from 'node:fs'
import { isBuiltin } from 'node:module'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build as bundle } from 'rolldown'

/** The repository's root and this package's directory. */
export const PACKAGE = fileURLToPath(new URL('..', import.meta.url))
export const ROOT = join(PACKAGE, '..', '..')

/** The bins: their names in package.json, and the source each is built from. */
export const ENTRIES: Readonly<Record<string, string>> = {
  bag: 'packages/cli/src/main.ts',
  'bag-mcp': 'packages/mcp/src/main.ts',
  'bag-a2a': 'packages/a2a/src/main.ts',
}

/** The package's version, from its package.json. */
export function packageVersion(dir = PACKAGE): string {
  return JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).version
}

/**
 * The commit the build is made from: HEAD of the repository at `root`, with `-dirty` when a tracked or untracked file
 * the bundle may read (packages/, the root package.json and lock) differs from it. A dirty commit is never a published
 * cut, so the telemetry report names it `other`.
 */
export function sourceCommit(root = ROOT): string {
  const git = (...args: string[]) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' }).trim()
  const head = git('rev-parse', '--verify', 'HEAD^{commit}')
  const changed = git('status', '--porcelain', '--', 'packages', 'package.json', 'package-lock.json')
  return changed === '' ? head : `${head}-dirty`
}

/** A built chunk as rolldown reports it: its file, what it imports, and the modules (absolute ids) it holds. */
export interface Chunk {
  readonly fileName: string
  readonly imports: readonly string[]
  readonly dynamicImports: readonly string[]
  readonly moduleIds: readonly string[]
}

/** Throws on an import of `chunks` that is neither another chunk nor a Node built-in, naming each as `<file>: <it>`. */
export function checkImports(chunks: readonly Chunk[]): void {
  const files = new Set(chunks.map((c) => c.fileName))
  const allowed = (s: string) => files.has(s) || isBuiltin(s)
  const stray = chunks.flatMap((c) =>
    [...c.imports, ...c.dynamicImports].filter((s) => !allowed(s)).map((s) => `${c.fileName}: ${s}`),
  )
  if (stray.length > 0) throw new Error(`the bundle imports what it does not hold: ${stray.join(', ')}`)
}

/** The npm packages the modules `ids` come from, as `node_modules/<name>` directories under `root`, sorted. */
export function bundledPackages(ids: readonly string[], root = ROOT): string[] {
  const dirs = new Set<string>()
  for (const id of ids) {
    const parts = relative(root, id).split(sep)
    const at = parts.lastIndexOf('node_modules')
    if (at < 0) continue
    const scoped = String(parts[at + 1]).startsWith('@')
    dirs.add(parts.slice(0, at + (scoped ? 3 : 2)).join('/'))
  }
  return [...dirs].sort()
}

/** The notice of one bundled package: name, version and licence from its package.json, then its licence files. */
export function notice(dir: string): string {
  const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'))
  const texts = readdirSync(dir)
    .filter((f) => /^(licen[cs]e|copying|notice)/i.test(f))
    .sort()
    .map((f) => readFileSync(join(dir, f), 'utf8').trim())
  if (texts.length === 0) throw new Error(`${dir} has no licence file to carry`)
  return `\n## ${pkg.name} ${pkg.version} (${pkg.license})\n\n${texts.join('\n\n')}\n`
}

/** What a build made: the version and the commit it carries, and the files in dist/. */
export interface Built {
  readonly version: string
  readonly commit: string
  readonly files: readonly string[]
  /** The bundled npm packages, as node_modules/<name>. */
  readonly packages: readonly string[]
}

/**
 * Builds the package into `out` (dist/ by default), emptied first: the bundle, wordlist.json beside it (the edge reads
 * it at its import.meta.url), the licence, and the third-party notices with every bundled npm package's licence.
 * Throws when the bundle imports anything but its own chunks and Node built-ins.
 */
export async function build(out = join(PACKAGE, 'dist'), commit = sourceCommit()): Promise<Built> {
  const version = packageVersion()
  const replaced = new Map([
    [
      realpathSync(join(ROOT, 'packages/edge/src/build-info.ts')),
      `export const BUILD_INFO = ${JSON.stringify({ version, commit })}\n`,
    ],
    [
      realpathSync(join(ROOT, 'packages/cli/src/entries.ts')),
      [
        "import { fileURLToPath } from 'node:url'",
        "export const CLI_MAIN = fileURLToPath(new URL('./bag.js', import.meta.url))",
        "export const MCP_MAIN = fileURLToPath(new URL('./bag-mcp.js', import.meta.url))",
        'export const PACKAGED = true',
        '',
      ].join('\n'),
    ],
  ])
  rmSync(out, { recursive: true, force: true })
  mkdirSync(out, { recursive: true })
  const input = Object.fromEntries(Object.entries(ENTRIES).map(([name, src]) => [name, join(ROOT, src)]))
  const { output } = await bundle({
    input,
    platform: 'node',
    cwd: ROOT,
    plugins: [{ name: 'bag-build-info', load: (id) => replaced.get(id) ?? null }],
    output: {
      dir: out,
      format: 'esm',
      entryFileNames: '[name].js',
      chunkFileNames: '[name]-[hash].js',
      banner: (chunk) => (chunk.isEntry ? '#!/usr/bin/env node' : ''),
    },
  })
  for (const name of Object.keys(ENTRIES)) chmodSync(join(out, `${name}.js`), 0o755)
  copyFileSync(join(ROOT, 'packages/edge/src/wordlist.json'), join(out, 'wordlist.json'))
  // The public repository has LICENSE at its root; the private one keeps it in cut/ until the public act, and a
  // private-mode cut has neither, so its gate builds without one (the publish workflow checks dist/LICENSE).
  const licence = [join(ROOT, 'LICENSE'), join(ROOT, 'cut/LICENSE')].find((f) => existsSync(f))
  if (licence !== undefined) copyFileSync(licence, join(out, 'LICENSE'))
  const chunks = output.filter((o) => o.type === 'chunk') as readonly Chunk[]
  checkImports(chunks)
  const third = join(out, 'THIRD-PARTY.md')
  copyFileSync(join(ROOT, 'THIRD-PARTY.md'), third)
  const packages = bundledPackages(chunks.flatMap((c) => c.moduleIds))
  appendFileSync(third, '\n# npm packages bundled in dist/ (packages/bag/src/build.ts)\n')
  for (const dir of packages) appendFileSync(third, notice(join(ROOT, dir)))
  return { version, commit, files: readdirSync(out).sort(), packages }
}

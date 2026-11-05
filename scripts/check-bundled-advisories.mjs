#!/usr/bin/env node
// Fails when an npm package bundled into @usebag/bag has a security advisory:
//
//   node scripts/check-bundled-advisories.mjs                     # npm run audit:bundled: builds the bundle, then asks
//   node scripts/check-bundled-advisories.mjs --manifest <file>   # a JSON list of {name, version} instead of a build
//
// The published package is one bundle with no dependencies field: packages/bag/src/build.ts inlines the MCP SDK, zod
// and their libraries from this repository's node_modules at the lock's versions. npm audit on this repository sees
// them only as dev dependencies (security.yml fails those at high and critical), Dependabot sees them the same way,
// and a user who installed the bundle sees nothing at all: a fixed advisory reaches users only when the package is
// published again. This check reads the bundle's own manifest (the packages the build reports, each name and version
// from its package.json), writes a synthetic lockfile holding exactly those, and runs `npm audit --package-lock-only`
// on it, so the question goes to the same bulk advisory endpoint npm audit uses, at the registry npm is configured
// for, through any proxy npm is configured for, with npm's own version matching, and with no token (GitHub's advisory
// API answers without one too, but at a per-address rate limit that a shared runner can hit; from memory). Any
// advisory, at any severity, fails: exit 1 with one plain line per advisory. A build or registry failure is exit 2,
// never a pass. The bundle is built into a temporary directory under AC_TEST_TMP (default TMPDIR), never into dist/.

import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))

/** The bundled packages: for each `node_modules/<name>` directory the build reports, its name and version. */
export function manifestOf(dirs, root = ROOT) {
  return dirs.map((path) => {
    const { name, version } = JSON.parse(readFileSync(join(root, path, 'package.json'), 'utf8'))
    return { path, name, version }
  })
}

/** A manifest read from a JSON file: a list of {name, version}, each placed at node_modules/<name>. */
export function manifestFrom(text) {
  const list = JSON.parse(text)
  if (!Array.isArray(list)) throw new Error('the manifest is not a JSON list')
  return list.map((entry, i) => {
    if (typeof entry?.name !== 'string' || typeof entry?.version !== 'string')
      throw new Error(`manifest entry ${i} has no name and version`)
    return { path: `node_modules/${entry.name}`, name: entry.name, version: entry.version }
  })
}

/**
 * A package.json and a v3 package-lock.json that hold exactly the manifest's packages, each at its path, so that
 * `npm audit --package-lock-only` judges those versions and nothing else (an entry without an edge to it is still
 * audited: nested and extraneous nodes count).
 */
export function syntheticProject(manifest) {
  const dependencies = {}
  const packages = { '': { name: 'bag-bundled-packages', version: '0.0.0', dependencies } }
  for (const { path, name, version } of manifest) {
    if (path === `node_modules/${name}`) dependencies[name] = version
    packages[path] = { version }
  }
  return {
    packageJson: { name: 'bag-bundled-packages', version: '0.0.0', private: true, dependencies },
    lock: { name: 'bag-bundled-packages', version: '0.0.0', lockfileVersion: 3, requires: true, packages },
  }
}

/** One line per advisory in an `npm audit --json` report, `<name>@<version>: <severity> <title> (<url>; <range>)`. */
export function advisoryLines(report, manifest) {
  const versionAt = new Map(manifest.map((m) => [m.path, m.version]))
  const lines = []
  for (const v of Object.values(report.vulnerabilities ?? {})) {
    const versions = [...new Set((v.nodes ?? []).map((n) => versionAt.get(n) ?? '?'))].join(', ')
    for (const via of v.via ?? []) {
      if (typeof via !== 'object') continue // a name: reached through another vulnerable package, listed on its own
      lines.push(`${v.name}@${versions}: ${via.severity} ${via.title} (${via.url}; vulnerable ${via.range})`)
    }
  }
  return lines.sort()
}

/** Builds the bundle into a fresh directory under `tmp` and returns its manifest. */
async function builtManifest(tmp) {
  const { build } = await import(pathToFileURL(join(ROOT, 'packages/bag/src/build.ts')).href)
  const built = await build(join(tmp, 'dist'), 'check')
  return manifestOf(built.packages)
}

/** Runs npm audit on the synthetic project in `dir`; the parsed report, or an error naming what npm said. */
function audit(dir, manifest) {
  const { packageJson, lock } = syntheticProject(manifest)
  writeFileSync(join(dir, 'package.json'), `${JSON.stringify(packageJson, null, 2)}\n`)
  writeFileSync(join(dir, 'package-lock.json'), `${JSON.stringify(lock, null, 2)}\n`)
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'
  const args = ['audit', '--json', '--package-lock-only', '--audit-level=low', '--no-fund']
  const run = spawnSync(npm, args, {
    cwd: dir,
    encoding: 'utf8',
    env: { ...process.env, NODE_ENV: undefined },
  })
  if (run.error) throw new Error(`npm did not start: ${run.error.message}`)
  let report
  try {
    report = JSON.parse(run.stdout)
  } catch {
    throw new Error(`npm audit gave no JSON report (exit ${run.status}): ${run.stderr.trim()}`)
  }
  if (report.error)
    throw new Error(`npm audit failed: ${report.error.summary ?? report.error.code ?? 'unknown'}`)
  if (!(run.status === 0 || run.status === 1))
    throw new Error(`npm audit exited ${run.status}: ${run.stderr.trim()}`)
  return report
}

async function main(argv) {
  const flag = argv.indexOf('--manifest')
  const tmpRoot = process.env.AC_TEST_TMP ?? tmpdir()
  const tmp = mkdtempSync(join(tmpRoot, 'bag-bundled-advisories-'))
  try {
    const manifest =
      flag >= 0 ? manifestFrom(readFileSync(String(argv[flag + 1]), 'utf8')) : await builtManifest(tmp)
    if (manifest.length === 0) throw new Error('the manifest names no package')
    const lines = advisoryLines(audit(tmp, manifest), manifest)
    const what = `${manifest.length} bundled package(s): ${manifest.map((m) => `${m.name}@${m.version}`).join(', ')}`
    for (const line of lines) console.error(`check-bundled-advisories: ${line}`)
    if (lines.length > 0) {
      console.error(
        `check-bundled-advisories: ${lines.length} advisory(ies) in ${what}; update the lock and publish`,
      )
      return 1
    }
    console.log(`check-bundled-advisories: pass (no advisory in ${what})`)
    return 0
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error) => {
      console.error(`check-bundled-advisories: ${error.message}`)
      process.exit(2)
    },
  )
}

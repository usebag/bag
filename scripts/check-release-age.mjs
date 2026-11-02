#!/usr/bin/env node
// Fails when package-lock.json holds a version younger than the cooldown, or one that did not come from the
// npm registry with an integrity hash:
//
//   node scripts/check-release-age.mjs                 # the cooldown from .npmrc (min-release-age), else 7 days
//   node scripts/check-release-age.mjs --days 7
//
// A malicious publish to npm has so far been found and pulled within hours to a few days, so a version is
// adopted only once it has been public for 7 days. npm 12 resolves that way itself (min-release-age in
// .npmrc); this check holds the lock to the rule whatever npm wrote it. Ages only grow, so a lock that passes
// once keeps passing. A package named in .npmrc's min-release-age-exclude[] is exempt from the age check (a
// security fix let through by hand, with a dated comment saying why) but never from the registry and
// integrity rules. Publish times come from the registry (https://registry.npmjs.org); nothing is installed.

import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

export const REGISTRY = 'https://registry.npmjs.org/'
const DAY_MS = 86_400_000

/** `min-release-age` and the `min-release-age-exclude[]` names from the text of an .npmrc. */
export function readNpmrc(text) {
  let days
  const exempt = new Set()
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || line.startsWith('#') || line.startsWith(';')) continue
    const at = line.indexOf('=')
    if (at < 0) continue
    const key = line.slice(0, at).trim()
    const value = line.slice(at + 1).trim()
    if (key === 'min-release-age') days = Number(value)
    if (key === 'min-release-age-exclude[]') exempt.add(value)
  }
  return { days, exempt }
}

/**
 * Every installed package of a v2/v3 lockfile: its name (from the path), version, resolved URL, integrity. The
 * root and this repository's own workspaces (`packages/*`, the entries outside node_modules/, and their links) are
 * not from the registry and are skipped.
 */
export function lockedPackages(lock) {
  const out = []
  for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    if (path === '' || entry.link || !path.includes('node_modules/')) continue
    const name = entry.name ?? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length)
    out.push({ path, name, version: entry.version, resolved: entry.resolved, integrity: entry.integrity })
  }
  return out
}

/** Entries not from the registry, or without a sha512 integrity: each is a problem, exempt or not. */
export function sourceProblems(packages) {
  const problems = []
  for (const p of packages) {
    if (typeof p.resolved !== 'string' || !p.resolved.startsWith(REGISTRY)) {
      problems.push(`${p.path}: resolved from ${p.resolved ?? 'nowhere'}, not ${REGISTRY}`)
    }
    if (typeof p.integrity !== 'string' || !p.integrity.startsWith('sha512-')) {
      problems.push(`${p.path}: no sha512 integrity`)
    }
  }
  return problems
}

/**
 * Versions younger than `days` at `now`. `published` maps `name@version` to its publish time (ISO text);
 * a version missing from it counts as young. Exempt names are skipped.
 */
export function youngVersions(packages, published, { now, days, exempt }) {
  const cutoff = now.getTime() - days * DAY_MS
  const seen = new Set()
  const young = []
  for (const { name, version } of packages) {
    const id = `${name}@${version}`
    if (seen.has(id) || exempt.has(name)) continue
    seen.add(id)
    const time = published.get(id)
    if (time === undefined) {
      young.push(`${id}: no publish time in the registry`)
      continue
    }
    const at = Date.parse(time)
    if (at > cutoff) {
      const hours = Math.floor((now.getTime() - at) / 3_600_000)
      young.push(
        `${id}: published ${time.slice(0, 16).replace('T', ' ')} UTC, ${Math.floor(hours / 24)} days ${hours % 24} h ago`,
      )
    }
  }
  return young
}

async function publishTimes(packages, fetchImpl = fetch) {
  const byName = new Map()
  for (const { name, version } of packages) byName.set(name, (byName.get(name) ?? new Set()).add(version))
  const published = new Map()
  const names = [...byName.keys()]
  const worker = async () => {
    for (let name = names.pop(); name !== undefined; name = names.pop()) {
      const response = await fetchImpl(REGISTRY + name.replace('/', '%2f'))
      if (!response.ok) throw new Error(`${REGISTRY}${name}: HTTP ${response.status}`)
      const { time = {} } = await response.json()
      for (const version of byName.get(name)) {
        if (time[version] !== undefined) published.set(`${name}@${version}`, time[version])
      }
    }
  }
  await Promise.all(Array.from({ length: 16 }, worker))
  return published
}

async function main(argv) {
  const npmrc = readNpmrc(readFileSync('.npmrc', 'utf8'))
  const flag = argv.indexOf('--days')
  const days = flag >= 0 ? Number(argv[flag + 1]) : (npmrc.days ?? 7)
  if (!Number.isFinite(days) || days < 0)
    throw new Error(`--days must be a number of days, got ${argv[flag + 1]}`)
  const packages = lockedPackages(JSON.parse(readFileSync('package-lock.json', 'utf8')))
  const problems = sourceProblems(packages)
  const young = youngVersions(packages, await publishTimes(packages), {
    now: new Date(),
    days,
    exempt: npmrc.exempt,
  })
  for (const line of [...problems, ...young]) console.error(`check-release-age: ${line}`)
  if (problems.length > 0 || young.length > 0) {
    console.error(
      `check-release-age: ${problems.length} source problem(s), ${young.length} version(s) younger than ${days} days; ` +
        'wait, or exempt a security fix in .npmrc (min-release-age-exclude[]) with a dated reason',
    )
    return 1
  }
  console.log(`check-release-age: pass (${packages.length} locked packages, cooldown ${days} days)`)
  return 0
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error) => {
      console.error(`check-release-age: ${error.message}`)
      process.exit(2)
    },
  )
}

#!/usr/bin/env node
// Writes, or checks, the notices of the Rust crates the relay binary is built from:
//
//   node scripts/rust-notices.mjs           # writes crates/ac-relay/THIRD-PARTY-RUST.md
//   node scripts/rust-notices.mjs --check   # fails when that file is not what this script writes
//
// The relay's release archives (.github/workflows/relay-binaries.yml) distribute ac-relay as a binary, and every crate
// compiled into it is distributed with it, so each crate's licence notice goes into the archive. This script reads
// `cargo metadata --format-version 1 --locked --offline --filter-platform <target>` for the three release targets (no
// network and no build: the resolve of Cargo.lock and the crate sources already in the local cargo cache), takes the
// crates ac-relay reaches through normal dependencies (not build or dev ones; this workspace's own crates excluded),
// and writes each crate's name, version, licence expression and repository, grouped by licence, followed by the licence
// texts the crates ship (their LICENSE, LICENCE, COPYING, NOTICE and COPYRIGHT files), each distinct text once. It
// fails, exit 1, when a crate has no licence expression or one deny.toml does not allow (its [licenses] allow list,
// and the per-crate exceptions there), and in --check mode when the committed file differs. A cargo failure is exit 2.

import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const OUT = 'crates/ac-relay/THIRD-PARTY-RUST.md'
const BINARY = 'ac-relay'
export const TARGETS = ['x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl', 'aarch64-apple-darwin']
const LICENCE_FILE = /^(licen[cs]e|copying|notice|copyright)/i

/** deny.toml's [licenses] allow list and its per-crate exceptions: { allow: Set, exceptions: Map<crate, Set> }. */
export function denyLicences(text) {
  const section = text.split(/^\[licenses\]\s*$/m)[1]?.split(/^\[/m)[0]
  if (section === undefined) throw new Error('deny.toml has no [licenses] section')
  const strings = (s) => [...s.matchAll(/"([^"]*)"/g)].map((m) => m[1])
  const allow = section.match(/^allow\s*=\s*\[([^\]]*)\]/m)
  if (allow === null) throw new Error('deny.toml [licenses] has no allow list')
  const exceptions = new Map()
  for (const m of section.matchAll(/\{\s*allow\s*=\s*\[([^\]]*)\]\s*,\s*crate\s*=\s*"([^"]+)"\s*\}/g))
    exceptions.set(m[2], new Set(strings(m[1])))
  return { allow: new Set(strings(allow[1])), exceptions }
}

/** The packages `binary` reaches through normal dependencies in one `cargo metadata` result, workspace members excluded. */
export function shippedPackages(metadata, binary = BINARY) {
  const packages = new Map(metadata.packages.map((p) => [p.id, p]))
  const members = new Set(metadata.workspace_members)
  const nodes = new Map(metadata.resolve.nodes.map((n) => [n.id, n]))
  const root = metadata.workspace_members.find((id) => packages.get(id)?.name === binary)
  if (root === undefined) throw new Error(`the workspace has no package ${binary}`)
  const seen = new Set()
  const stack = [root]
  while (stack.length > 0) {
    for (const dep of nodes.get(stack.pop())?.deps ?? []) {
      if (seen.has(dep.pkg) || !dep.dep_kinds.some((k) => k.kind === null)) continue
      seen.add(dep.pkg)
      stack.push(dep.pkg)
    }
  }
  return [...seen].filter((id) => !members.has(id)).map((id) => packages.get(id))
}

/** Whether an SPDX expression (AND, OR, WITH, parentheses; the old "A/B" form read as OR) holds under `allowed`. */
export function expressionAllowed(expression, allowed) {
  const tokens = expression
    .replaceAll('/', ' OR ')
    .replaceAll('(', ' ( ')
    .replaceAll(')', ' ) ')
    .split(/\s+/)
    .filter(Boolean)
  let i = 0
  const peek = () => tokens[i]
  const take = () => tokens[i++]
  const atom = () => {
    const t = take()
    if (t === undefined) throw new Error('the expression ends early')
    if (t === '(') {
      const v = or()
      if (take() !== ')') throw new Error('a parenthesis is not closed')
      return v
    }
    if (['AND', 'OR', 'WITH', ')'].includes(t)) throw new Error(`"${t}" where a licence belongs`)
    const id = t.replace(/\+$/, '')
    if (peek() === 'WITH') {
      take()
      const exception = take()
      if (exception === undefined) throw new Error('WITH names no exception')
      return allowed.has(`${id} WITH ${exception}`)
    }
    return allowed.has(id)
  }
  const and = () => {
    let v = atom()
    while (peek() === 'AND') {
      take()
      v = atom() && v
    }
    return v
  }
  const or = () => {
    let v = and()
    while (peek() === 'OR') {
      take()
      v = and() || v
    }
    return v
  }
  const value = or()
  if (i !== tokens.length) throw new Error(`"${tokens[i]}" after the expression`)
  return value
}

/** The licence files at the root of a crate's source, each { file, text }, the text with LF ends and no trailing spaces. */
export function licenceTexts(manifestPath) {
  const dir = dirname(manifestPath)
  return readdirSync(dir)
    .filter((f) => LICENCE_FILE.test(f) && statSync(join(dir, f)).isFile())
    .sort()
    .map((file) => {
      const lines = readFileSync(join(dir, file), 'utf8').replaceAll('\r\n', '\n').split('\n')
      const text = lines
        .map((l) => l.trimEnd())
        .join('\n')
        .trim()
      return { file, text }
    })
}

/** One problem line per crate whose licence is missing or not allowed by deny.toml. */
export function licenceProblems(crates, deny) {
  const problems = []
  for (const c of crates) {
    if (!c.license) {
      problems.push(`${c.name} ${c.version}: no licence expression in its Cargo.toml`)
      continue
    }
    const allowed = new Set([...deny.allow, ...(deny.exceptions.get(c.name) ?? [])])
    let ok
    try {
      ok = expressionAllowed(c.license, allowed)
    } catch (error) {
      problems.push(`${c.name} ${c.version}: the licence "${c.license}" does not parse (${error.message})`)
      continue
    }
    if (!ok) problems.push(`${c.name} ${c.version}: the licence "${c.license}" is not allowed by deny.toml`)
  }
  return problems
}

/** The notices file: the crates grouped by licence expression, then each distinct licence text once. */
export function render(crates) {
  const byName = (a, b) =>
    a.name === b.name ? a.version.localeCompare(b.version) : a.name.localeCompare(b.name)
  const sorted = [...crates].sort(byName)
  const groups = new Map()
  for (const c of sorted) {
    const key = c.license.replaceAll('/', ' OR ')
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(c)
  }
  const texts = new Map() // the same text, up to white space: one entry, the first crate's copy printed
  for (const c of sorted) {
    for (const { file, text } of c.texts) {
      const key = text.replace(/\s+/g, ' ')
      if (!texts.has(key)) texts.set(key, { text, users: [] })
      texts.get(key).users.push(`${c.name} ${c.version} (${file})`)
    }
  }
  const out = [
    '# Third-party notices: the Rust crates of the relay',
    '',
    'The relay binary, `ac-relay`, is built from the crates below, and its release archives distribute them with it.',
    'This file is generated by `scripts/rust-notices.mjs` from `Cargo.lock`: the crates `ac-relay` reaches through',
    'normal dependencies, not build or dev ones, for the targets of the release archives:',
    '',
    ...TARGETS.map((t) => `- ${t}`),
    '',
    'Do not edit it; run `node scripts/rust-notices.mjs` after a change to `Cargo.lock`. A licence text that several',
    'crates ship is printed once, under the first of them, and names the others.',
    '',
    `## The crates, by licence (${sorted.length})`,
    '',
  ]
  for (const key of [...groups.keys()].sort()) {
    out.push(`### ${key}`, '')
    for (const c of groups.get(key))
      out.push(`- ${c.name} ${c.version}${c.repository ? `, ${c.repository}` : ''}`)
    out.push('')
  }
  out.push(`## The licence texts (${texts.size})`, '')
  const entries = [...texts.values()].sort((a, b) => a.users[0].localeCompare(b.users[0]))
  for (const { text, users } of entries) {
    out.push(`### ${users[0]}`, '')
    if (users.length > 1) out.push(`The same text: ${users.slice(1).join(', ')}.`, '')
    out.push('````text', text, '````', '')
  }
  return `${out.join('\n').trimEnd()}\n`
}

/** The union over the release targets of the crates ac-relay ships, each with its licence texts. */
function crates() {
  const byId = new Map()
  for (const target of TARGETS) {
    const args = ['metadata', '--format-version', '1', '--locked', '--offline', '--filter-platform', target]
    const run = spawnSync('cargo', args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
    if (run.error) throw new Error(`cargo did not start: ${run.error.message}`)
    if (run.status !== 0)
      throw new Error(`cargo metadata for ${target} exited ${run.status}: ${run.stderr.trim()}`)
    for (const p of shippedPackages(JSON.parse(run.stdout))) byId.set(p.id, p)
  }
  return [...byId.values()].map((p) => ({
    name: p.name,
    version: p.version,
    license: p.license ?? null,
    repository: p.repository ?? null,
    texts: licenceTexts(p.manifest_path),
  }))
}

function main(argv) {
  const check = argv.includes('--check')
  const deny = denyLicences(readFileSync(join(ROOT, 'deny.toml'), 'utf8'))
  const list = crates()
  const problems = licenceProblems(list, deny)
  for (const line of problems) console.error(`rust-notices: ${line}`)
  if (problems.length > 0) {
    console.error(`rust-notices: ${problems.length} crate(s) of ${list.length} without an allowed licence`)
    return 1
  }
  const text = render(list)
  const path = join(ROOT, OUT)
  if (check) {
    if (!existsSync(path) || readFileSync(path, 'utf8') !== text) {
      console.error(`rust-notices: ${OUT} is stale; run node scripts/rust-notices.mjs and commit it`)
      return 1
    }
    console.log(`rust-notices: pass (${list.length} crates, every licence allowed, ${OUT} current)`)
    return 0
  }
  writeFileSync(path, text)
  console.log(`rust-notices: wrote ${OUT} (${list.length} crates, every licence allowed)`)
  return 0
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exit(main(process.argv.slice(2)))
  } catch (error) {
    console.error(`rust-notices: ${error.message}`)
    process.exit(2)
  }
}

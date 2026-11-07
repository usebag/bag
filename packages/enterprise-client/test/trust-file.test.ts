import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import * as core from '@usebag/core'
import { afterAll, describe, expect, it } from 'vitest'
import { readTrustFile, syncSourcedTrust, type TrustRoots, writeTrustFile } from '../src/trust-file.ts'
import { T0, tempDir } from './support/fixtures.ts'

// The trust file's provenance (the agent contract's trust roots), as bag's own readers read it.

const tmp = tempDir('trust')
afterAll(() => tmp.cleanup())
let n = 0
const home = (roots?: unknown): string => {
  const dir = join(tmp.dir, `h${n++}`)
  mkdirSync(dir)
  if (roots !== undefined)
    writeFileSync(join(dir, 'trust.json'), JSON.stringify({ version: 1, roots }), { mode: 0o600 })
  return dir
}
const fail = (detail: string): Error => Object.assign(new Error(detail), { code: 'trust-invalid' })
const org = (root: string, source = 'org:acme.example') => ({ root, source, granted_by: 'p1', granted_at: 7 })
const owns = (s: string) => s === 'org:acme.example' || s.startsWith('peer:')
/** The rule of bag's own readers: a root and an integer added_at, other members ignored. */
const oldReader = (roots: TrustRoots) =>
  Object.entries(roots).every(
    ([a, e]) => (core.isAddress(a) || core.domainOfRoot(a) !== null) && Number.isSafeInteger(e.added_at),
  )

describe('the trust file with provenance', () => {
  it('adds the organisation roots with provenance, keeps a person root as it is, and removes the set at sign-out', () => {
    const h = home({ 'domain:friend.example': { added_at: 1 }, 'domain:acme.example': { added_at: 2 } })
    const sync = syncSourcedTrust(
      h,
      owns,
      [org('domain:acme.example'), org('domain:peer.example', 'peer:l1')],
      T0,
      fail,
    )
    expect(sync).toEqual({ added: ['domain:peer.example'], removed: [], person: ['domain:acme.example'] })
    const roots = readTrustFile(h, fail)
    expect(roots['domain:peer.example']).toEqual({
      added_at: T0,
      source: 'peer:l1',
      granted_by: 'p1',
      granted_at: 7,
    })
    expect(roots['domain:acme.example']).toEqual({ added_at: 2 })
    expect(oldReader(roots)).toBe(true)
    expect(syncSourcedTrust(h, owns, [], T0, fail).removed).toEqual(['domain:peer.example'])
    expect(Object.keys(readTrustFile(h, fail))).toEqual(['domain:friend.example', 'domain:acme.example'])
  })

  it('another organisation entry is not this session to remove; never *, never a bad source, at most 64', () => {
    const h = home({
      'domain:o.example': { added_at: 1, source: 'org:other.example', granted_by: null, granted_at: 1 },
    })
    syncSourcedTrust(h, owns, [], T0, fail)
    expect(Object.keys(readTrustFile(h, fail))).toEqual(['domain:o.example'])
    for (const bad of [
      org('*'),
      org('domain:x.example', 'org:other.example'),
      org('domain:x.example', 'person'),
      { ...org('domain:x.example'), granted_by: 5 },
    ]) {
      expect(() => syncSourcedTrust(h, owns, [bad as never], T0, fail)).toThrow(/a trust file never holds/)
    }
    const many = Array.from({ length: 64 }, (_, i) => org(`domain:p${i}.example`))
    expect(() => syncSourcedTrust(h, owns, many, T0, fail)).toThrow(/over 64/)
    expect(syncSourcedTrust(h, owns, many.slice(1), T0, fail).added).toHaveLength(63)
  })

  it('a reader refuses an entry whose provenance is malformed, or more than 64 sourced entries', () => {
    const bad = [
      { 'domain:a.example': { added_at: 1, source: 'org:Bad Domain', granted_by: null, granted_at: 1 } },
      { 'domain:a.example': { added_at: 1, source: 'org:a.example', granted_by: null } },
      { 'domain:a.example': { added_at: 1, granted_by: 'p' } },
      { '*': { added_at: 1 } },
      Object.fromEntries(
        Array.from({ length: 65 }, (_, i) => [`domain:p${i}.example`, { added_at: 1, ...org('', 'peer:x') }]),
      ),
    ]
    for (const roots of bad)
      expect(() => readTrustFile(home(roots), fail)).toThrow(/is not a trust file of version 1/)
    const h = home()
    writeFileSync(join(h, 'trust.json'), '{', { mode: 0o600 })
    expect(() => readTrustFile(h, fail)).toThrow(/cannot be read as JSON/)
    writeTrustFile(h, { 'domain:a.example': { added_at: 1 } })
    expect(JSON.parse(readFileSync(join(h, 'trust.json'), 'utf8')).version).toBe(1)
  })
})

import { mkdirSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { MAX_RELAYS } from '@usebag/core'
import { generateEdgeKeys, systemRng } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  addIdentity,
  checkIdentities,
  type Identities,
  keyOf,
  MAX_IDENTITIES,
  PROFILES,
  publishedRefusal,
  readIdentities,
  relayUrl,
  removeIdentity,
  saveIdentities,
  trustedRoot,
} from '../src/index.ts'
import { PUBLISHED_REFUSAL, RELAYS_CASES, relaysHome } from './fixtures/identities-relays.ts'
import { folder } from './support.ts'

// The identities file: read, checked whole, written whole; entries added and removed.

const R1 = 'https://relay1.example'
const address = generateEdgeKeys(systemRng).signing.address
const entry = (label: string, home: string, more: Record<string, unknown> = {}) => ({
  label,
  home,
  relays: [R1],
  ...more,
})
const doc = (...identities: unknown[]): unknown => ({ version: 1, identities })

describe('relayUrl, trustedRoot and PROFILES', () => {
  it('takes an http or https URL without its trailing slash, else usage', () => {
    expect(relayUrl('https://relay1.example//')).toBe('https://relay1.example')
    expect(() => relayUrl('nope')).toThrow('usage: "nope" is not a URL')
    expect(() => relayUrl('ftp://x')).toThrow('usage: "ftp://x" is not an http or https URL')
  })

  it('takes an address or a domain as a trust root, else usage', () => {
    expect(trustedRoot(address)).toEqual({ address })
    expect(trustedRoot('example.com:8443')).toEqual({ domain: 'example.com:8443' })
    expect(() => trustedRoot('Not A Root')).toThrow('usage: --trust-root "Not A Root" is neither')
    expect([...PROFILES.keys()]).toEqual(['coding'])
  })
})

describe('checkIdentities', () => {
  const h = (n: string) => join(folder(), n)

  it('takes or refuses each relays case of the table both readers share', () => {
    for (const c of RELAYS_CASES) {
      const { home } = relaysHome(folder(), 'jane', c.published)
      const d = doc({ label: 'jane', key: 'jane', home, relays: c.relays })
      if (c.taken) expect(() => checkIdentities(d, 'linux'), c.why).not.toThrow()
      else expect(() => checkIdentities(d, 'linux'), c.why).toThrow(/^identities-invalid: /)
      if (c.detail !== undefined) expect(() => checkIdentities(d, 'linux'), c.why).toThrow(c.detail('jane'))
    }
    expect(publishedRefusal('jane')).toBe(PUBLISHED_REFUSAL('jane'))
  })

  it('refuses relays [] on a published key named by another spelling of its home: a trailing slash, a link', () => {
    const { home } = relaysHome(folder(), 'jane', true)
    const link = join(folder(), 'link')
    symlinkSync(home, link)
    for (const at of [`${home}/`, link, `${link}/`]) {
      const d = doc({ label: 'jane', key: 'jane', home: at, relays: [] })
      expect(() => checkIdentities(d, 'linux'), at).toThrow(PUBLISHED_REFUSAL('jane'))
    }
  })

  it('takes an entry with no relays, an identity on this machine only, and one with MAX_RELAYS', () => {
    const many = Array.from({ length: MAX_RELAYS }, (_, i) => `https://r${i}.example`)
    const d = doc(entry('a', h('a'), { relays: [] }), entry('b', h('b'), { relays: many }))
    expect(checkIdentities(d, 'linux').identities.map((e) => e.relays.length)).toEqual([0, MAX_RELAYS])
  })

  it('takes a whole file, with every optional member, and keyOf names the key', () => {
    const one = entry('one', h('a'), {
      key: 'k1',
      rendezvous: R1,
      trust_roots: [address, 'example.com'],
      honor: ['coding'],
      accept_types: ['note'],
      receipts_to: [address],
      keep_alive_records: true,
      allow_delegate: false,
      policy: '/p',
      members: '/m',
    })
    const ok = checkIdentities(doc(one, entry('two', h('b'))), 'linux') as Identities
    expect(ok.identities.map(keyOf)).toEqual(['k1', 'two'])
    expect(checkIdentities({ ...(doc(one) as object), default: 'one' }, 'linux').default).toBe('one')
  })

  it('refuses each fault with identities-invalid, naming it', () => {
    const at = h('x')
    const bad: [unknown, string][] = [
      [[], 'the file is not a JSON object'],
      [{ version: 1, identities: [], extra: 1 }, 'unknown member "extra"'],
      [{ version: 2, identities: [] }, 'version is not 1'],
      [{ version: 1, identities: [] }, `identities is not a list of 1 to ${MAX_IDENTITIES}`],
      [doc(7), 'identities[0] is not an object'],
      [doc({ ...entry('a', at), more: 1 }), 'has an unknown member "more"'],
      [doc(entry('A', at)), 'identities[0].label is not'],
      [doc(entry('a', at, { key: 7 })), 'identities[0].key is not a string'],
      [doc(entry('a', 'relative')), 'identities[0].home is not an absolute path'],
      [doc({ ...entry('a', at), relays: 'x' }), 'identities[0].relays is not a list of 0 to'],
      [
        doc({
          ...entry('a', at),
          relays: Array.from({ length: MAX_RELAYS + 1 }, (_, i) => `https://r${i}.example`),
        }),
        `identities[0].relays is not a list of 0 to ${MAX_RELAYS} URLs`,
      ],
      [doc({ ...entry('a', at), relays: [R1, R1] }), 'identities[0].relays repeats a relay'],
      [doc({ ...entry('a', at), relays: ['nope'] }), 'identities[0].relays: "nope" is not a URL'],
      [doc({ ...entry('a', at), relays: [R1, `${R1}/`] }), 'identities[0].relays repeats a relay'],
      [doc(entry('a', at, { rendezvous: 'nope' })), 'identities[0].rendezvous: "nope" is not a URL'],
      [doc(entry('a', at, { honor: 'coding' })), 'identities[0].honor is not a list of strings'],
      [doc(entry('a', at, { trust_roots: ['Bad Root'] })), 'identities[0].trust_roots: --trust-root'],
      [doc(entry('a', at, { honor: ['law'] })), 'identities[0].honor "law" is not a profile: coding'],
      [doc(entry('a', at, { accept_types: [''] })), 'identities[0].accept_types holds an empty type'],
      [doc(entry('a', at, { receipts_to: ['bob'] })), 'identities[0].receipts_to "bob" is not an address'],
      [doc(entry('a', at, { allow_delegate: 'yes' })), 'identities[0].allow_delegate is not true or false'],
      [doc(entry('a', at, { policy: 'rel' })), 'identities[0].policy is not an absolute path'],
      [doc(entry('a', h('y')), entry('a', h('z'))), 'a label repeats'],
      [{ ...(doc(entry('a', at)) as object), default: 'b' }, 'default "b" names no label'],
    ]
    for (const [d, why] of bad) {
      expect(() => checkIdentities(d, 'linux'), why).toThrow(why)
      try {
        checkIdentities(d, 'linux')
      } catch (e) {
        expect((e as { code?: unknown }).code, why).toBe('identities-invalid')
      }
    }
  })

  it('refuses a home another entry holds (home-shared), by case on darwin, unless the file is the service one', () => {
    const at = h('Same')
    const twice = doc(entry('a', at), entry('b', at))
    expect(() => checkIdentities(twice, 'linux')).toThrow(/^home-shared: .*one home per identity/)
    expect(checkIdentities(twice, 'linux', true).identities).toHaveLength(2)
    const cased = doc(entry('a', at), entry('b', at.replace('Same', 'same')))
    expect(() => checkIdentities(cased, 'darwin')).toThrow('home-shared')
    expect(checkIdentities(cased, 'linux').identities).toHaveLength(2)
    // A home that exists is its real path; one that cannot be resolved is refused.
    const real = folder()
    expect(() => checkIdentities(doc(entry('a', real), entry('b', `${real}/.`)), 'linux')).toThrow(
      'home-shared',
    )
    const file = join(folder(), 'f')
    writeFileSync(file, '')
    expect(() => checkIdentities(doc(entry('a', join(file, 'under'))), 'linux')).toThrow(
      'cannot be resolved (ENOTDIR)',
    )
  })
})

describe('readIdentities and saveIdentities', () => {
  it('writes 0600 in a made 0700 folder and reads it back; refuses a folder, an open mode and a non-JSON file', () => {
    const d = folder()
    const file = join(d, 'sub', 'identities.json')
    const want = checkIdentities(doc(entry('a', join(d, 'h'))), process.platform)
    saveIdentities(file, want)
    expect(statSync(file).mode & 0o777).toBe(0o600)
    expect(statSync(join(d, 'sub')).mode & 0o777).toBe(0o700)
    expect(readIdentities(file)).toEqual(want)
    expect(() => readIdentities(d)).toThrow(`identities-invalid: ${d} is not a regular file`)
    const open = join(d, 'open.json')
    writeFileSync(open, JSON.stringify(want), { mode: 0o644 })
    expect(() => readIdentities(open)).toThrow('is open to the group or others: chmod 600 it')
    const junk = join(d, 'junk.json')
    writeFileSync(junk, '{', { mode: 0o600 })
    expect(() => readIdentities(junk)).toThrow(`${junk} is not JSON`)
    expect(() => readIdentities(join(d, 'none.json'))).toThrow(/ENOENT/)
  })

  it('refuses a symbolic link to a 0600 regular file, and reads that file at its own path', () => {
    const d = folder()
    const file = join(d, 'real.json')
    const want = checkIdentities(doc(entry('a', join(d, 'h'))), process.platform)
    saveIdentities(file, want)
    const link = join(d, 'identities.json')
    symlinkSync(file, link)
    expect(() => readIdentities(link)).toThrow(
      `identities-invalid: ${link} is a symbolic link: it is read only as a regular file, never through a link; ` +
        'replace the link with a 0600 copy of the file it points to',
    )
    expect(readIdentities(file)).toEqual(want)
  })

  it('a save that cannot rename leaves no temporary file behind', () => {
    const d = folder()
    const file = join(d, 'identities.json')
    mkdirSync(file)
    mkdirSync(join(file, 'full'))
    expect(() => saveIdentities(file, checkIdentities(doc(entry('a', join(d, 'h'))), 'linux'))).toThrow()
  })
})

describe('addIdentity and removeIdentity', () => {
  const home = join(folder(), 'h')
  const base = checkIdentities(doc(entry('a', home)), 'linux')

  it('adds at the end or the front; the same installed members again is null; other settings are exists', () => {
    const other = join(folder(), 'o')
    expect(addIdentity(base, entry('b', other))?.identities.map((e) => e.label)).toEqual(['a', 'b'])
    expect(addIdentity(base, entry('b', other), true)?.identities.map((e) => e.label)).toEqual(['b', 'a'])
    expect(addIdentity(base, entry('a', home))).toBeNull()
    expect(() => addIdentity(base, entry('a', home, { relays: ['https://other.example'] }))).toThrow(
      'exists: identity a is in the file with other settings: edit or remove it first',
    )
  })

  it('removes a label and the default naming it; unknown-identity and last-identity refuse', () => {
    const two = { ...(addIdentity(base, entry('b', join(folder(), 'o'))) as Identities), default: 'a' }
    expect(removeIdentity(two, 'a')).toEqual({ version: 1, identities: [two.identities[1]] })
    expect(removeIdentity(two, 'b').default).toBe('a')
    expect(() => removeIdentity(two, 'c')).toThrow(
      'unknown-identity: no identity c in the file; its labels: a, b',
    )
    expect(() => removeIdentity(base, 'a')).toThrow('last-identity: a is the last identity')
  })
})

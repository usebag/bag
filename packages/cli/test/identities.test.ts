import { execFileSync } from 'node:child_process'
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { MAX_RELAYS } from '@usebag/core'
import { afterAll, describe, expect, it } from 'vitest'
import {
  addIdentity,
  checkIdentities,
  type Identities,
  type Identity,
  MAX_IDENTITIES,
  readIdentities,
  removeIdentity,
  saveIdentities,
} from '../src/identities.ts'
import { tempDir } from './support/io.ts'

// The identities file: the reader, the checks, the writer, and
// add and remove. The fixture is shared with packages/mcp's reader tests, so the two readers cannot drift.

const tmp = tempDir('identities')
afterAll(() => tmp.cleanup())
const FIXTURE = fileURLToPath(new URL('./fixtures/identities-v1.json', import.meta.url))
const fixture = (): Identities => JSON.parse(readFileSync(FIXTURE, 'utf8'))
const [PERSONAL, LAB] = fixture().identities as [Identity, Identity]
let n = 0

/** `text` in a fresh file of mode `mode`. */
function fileOf(text: string, mode = 0o600): string {
  const file = join(tmp.dir, `f${n++}.json`)
  writeFileSync(file, text)
  chmodSync(file, mode) // the umask would take the group's write bit off a mode given at creation
  return file
}

/** What checkIdentities says of `doc`: ok, or the error's message. */
function fault(doc: unknown): string {
  try {
    checkIdentities(doc)
    return 'ok'
  } catch (e) {
    return (e as Error).message
  }
}

/** A file of the one identity `lab` with `patch` over it. */
const one = (patch: Record<string, unknown>) => ({ version: 1, identities: [{ ...LAB, ...patch }] })

describe('the identities file: reading', () => {
  it('reads the shared fixture, copied to a 0600 file', () => {
    const file = join(tmp.dir, `f${n++}.json`)
    copyFileSync(FIXTURE, file)
    chmodSync(file, 0o600)
    const doc = readIdentities(file)
    expect(doc).toEqual(fixture())
    expect(doc.default).toBe('personal')
    expect(doc.identities.map((e) => [e.label, e.key, e.home])).toEqual([
      ['personal', 'alice', '/home/u/.bag'],
      ['lab', 'lab', '/home/u/.bag-lab'],
    ])
    expect(LAB.rendezvous).toBe('https://relay-a.example')
    expect(PERSONAL.trust_roots).toHaveLength(2)
  })

  it('refuses a file the group or others may read or write, one that is not JSON, and a missing one', () => {
    const text = readFileSync(FIXTURE, 'utf8')
    for (const mode of [0o640, 0o604, 0o620]) {
      const file = fileOf(text, mode)
      expect(() => readIdentities(file)).toThrow(
        `identities-invalid: ${file} is open to the group or others: chmod 600 it`,
      )
    }
    const folder = join(tmp.dir, `dir-${n++}`)
    mkdirSync(folder, { mode: 0o700 })
    expect(() => readIdentities(folder)).toThrow(`identities-invalid: ${folder} is not a regular file`)
    const fifo = join(tmp.dir, `fifo-${n++}`)
    execFileSync('mkfifo', ['-m', '600', fifo])
    expect(() => readIdentities(fifo)).toThrow(`identities-invalid: ${fifo} is not a regular file`)
    const junk = fileOf('{"version": 1,')
    expect(() => readIdentities(junk)).toThrow(`identities-invalid: ${junk} is not JSON`)
    expect(() => readIdentities(join(tmp.dir, 'none.json'))).toThrow(
      expect.objectContaining({ code: 'ENOENT' }),
    )
  })

  it('refuses each fault with identities-invalid, naming it, and a shared home with home-shared', () => {
    const bad = (detail: string) => `identities-invalid: ${detail}`
    const many = Array.from({ length: MAX_IDENTITIES + 1 }, (_, i) => ({
      ...LAB,
      label: `l${i}`,
      home: `/h/${i}`,
    }))
    const cases: [unknown, string][] = [
      [[], bad('the file is not a JSON object')],
      [null, bad('the file is not a JSON object')],
      [{ ...fixture(), extra: 1 }, bad('unknown member "extra"')],
      [{ ...fixture(), version: 2 }, bad('version is not 1')],
      [{ version: 1, identities: [] }, bad(`identities is not a list of 1 to ${MAX_IDENTITIES}`)],
      [{ version: 1, identities: {} }, bad(`identities is not a list of 1 to ${MAX_IDENTITIES}`)],
      [{ version: 1, identities: many }, bad(`identities is not a list of 1 to ${MAX_IDENTITIES}`)],
      [{ version: 1, identities: ['lab'] }, bad('identities[0] is not an object')],
      [one({ honour: [] }), bad('identities[0] has an unknown member "honour"')],
      [one({ label: 'Lab' }), bad('identities[0].label is not ^[a-z0-9][a-z0-9_-]{0,31}$')],
      [one({ label: 'a.b' }), bad('identities[0].label is not ^[a-z0-9][a-z0-9_-]{0,31}$')],
      [one({ label: 7 }), bad('identities[0].label is not ^[a-z0-9][a-z0-9_-]{0,31}$')],
      [one({ key: '../x' }), bad('identities[0]: key: a key name is 1 to 64 of [a-z0-9._-], not "../x"')],
      [one({ key: 5 }), bad('identities[0].key is not a string')],
      [one({ honor: ['coding', 'cooking'] }), bad('identities[0].honor "cooking" is not a profile: coding')],
      [one({ accept_types: ['text', ''] }), bad('identities[0].accept_types holds an empty type')],
      [
        { version: 1, identities: [LAB, { ...PERSONAL, home: `${LAB.home}/` }] },
        "home-shared: identities[1].home /home/u/.bag-lab/ is another identity's: one home per identity",
      ],
      [one({ home: 'rel/home' }), bad('identities[0].home is not an absolute path')],
      [one({ home: undefined }), bad('identities[0].home is not an absolute path')],
      [one({ relays: [] }), bad(`identities[0].relays is not a list of 1 to ${MAX_RELAYS} URLs`)],
      [
        one({ relays: 'https://r.example' }),
        bad(`identities[0].relays is not a list of 1 to ${MAX_RELAYS} URLs`),
      ],
      [
        one({ relays: Array.from({ length: MAX_RELAYS + 1 }, (_, i) => `https://r${i}.example`) }),
        bad(`identities[0].relays is not a list of 1 to ${MAX_RELAYS} URLs`),
      ],
      [
        one({ relays: ['ftp://r.example'] }),
        bad('identities[0].relays: "ftp://r.example" is not an http or https URL'),
      ],
      [
        one({ relays: ['https://r.example', 'https://r.example/'] }),
        bad('identities[0].relays repeats a relay'),
      ],
      [one({ rendezvous: 'nope' }), bad('identities[0].rendezvous: "nope" is not a URL')],
      [one({ trust_roots: [5] }), bad('identities[0].trust_roots is not a list of strings')],
      [
        one({ trust_roots: ['not a root!'] }),
        bad('identities[0].trust_roots: --trust-root "not a root!" is neither an address nor a domain'),
      ],
      [one({ honor: 'x' }), bad('identities[0].honor is not a list of strings')],
      [one({ receipts_to: PERSONAL.home }), bad('identities[0].receipts_to is not a list of strings')],
      [one({ receipts_to: ['bob'] }), bad('identities[0].receipts_to "bob" is not an address')],
      [one({ accept_types: [null] }), bad('identities[0].accept_types is not a list of strings')],
      [one({ keep_alive_records: 'yes' }), bad('identities[0].keep_alive_records is not true or false')],
      [one({ allow_delegate: 1 }), bad('identities[0].allow_delegate is not true or false')],
      [one({ policy: 'policy.json' }), bad('identities[0].policy is not an absolute path')],
      [one({ members: 5 }), bad('identities[0].members is not an absolute path')],
      [{ ...fixture(), default: 'nobody' }, bad('default "nobody" names no label')],
      [{ version: 1, identities: [LAB, { ...PERSONAL, label: 'lab' }] }, bad('a label repeats')],
      [
        { version: 1, identities: [LAB, { ...PERSONAL, home: LAB.home }] },
        "home-shared: identities[1].home /home/u/.bag-lab is another identity's: one home per identity",
      ],
    ]
    for (const [doc, want] of cases) expect([doc, fault(doc)]).toEqual([doc, want])
  })

  it('folds the case of homes not made yet on macOS only: elsewhere two such homes that differ by case are two', () => {
    const doc = { version: 1, identities: [LAB, { ...PERSONAL, home: '/home/u/.Bag-Lab' }] }
    expect(() => checkIdentities(doc, 'darwin')).toThrow(
      "home-shared: identities[1].home /home/u/.Bag-Lab is another identity's: one home per identity",
    )
    expect(checkIdentities(doc, 'linux')).toEqual(doc)
  })

  it('takes two names of one folder for one home: a link to it is home-shared', () => {
    const real = join(tmp.dir, `home-${n++}`)
    mkdirSync(real)
    const link = `${real}-link`
    symlinkSync(real, link)
    expect(
      fault({
        version: 1,
        identities: [
          { ...LAB, home: real },
          { ...PERSONAL, home: link },
        ],
      }),
    ).toBe(`home-shared: identities[1].home ${link} is another identity's: one home per identity`)
  })

  it('refuses a home that exists but cannot be resolved, rather than compare it as text', () => {
    const plain = fileOf('')
    expect(fault(one({ home: join(plain, 'home') }))).toBe(
      `identities-invalid: identities[0].home ${JSON.stringify(join(plain, 'home'))} cannot be resolved (ENOTDIR)`,
    )
  })

  it('takes every optional member, and an identity without a key', () => {
    const full = {
      honor: ['coding', 'coding'],
      receipts_to: ['ed25519:'.concat('2a'.repeat(32))],
      accept_types: ['text'],
      allow_delegate: true,
      keep_alive_records: false,
      policy: '/home/u/policy.json',
      members: '/home/u/members.json',
    }
    expect(fault(one(full))).toBe('ok')
    const { key: _, ...keyless } = LAB
    expect(fault({ version: 1, identities: [keyless] })).toBe('ok')
    expect(
      fault({
        version: 1,
        identities: Array.from({ length: MAX_IDENTITIES }, (_, i) => ({
          ...LAB,
          label: `l${i}`,
          home: `/h/${i}`,
        })),
      }),
    ).toBe('ok')
  })
})

describe('the identities file: writing, adding and removing', () => {
  it('writes two-space JSON and a newline, 0600, in a 0700 directory it makes, and leaves no temporary file', () => {
    const dir = join(tmp.dir, `d${n++}`, 'ids')
    const file = join(dir, 'p.json')
    saveIdentities(file, fixture())
    expect(readFileSync(file, 'utf8')).toBe(`${JSON.stringify(fixture(), null, 2)}\n`)
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(fixture())
    expect([statSync(file).mode & 0o777, statSync(dir).mode & 0o777]).toEqual([0o600, 0o700])
    expect(readdirSync(dir)).toEqual(['p.json'])
    expect(readIdentities(file)).toEqual(fixture())
  })

  it('removes its temporary file when the rename fails', () => {
    const dir = join(tmp.dir, `d${n++}`)
    mkdirSync(join(dir, 'p.json', 'inside'), { recursive: true })
    expect(() => saveIdentities(join(dir, 'p.json'), fixture())).toThrow()
    expect(readdirSync(dir)).toEqual(['p.json'])
  })

  it('appends an identity, or puts it first; an equal one is null; the label, or the home and key, with other settings is exists', () => {
    const club = {
      label: 'club',
      key: 'club',
      home: '/home/u/.bag-club',
      relays: ['https://relay-d.example'],
    }
    expect(addIdentity(fixture(), club)?.identities.map((e) => e.label)).toEqual(['personal', 'lab', 'club'])
    expect(addIdentity(fixture(), club, true)?.identities.map((e) => e.label)).toEqual([
      'club',
      'personal',
      'lab',
    ])
    expect(addIdentity(fixture(), { ...LAB })).toBeNull()
    const chosen = {
      version: 1,
      identities: [{ ...LAB, receipts_to: ['ed25519:'.concat('2a'.repeat(32))] }],
    } as const
    expect(addIdentity(chosen, { ...LAB })).toBeNull()
    expect(addIdentity(chosen, club)?.identities[0]).toEqual(chosen.identities[0])
    const exists = 'exists: identity lab is in the file with other settings: edit or remove it first'
    expect(() => addIdentity(fixture(), { ...LAB, relays: ['https://relay-d.example'] })).toThrow(exists)
    expect(() => addIdentity(fixture(), { ...LAB, label: 'lab2' })).toThrow(exists)
    const { key: _, ...keyless } = LAB
    const doc: Identities = { version: 1, identities: [keyless] }
    expect(() => addIdentity(doc, { ...club, key: 'lab', home: LAB.home })).toThrow(exists)
    expect(() => addIdentity(doc, { ...club, home: LAB.home })).toThrow('home-shared: ')
  })

  it('refuses one identity past MAX_IDENTITIES', () => {
    const full: Identities = {
      version: 1,
      identities: Array.from({ length: MAX_IDENTITIES }, (_, i) => ({
        ...LAB,
        label: `l${i}`,
        key: `l${i}`,
        home: `/h/${i}`,
      })),
    }
    const next = { ...LAB, label: `l${MAX_IDENTITIES}`, key: `l${MAX_IDENTITIES}`, home: '/h/next' }
    expect(() => addIdentity(full, next)).toThrow(
      `identities-invalid: identities is not a list of 1 to ${MAX_IDENTITIES}`,
    )
  })

  it('removes an identity, and default with it when it named it; refuses an unknown label and the last identity', () => {
    expect(removeIdentity(fixture(), 'lab')).toEqual({
      version: 1,
      default: 'personal',
      identities: [PERSONAL],
    })
    expect(removeIdentity(fixture(), 'personal')).toEqual({ version: 1, identities: [LAB] })
    expect(() => removeIdentity(fixture(), 'club')).toThrow(
      'unknown-identity: no identity club in the file; its labels: personal, lab',
    )
    expect(() => removeIdentity({ version: 1, identities: [LAB] }, 'lab')).toThrow(
      'last-identity: lab is the last identity: keep one, or remove the server entry by hand',
    )
  })
})

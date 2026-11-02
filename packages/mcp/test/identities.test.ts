import { execFileSync } from 'node:child_process'
import { chmodSync, copyFileSync, mkdirSync, symlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { MAX_RELAYS } from '@usebag/core'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { type Config, ConfigError, type ServerWide } from '../src/config.ts'
import { LABEL, MAX_IDENTITIES, readIdentities } from '../src/identities.ts'
import { P, tempDir } from './support/ports.ts'

// The --identities file (design 2026-10-30-multi-identity-sessions §2.2 and §8.1): the shared fixture the CLI writes,
// valid files of one, three and 64 identities, and every refusal one by one.

const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), '../../cli/test/fixtures/identities-v1.json')
/** Server-wide values off their defaults, so each identity is seen to take them. */
const WIDE: ServerWide = {
  maxToolSeconds: 55,
  progressSeconds: 10,
  push: ['log'],
  allowPrivateRelays: true,
  defaultHandler: 'queue',
}
const AT = '--identities: identities[0] "personal"'

let tmp: ReturnType<typeof tempDir>
beforeEach(() => {
  tmp = tempDir('identities')
})
afterEach(() => tmp.cleanup())

/** Writes `doc` (its JSON, or the text itself) to ids.json in the temp directory, with `mode`; the path. */
function file(doc: unknown, mode = 0o600): string {
  const path = join(tmp.dir, 'ids.json')
  writeFileSync(path, typeof doc === 'string' ? doc : JSON.stringify(doc))
  chmodSync(path, mode)
  return path
}

/** An entry with its required members, its home its own, and `extra` over them. */
const entry = (label: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  label,
  home: `/home/u/.ac-${label}`,
  relays: ['https://r.test'],
  ...extra,
})
const one = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  version: 1,
  identities: [entry('personal', extra)],
})

function refused(path: string): { code: string; message: string } {
  try {
    readIdentities(path, WIDE)
  } catch (e) {
    expect(e).toBeInstanceOf(ConfigError)
    return { code: (e as ConfigError).code, message: (e as ConfigError).message }
  }
  throw new Error('readIdentities accepted it')
}

/** The usage message of a file holding `doc`. */
const message = (doc: unknown): string => {
  const r = refused(file(doc))
  expect(r.code).toBe('usage')
  return r.message
}

describe('readIdentities: valid files', () => {
  it("reads the CLI's shared fixture (packages/cli/test/fixtures/identities-v1.json), copied and 0600", () => {
    const path = join(tmp.dir, 'identities-v1.json')
    copyFileSync(FIXTURE, path)
    chmodSync(path, 0o600)
    const read = readIdentities(path, WIDE)
    const root = `ed25519:${'1f'.repeat(32)}`
    expect(read.defaultLabel).toBe('personal')
    expect(read.identities).toEqual([
      {
        label: 'personal',
        as: 'alice',
        home: '/home/u/.bag',
        relays: ['https://relay-a.example'],
        rendezvous: 'https://relay-a.example',
        trustRootTexts: [root, 'example.org'],
        trustRoots: [{ address: root }, { domain: 'example.org' }],
        honor: [],
        acceptTypes: ['*'],
        auth: null,
        chainCmd: null,
        mailbox: null,
        session: null,
        allowDelegate: false,
        allowSessionDelegation: false,
        keepAliveRecords: true,
        receiptsTo: [],
        policy: null,
        members: null,
        ...WIDE,
      },
      expect.objectContaining({
        label: 'lab',
        as: 'lab',
        home: '/home/u/.bag-lab',
        relays: ['https://relay-b.example', 'https://relay-c.example'],
        rendezvous: 'https://relay-a.example',
        trustRootTexts: [],
        keepAliveRecords: true,
        receiptsTo: [],
        allowDelegate: false,
      }),
    ])
  })

  it('reads one identity with every default: key the label, rendezvous its first relay, the server-wide values', () => {
    expect(readIdentities(file(one()), WIDE)).toEqual({
      identities: [
        {
          label: 'personal',
          as: 'personal',
          home: '/home/u/.ac-personal',
          relays: ['https://r.test'],
          rendezvous: 'https://r.test',
          trustRootTexts: [],
          trustRoots: [],
          honor: [],
          acceptTypes: ['*'],
          auth: null,
          chainCmd: null,
          mailbox: null,
          session: null,
          allowDelegate: false,
          allowSessionDelegation: false,
          keepAliveRecords: false,
          receiptsTo: [],
          policy: null,
          members: null,
          maxToolSeconds: 55,
          progressSeconds: 10,
          push: ['log'],
          allowPrivateRelays: true,
          defaultHandler: 'queue',
        } satisfies Config,
      ],
      defaultLabel: 'personal',
    })
  })

  it('reads three identities with every member, and the default they name', () => {
    const full = entry('personal', {
      key: 'alice.v2',
      relays: ['https://a.test/', 'https://b.test'],
      rendezvous: 'https://meet.test//',
      trust_roots: [P.bob.address, 'acme.test'],
      honor: ['coding', 'coding'],
      accept_types: ['chat.v1', 'coding.*', 'chat.v1'],
      keep_alive_records: true,
      allow_delegate: true,
      policy: '/o/policy.json',
      members: '/o/members.json',
    })
    const read = readIdentities(
      file({ version: 1, default: 'lab', identities: [full, entry('lab'), entry('w-2_x')] }),
      WIDE,
    )
    expect(read.defaultLabel).toBe('lab')
    expect(read.identities.map((c) => [c.label, c.as, c.home])).toEqual([
      ['personal', 'alice.v2', '/home/u/.ac-personal'],
      ['lab', 'lab', '/home/u/.ac-lab'],
      ['w-2_x', 'w-2_x', '/home/u/.ac-w-2_x'],
    ])
    expect(read.identities[0]).toMatchObject({
      relays: ['https://a.test', 'https://b.test'],
      rendezvous: 'https://meet.test',
      trustRootTexts: [P.bob.address, 'acme.test'],
      trustRoots: [{ address: P.bob.address }, { domain: 'acme.test' }],
      honor: ['coding'],
      acceptTypes: ['chat.v1', 'coding.*'],
      keepAliveRecords: true,
      receiptsTo: [],
      allowDelegate: true,
      allowSessionDelegation: false,
      policy: '/o/policy.json',
      members: '/o/members.json',
    } satisfies Partial<Config>)
  })

  it(`takes ${MAX_IDENTITIES} identities and ${MAX_RELAYS} relays, the most it reads`, () => {
    const relays = Array.from({ length: MAX_RELAYS }, (_, i) => `https://r${i}.test`)
    const identities = Array.from({ length: MAX_IDENTITIES }, (_, i) => entry(`i${i}`, { relays }))
    const read = readIdentities(file({ version: 1, identities }), WIDE)
    expect([read.identities.length, read.identities[31]?.relays.length, read.defaultLabel]).toEqual([
      MAX_IDENTITIES,
      MAX_RELAYS,
      'i0',
    ])
    expect(LABEL.source).toBe('^[a-z0-9][a-z0-9_-]{0,31}$')
  })
})

describe('readIdentities: the file itself', () => {
  it('refuses a relative path, a missing file, and what is not a regular file: a directory, a device', () => {
    expect(refused('ids.json')).toEqual({
      code: 'usage',
      message: 'usage: --identities: "ids.json" is not an absolute path',
    })
    const none = join(tmp.dir, 'none.json')
    expect(refused(none).message).toBe(`usage: --identities: ${none} cannot be read (ENOENT)`)
    // A FIFO or /dev/stdin would eat the server's stdin: only a regular file is read. /dev/null is a character device.
    const fifo = join(tmp.dir, 'fifo')
    execFileSync('mkfifo', ['-m', '600', fifo])
    for (const path of [tmp.dir, '/dev/null', fifo]) {
      expect(refused(path)).toEqual({
        code: 'usage',
        message: `usage: --identities: ${path} is not a regular file`,
      })
    }
  })

  it('refuses a file with any group or other bit (0644, 0640, 0604, 0601), before its contents', () => {
    for (const mode of [0o644, 0o640, 0o604, 0o601]) {
      const path = file('not JSON', mode)
      const octal = mode.toString(8).padStart(4, '0')
      expect(refused(path)).toEqual({
        code: 'usage',
        message: `usage: --identities: ${path} has mode ${octal}; it must be 0600 (it lists every identity together)`,
      })
    }
  })

  it('refuses a file that is not JSON, or JSON but not an object', () => {
    for (const text of ['{', '', '[]', 'null', '1', '"x"']) {
      expect(message(text)).toBe(`usage: --identities: ${join(tmp.dir, 'ids.json')} is not a JSON object`)
    }
  })

  it('refuses an unknown member at the top, a version but 1, and an identities list empty, absent or over 32', () => {
    expect(message({ ...one(), extra: 1 })).toBe('usage: --identities: unknown member "extra"')
    for (const [version, shown] of [
      [2, '2'],
      ['1', '"1"'],
      [undefined, 'absent'],
    ]) {
      expect(message({ ...one(), version })).toBe(
        `usage: --identities: version is ${shown}; this server reads version 1`,
      )
    }
    const over = Array.from({ length: MAX_IDENTITIES + 1 }, (_, i) => entry(`i${i}`))
    for (const identities of [[], undefined, {}, 'personal', over]) {
      expect(message({ version: 1, identities })).toBe(
        'usage: --identities: identities is a list of 1 to 64 identities',
      )
    }
  })

  it('refuses a default that names no identity', () => {
    for (const [given, shown] of [
      ['nobody', '"nobody"'],
      [null, 'null'],
      [5, '5'],
    ]) {
      expect(message({ ...one(), default: given })).toBe(
        `usage: --identities: default ${shown} names no identity`,
      )
    }
  })
})

describe('readIdentities: each entry', () => {
  it('refuses an entry that is not an object, and a label that is absent, breaks the pattern or repeats', () => {
    for (const e of [null, 'personal', [], 7]) {
      expect(message({ version: 1, identities: [e] })).toBe(
        'usage: --identities: identities[0] is not an object',
      )
    }
    for (const [label, shown] of [
      [undefined, 'absent'],
      ['Lab', '"Lab"'],
      ['-lab', '"-lab"'],
      ['a.b', '"a.b"'],
      ['a'.repeat(33), `"${'a'.repeat(33)}"`],
      [7, '7'],
    ]) {
      expect(message({ version: 1, identities: [{ ...entry('x'), label }] })).toBe(
        `usage: --identities: identities[0]: label is ${shown}; it must match ^[a-z0-9][a-z0-9_-]{0,31}$`,
      )
    }
    const twice = { version: 1, identities: [entry('lab'), entry('lab', { home: '/home/u/other' })] }
    expect(message(twice)).toBe('usage: --identities: identities[1] repeats the label "lab" of identities[0]')
  })

  it("refuses an unknown member, naming the label: a flag's name is not a member", () => {
    for (const member of ['as', 'dir', 'trust-root', 'session', 'auth']) {
      expect(message(one({ [member]: 'x' }))).toBe(`usage: ${AT}: unknown member "${member}"`)
    }
  })

  it("refuses a key that is not a string, or that edge's checkName refuses, naming the entry", () => {
    expect(message(one({ key: 5 }))).toBe(`usage: ${AT}: key is not a string`)
    for (const key of ['', 'Alice', '../alice', 'a/b', '.a', 'a'.repeat(65)]) {
      expect(message(one({ key }))).toBe(
        `usage: ${AT}: key: a key name is 1 to 64 of [a-z0-9._-], not ${JSON.stringify(key)}`,
      )
    }
    const second = { version: 1, identities: [entry('personal'), entry('lab', { key: 'Lab' })] }
    expect(refused(file(second))).toEqual({
      code: 'usage',
      message:
        'usage: --identities: identities[1] "lab": key: a key name is 1 to 64 of [a-z0-9._-], not "Lab"',
    })
  })

  it('refuses a home that is absent, not a string or relative, and a relative policy or members path', () => {
    expect(message({ version: 1, identities: [{ label: 'personal', relays: ['https://r.test'] }] })).toBe(
      `usage: ${AT}: home is required`,
    )
    expect(message(one({ home: 5 }))).toBe(`usage: ${AT}: home is not a string`)
    for (const member of ['home', 'policy', 'members']) {
      for (const path of ['home/u/x', '', './x']) {
        expect(message(one({ [member]: path }))).toBe(
          `usage: ${AT}: ${member} ${JSON.stringify(path)} is not an absolute path`,
        )
      }
    }
  })

  it('refuses two identities with one home (home-shared), however it is spelled, by its real path', () => {
    // Homes that exist are compared by their real paths: a symlink to another's home, or a trailing slash.
    const real = join(tmp.dir, 'real')
    const other = join(tmp.dir, 'other')
    mkdirSync(real)
    mkdirSync(other)
    const link = join(tmp.dir, 'link')
    symlinkSync(real, link)
    for (const [first, home] of [
      // Homes that do not exist (as the shared fixture's) are compared resolved.
      ['/home/u/.ac-personal', '/home/u/.ac-personal'],
      ['/home/u/.ac-personal', '/home/u/.ac-personal/'],
      ['/home/u/.ac-personal', '/home/u/x/../.ac-personal'],
      [real, link],
      [link, real],
      [real, `${real}/`],
    ]) {
      const doc = { version: 1, identities: [entry('personal', { home: first }), entry('lab', { home })] }
      expect(refused(file(doc))).toEqual({
        code: 'home-shared',
        message:
          'home-shared: --identities: identities[1] "lab" has the home of identities[0] "personal"; ' +
          'each identity has its own',
      })
    }
    const apart = {
      version: 1,
      identities: [entry('personal', { home: real }), entry('lab', { home: other })],
    }
    expect(readIdentities(file(apart), WIDE).identities.map((c) => c.home)).toEqual([real, other])
    // Homes not made yet that differ only by case: one home on darwin (its file systems fold case), two elsewhere.
    const cased = {
      version: 1,
      identities: [entry('personal', { home: '/home/u/AC' }), entry('lab', { home: '/home/u/ac' })],
    }
    expect(() => readIdentities(file(cased), WIDE, 'darwin')).toThrow(/^home-shared: /)
    expect(readIdentities(file(cased), WIDE, 'linux').identities).toHaveLength(2)
    // Only a home not made yet falls back to its resolved path; any other failure refuses, never compares by text.
    const under = join(tmp.dir, 'ids.json', 'home')
    const blocked = { version: 1, identities: [entry('personal', { home: under })] }
    expect(refused(file(blocked))).toEqual({
      code: 'usage',
      message: `usage: --identities: home ${JSON.stringify(under)} cannot be resolved (ENOTDIR)`,
    })
  })

  it(`refuses relays absent, empty, over ${MAX_RELAYS}, repeated, not a list of strings, or not http(s) URLs`, () => {
    const over = Array.from({ length: MAX_RELAYS + 1 }, (_, i) => `https://r${i}.test`)
    for (const [relays, n, distinct] of [
      [undefined, 0, 0],
      [[], 0, 0],
      [over, MAX_RELAYS + 1, MAX_RELAYS + 1],
      [['https://r.test', 'https://r.test/'], 2, 1],
    ] as const) {
      expect(message(one({ relays }))).toBe(
        `usage: ${AT}: relays is 1 to ${MAX_RELAYS} distinct relay URLs, not ${n} (${distinct} distinct)`,
      )
    }
    for (const relays of ['https://r.test', [5], {}]) {
      expect(message(one({ relays }))).toBe(`usage: ${AT}: relays is not a list of strings`)
    }
    expect(message(one({ relays: ['not a url'] }))).toBe(`usage: ${AT}: relays "not a url" is not a URL`)
    expect(message(one({ relays: ['ftp://r.test'] }))).toBe(
      `usage: ${AT}: relays "ftp://r.test" is not an http or https URL`,
    )
  })

  it('refuses a bad rendezvous, trust root, profile, accept type or boolean, naming the member', () => {
    expect(message(one({ rendezvous: 5 }))).toBe(`usage: ${AT}: rendezvous is not a string`)
    expect(message(one({ rendezvous: 'ftp://m.test' }))).toBe(
      `usage: ${AT}: rendezvous "ftp://m.test" is not an http or https URL`,
    )
    expect(message(one({ trust_roots: ['https://acme.test/x'] }))).toBe(
      `usage: ${AT}: trust_roots "https://acme.test/x" is neither an address nor a domain`,
    )
    expect(message(one({ trust_roots: 'acme.test' }))).toBe(
      `usage: ${AT}: trust_roots is not a list of strings`,
    )
    expect(message(one({ honor: ['payments'] }))).toBe(
      `usage: ${AT}: honor "payments" is not a profile; the profiles are coding`,
    )
    expect(message(one({ accept_types: ['chat.v1', ''] }))).toBe(
      `usage: ${AT}: accept_types holds an empty type`,
    )
    for (const member of ['keep_alive_records', 'allow_delegate']) {
      for (const value of ['true', 1, null]) {
        expect(message(one({ [member]: value }))).toBe(`usage: ${AT}: ${member} is not true or false`)
      }
    }
  })
})

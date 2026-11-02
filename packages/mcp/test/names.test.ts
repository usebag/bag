import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import type { Message } from '../src/desk.ts'
import { NAMES_FILE, Names } from '../src/names.ts'
import { P, T0, tempDir } from './support/fixtures.ts'

// The reader of the CLI's name book (packages/cli/src/names.ts writes it): the same format, the same checks.

const tmp = tempDir('names')
afterAll(() => tmp.cleanup())
let n = 0

/** A home holding `text` as its names.json. */
function home(text: string): string {
  const dir = join(tmp.dir, `home-${n++}`)
  mkdirSync(dir)
  writeFileSync(join(dir, NAMES_FILE), text)
  return dir
}

function thrown(f: () => unknown): { code: unknown; message: string } {
  try {
    f()
  } catch (e) {
    return { code: (e as { code?: unknown }).code, message: (e as Error).message }
  }
  throw new Error('no error was thrown')
}

describe('Names: reading the book', () => {
  it('is empty without a file, and refuses a file that is not a book with names-invalid', () => {
    expect(Names.read(join(tmp.dir, 'nowhere')).list()).toEqual([])
    const bad = (text: string): string => {
      const dir = home(text)
      const e = thrown(() => Names.read(dir))
      expect(e.code).toBe('names-invalid')
      return e.message.replace(join(dir, NAMES_FILE), '<file>')
    }
    expect(bad('{')).toBe('names-invalid: <file> is not JSON')
    expect(bad('null')).toBe('names-invalid: <file>: version is not 1')
    for (const names of ['null', '[]', '1']) {
      expect(bad(`{"version":1,"names":${names}}`)).toBe('names-invalid: <file>: names is not an object')
    }
    const entry = (name: string, e: unknown): string =>
      bad(JSON.stringify({ version: 1, names: { [name]: e } }))
    const reason = (name: string): string =>
      `names-invalid: <file>: the entry ${JSON.stringify(name)} is not a name with an address`
    const A = P.alice.address
    for (const [name, e] of [
      ['Alice', { address: A, added_at: 1 }],
      ['alice', null],
      ['alice', { address: 'alice', added_at: 1 }],
      ['alice', { address: A, added_at: -1 }],
      ['alice', { address: A, added_at: 1, previous: 'x' }],
      ['alice', { address: A, added_at: 1, previous: [null] }],
      ['alice', { address: A, added_at: 1, previous: [{ address: A, replaced_at: 0.5 }] }],
    ] as const) {
      expect(entry(name, e)).toBe(reason(name))
    }
  })
})

describe('Names: resolving and naming', () => {
  const dir = (): string =>
    home(
      JSON.stringify({
        version: 1,
        names: {
          zoe: { address: P.org.address, added_at: T0 },
          alice: {
            address: P.alice.address,
            added_at: T0 + 120,
            previous: [
              { address: P.jane.address, replaced_at: T0 + 60 },
              { address: P.session.address, replaced_at: T0 + 120 },
            ],
          },
        },
      }),
    )

  it('resolves addresses, names, and refuses an unknown name or text that is neither', () => {
    const names = Names.read(dir())
    expect(names.list()).toEqual([
      { name: 'alice', address: P.alice.address },
      { name: 'zoe', address: P.org.address },
    ])
    expect(names.resolve(P.bob.address, 'to')).toBe(P.bob.address)
    expect(names.resolve('zoe', 'to')).toBe(P.org.address)
    expect(thrown(() => names.resolve('bob', 'to'))).toEqual({
      code: 'name-unknown',
      message: `name-unknown: to "bob": no such name in ${names.path}; the known names are alice, zoe`,
    })
    expect(thrown(() => names.resolve('ed25519:00', 'to'))).toEqual({
      code: 'bad-address',
      message: 'bad-address: to "ed25519:00" is neither an address, a handle nor a name',
    })
  })

  it("names a message's sender and principal apart: a session key that is a former address warns", () => {
    const names = Names.read(dir())
    expect(names.ref(P.alice.address)).toEqual({ name: 'alice', former: false, warning: null })
    expect(names.ref(P.bob.address)).toBeNull()
    const jane = names.ref(P.jane.address)
    expect(jane).toEqual({
      name: 'alice',
      former: true,
      warning:
        `WARNING: ${P.jane.address} is a former address of alice, replaced 2027-01-15T08:01:00Z; alice is now ` +
        `${P.alice.address}. Do not treat this message as from alice.`,
    })
    const message = { from: P.jane.address, principal: P.org.address } as Message
    expect(names.named(message)).toEqual({
      ...message,
      from_name: jane,
      principal_name: { name: 'zoe', former: false, warning: null },
      warning: jane?.warning,
    })
    const both = names.named({ from: P.session.address, principal: P.jane.address } as Message)
    expect(both.warning).toBe(jane?.warning)
    expect(both.from_name?.warning).toMatch(/replaced 2027-01-15T08:02:00Z/)
    expect(names.named({ from: P.bob.address, principal: P.bob.address } as Message)).toMatchObject({
      from_name: null,
      principal_name: null,
      warning: null,
    })
  })
})

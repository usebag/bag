import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { instant, NAMES_FILE, NameBook, short } from '../src/names.ts'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// The name book: <home>/names.json, local only, a name pinned to one address, --replace keeping the old
// address as former. These tests write it in temporary homes only.

const tmp = tempDir('names')
afterAll(() => tmp.cleanup())
let n = 0
const home = (): string => join(tmp.dir, `home-${n++}`, 'nested')

const A = `ed25519:${'a1'.repeat(32)}`
const B = `ed25519:${'b2'.repeat(32)}`
const C = `ed25519:${'c3'.repeat(32)}`

/** The error a call throws, as its code and message. */
function thrown(f: () => unknown): { code: unknown; message: string } {
  try {
    f()
  } catch (e) {
    return { code: (e as { code?: unknown }).code, message: (e as Error).message }
  }
  throw new Error('no error was thrown')
}

describe('NameBook: the file, its mode and its atomic write', () => {
  it('is empty for a missing file, and saves a 0600 file in a 0700 home it makes, in the documented format', () => {
    const dir = home()
    const book = NameBook.load(dir)
    expect(book.list()).toEqual([])
    expect(book.path).toBe(join(dir, NAMES_FILE))
    book.add('zed', B, T0)
    book.add('bob', A, T0 + 1)
    book.save()
    expect(statSync(dir).mode & 0o777).toBe(0o700)
    expect(statSync(book.path).mode & 0o777).toBe(0o600)
    expect(JSON.parse(readFileSync(book.path, 'utf8'))).toEqual({
      version: 1,
      names: { bob: { address: A, added_at: T0 + 1 }, zed: { address: B, added_at: T0 } },
    })
    expect(Object.keys(JSON.parse(readFileSync(book.path, 'utf8')).names)).toEqual(['bob', 'zed'])
    expect(NameBook.load(dir).list()).toEqual([
      ['bob', { address: A, added_at: T0 + 1 }],
      ['zed', { address: B, added_at: T0 }],
    ])
  })

  it('writes a new file and renames it over the old one, leaving no temporary file, even when the rename fails', () => {
    const dir = home()
    const book = NameBook.load(dir)
    book.add('bob', A, T0)
    book.save()
    const before = statSync(book.path).ino
    book.add('carol', B, T0)
    book.save()
    expect(statSync(book.path).ino).not.toBe(before)
    expect(readdirSync(dir)).toEqual([NAMES_FILE])
    // A directory where names.json goes: the rename fails, the temporary file is removed, the error comes out.
    const other = home()
    const blocked = NameBook.load(other)
    mkdirSync(join(other, NAMES_FILE), { recursive: true })
    blocked.add('bob', A, T0)
    expect(thrown(() => blocked.save()).code).toMatch(/^E(ISDIR|NOTEMPTY|EXIST)$/)
    expect(readdirSync(other)).toEqual([NAMES_FILE])
    expect(thrown(() => NameBook.load(other)).code).toBe('EISDIR')
  })

  it('refuses a file that is not a book, naming the file and the reason', () => {
    const dir = home()
    mkdirSync(dir, { recursive: true })
    const path = join(dir, NAMES_FILE)
    const bad = (text: string): string => {
      writeFileSync(path, text)
      const e = thrown(() => NameBook.load(dir))
      expect(e.code).toBe('names-invalid')
      return e.message
    }
    expect(bad('{')).toBe(`names-invalid: ${path} is not JSON`)
    expect(bad('null')).toBe(`names-invalid: ${path}: version is not 1`)
    expect(bad('{"version":2,"names":{}}')).toBe(`names-invalid: ${path}: version is not 1`)
    for (const names of ['null', '[]', '"x"']) {
      expect(bad(`{"version":1,"names":${names}}`)).toBe(`names-invalid: ${path}: names is not an object`)
    }
    const entry = (name: string, e: unknown): string =>
      bad(JSON.stringify({ version: 1, names: { [name]: e } }))
    const reason = (name: string): string =>
      `names-invalid: ${path}: the entry ${JSON.stringify(name)} is not a name with an address`
    expect(entry('Bob', { address: A, added_at: 1 })).toBe(reason('Bob'))
    expect(entry('bob', null)).toBe(reason('bob'))
    expect(entry('bob', { address: 'bob', added_at: 1 })).toBe(reason('bob'))
    expect(entry('bob', { address: A, added_at: -1 })).toBe(reason('bob'))
    expect(entry('bob', { address: A, added_at: 1.5 })).toBe(reason('bob'))
    expect(entry('bob', { address: A, added_at: 1, previous: {} })).toBe(reason('bob'))
    expect(entry('bob', { address: A, added_at: 1, previous: [null] })).toBe(reason('bob'))
    expect(entry('bob', { address: A, added_at: 1, previous: [{ address: B }] })).toBe(reason('bob'))
    expect(entry('bob', { address: A, added_at: 1, previous: [{ address: 'x', replaced_at: 1 }] })).toBe(
      reason('bob'),
    )
    writeFileSync(
      path,
      JSON.stringify({
        version: 1,
        names: { bob: { address: A, added_at: 1, previous: [{ address: B, replaced_at: 0 }] } },
      }),
    )
    expect(NameBook.load(dir).display(B)).toEqual({ name: 'bob', former: true, replacedAt: 0 })
  })
})

describe('NameBook: pinning, replacing, forgetting and resolving', () => {
  it('pins a name: the same address again is a no-op, another one is name-exists without replace', () => {
    const book = NameBook.load(home())
    book.add('bob', A, T0)
    book.add('bob', A, T0 + 5)
    expect(book.list()).toEqual([['bob', { address: A, added_at: T0 }]])
    expect(thrown(() => book.add('bob', B, T0 + 5))).toEqual({
      code: 'name-exists',
      message: `name-exists: bob is ${A}; pass --replace to change it`,
    })
    expect(book.resolve('bob')).toBe(A)
  })

  it('replaces with replace, keeping the old address as former, and drops a former address that comes back', () => {
    const book = NameBook.load(home())
    book.add('bob', A, T0)
    book.add('bob', B, T0 + 10, true)
    expect(book.list()).toEqual([
      ['bob', { address: B, added_at: T0 + 10, previous: [{ address: A, replaced_at: T0 + 10 }] }],
    ])
    book.add('bob', C, T0 + 20, true)
    book.add('bob', A, T0 + 30, true)
    expect(book.list()).toEqual([
      [
        'bob',
        {
          address: A,
          added_at: T0 + 30,
          previous: [
            { address: B, replaced_at: T0 + 20 },
            { address: C, replaced_at: T0 + 30 },
          ],
        },
      ],
    ])
    book.save()
    expect(NameBook.load(book.home).list()).toEqual(book.list())
  })

  it('refuses a name outside the pattern, an address for a name, and an address that is not one', () => {
    const book = NameBook.load(home())
    for (const bad of ['', 'Bob', '-bob', '.bob', 'a'.repeat(33), 'bob alice', A]) {
      expect(thrown(() => book.add(bad, A, T0)).code).toBe('bad-name')
    }
    book.add('a'.repeat(32), A, T0)
    book.add('0.b_c-d', A, T0)
    expect(thrown(() => book.add('bob', 'bob', T0))).toEqual({
      code: 'bad-address',
      message: 'bad-address: "bob" is not an address',
    })
  })

  it('forgets a name, and refuses one it does not have with the names it has', () => {
    const book = NameBook.load(home())
    expect(thrown(() => book.forget('bob'))).toEqual({
      code: 'name-unknown',
      message: `name-unknown: no name "bob" in ${book.path}; the book is empty`,
    })
    book.add('bob', A, T0)
    book.add('alice', B, T0)
    book.forget('bob')
    expect(book.list().map(([name]) => name)).toEqual(['alice'])
  })

  it('resolves an address to itself, a name to its address, and refuses an unknown name or text that is neither', () => {
    const book = NameBook.load(home())
    book.add('carol', C, T0)
    book.add('alice', A, T0)
    expect(book.resolve(B)).toBe(B)
    expect(book.resolve('alice')).toBe(A)
    expect(thrown(() => book.resolve('bob'))).toEqual({
      code: 'name-unknown',
      message: `name-unknown: no name "bob" in ${book.path}; the known names are alice, carol`,
    })
    expect(thrown(() => book.resolve('ed25519:12'))).toEqual({
      code: 'bad-address',
      message: 'bad-address: "ed25519:12" is neither an address nor a name',
    })
  })
})

describe('NameBook: how an address is shown', () => {
  it('names a current address, warns on a former one, and leaves an unknown one whole', () => {
    const book = NameBook.load(home())
    book.add('bob', A, T0)
    book.add('bob', B, T0 + 60, true)
    book.add('alice', C, T0)
    expect(book.display(B)).toEqual({ name: 'bob', former: false })
    expect(book.display(A)).toEqual({ name: 'bob', former: true, replacedAt: T0 + 60 })
    expect(book.display(`ed25519:${'d4'.repeat(32)}`)).toBeNull()
    expect(short(B)).toBe('ed25519:b2b2b2b2…')
    expect(book.label(B)).toBe('bob (ed25519:b2b2b2b2…)')
    expect(book.label(C)).toBe('alice (ed25519:c3c3c3c3…)')
    expect(book.label(A)).toBe(
      'bob? (ed25519:a1a1a1a1…) WARNING: former address of bob, replaced 2027-01-15T08:01:00Z',
    )
    expect(book.label(`ed25519:${'d4'.repeat(32)}`)).toBe(`ed25519:${'d4'.repeat(32)}`)
    // A current address wins over the same address as some other name's former one.
    book.add('carl', A, T0)
    expect(book.label(A)).toBe('carl (ed25519:a1a1a1a1…)')
    expect(instant(1792941104)).toBe('2026-10-25T15:11:44Z')
  })
})

describe('name: the command line of the book', () => {
  it('adds, lists with former addresses, replaces and forgets, in the home of --dir, AC_HOME or HOME', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    const d = ['--dir', dir]
    expect(await cli(io, 'name', 'add', 'bob', A, ...d)).toEqual({ code: 0, out: [`bob ${A}`], err: [] })
    expect(await cli(io, 'name', 'add', 'alice', C, ...d)).toEqual({ code: 0, out: [`alice ${C}`], err: [] })
    expect(await cli(io, 'name', 'add', 'bob', B, ...d)).toEqual({
      code: 1,
      out: [],
      err: [`bag: name-exists: bob is ${A}; pass --replace to change it`],
    })
    io.time.now = T0 + 7
    expect((await cli(io, 'name', 'add', 'bob', B, '--replace', ...d)).out).toEqual([`bob ${B}`])
    expect(await cli(io, 'name', 'list', ...d)).toEqual({
      code: 0,
      out: [`alice ${C}`, `bob ${B}`, `  former ${A} replaced ${T0 + 7}`],
      err: [],
    })
    expect(await cli(io, 'name', 'forget', 'alice', ...d)).toEqual({ code: 0, out: [], err: [] })
    expect((await cli(io, 'name', 'list', ...d)).out).toEqual([
      `bob ${B}`,
      `  former ${A} replaced ${T0 + 7}`,
    ])
    expect((await cli(io, 'name', 'forget', 'alice', ...d)).err).toEqual([
      `bag: name-unknown: no name "alice" in ${join(dir, NAMES_FILE)}; the known names are bob`,
    ])
    const env = testIo(new MemoryRelay(), { AC_HOME: dir })
    expect((await cli(env, 'name', 'list')).out).toEqual([`bob ${B}`, `  former ${A} replaced ${T0 + 7}`])
    expect((await cli(testIo(new MemoryRelay()), 'name', 'list')).err[0]).toBe(
      'bag: usage: no home directory: pass --dir, or set AC_HOME or HOME',
    )
  })

  it('refuses an unknown verb, a missing argument and a bad name or address', async () => {
    const io = testIo(new MemoryRelay())
    const d = ['--dir', home()]
    const usage =
      'bag: usage: name add <name> <address> [--replace] | name list | name forget <name>, each [--dir <home>]'
    expect((await cli(io, 'name')).err[0]).toBe(usage)
    expect((await cli(io, 'name', 'rename', 'a', 'b')).err[0]).toBe(usage)
    expect((await cli(io, 'name', 'add', 'bob', ...d)).err[0]).toBe('bag: usage: expected <name> <address>')
    expect((await cli(io, 'name', 'add', 'Bob', A, ...d)).err[0]).toMatch(
      /^bag: bad-name: "Bob" is not a name/,
    )
    expect((await cli(io, 'name', 'add', 'bob', 'x', ...d)).err[0]).toBe(
      'bag: bad-address: "x" is not an address',
    )
    expect((await cli(io, 'name', 'list', 'x', ...d)).err[0]).toMatch(/^bag: usage: no positional argument/)
  })
})

describe('NameBook.find: resolve, then the enterprise directory only with a session', () => {
  it('with no enterprise session is resolve: an address, a known name, name-unknown, bad-address; no call', async () => {
    const h = home()
    const book = NameBook.load(h)
    book.add('ann', A, T0)
    const fetch = async (): Promise<Response> => {
      throw new Error('no call without a session')
    }
    expect([await book.find(B, fetch), await book.find('ann', fetch)]).toEqual([B, A])
    await expect(book.find('bob', fetch)).rejects.toMatchObject({ code: 'name-unknown' })
    await expect(book.find('Not A Name', fetch)).rejects.toMatchObject({ code: 'bad-address' })
  })
})

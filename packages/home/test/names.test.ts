import { readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { generateEdgeKeys, systemRng } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { instant, NAMES_FILE, NameBook, short } from '../src/index.ts'
import { folder } from './support.ts'

// The name book of a home: petnames pinned to addresses, a replaced address kept as a former one.

const a1 = generateEdgeKeys(systemRng).signing.address
const a2 = generateEdgeKeys(systemRng).signing.address

describe('NameBook', () => {
  it('is empty with no file, and writes 0600 sorted, read back the same', () => {
    const home = join(folder(), 'home')
    const book = NameBook.load(home)
    expect(book.list()).toEqual([])
    book.add('zed', a1, 10)
    book.add('amy', a2, 11)
    book.save()
    expect(statSync(join(home, NAMES_FILE)).mode & 0o777).toBe(0o600)
    const again = NameBook.load(home)
    expect(again.list().map(([n]) => n)).toEqual(['amy', 'zed'])
    expect(again.has('amy')).toBe(true)
    expect(again.has('bob')).toBe(false)
    expect(JSON.parse(readFileSync(join(home, NAMES_FILE), 'utf8')).version).toBe(1)
  })

  it('refuses a file that is not a book (names-invalid), and passes on any other read error', () => {
    const home = folder()
    writeFileSync(join(home, NAMES_FILE), '{')
    expect(() => NameBook.load(home)).toThrow(`names-invalid: ${join(home, NAMES_FILE)} is not JSON`)
    for (const [d, why] of [
      [{ version: 2, names: {} }, 'version is not 1'],
      [{ version: 1, names: [] }, 'names is not an object'],
      [
        { version: 1, names: { bob: { address: 'x', added_at: 1 } } },
        'the entry "bob" is not a name with an address',
      ],
      [
        { version: 1, names: { bob: { address: a1, added_at: 1, previous: [{ address: a2 }] } } },
        'the entry "bob"',
      ],
    ] as const) {
      writeFileSync(join(home, NAMES_FILE), JSON.stringify(d))
      expect(() => NameBook.load(home), why).toThrow(why)
    }
    const file = join(folder(), 'f')
    writeFileSync(file, '')
    expect(() => NameBook.load(join(file, 'under'))).toThrow(/ENOTDIR/)
  })

  it('adds, keeps the same address, refuses another unless replaced, and keeps the former one', () => {
    const book = NameBook.load(folder())
    expect(() => book.add('Bad Name', a1, 1)).toThrow('bad-name: "Bad Name" is not a name')
    expect(() => book.add(a1, a1, 1)).toThrow('bad-name')
    expect(() => book.add('bob', 'nope', 1)).toThrow('bad-address')
    book.add('bob', a1, 1)
    book.add('bob', a1, 2)
    expect(book.list()).toEqual([['bob', { address: a1, added_at: 1 }]])
    expect(() => book.add('bob', a2, 3)).toThrow(`name-exists: bob is ${a1}; pass --replace to change it`)
    expect(() => book.check('bob', a2)).toThrow('name-exists')
    expect(() => book.check('bob')).toThrow('name-exists')
    expect(() => book.check('bob', a1)).not.toThrow()
    book.add('bob', a2, 3, true)
    expect(book.list()).toEqual([
      ['bob', { address: a2, added_at: 3, previous: [{ address: a1, replaced_at: 3 }] }],
    ])
    expect(book.display(a2)).toEqual({ name: 'bob', former: false })
    expect(book.display(a1)).toEqual({ name: 'bob', former: true, replacedAt: 3 })
    expect(book.label(a2)).toBe(`bob (${short(a2)})`)
    expect(book.label(a1)).toContain(`WARNING: former address of bob, replaced ${instant(3)}`)
    book.add('bob', a1, 4, true)
    expect(book.list()[0]?.[1].previous).toEqual([{ address: a2, replaced_at: 4 }])
  })

  it('resolves an address, a name, and refuses the rest; forgets a name it has', () => {
    const book = NameBook.load(folder())
    expect(() => book.forget('bob')).toThrow(/name-unknown: no name "bob" in .*; the book is empty/)
    book.add('bob', a1, 1)
    expect(book.resolve(a2)).toBe(a2)
    expect(book.resolve('bob')).toBe(a1)
    expect(() => book.resolve('Not A Name')).toThrow('bad-address')
    expect(() => book.resolve('amy')).toThrow('the known names are bob')
    expect(book.display(a2)).toBeNull()
    expect(book.label(a2)).toBe(a2)
    book.forget('bob')
    expect(book.list()).toEqual([])
  })

  it('load makes the class it is called on, so a subclass keeps its own methods', () => {
    class Shout extends NameBook {
      loud(): string {
        return this.home.toUpperCase()
      }
    }
    const home = folder()
    expect(Shout.load(home).loud()).toBe(home.toUpperCase())
    expect(Shout.load(home)).toBeInstanceOf(NameBook)
  })
})

describe('instant and short', () => {
  it('formats seconds as an ISO instant and an address as its first 8 hex digits', () => {
    expect(instant(1792941104)).toBe('2026-10-25T15:11:44Z')
    expect(short(a1)).toBe(`${a1.slice(0, 16)}\u2026`)
  })
})

import { chmodSync, mkdirSync, statSync, utimesSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { FsKeyStore } from '../src/adapters/fs-keys.ts'
import { P, tempDir } from './support/fixtures.ts'

// The file custody: FsKeyStore as a KeyCustody lists its key files, and its signer and opener of
// an address are the keys load returns, with load's refusals; fs-keys.test.ts keeps load and save as they were.

const tmp = tempDir('custody-fs')
afterAll(() => tmp.cleanup())
let n = 0
const fresh = (): string => join(tmp.dir, `keys-${n++}`)

describe('FsKeyStore as the file custody: list, entry, create, signer and opener by address', () => {
  it('lists its key files by name with their addresses and mtimes, and nothing without a directory', () => {
    const dir = fresh()
    const store = new FsKeyStore(dir)
    expect(store.kind).toBe('file')
    expect(store.list()).toEqual([])
    store.save('zed', P.carol.keys)
    store.save('amy', P.jane.keys)
    utimesSync(join(dir, 'amy.json'), 1_800_000_100, 1_800_000_100)
    writeFileSync(join(dir, 'notes.txt'), 'not a key')
    writeFileSync(join(dir, 'Upper.json'), '{}')
    mkdirSync(join(dir, 'sub'))
    const entries = store.list()
    expect(entries.map((e) => [e.name, e.address, e.custody])).toEqual([
      ['amy', P.jane.address, 'file'],
      ['zed', P.carol.address, 'file'],
    ])
    expect(entries[0]?.created).toBe(1_800_000_100)
    expect(entries[1]?.created).toBe(Math.floor(statSync(join(dir, 'zed.json')).mtimeMs / 1000))
  })

  it("creates as save does, never over a file, and its entry is load's address", () => {
    const store = new FsKeyStore(fresh())
    const entry = store.create('jane', P.jane.keys)
    expect(entry.address).toBe(store.load('jane').signing.address)
    expect(store.entry('jane')).toEqual(entry)
    expect(() => store.create('jane', P.bob.keys)).toThrow(/^EEXIST: file already exists, open /)
    expect(() => store.create('../x', P.bob.keys)).toThrow(
      'fs-keys: a key name is 1 to 64 of [a-z0-9._-], not "../x"',
    )
  })

  it('gives the signer and the opener of an address, read once, found by reading the files when not read yet', () => {
    const dir = fresh()
    new FsKeyStore(dir).save('jane', P.jane.keys)
    new FsKeyStore(dir).save('bob', P.bob.keys)
    const store = new FsKeyStore(dir)
    const signer = store.signer(P.bob.address)
    expect(signer.address).toBe(P.bob.address)
    expect(signer.sign(new Uint8Array(32))).toEqual(P.bob.signing.sign(new Uint8Array(32)))
    expect(store.opener(P.jane.address).publicKey).toEqual(P.jane.sealing.publicKey)
    expect(store.opener(P.bob.address)).toBe(store.opener(P.bob.address))
    let code = ''
    try {
      store.signer(P.carol.address)
    } catch (e) {
      code = `${(e as { code: string }).code} ${(e as Error).message}`
    }
    expect(code).toBe(`ENOENT fs-keys: no key file in ${dir} is ${P.carol.address}'s`)
  })

  it("refuses with load's refusals: a directory others can enter, a key file that is not private or not a key", () => {
    const dir = fresh()
    const store = new FsKeyStore(dir)
    store.save('jane', P.jane.keys)
    chmodSync(dir, 0o755)
    expect(() => store.list()).toThrow(`fs-keys: ${dir} has mode 0755; it must be 0700`)
    chmodSync(dir, 0o700)
    chmodSync(join(dir, 'jane.json'), 0o644)
    expect(() => store.signer(P.jane.address)).toThrow('has mode 0644; it must be 0600')
    chmodSync(join(dir, 'jane.json'), 0o600)
    writeFileSync(join(dir, 'cut.json'), '{"suite":1', { mode: 0o600 })
    expect(() => store.list()).toThrow(`fs-keys: ${join(dir, 'cut.json')} is not JSON`)
    const plain = join(tmp.dir, `plain-${n++}`)
    writeFileSync(plain, 'x')
    expect(() => new FsKeyStore(plain).list()).toThrow(`fs-keys: ${plain} is not a directory`)
  })
})

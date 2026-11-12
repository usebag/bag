import {
  chmodSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { sealingKeyFromSeed } from '@usebag/core'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { checkName, errno, keysOf, keyText, names, present, writeNew } from '../src/custody/files.ts'
import { HomeCustody } from '../src/custody/home.ts'
import type { EdgeKeys } from '../src/ports.ts'
import { P, tempDir } from './support/fixtures.ts'
import { FakeSecurity, type Item } from './support/security.ts'

// The home's two custodies: which one holds a name, the list of both, and a name in only
// one of them; and the file rules both share.

const tmp = tempDir('custody-home')
afterAll(() => tmp.cleanup())
let n = 0
const fresh = (): string => join(tmp.dir, `home-${n++}`)
const failure = (f: () => unknown): string => {
  try {
    f()
  } catch (e) {
    return `${(e as { code?: string }).code ?? 'no code'} ${(e as Error).message}`
  }
  return 'no error'
}

describe('HomeCustody: an identity in one custody, found by name', () => {
  it('finds a key file in <home>/keys, and a keychain pointer in <home>/keychain, with one read for both keys', () => {
    const fake = new FakeSecurity()
    const home = fresh()
    const custody = new HomeCustody(home, { run: fake.run })
    custody.create('jane', P.jane.keys, { custody: 'file' })
    custody.create('bob', P.bob.keys, {
      custody: 'keychain',
      keychain: '/tmp/k.keychain-db',
      access: 'security',
    })
    custody.create('carol', P.carol.keys, { custody: 'keychain' })
    expect(custody.holder('jane')).toBe(custody.files)
    expect(custody.holder('bob')).toBe(custody.keychain)
    expect(custody.list().map((e) => [e.name, e.address, e.custody])).toEqual([
      ['bob', P.bob.address, 'keychain'],
      ['carol', P.carol.address, 'keychain'],
      ['jane', P.jane.address, 'file'],
    ])
    expect(fake.calls).toHaveLength(2)
    expect(custody.entry('bob').address).toBe(P.bob.address)
    expect(fake.calls).toHaveLength(2)
    const keys = custody.keys('bob')
    expect([keys.signing.address, keys.sealing.publicKey]).toEqual([P.bob.address, P.bob.sealing.publicKey])
    expect(fake.calls.map((c) => c.args[0])).toEqual(['-i', '-i', 'find-generic-password'])
    expect(custody.keys('jane').signing.address).toBe(P.jane.address)
    expect(fake.items.get(FakeSecurity.key(null, 'bag:carol', P.carol.address))?.noApplication).toBe(true)
  })

  it('refuses a name either custody holds, a name both hold, and a bad name with the key files message', () => {
    const fake = new FakeSecurity()
    const home = fresh()
    const custody = new HomeCustody(home, { run: fake.run })
    custody.create('jane', P.jane.keys, { custody: 'file' })
    custody.create('bob', P.bob.keys, { custody: 'keychain' })
    expect(failure(() => custody.create('jane', P.carol.keys, { custody: 'keychain' }))).toBe(
      `EEXIST jane is held already, by ${join(home, 'keys', 'jane.json')}`,
    )
    expect(failure(() => custody.create('bob', P.carol.keys, { custody: 'file' }))).toBe(
      `EEXIST bob is held already, by ${join(home, 'keychain', 'bob.json')}`,
    )
    expect(fake.calls).toHaveLength(1)
    custody.files.save('bob', P.carol.keys)
    expect(failure(() => custody.keys('bob'))).toBe(
      'EEXIST bob has both a key file and a keychain pointer: an identity custody move stopped; run bag identity custody bob --to keychain (or --to file) to finish',
    )
    expect(failure(() => custody.holder('../keys/jane'))).toBe(
      'no code fs-keys: a key name is 1 to 64 of [a-z0-9._-], not "../keys/jane"',
    )
    expect(failure(() => custody.keys('ghost'))).toMatch(/^ENOENT ENOENT: no such file or directory, lstat /)
  })

  it('runs the keychain custody with its own runner when given none', () => {
    const custody = new HomeCustody(fresh())
    expect(custody.list()).toEqual([])
    expect(custody.create('jane', P.jane.keys, { custody: 'file' }).custody).toBe('file')
  })
})

describe('HomeCustody.replaceSealing: the long-term sealing key replaced', () => {
  const seed = new Uint8Array(32).fill(7)
  const fresh32 = sealingKeyFromSeed(seed).publicKey
  const text = (data: Uint8Array) => keysOf(() => new TextDecoder().decode(data)) as EdgeKeys
  const stop = { status: 36, stdout: new Uint8Array(), stderr: new Uint8Array() }

  it('rewrites a key file through a new 0600 file, keeping its mtime: the signing key stays, the other files are untouched', () => {
    const home = fresh()
    const custody = new HomeCustody(home)
    custody.create('jane', P.jane.keys, { custody: 'file' })
    custody.create('bob', P.bob.keys, { custody: 'file' })
    const bob = readFileSync(join(home, 'keys', 'bob.json'), 'utf8')
    utimesSync(join(home, 'keys', 'jane.json'), 1_700_000_000, 1_700_000_000)
    custody.replaceSealing('jane', seed)
    expect(statSync(join(home, 'keys', 'jane.json')).mtimeMs).toBe(1_700_000_000_000) // when it was made: kept
    const kept = new HomeCustody(home).keys('jane')
    expect([kept.signing.address, kept.sealing.publicKey]).toEqual([P.jane.address, fresh32])
    expect(readdirSync(join(home, 'keys'))).toEqual(['bob.json', 'jane.json'])
    expect(statSync(join(home, 'keys', 'jane.json')).mode & 0o777).toBe(0o600)
    expect(readFileSync(join(home, 'keys', 'bob.json'), 'utf8')).toBe(bob)
  })

  it('removes its temporary file, which holds sign_seed, when the rename fails', () => {
    const home = fresh()
    const custody = new HomeCustody(home)
    custody.create('jane', P.jane.keys, { custody: 'file' })
    const file = join(home, 'keys', 'jane.json')
    const signer = custody.files.signer.bind(custody.files)
    // The key file becomes a directory after it is read, so the rename onto it fails.
    vi.spyOn(custody.files, 'signer').mockImplementation((address) => {
      const read = signer(address)
      unlinkSync(file)
      mkdirSync(file)
      return read
    })
    expect(failure(() => custody.replaceSealing('jane', seed))).toMatch(/^(EISDIR|ENOTEMPTY|EEXIST)/)
    expect(readdirSync(join(home, 'keys'))).toEqual(['jane.json'])
    vi.restoreAllMocks()
  })

  it('updates a keychain item by one -U line, keeping its pointer and its access; a path in the line is quoted', () => {
    const fake = new FakeSecurity()
    const home = fresh()
    const custody = new HomeCustody(home, { run: fake.run })
    custody.create('bob', P.bob.keys, { custody: 'keychain' })
    custody.create('carol', P.carol.keys, { custody: 'keychain', keychain: '/tmp/k.keychain-db' })
    const pointers = ['bob', 'carol'].map((x) => readFileSync(join(home, 'keychain', `${x}.json`), 'utf8'))
    custody.replaceSealing('bob', seed)
    custody.replaceSealing('carol', seed)
    const [bob, carol] = fake.calls.filter((c) => c.args[0] === '-i').slice(-2)
    const line = (who: typeof P.bob) => `-s bag:${who.name} -a ${who.address} -T "" -X `
    expect(bob?.input).toMatch(new RegExp(`^add-generic-password -U ${line(P.bob)}[0-9a-f]+\\n$`))
    expect(carol?.input).toMatch(
      new RegExp(`^add-generic-password -U ${line(P.carol)}[0-9a-f]+ "/tmp/k.keychain-db"\\n$`),
    )
    const held = [
      fake.items.get(FakeSecurity.key(null, 'bag:bob', P.bob.address)),
      fake.items.get(FakeSecurity.key('/tmp/k.keychain-db', 'bag:carol', P.carol.address)),
    ]
    for (const [i, who] of [P.bob, P.carol].entries()) {
      const keys = text(held[i]?.data as Uint8Array)
      expect([keys.signing.address, keys.sealing.publicKey]).toEqual([who.address, fresh32])
      expect(held[i]?.noApplication).toBe(true)
    }
    expect(fake.items.size).toBe(2)
    expect(['bob', 'carol'].map((x) => readFileSync(join(home, 'keychain', `${x}.json`), 'utf8'))).toEqual(
      pointers,
    )
  })

  it('names the access in the line: an item it has to add trusts no application under prompt, and security alone otherwise', () => {
    const fake = new FakeSecurity()
    const home = fresh()
    const custody = new HomeCustody(home, { run: fake.run })
    custody.create('bob', P.bob.keys, { custody: 'keychain' })
    custody.create('carol', P.carol.keys, { custody: 'keychain', access: 'security' })
    for (const [name, who] of [
      ['bob', P.bob],
      ['carol', P.carol],
    ] as const) {
      custody.keys(name) // read and cached, then the item goes: the update has to add it
      fake.items.delete(FakeSecurity.key(null, `bag:${name}`, who.address))
      custody.replaceSealing(name, seed)
    }
    const [bob, carol] = fake.calls.filter((c) => c.args[0] === '-i').slice(-2)
    expect(bob?.input).toContain(' -T "" -X ')
    expect(carol?.input).not.toContain(' -T ')
    expect(fake.items.get(FakeSecurity.key(null, 'bag:bob', P.bob.address))?.noApplication).toBe(true)
    expect(fake.items.get(FakeSecurity.key(null, 'bag:carol', P.carol.address))?.noApplication).toBe(false)
  })

  it('throws when security refuses the update, leaving the item as it was, and refuses a path it cannot quote before any call', () => {
    const fake = new FakeSecurity()
    const home = fresh()
    const custody = new HomeCustody(home, { run: fake.run })
    custody.create('bob', P.bob.keys, { custody: 'keychain', keychain: '/tmp/k.keychain-db' })
    const key = FakeSecurity.key('/tmp/k.keychain-db', 'bag:bob', P.bob.address)
    const item = fake.items.get(key)
    custody.keys('bob') // read once: the replacement's own read is from the custody's cache
    fake.next.push(stop)
    expect(failure(() => custody.replaceSealing('bob', seed))).toBe(
      'EACCES keychain: replacing the item of bob: refused, locked or denied at the dialog (security exited 36)',
    )
    expect(fake.items.get(key)).toBe(item)
    const pointer = join(home, 'keychain', 'bob.json')
    // The pointer stays JSON: its keychain field becomes a path with a quote, which `security -i` cannot take.
    writeFileSync(pointer, JSON.stringify({ ...JSON.parse(readFileSync(pointer, 'utf8')), keychain: 'a"b' }))
    fake.items.set(FakeSecurity.key('a"b', 'bag:bob', P.bob.address), item as Item)
    const calls = fake.calls.length
    expect(failure(() => new HomeCustody(home, { run: fake.run }).replaceSealing('bob', seed))).toBe(
      'no code keychain: security -i cannot quote the path',
    )
    expect(fake.calls.slice(calls).map((c) => c.args[0])).toEqual(['find-generic-password'])
  })
})

describe('the file rules both custodies keep', () => {
  it('names, presence, new files and the key text', () => {
    expect(() => checkName('x', 'ok.name-1_')).not.toThrow()
    expect(() => checkName('x', 'A')).toThrow('x: a key name is 1 to 64 of [a-z0-9._-], not "A"')
    expect(errno('EACCES', 'm')).toMatchObject({ code: 'EACCES', message: 'm' })
    const dir = join(fresh(), 'd')
    expect(names('x', dir)).toEqual([])
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    chmodSync(dir, 0o700)
    writeNew(join(dir, 'b.json'), 't')
    writeNew(join(dir, 'a.json'), 't')
    expect(names('x', dir)).toEqual(['a', 'b'])
    expect(() => writeNew(join(dir, 'a.json'), 'u')).toThrow(/^EEXIST/)
    expect(present(join(dir, 'a.json'))).toBe(true)
    expect(present(join(dir, 'none.json'))).toBe(false)
    writeFileSync(join(dir, 'file'), 'x')
    expect(() => present(join(dir, 'file', 'below'))).toThrow(/^ENOTDIR/)
    expect(keysOf(() => keyText(P.jane.keys))).toMatchObject({ signing: { address: P.jane.address } })
    expect(keysOf(() => 'nope')).toBe('json')
    expect(keysOf(() => '[]')).toBe('shape')
    expect(
      keysOf(() => {
        throw new Error('unreadable')
      }),
    ).toBe('json')
  })
})

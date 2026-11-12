import { chmodSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { defaultKeychain, type SecurityResult } from '../src/adapters/keychain.ts'
import { custodyClass, HomeCustody, openIdentityKeys, serviceCustody } from '../src/custody/home.ts'
import { P, seed, tempDir } from './support/fixtures.ts'
import { FakeSecurity } from './support/security.ts'

// The custody class a bag service checks per call (custodyClass, serviceCustody), which reads no key; the keys a
// service loads at start and again after a drain-and-restart (a new HomeCustody in the new process: the item is
// read again, never reused); and the default keychain keygen's default custody turns on.

const tmp = tempDir('custody-class')
afterAll(() => tmp.cleanup())
let n = 0
const fresh = (): string => join(tmp.dir, `h${n++}`)
const code = (f: () => unknown): string => {
  try {
    f()
  } catch (e) {
    return String((e as { code?: unknown }).code ?? (e as Error).message)
  }
  return 'none'
}
const codeOf = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p
  } catch (e) {
    return String((e as { code?: unknown }).code ?? (e as Error).message)
  }
  return 'none'
}
const finds = (fake: FakeSecurity): number =>
  fake.calls.filter((c) => c.args[0] === 'find-generic-password').length

describe('custodyClass: file, keychain or agent, from which pointer exists, never a key', () => {
  it('names each custody, the wire words of serviceCustody, and refuses doubles and a missing identity', () => {
    const fake = new FakeSecurity()
    const home = fresh()
    const custody = new HomeCustody(home, { run: fake.run })
    custody.create('alice', P.jane.keys, { custody: 'file' })
    custody.create('bob', P.bob.keys, { custody: 'keychain' })
    custody.agent.create('ag', P.carol.keys)
    const calls = fake.calls.length
    expect(['alice', 'bob', 'ag'].map((x) => custodyClass(home, x))).toEqual(['file', 'keychain', 'agent'])
    expect(['alice', 'bob', 'ag'].map((x) => serviceCustody(home, x))).toEqual([
      'home-key',
      'keychain',
      'agent',
    ])
    expect(fake.calls.length).toBe(calls) // no keychain call
    expect(code(() => custodyClass(home, 'nobody'))).toBe('ENOENT')
    expect(code(() => custodyClass(home, '../x'))).toMatch(/a key name is 1 to 64/)
    writeFileSync(join(home, 'keys', 'bob.json'), '{}', { mode: 0o600 })
    expect(code(() => custodyClass(home, 'bob'))).toBe('EEXIST')
    writeFileSync(join(home, 'keys', 'ag.json'), '{}', { mode: 0o600 })
    expect(code(() => custodyClass(home, 'ag'))).toBe('EEXIST')
  })

  it('reads no key file: a key file that is not a key (and is 0644) is still class file', () => {
    const home = fresh()
    mkdirSync(join(home, 'keys'), { recursive: true, mode: 0o700 })
    writeFileSync(join(home, 'keys', 'x.json'), 'not a key')
    chmodSync(join(home, 'keys', 'x.json'), 0o644)
    expect(custodyClass(home, 'x')).toBe('file')
    expect(() => new HomeCustody(home).keys('x')).toThrow(/mode 0644/)
  })
})

describe('the keys a service loads: at start, and fresh after a drain-and-restart', () => {
  it('a start reads each keychain item once; a restart (a new HomeCustody) reads it again and sees the item as it is now', () => {
    const fake = new FakeSecurity()
    const home = fresh()
    new HomeCustody(home, { run: fake.run }).create('bob', P.bob.keys, { custody: 'keychain' })
    const start = new HomeCustody(home, { run: fake.run })
    const a = start.keys('bob')
    expect(finds(fake)).toBe(1)
    start.keys('bob')
    expect(finds(fake)).toBe(1) // one read, one dialog, per identity and process
    expect(Buffer.from(a.sealing.exportSeed())).toEqual(Buffer.from(P.bob.sealing.exportSeed()))
    // the item changes on disk while the service runs (keys prune from a terminal)
    new HomeCustody(home, { run: fake.run }).replaceSealing('bob', seed(0x55))
    const before = finds(fake)
    const restart = new HomeCustody(home, { run: fake.run })
    const b = restart.keys('bob')
    expect(finds(fake)).toBe(before + 1)
    expect(Buffer.from(b.sealing.exportSeed())).toEqual(Buffer.from(seed(0x55)))
    expect(Buffer.from(a.sealing.exportSeed())).toEqual(Buffer.from(P.bob.sealing.exportSeed()))
    expect(b.signing.address).toBe(P.bob.address)
  })

  it('a key file the same: read at start, read again at restart', () => {
    const home = fresh()
    new HomeCustody(home).create('alice', P.jane.keys, { custody: 'file' })
    const a = new HomeCustody(home).keys('alice')
    new HomeCustody(home).replaceSealing('alice', seed(0x66))
    const b = new HomeCustody(home).keys('alice')
    expect(Buffer.from(a.sealing.exportSeed())).not.toEqual(Buffer.from(b.sealing.exportSeed()))
    expect(Buffer.from(b.sealing.exportSeed())).toEqual(Buffer.from(seed(0x66)))
  })

  it('keys never serialise: JSON of the loaded keys holds addresses and public keys only', () => {
    const fake = new FakeSecurity()
    const home = fresh()
    new HomeCustody(home, { run: fake.run }).create('bob', P.bob.keys, { custody: 'keychain' })
    const json = JSON.stringify(new HomeCustody(home, { run: fake.run }).keys('bob'))
    for (const s of P.bob.secrets) expect(json).not.toContain(s)
  })
})

describe("openIdentityKeys: the service's one open path, per identity", () => {
  it('reads each call afresh (start, after a drain, after a CLI lend that re-keyed it); agent yields no keys', async () => {
    const fake = new FakeSecurity()
    const home = fresh()
    const make = new HomeCustody(home, { run: fake.run })
    make.create('bob', P.bob.keys, { custody: 'keychain' })
    make.create('alice', P.jane.keys, { custody: 'file' })
    make.agent.create('ag', P.carol.keys)
    const o = { run: fake.run, runAsync: async (a: readonly string[], i?: Uint8Array) => fake.run(a, i) }
    const start = await openIdentityKeys(home, 'bob', o)
    expect([start.custody, start.address, finds(fake)]).toEqual(['keychain', P.bob.address, 1])
    const drained = await openIdentityKeys(home, 'bob', o)
    expect(finds(fake)).toBe(2) // a second open reads the item again, never a cache
    expect(Buffer.from(drained.keys?.sealing.exportSeed() ?? [])).toEqual(
      Buffer.from(P.bob.sealing.exportSeed()),
    )
    new HomeCustody(home, o).replaceSealing('bob', seed(0x77)) // the CLI, during a lend
    const back = await openIdentityKeys(home, 'bob', o)
    expect(Buffer.from(back.keys?.sealing.exportSeed() ?? [])).toEqual(Buffer.from(seed(0x77)))
    const file = await openIdentityKeys(home, 'alice', o)
    expect([file.custody, file.address]).toEqual(['home-key', P.jane.address])
    new HomeCustody(home).replaceSealing('alice', seed(0x78))
    expect(Buffer.from((await openIdentityKeys(home, 'alice', o)).keys?.sealing.exportSeed() ?? [])).toEqual(
      Buffer.from(seed(0x78)),
    )
    expect(await openIdentityKeys(home, 'ag', o)).toEqual({
      custody: 'agent',
      address: P.carol.address,
      keys: null,
    })
    const json = JSON.stringify(back)
    for (const s of P.bob.secrets) expect(json).not.toContain(s)
    expect(await codeOf(openIdentityKeys(home, 'nobody', o))).toBe('ENOENT')
    fake.next.push({ status: 128, stdout: new Uint8Array(), stderr: new Uint8Array() })
    expect(await codeOf(openIdentityKeys(home, 'bob', o))).toBe('EACCES') // a Deny at the dialog
  })
})

describe('defaultKeychain: the file security default-keychain names, when it exists', () => {
  const r = (status: number, out = ''): SecurityResult => ({
    status,
    stdout: new TextEncoder().encode(out),
    stderr: new Uint8Array(),
  })
  it('a quoted path that exists; else null', () => {
    const file = join(fresh())
    writeFileSync(file, '')
    expect(defaultKeychain(() => r(0, `    "${file}"\n`))).toBe(file)
    expect(defaultKeychain(() => r(0, `    "${file}.gone"\n`))).toBeNull()
    expect(defaultKeychain(() => r(50))).toBeNull()
    expect(defaultKeychain(() => r(0, 'two\nlines'))).toBeNull()
    expect(defaultKeychain(() => ({ ...r(0, `"${file}"`), error: 'ENOENT' }))).toBeNull()
    expect(
      defaultKeychain(() => {
        throw new Error('no security')
      }),
    ).toBeNull()
  })
})

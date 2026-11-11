import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type AddressRecord, isAddress, parseRecord, toHex, verifyRecord, verifyRotation } from '@usebag/core'
import { RelayError } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

const tmp = tempDir('commands')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
let n = 0
const home = (): string => join(tmp.dir, `home-${n++}`)

/** The hex of an identity's two private keys, read from its key file, to prove that no output ever holds them. */
function secrets(dir: string, name: string): string[] {
  const f = JSON.parse(readFileSync(join(dir, 'keys', `${name}.json`), 'utf8')) as Record<string, string>
  return [f.sign_seed as string, f.seal_priv as string]
}

describe('keygen and address: keys through the edge key store, addresses printed, key material never', () => {
  it('makes a 0600 key file in a 0700 directory and prints only the address, which address prints again', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    const made = await cli(io, 'keygen', 'alice', '--dir', dir)
    expect(made.code).toBe(0)
    expect(made.out).toHaveLength(1)
    expect(isAddress(made.out[0])).toBe(true)
    expect(statSync(join(dir, 'keys')).mode & 0o777).toBe(0o700)
    expect(statSync(join(dir, 'keys', 'alice.json')).mode & 0o777).toBe(0o600)
    expect(await cli(io, 'address', 'alice', '--dir', dir)).toEqual({ code: 0, out: made.out, err: [] })
    const all = [...io.stdout, ...io.stderr].join('\n')
    for (const s of secrets(dir, 'alice')) expect(all).not.toContain(s)
  })

  it('never overwrites a key file, and refuses a name that could leave the directory', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    const first = await cli(io, 'keygen', 'bob', '--dir', dir)
    const again = await cli(io, 'keygen', 'bob', '--dir', dir)
    expect(again.code).toBe(1)
    expect(again.err[0]).toMatch(/^bag: EEXIST: file already exists, open '.*bob\.json'$/)
    expect((await cli(io, 'address', 'bob', '--dir', dir)).out).toEqual(first.out)
    const bad = await cli(io, 'keygen', '../escape', '--dir', dir)
    expect(bad.code).toBe(1)
    expect(bad.err[0]).toContain('bag: error: fs-keys: a key name is 1 to 64 of [a-z0-9._-]')
    expect((await cli(io, 'address', 'nobody', '--dir', dir)).err[0]).toMatch(/^bag: ENOENT: /)
  })

  it('finds the home in --dir, else AC_HOME, else HOME/.bag, else refuses', async () => {
    const a = home()
    const viaEnv = testIo(new MemoryRelay(), { AC_HOME: a })
    const made = await cli(viaEnv, 'keygen', 'carol')
    expect((await cli(testIo(new MemoryRelay()), 'address', 'carol', '--dir', a)).out).toEqual(made.out)
    const h = home()
    const viaHome = testIo(new MemoryRelay(), { HOME: h })
    const dave = await cli(viaHome, 'keygen', 'dave')
    expect((await cli(viaHome, 'address', 'dave', '--dir', join(h, '.bag'))).out).toEqual(dave.out)
    expect((await cli(testIo(new MemoryRelay()), 'keygen', 'erin')).err[0]).toBe(
      'bag: usage: no home directory: pass --dir, or set AC_HOME or HOME',
    )
  })
})

describe('record: signed address and accept-from records, at the clock, to stdout or --out', () => {
  it('signs an address record with relays, the sealing key when asked, and the ttl (a day by default)', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    const address = (await cli(io, 'keygen', 'alice', '--dir', dir)).out[0] as string
    const plain = await cli(io, 'record', 'address', 'alice', '--relay', `${RELAY}/`, '--dir', dir)
    expect(plain.code).toBe(0)
    const r = verifyRecord(parseRecord(plain.out[0] as string), T0)
    expect(r).toMatchObject({
      kind: 'address',
      key: address,
      sealing_key: null,
      relays: [RELAY],
      rotation_key: null,
      revoked: [],
      ttl: 86_400,
      iat: T0,
      rotated_from: null,
      rotation_sig: null,
    })
    const out = join(dir, 'alice.address.json')
    const sealed = await cli(
      io,
      'record',
      'address',
      'alice',
      '--relay',
      RELAY,
      '--relay',
      'https://b.example',
    )
    expect(sealed.err[0]).toBe('bag: usage: no home directory: pass --dir, or set AC_HOME or HOME')
    const withKey = ['--sealing-key', '--ttl', '3600', '--out', out, '--dir', dir]
    expect(await cli(io, 'record', 'address', 'alice', '--relay', RELAY, ...withKey)).toEqual({
      code: 0,
      out: [],
      err: [],
    })
    const file = readFileSync(out, 'utf8')
    expect(file.endsWith('}\n')).toBe(true)
    const s = verifyRecord(parseRecord(file), T0)
    expect(s).toMatchObject({ sealing_key: expect.stringMatching(/^[0-9a-f]{64}$/), ttl: 3600 })
    expect(file).not.toContain(secrets(dir, 'alice')[1] as string)
  })

  it('refuses an address record without a relay, with a ttl over a day, or with a relay that is not a URL', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    await cli(io, 'keygen', 'alice', '--dir', dir)
    expect((await cli(io, 'record', 'address', 'alice', '--dir', dir)).err[0]).toBe(
      'bag: usage: --relay is required',
    )
    const long = await cli(io, 'record', 'address', 'alice', '--relay', RELAY, '--ttl', '86401', '--dir', dir)
    expect(long.err[0]).toBe('bag: bad-record: ttl is from 1 to 86400 seconds')
    expect((await cli(io, 'record', 'address', 'alice', '--relay', 'x', '--dir', dir)).err[0]).toBe(
      'bag: usage: "x" is not a URL',
    )
  })

  it('writes a rotation with --rotated-from, countersigned by the old key, and refuses itself and an unknown name', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    const org = (await cli(io, 'keygen', 'org', '--dir', dir)).out[0] as string
    const next = (await cli(io, 'keygen', 'org-2', '--dir', dir)).out[0] as string
    const args = ['--relay', RELAY, '--sealing-key', '--ttl', '600', '--dir', dir]
    const prev = parseRecord((await cli(io, 'record', 'address', 'org', ...args)).out[0] as string)
    const rotated = await cli(io, 'record', 'address', 'org-2', ...args, '--rotated-from', 'org')
    expect(rotated.code).toBe(0)
    const r = verifyRecord(parseRecord(rotated.out[0] as string), T0) as AddressRecord
    expect(r).toMatchObject({ kind: 'address', key: next, rotated_from: org, ttl: 600 })
    expect(r.rotation_sig).toMatch(/^[0-9a-f]{128}$/)
    expect(() => verifyRotation(prev as AddressRecord, r)).not.toThrow()
    const bare = parseRecord((await cli(io, 'record', 'address', 'org-2', ...args)).out[0] as string)
    expect(() => verifyRotation(prev as AddressRecord, bare as AddressRecord)).toThrow(/^bad-rotation: /)
    const all = [...io.stdout, ...io.stderr].join('\n')
    for (const name of ['org', 'org-2']) for (const k of secrets(dir, name)) expect(all).not.toContain(k)
    expect((await cli(io, 'record', 'address', 'org', ...args, '--rotated-from', 'org')).err[0]).toBe(
      'bag: usage: --rotated-from names the identity itself; a rotation moves to another key',
    )
    expect((await cli(io, 'record', 'address', 'org-2', ...args, '--rotated-from', 'nobody')).err[0]).toMatch(
      /^bag: ENOENT: /,
    )
  })

  it('signs an accept-from record with its roots or the wildcard, its size limit and its retention', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    const bob = (await cli(io, 'keygen', 'bob', '--dir', dir)).out[0] as string
    const alice = (await cli(io, 'keygen', 'alice', '--dir', dir)).out[0] as string
    const args = ['--max-bytes', '65536', '--ttl', '604800', '--dir', dir]
    const r = await cli(io, 'record', 'accept-from', 'bob', '--root', alice, '--root', bob, ...args)
    expect(verifyRecord(parseRecord(r.out[0] as string), T0)).toMatchObject({
      kind: 'accept-from',
      owner: bob,
      roots: [alice, bob],
      max_bytes: 65_536,
      ttl: 604_800,
      iat: T0,
    })
    const any = await cli(io, 'record', 'accept-from', 'bob', '--root', '*', ...args)
    expect(parseRecord(any.out[0] as string)).toMatchObject({ roots: ['*'] })
    const mixed = await cli(io, 'record', 'accept-from', 'bob', '--root', '*', '--root', alice, ...args)
    expect(mixed.err[0]).toBe('bag: bad-record: "*" stands alone in roots')
    expect((await cli(io, 'record', 'accept-from', 'bob', '--root', '*', '--dir', dir)).err[0]).toBe(
      'bag: usage: --max-bytes is required',
    )
    expect((await cli(io, 'record', 'key', 'bob')).err[0]).toBe(
      'bag: usage: record address <name> ..., record accept-from <name> ... or record keep --as <name> ...',
    )
  })

  it('refuses a non-terminal caller that drops a held root, confirms the drop on a terminal (83c)', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    const bob = (await cli(io, 'keygen', 'bob', '--dir', dir)).out[0] as string
    const alice = (await cli(io, 'keygen', 'alice', '--dir', dir)).out[0] as string
    const args = ['--max-bytes', '65536', '--ttl', '604800', '--dir', dir]
    // Seed the home copy (bob's accept-from record in the home) with [alice, bob]: no drop, so this write needs no
    // terminal.
    mkdirSync(join(dir, 'records'), { recursive: true })
    const copy = join(dir, 'records', 'bob.accept.json')
    const drop = ['record', 'accept-from', 'bob', '--root', bob, ...args]
    expect(
      (await cli(io, 'record', 'accept-from', 'bob', '--root', alice, '--root', bob, ...args, '--out', copy))
        .code,
    ).toBe(0)
    // Dropping alice is a person's act, like unpair: refused when stdin is not a terminal, nothing written.
    io.tty = false
    expect((await cli(io, ...drop)).err[0]).toMatch(
      /^bag: no-tty: record accept-from that drops a root is a person's act/,
    )
    // On a terminal, a no leaves nothing written; the prompt names the dropped root.
    io.tty = true
    io.answers.push(false)
    expect((await cli(io, ...drop)).err[0]).toBe('bag: declined: nothing was written')
    expect(io.asked.at(-1)).toBe(`drop ${alice} from the accept-from of bob?`)
    // A yes writes the narrowed record.
    io.answers.push(true)
    expect(verifyRecord(parseRecord((await cli(io, ...drop)).out[0] as string), T0)).toMatchObject({
      roots: [bob],
    })
    // A run that keeps every held root (adds one) drops nothing, so a non-terminal cron run is never refused.
    io.tty = false
    const grow = await cli(io, 'record', 'accept-from', 'bob', '--root', alice, '--root', bob, ...args)
    expect(grow.code).toBe(0)
  })
})

describe('publish and health: the relay calls that need no identity', () => {
  it('publishes a record file through the relay client and prints its kind and signer', async () => {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = home()
    const alice = (await cli(io, 'keygen', 'alice', '--dir', dir)).out[0] as string
    const file = join(dir, 'alice.json')
    await cli(
      io,
      'record',
      'address',
      'alice',
      '--relay',
      RELAY,
      '--sealing-key',
      '--out',
      file,
      '--dir',
      dir,
    )
    expect(await cli(io, 'publish', RELAY, file)).toEqual({ code: 0, out: [`ok address ${alice}`], err: [] })
    expect(relay.published).toEqual([RELAY])
    expect(toHex(relay.records.get(`${alice} address`) as Uint8Array)).toBe(
      toHex(new TextEncoder().encode(readFileSync(file, 'utf8').trim())),
    )
  })

  it('offers an address record that revokes to every relay it lists, and names one that did not take it, exit 3', async () => {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = home()
    const alice = (await cli(io, 'keygen', 'alice', '--dir', dir)).out[0] as string
    const gone = (await cli(io, 'keygen', 'gone', '--dir', dir)).out[0] as string
    const other = 'http://127.0.0.1:10'
    const file = join(dir, 'alice.json')
    const relays = ['--relay', RELAY, '--relay', other]
    await cli(io, 'record', 'address', 'alice', ...relays, '--revoke', gone, '--out', file, '--dir', dir)
    relay.failRecordPublish.set(other, new RelayError(null, 0, null, 'down'))
    const ran = await cli(io, 'publish', RELAY, file)
    expect(ran.code).toBe(3)
    expect(ran.out).toEqual([
      `failed address ${alice} ${other} unreachable`,
      expect.stringMatching(/^incomplete revocation /),
      `ok address ${alice}`,
    ])
    expect(relay.published).toEqual([RELAY, other])
  })

  it('refuses a file that is not a record, a missing file and a bad relay URL, before any call', async () => {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = home()
    const notRecord = join(dir, 'x.json')
    await cli(io, 'keygen', 'x', '--dir', dir)
    writeFileSync(notRecord, '{"kind":"address"}')
    expect((await cli(io, 'publish', RELAY, notRecord)).err[0]).toBe(
      'bag: bad-record: an address record has exactly its eleven members',
    )
    writeFileSync(notRecord, 'not json')
    expect((await cli(io, 'publish', RELAY, notRecord)).err[0]).toMatch(/^bag: bad-json: /)
    expect((await cli(io, 'publish', RELAY, join(dir, 'missing.json'))).err[0]).toMatch(/^bag: ENOENT: /)
    expect((await cli(io, 'publish', 'nope', notRecord)).err[0]).toBe('bag: usage: "nope" is not a URL')
    expect((await cli(io, 'publish', RELAY)).err[0]).toBe('bag: usage: expected <relay-url> <record-file>')
    expect(relay.published).toEqual([])
  })

  it('prints ok for a healthy relay, and fails unhealthy or unreachable otherwise', async () => {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    expect(await cli(io, 'health', RELAY)).toEqual({ code: 0, out: ['ok'], err: [] })
    relay.healthy = false
    expect(await cli(io, 'health', RELAY)).toEqual({
      code: 1,
      out: [],
      err: [`bag: unhealthy: ${RELAY} did not answer 200`],
    })
    relay.healthy = new RelayError(null, 0, null, `${RELAY}/v0/health: fetch failed`)
    expect((await cli(io, 'health', RELAY)).err[0]).toBe(
      `bag: unreachable: no response: ${RELAY}/v0/health: fetch failed`,
    )
  })
})

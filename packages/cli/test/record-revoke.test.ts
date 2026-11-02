import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  type AddressRecord,
  countersignRotation,
  parseRecord,
  signRecord,
  toHex,
  verifyRecord,
  verifyRotation,
} from '@usebag/core'
import { FsKeyStore } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// record address --rotation-key and --revoke (L1): the CLI writes the two members
// the core already defines, the core verifies them, a rotation key it names countersigns a rotation, and the edge
// refuses a session the record revokes. Each test prints its measurement as a MEASURE line.

const tmp = tempDir('record-revoke')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
let n = 0
const home = (): string => join(tmp.dir, `home-${n++}`)

/** Makes identities in a home and returns their addresses by name. */
async function identities(io: ReturnType<typeof testIo>, dir: string, ...names: string[]) {
  const out: Record<string, string> = {}
  for (const name of names) out[name] = (await cli(io, 'keygen', name, '--dir', dir)).out[0] as string
  return out
}

describe('record address --rotation-key and --revoke (L1)', () => {
  it('(L1 a, b) writes rotation_key and revoked in the order given; the core verifies the record, and a rotation its rotation key countersigns', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    const a = await identities(io, dir, 'jane', 'jane-rotation', 'jane-next', 's1', 's2', 'mallory')
    const file = join(dir, 'jane.json')
    const made = await cli(
      io,
      'record',
      'address',
      'jane',
      '--relay',
      RELAY,
      '--sealing-key',
      '--rotation-key',
      a['jane-rotation'] as string,
      '--revoke',
      a.s2 as string,
      '--revoke',
      a.s1 as string,
      '--out',
      file,
      '--dir',
      dir,
    )
    expect(made).toEqual({ code: 0, out: [], err: [] })
    const r = verifyRecord(parseRecord(readFileSync(file, 'utf8')), T0) as AddressRecord
    expect(r).toMatchObject({
      kind: 'address',
      key: a.jane,
      rotation_key: a['jane-rotation'],
      revoked: [a.s2, a.s1],
      rotated_from: null,
      rotation_sig: null,
    })
    // (b) The rotation key the CLI wrote is the one the core accepts for jane's next rotation, beside jane's own key.
    const keys = new FsKeyStore(join(dir, 'keys'))
    const next = signRecord(keys.load('jane-next').signing, {
      kind: 'address',
      key: a['jane-next'] as string,
      sealing_key: toHex(keys.load('jane-next').sealing.publicKey),
      relays: [RELAY],
      rotation_key: null,
      revoked: [],
      ttl: 3600,
      iat: T0 + 1,
      rotated_from: a.jane as string,
    })
    const by = (name: string): AddressRecord => countersignRotation(keys.load(name).signing, next)
    expect(() => verifyRotation(r, by('jane-rotation'))).not.toThrow()
    expect(() => verifyRotation(r, by('jane'))).not.toThrow()
    expect(() => verifyRotation(r, by('mallory'))).toThrow(/^bad-rotation: /)
    const without = parseRecord(
      (await cli(io, 'record', 'address', 'jane', '--relay', RELAY, '--dir', dir)).out[0] as string,
    ) as AddressRecord
    expect(without).toMatchObject({ rotation_key: null, revoked: [] })
    expect(() => verifyRotation(without, by('jane-rotation'))).toThrow(/^bad-rotation: /)
    console.log(
      `MEASURE L1(a,b): rotation_key ${r.rotation_key === a['jane-rotation'] ? 'written' : 'lost'}, revoked ${r.revoked.length} in order; rotation by the rotation key accepted, by a third key bad-rotation`,
    )
  })

  it('(L1 c) refuses a value that is not an address, a duplicate, the identity itself and 1,025 entries, and writes no file', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    const a = await identities(io, dir, 'jane', 's1')
    const out = join(dir, 'refused.json')
    const attempt = async (...more: string[]) => {
      const r = await cli(
        io,
        'record',
        'address',
        'jane',
        '--relay',
        RELAY,
        '--out',
        out,
        '--dir',
        dir,
        ...more,
      )
      expect(existsSync(out), more.slice(0, 2).join(' ')).toBe(false)
      return [r.code, r.err[0]]
    }
    expect(await attempt('--rotation-key', 'jane-rotation')).toEqual([
      1,
      'bag: bad-address: --rotation-key "jane-rotation" is not an address',
    ])
    expect(await attempt('--revoke', 'ED25519:00')).toEqual([
      1,
      'bag: bad-address: --revoke "ED25519:00" is not an address',
    ])
    expect(await attempt('--revoke', a.s1 as string, '--revoke', a.s1 as string)).toEqual([
      1,
      'bag: bad-record: revoked lists distinct addresses',
    ])
    expect(await attempt('--rotation-key', a.jane as string)).toEqual([
      1,
      'bag: usage: --rotation-key names the identity itself; it names another key',
    ])
    expect(await attempt('--revoke', a.s1 as string, '--revoke', a.jane as string)).toEqual([
      1,
      'bag: usage: --revoke names the identity itself; it names another key',
    ])
    const many = Array.from({ length: 1025 }, (_, i) => [
      '--revoke',
      `ed25519:${i.toString(16).padStart(64, '0')}`,
    ])
    expect(await attempt(...many.flat())).toEqual([
      1,
      'bag: too-many-revoked: 1025 revoked keys; the cap is 1024',
    ])
    const most = await cli(
      io,
      'record',
      'address',
      'jane',
      '--relay',
      RELAY,
      '--dir',
      dir,
      ...many.slice(0, 1024).flat(),
    )
    expect(verifyRecord(parseRecord(most.out[0] as string), T0)).toMatchObject({ revoked: expect.any(Array) })
    expect((parseRecord(most.out[0] as string) as AddressRecord).revoked).toHaveLength(1024)
    console.log('MEASURE L1(c): 6 of 6 refusals with their codes, no file written; 1,024 entries accepted')
  })

  it("(L1 d) a session jane revoked is refused revoked at bob's inbox, and accepted once jane's record drops it, all through the CLI", async () => {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = home()
    const a = await identities(io, dir, 'jane', 'session', 'bob')
    const chain = join(dir, 'session.chain.json')
    const delegated = await cli(
      io,
      'delegate',
      '--from',
      'jane',
      '--to',
      a.session as string,
      '--caveat',
      'type=chat.v1',
      '--exp',
      '+86400',
      '--out',
      chain,
      '--dir',
      dir,
    )
    expect(delegated.code).toBe(0)
    const publish = async (name: string, ...more: string[]) => {
      const file = join(dir, `${name}.${n++}.json`)
      const made = await cli(
        io,
        'record',
        'address',
        name,
        '--relay',
        RELAY,
        '--out',
        file,
        '--dir',
        dir,
        ...more,
      )
      expect(made.code).toBe(0)
      expect((await cli(io, 'publish', RELAY, file)).code).toBe(0)
    }
    await publish('bob', '--sealing-key')
    // Jane's record lives a minute, so that bob's edge reads it again after the clock moves past it.
    await publish('jane', '--ttl', '60', '--revoke', a.session as string)
    const send = async (): Promise<string> => {
      const sent = await cli(
        io,
        'send',
        '--as',
        'session',
        '--auth',
        chain,
        '--to',
        a.bob as string,
        '--relay',
        RELAY,
        '--type',
        'chat.v1',
        '--body',
        '{"n":1}',
        '--dir',
        dir,
      )
      expect(sent.code).toBe(0)
      return sent.out[0] as string
    }
    const inbox = () =>
      cli(
        io,
        'inbox',
        '--as',
        'bob',
        '--relay',
        RELAY,
        '--once',
        '--trust-root',
        a.jane as string,
        '--honor',
        'coding',
        '--dir',
        dir,
      )
    const refused = await send()
    expect(await inbox()).toEqual({ code: 0, out: [`reject ${refused} revoked`], err: [] })
    io.time.now += 61
    await publish('jane', '--ttl', '60')
    const accepted = await send()
    expect(await inbox()).toEqual({
      code: 0,
      out: [`accept ${accepted} ${a.session} ${a.jane} chat.v1 {"n":1}`],
      err: [],
    })
    console.log('MEASURE L1(d): revoked session -> reject revoked; entry dropped -> accept (CLI output only)')
  })
})

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { RelayError } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { lookupLines } from '../src/commands/lookup.ts'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// lookup: where an address's records live, in the order a send resolves, after what the cache holds.

const tmp = tempDir('lookup')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
const HINT = 'http://127.0.0.2:9'
let n = 0

async function world() {
  const relay = new MemoryRelay()
  const io = testIo(relay)
  const dir = join(tmp.dir, `home-${n++}`)
  const alice = (await cli(io, 'keygen', 'alice', '--dir', dir)).out[0] as string
  const bob = (await cli(io, 'keygen', 'bob', '--dir', dir)).out[0] as string
  const file = join(dir, 'bob.address.json')
  await cli(io, 'record', 'address', 'bob', '--relay', RELAY, '--sealing-key', '--out', file, '--dir', dir)
  return { relay, io, dir, alice, bob, file }
}

describe('lookup <address|domain:<host>|handle>: the cache, then each relay asked, one line each', () => {
  it('prints none before any record exists, found once one does, and the cache after a send resolved it', async () => {
    const w = await world()
    const look = (...more: string[]) =>
      cli(w.io, 'lookup', w.bob, '--as', 'alice', '--relay', RELAY, '--dir', w.dir, ...more)
    expect(await look()).toEqual({
      code: 0,
      out: [`cache address:${w.bob} none`, `${RELAY} none kind=address`, `${RELAY} none kind=key`],
      err: [],
    })
    await cli(w.io, 'publish', RELAY, w.file)
    const found = await look()
    expect(found.out[1]).toBe(`${RELAY} found kind=address iat=${T0} valid_until=${T0 + 86_400} key=${w.bob}`)
    const sent = await cli(
      w.io,
      'send',
      '--as',
      'alice',
      '--to',
      w.bob,
      '--relay',
      RELAY,
      '--type',
      't',
      '--body',
      '1',
      '--dir',
      w.dir,
    )
    expect(sent.code).toBe(0)
    expect((await look()).out[0]).toBe(
      `cache address:${w.bob} kind=address iat=${T0} valid_until=${T0 + 86_400} source=-`,
    )
  })

  it('asks the --at hints first; refuses a private hint without --allow-private-relays, and reports no answer as an error', async () => {
    const w = await world()
    await cli(w.io, 'publish', RELAY, w.file)
    const args = ['lookup', w.bob, '--as', 'alice', '--relay', RELAY, '--at', HINT, '--dir', w.dir]
    const refused = await cli(w.io, ...args)
    expect(refused.out.slice(1, 3)).toEqual([
      `${HINT} refused kind=address ${HINT}: 127.0.0.2 is a loopback address`,
      `${RELAY} found kind=address iat=${T0} valid_until=${T0 + 86_400} key=${w.bob}`,
    ])
    w.relay.failRecordFetch.set(HINT, new RelayError(null, 0, null, 'connection refused'))
    const down = await cli(w.io, ...args, '--allow-private-relays')
    expect(down.out.slice(1)).toEqual([
      `${HINT} error kind=address unreachable`,
      `${RELAY} found kind=address iat=${T0} valid_until=${T0 + 86_400} key=${w.bob}`,
      `${HINT} error kind=key unreachable`,
      `${RELAY} none kind=key`,
    ])
  })

  it("reads a domain's well-known record, and reports a domain without one as an error", async () => {
    const w = await world()
    w.io.wellKnown.set('acme.test', readFileSync(w.file))
    const ok = await cli(
      w.io,
      'lookup',
      'domain:acme.test',
      '--as',
      'alice',
      '--relay',
      RELAY,
      '--dir',
      w.dir,
    )
    expect(ok.out).toEqual([
      'cache domain:acme.test none',
      '_bag.acme.test none kind=txt origin https://acme.test',
      `https://acme.test/.well-known/bag/address.json found kind=address iat=${T0} valid_until=${T0 + 86_400} key=${w.bob}`,
    ])
    const none = await cli(
      w.io,
      'lookup',
      'domain:none.test',
      '--as',
      'alice',
      '--relay',
      RELAY,
      '--dir',
      w.dir,
    )
    expect(none.out[2]).toBe('https://none.test/.well-known/bag/address.json error kind=address error')
  })

  it('refuses what is neither an address nor domain:<host>, and a missing --relay or --as', async () => {
    const w = await world()
    for (const subject of ['bob', 'domain:Not A Host']) {
      const r = await cli(w.io, 'lookup', subject, '--as', 'alice', '--relay', RELAY, '--dir', w.dir)
      expect([r.code, r.err[0]]).toEqual([
        1,
        `bag: usage: ${JSON.stringify(subject)} is neither an address, domain:<host> nor a handle`,
      ])
    }
    expect((await cli(w.io, 'lookup', w.bob, '--as', 'alice', '--dir', w.dir)).err[0]).toBe(
      'bag: usage: --relay is required',
    )
  })

  it('prints the source of a record this process cached', () => {
    const cached = { kind: 'address' as const, iat: 1, valid_until: 2, source: RELAY }
    expect(lookupLines({ subject: 'address:x', cached, results: [] })).toEqual([
      `cache address:x kind=address iat=1 valid_until=2 source=${RELAY}`,
    ])
  })
})

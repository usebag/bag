import { join } from 'node:path'
import type { Edge, EdgeOptions } from '@usebag/edge'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// L5: --allow-private-relays turns the edge's private-address guard off for send and inbox, and it is off
// by default. The Edge the commands open is the edge's own, recorded as it is made.

const seen = vi.hoisted(() => [] as { options: EdgeOptions; edge: Edge }[])

vi.mock('@usebag/edge', async (importOriginal) => {
  const real = await importOriginal<typeof import('@usebag/edge')>()
  class RecordedEdge extends real.Edge {
    constructor(options: EdgeOptions) {
      super(options)
      seen.push({ options, edge: this })
    }
  }
  return { ...real, Edge: RecordedEdge }
})

const tmp = tempDir('private-relays')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
const PRIVATE = 'http://10.0.0.7:4000'

/** Alice and bob in one home; bob's address record names a relay on a private address, not the one alice gives. */
async function world() {
  const relay = new MemoryRelay()
  const io = testIo(relay)
  const dir = join(tmp.dir, `home-${seen.length}-${Date.now()}`)
  await cli(io, 'keygen', 'alice', '--dir', dir)
  const bob = (await cli(io, 'keygen', 'bob', '--dir', dir)).out[0] as string
  const file = join(dir, 'bob.address.json')
  await cli(io, 'record', 'address', 'bob', '--relay', PRIVATE, '--sealing-key', '--out', file, '--dir', dir)
  await cli(io, 'publish', RELAY, file)
  const send = (...more: string[]) =>
    cli(
      io,
      'send',
      '--as',
      'alice',
      '--to',
      bob,
      '--relay',
      RELAY,
      '--type',
      'chat.v1',
      '--body',
      '{}',
      '--dir',
      dir,
      ...more,
    )
  return { relay, io, dir, send }
}

describe('--allow-private-relays (L5)', () => {
  it('send: a recipient relay on a private address is refused before any request, and published with the flag', async () => {
    const w = await world()
    const refused = await w.send()
    expect([refused.code, refused.out[1]]).toEqual([1, `failed ${PRIVATE} tries=1 reason=resolve-failed`])
    expect(w.relay.published.filter((u) => u === PRIVATE)).toEqual([])
    const allowed = await w.send('--allow-private-relays')
    expect([allowed.code, allowed.out[1]]).toEqual([0, `published ${PRIVATE} tries=1`])
    expect(w.relay.published.filter((u) => u === PRIVATE)).toEqual([PRIVATE])
    const [off, on] = seen.slice(-2)
    expect([off?.options.allowPrivateRelays, on?.options.allowPrivateRelays]).toEqual([undefined, true])
    console.log(
      `MEASURE L5(a): without the flag ${refused.out[1]}, 0 publishes there; with it ${allowed.out[1]}`,
    )
  })

  it('inbox: the Edge it opens has the guard off with the flag and on without; a private URL not its own', async () => {
    const w = await world()
    const inbox = (...more: string[]) =>
      cli(w.io, 'inbox', '--as', 'bob', '--relay', RELAY, '--once', '--dir', w.dir, ...more)
    expect((await inbox()).code).toBe(0)
    const off = seen.at(-1)
    expect((await inbox('--allow-private-relays')).code).toBe(0)
    const on = seen.at(-1)
    expect([off?.options.allowPrivateRelays, on?.options.allowPrivateRelays]).toEqual([undefined, true])
    expect([off?.edge.guard.allows(PRIVATE), on?.edge.guard.allows(PRIVATE)]).toEqual([false, true])
    expect([off?.edge.guard.allows(RELAY), on?.edge.guard.allows(RELAY)]).toEqual([true, true])
    expect(await off?.edge.guard.refusal(PRIVATE)).toMatchObject({ range: 'private' })
  })
})

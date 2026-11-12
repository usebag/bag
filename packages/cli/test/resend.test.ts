import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { RelayError, SqliteStore } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { rootHint, unpairedNote } from '../src/commands/send.ts'
import { openEdge } from '../src/home.ts'
import { type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// resend: one flush of an identity's outbox from the CLI (spec/SPEC.md §9 item 1, "kept so that `resend` sends the same
// bytes"; §4.3, "`resend` on the same identity reaches it too"). Each command here opens the store and closes it, as a
// person's would, so what a run reads is what the one before left on disk.

const tmp = tempDir('resend')
afterAll(() => tmp.cleanup())
const [R1, R2, R3, R4] = ['1', '2', '3', '4'].map((p) => `http://127.0.0.1:${p}`) as [
  string,
  string,
  string,
  string,
]
let n = 0
const DOWN = new RelayError(null, 0, null, 'fetch failed')

interface World {
  readonly relay: MemoryRelay
  readonly io: TestIo
  readonly dir: string
  readonly alice: string
  readonly bob: string
  readonly carol: string
}

/** Alice, bob and carol in one home; bob's address record, naming `relays`, published. */
async function world(...relays: string[]): Promise<World> {
  const relay = new MemoryRelay()
  const io = testIo(relay)
  const dir = join(tmp.dir, `home-${n++}`)
  const [alice, bob, carol] = (await Promise.all(
    ['alice', 'bob', 'carol'].map(
      async (who) => (await cli(io, 'keygen', who, '--dir', dir)).out[0] as string,
    ),
  )) as [string, string, string]
  await published(io, dir, 'bob', relays.length === 0 ? [R1] : relays)
  return { relay, io, dir, alice, bob, carol }
}

async function published(io: TestIo, dir: string, who: string, relays: string[]): Promise<void> {
  const file = join(dir, `${who}.address.json`)
  const at = relays.flatMap((r) => ['--relay', r])
  await cli(io, 'record', 'address', who, ...at, '--sealing-key', '--out', file, '--dir', dir)
  await cli(io, 'publish', relays[0] as string, file)
}

const send = (w: World, ...more: string[]) =>
  cli(
    w.io,
    'send',
    ...['--as', 'alice', '--to', w.bob, '--relay', R1, '--type', 'chat.v1', '--body', '{"n":1}'],
    ...['--dir', w.dir, ...more],
  )
const resend = (w: World, ...more: string[]) =>
  cli(w.io, 'resend', '--as', 'alice', '--relay', R1, '--dir', w.dir, ...more)
const inbox = (w: World) =>
  cli(w.io, 'inbox', '--as', 'bob', '--relay', R1, '--once', '--dir', w.dir, '--trust-root', w.alice)

/** The bytes the outbox keeps for `id`. */
function kept(w: World, id: string): Uint8Array | undefined {
  const store = new SqliteStore(join(w.dir, 'state', 'alice', 'edge.sqlite'))
  try {
    return store.outboxGet(id)?.bytes
  } finally {
    store.close()
  }
}

const hint = (id: string): string => `the bytes stay in the outbox, and resend --id ${id} sends them`

describe('send: a partial delivery is a success with a warning, as the MCP send answers it (W9)', () => {
  it('exits 0 when one relay took it, naming each relay that refused with its reason; every relay refusing exits 1', async () => {
    const w = await world(R1, R2, R3)
    const publish = w.relay.publish.bind(w.relay)
    const big = new RelayError('envelope-too-large', 413, null, 'too large')
    w.relay.publish = (url, bytes) => (url === R3 ? Promise.reject(big) : publish(url, bytes))
    const partial = await send(w, '--allow-private-relays')
    const id = partial.out[0] as string
    expect(partial).toEqual({
      code: 0,
      out: [
        id,
        `published ${R1} tries=1`,
        `published ${R2} tries=1`,
        `failed ${R3} tries=1 reason=envelope-too-large`,
      ],
      err: [`warning: delivered via 2 of 3 relays; refused 1: ${R3} envelope-too-large; ${hint(id)}`],
    })
    expect(w.relay.box(w.bob)).toHaveLength(1)
    // No relay took it: an error, as before, with the first refusal's reason and the resend hint.
    w.relay.publish = () => Promise.reject(big)
    const none = await send(w, '--allow-private-relays')
    const other = none.out[0] as string
    expect([none.code, none.err]).toEqual([1, [`bag: envelope-too-large: ${R1} failed; ${hint(other)}`]])
  })
})

describe('resend: a refused send lands once, the same bytes under the same id', () => {
  it('sends what the relay did not take when it is back, and a later run has nothing left', async () => {
    const w = await world()
    w.relay.failPublish = DOWN
    const refused = await send(w)
    const id = refused.out[0] as string
    expect([refused.code, refused.err]).toEqual([1, [`bag: unreachable: ${R1} retry; ${hint(id)}`]])
    expect(w.relay.envelopes.size).toBe(0)
    const bytes = kept(w, id)

    w.relay.failPublish = null
    w.io.time.now += 2
    expect(await resend(w)).toEqual({ code: 0, out: [id, `published ${R1} tries=2`], err: [] })
    expect([...w.relay.envelopes.keys()]).toEqual([id])
    expect(w.relay.envelopes.get(id)).toEqual(bytes)
    expect(w.relay.box(w.bob)).toHaveLength(1)
    const got = await inbox(w)
    expect(got.out.filter((l) => l.startsWith(`accept ${id} `))).toHaveLength(1)

    expect(await resend(w)).toEqual({ code: 0, out: ['nothing is waiting'], err: [] })
    expect((await inbox(w)).out).toEqual([])
    expect(w.relay.box(w.bob)).toHaveLength(1)
  })

  it('lands once when the first try reached the relay and its answer was lost: the relay holds the id', async () => {
    const w = await world()
    w.relay.failPublish = DOWN
    const id = (await send(w)).out[0] as string
    w.relay.failPublish = null
    await w.relay.publish(R1, kept(w, id) as Uint8Array)
    w.io.time.now += 2
    expect(await resend(w)).toEqual({ code: 0, out: [id, `published ${R1} tries=2`], err: [] })
    expect(w.relay.box(w.bob)).toHaveLength(1)
  })

  it('keeps a next_at: a retry not due stays, is not tried, and fails with its reason', async () => {
    const w = await world()
    w.relay.failPublish = DOWN
    const id = (await send(w)).out[0] as string
    w.relay.failPublish = null
    const tries = w.relay.published.length
    const early = await resend(w)
    expect(early).toEqual({
      code: 1,
      out: [id, `retry ${R1} tries=1 reason=unreachable next_at=${w.io.time.now + 1}`],
      err: [`bag: unreachable: ${R1} retry; ${hint(id)}`],
    })
    expect(w.relay.published.length).toBe(tries)
  })

  it('counts a try while the relay is still down, and waits longer', async () => {
    const w = await world()
    w.relay.failPublish = DOWN
    const id = (await send(w)).out[0] as string
    w.io.time.now += 2
    const again = await resend(w)
    expect(again.code).toBe(1)
    expect(again.out).toEqual([id, expect.stringMatching(/ tries=2 reason=unreachable next_at=\d+$/)])
  })

  it('prints every envelope before it fails: one that landed, then one not due', async () => {
    const w = await world()
    w.relay.failPublish = DOWN
    const first = (await send(w)).out[0] as string
    w.io.time.now += 1
    const second = (await send(w)).out[0] as string
    w.relay.failPublish = null
    const run = await resend(w)
    expect(run.out).toEqual([
      first,
      `published ${R1} tries=2`,
      second,
      `retry ${R1} tries=1 reason=unreachable next_at=${w.io.time.now + 1}`,
    ])
    expect([run.code, run.err]).toEqual([1, [`bag: unreachable: ${R1} retry; ${hint(second)}`]])
  })

  it('goes on after one that has not landed: --id prints its envelope first, and the next still prints', async () => {
    const w = await world()
    w.relay.failPublish = DOWN
    const first = (await send(w)).out[0] as string
    w.io.time.now += 1
    const second = (await send(w)).out[0] as string
    w.relay.failPublish = null
    const run = await resend(w, '--id', second)
    expect(run.out).toEqual([
      second,
      `retry ${R1} tries=1 reason=unreachable next_at=${w.io.time.now + 1}`,
      first,
      `published ${R1} tries=2`,
    ])
    expect([run.code, run.err]).toEqual([1, [`bag: unreachable: ${R1} retry; ${hint(second)}`]])
  })
})

describe('resend --id: a failed target goes only when a person names it', () => {
  it('says a peer unpaired this identity, read from the kept envelope, when --id is refused again', async () => {
    const w = await world()
    await cli(w.io, 'name', 'add', 'bobby', w.bob, '--dir', w.dir)
    const roots = { [w.bob]: { added_at: 1 } }
    writeFileSync(join(w.dir, 'trust.json'), JSON.stringify({ version: 1, roots }), { mode: 0o600 })
    w.relay.failPublish = new RelayError('root-not-accepted', 403, null, 'refused')
    const id = (await send(w)).out[0] as string
    const still = await resend(w, '--id', id)
    expect(still.code).toBe(1)
    expect(still.err[0]).toContain(unpairedNote('bobby', w.bob, 'alice', R1))
  })

  it('leaves a refusal alone with no --id, and with --id sends the same bytes once the refusal has gone', async () => {
    const w = await world()
    w.relay.failPublish = new RelayError('root-not-accepted', 403, null, 'refused')
    const refused = await send(w)
    const id = refused.out[0] as string
    expect(refused.err).toEqual([`bag: root-not-accepted: ${R1} failed; ${hint(id)}; ${rootHint(w.alice)}`])
    w.io.time.now += 3600
    expect(await resend(w)).toEqual({ code: 0, out: ['nothing is waiting'], err: [] })

    const still = await resend(w, '--id', id)
    expect([still.code, still.out]).toEqual([1, [id, `failed ${R1} tries=1 reason=root-not-accepted`]])
    expect(still.err[0]).toContain(rootHint(w.alice))

    const bytes = kept(w, id)
    w.relay.failPublish = null
    expect(await resend(w, '--id', id)).toEqual({
      code: 0,
      out: [id, `published ${R1} tries=1`],
      err: [],
    })
    expect(w.relay.envelopes.get(id)).toEqual(bytes)
    // Published is final: naming it again sends nothing and reports where it stands.
    const tries = w.relay.published.length
    expect((await resend(w, '--id', id)).out).toEqual([id, `published ${R1} tries=1`])
    expect(w.relay.published.length).toBe(tries)
  })

  it('refuses an id the outbox lacks, and needs --as and --relay', async () => {
    const w = await world()
    const id = 'a'.repeat(64)
    expect((await resend(w, '--id', id)).err).toEqual([
      `bag: not-found: no envelope ${id} in this identity's outbox`,
    ])
    expect((await cli(w.io, 'resend', '--as', 'alice')).err[0]).toBe('bag: usage: --relay is required')
  })

  it('is busy beside an edge of the identity, which flushes by itself', async () => {
    const w = await world()
    await send(w)
    const held = new SqliteStore(join(w.dir, 'state', 'alice', 'edge.sqlite'))
    try {
      expect((await resend(w)).err[0]).toMatch(/^bag: busy: /)
    } finally {
      held.close()
    }
  })
})

describe("resend reaches the edge's failover and its waiting sends", () => {
  it('promotes the next listed relay once three are given up (§4.3), across separate commands', async () => {
    const w = await world(R1, R2, R3, R4)
    const publish = w.relay.publish.bind(w.relay)
    const down = new Set([R1, R2, R3])
    w.relay.publish = (url, bytes) => (down.has(url) ? Promise.reject(DOWN) : publish(url, bytes))
    const refused = await send(w, '--allow-private-relays')
    const id = refused.out[0] as string
    expect(refused.out.slice(1).map((l) => l.split(' ')[1])).toEqual([R1, R2, R3])
    w.io.time.now += 2
    expect((await resend(w, '--allow-private-relays')).code).toBe(1)
    w.io.time.now += 4
    // R1 is retired for R4, which lands; R2 and R3 have no spare left, so they retry (§4.3). Delivered via R4, the run
    // exits 0 with a warning line that counts it and names the retries (W9: a partial delivery is a success).
    const landed = await resend(w, '--allow-private-relays')
    expect(landed.code).toBe(0)
    expect(landed.err).toEqual([
      `warning: delivered via 1 of 3 relays; retrying 2; the bytes stay in the outbox, and resend --id ${id} sends them`,
    ])
    expect(landed.out).toEqual([
      id,
      expect.stringMatching(new RegExp(`^retry ${R2} tries=3 `)),
      expect.stringMatching(new RegExp(`^retry ${R3} tries=3 `)),
      `published ${R4} tries=1`,
    ])
    expect(w.relay.box(w.bob)).toHaveLength(1)

    down.clear()
    w.io.time.now += 8
    expect(await resend(w, '--allow-private-relays')).toEqual({
      code: 0,
      out: [id, `published ${R2} tries=4`, `published ${R3} tries=4`, `published ${R4} tries=1`],
      err: [],
    })
    expect([...w.relay.envelopes.keys()]).toEqual([id])
    expect(w.relay.box(w.bob)).toHaveLength(1)
  })

  it('tries a send that waits on a recipient, prints it while it waits, and sends it when it resolves', async () => {
    const w = await world()
    const opened = openEdge(w.io, {
      home: w.dir,
      name: 'alice',
      relay: R1,
      client: w.relay,
      policy: { roots: [], types: [] },
    })
    const queued = await opened.edge.sender.sendOrWait({ to: [w.carol], type: 'chat.v1', body: {} })
    opened.close()
    expect('waiting' in queued).toBe(true)

    w.io.time.now += 2
    const waits = await resend(w)
    expect(waits.code).toBe(1)
    expect(waits.out).toEqual([
      expect.stringMatching(new RegExp(`^waiting ${w.carol} tries=2 next_at=\\d+$`)),
    ])
    expect(waits.err).toEqual([expect.stringMatching(/^bag: resolve-failed: /)])

    await published(w.io, w.dir, 'carol', [R1])
    w.io.time.now += 3
    const sent = await resend(w)
    expect(sent.code).toBe(0)
    expect(sent.out).toEqual([expect.stringMatching(/^[0-9a-f]{64}$/), `published ${R1} tries=1`])
    expect(w.relay.box(w.carol)).toHaveLength(1)
  })
})

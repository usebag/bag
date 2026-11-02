import { randomBytes } from 'node:crypto'
import {
  buildEnvelope,
  newThread,
  serializeHandleRecord,
  serializeRecord,
  signHandleRecord,
  signRecord,
} from '@usebag/core'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  addressRecord,
  FakeClock,
  type FakeNaming,
  ManualTimers,
  P,
  publishAddress,
  RELAY,
  saveKeys,
  sessionChain,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// Handles through the tools (spec/SPEC.md §12.4): send and ask take jane@acme.test, which the edge resolves
// through the domain's TXT record, its org record and the handle record the org signs; lookup reports each step; a
// received message carries `handle` only from a binding this server resolved. No DNS and no fetch: the records come from
// the test's maps.

const DOMAIN = 'acme.test'
const ORIGIN = `bag.${DOMAIN}`
const JANE = `jane@${DOMAIN}`

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
let bob: TestServer
let naming: FakeNaming
const stdout = watchStdout()

beforeEach(async () => {
  stdout.start()
  tmp = tempDir('handles')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
  naming = { txt: new Map(), handles: new Map() }
  naming.txt.set(`_bag.${DOMAIN}`, [[`v=ac1; key=${P.org.address}; host=bag`]])
  const org = signRecord(P.org.keys.signing, {
    kind: 'address',
    key: P.org.address,
    sealing_key: null,
    relays: [RELAY],
    rotation_key: null,
    revoked: [],
    ttl: 86_400,
    iat: T0,
    rotated_from: null,
  })
  const handle = { kind: 'handle', org: P.org.address, handle: JANE, address: P.jane.address } as const
  naming.handles.set(
    `${ORIGIN} ${JANE}`,
    serializeHandleRecord(signHandleRecord(P.org.keys.signing, { ...handle, iat: T0, ttl: 3600 })),
  )
  // The org root delegates, so its record is at its recipients' relay (spec/SPEC.md §9 item 5); jane's is there too.
  await relay.publish(RELAY, serializeRecord(org))
  await publishAddress(relay, P.jane)
  saveKeys(`${tmp.dir}/bob`, P.bob)
  await publishAddress(relay, P.bob)
  bob = await testServer({
    home: `${tmp.dir}/bob`,
    name: 'bob',
    relay,
    clock,
    timers,
    args: ['--trust-root', P.org.address, '--honor', 'coding'],
    domains: new Map([[ORIGIN, serializeRecord(org)]]),
    naming,
  })
})

afterEach(async () => {
  await bob.close()
  tmp.cleanup()
  stdout.check()
})

/** A message from jane's session under org -> jane -> session, sealed to bob, at the relay. */
async function fromJane(body: unknown): Promise<void> {
  const rng = (length: number) => new Uint8Array(randomBytes(length))
  const { bytes } = buildEnvelope({
    from: P.session.keys.signing,
    to: [{ address: P.bob.address, sealingKey: P.bob.keys.sealing.publicKey }],
    auth: sessionChain(),
    type: 'chat.v1',
    thread: newThread(rng),
    body,
    ts: T0,
    rng,
  })
  await relay.publish(RELAY, bytes)
}

describe('send, ask and lookup by handle, and the handle of a received message', () => {
  it("sends to jane@acme.test at her address, and her session's messages carry her verified handle from then on", async () => {
    await fromJane({ n: 1 })
    const before = (await bob.call('wait', { timeout_s: 1 })).value.message as Record<string, unknown>
    expect(before.handle).toBeNull()
    const sent = await bob.call('send', { to: [JANE], type: 'chat.v1', body: { hi: 1 } })
    expect(sent.value).toMatchObject({ targets: [{ relay: RELAY, status: 'published' }] })
    expect(relay.box(RELAY, P.jane.address)).toHaveLength(1)
    await fromJane({ n: 2 })
    const after = (await bob.call('wait', { timeout_s: 1 })).value.message as Record<string, unknown>
    expect(after).toMatchObject({
      principal: P.jane.address,
      root: P.org.address,
      from_name: null,
      principal_name: null,
      handle: { handle: JANE, domain: DOMAIN, verified: true },
    })
    // inbox reads the rows again, now: the binding this server holds shows on both of jane's messages.
    const inbox = (await bob.call('inbox')).value.messages as Record<string, unknown>[]
    expect(inbox.map((m) => m.handle)).toEqual([
      { handle: JANE, domain: DOMAIN, verified: true },
      { handle: JANE, domain: DOMAIN, verified: true },
    ])
  })

  it('asks by handle, and names the step a failed resolution stopped at', async () => {
    const asked = bob.call('ask', { to: JANE, body: { q: 1 }, timeout_s: 1 })
    await until('the ask waits', () => timers.live().length === 1)
    timers.fire()
    expect((await asked).value).toMatchObject({
      question: { targets: [{ relay: RELAY, status: 'published' }] },
    })
    expect(relay.box(RELAY, P.jane.address)).toHaveLength(1)
    const missing = await bob.call('send', { to: [`nobody@${DOMAIN}`], type: 'chat.v1', body: {} })
    expect(missing.value).toEqual({
      error: 'resolve-failed',
      detail: `handle:nobody@${DOMAIN} from handle: no such handle at ${ORIGIN}`,
    })
    const askMissing = await bob.call('ask', { to: `nobody@${DOMAIN}`, body: {} })
    expect(askMissing.value.error).toBe('resolve-failed')
  })

  it('looks a handle up step by step, writing nothing', async () => {
    const out = await bob.call('lookup', { address: JANE })
    expect(out.value.subject).toBe(`handle:${JANE}`)
    expect(out.value.cached).toBeNull()
    expect(
      (out.value.results as { kind: string; outcome: string }[]).map((r) => [r.kind, r.outcome]),
    ).toEqual([
      ['txt', 'found'],
      ['address', 'found'],
      ['handle', 'found'],
      ['address', 'found'],
      ['key', 'none'],
    ])
    expect(addressRecord(P.jane).key).toBe(P.jane.address)
  })
})

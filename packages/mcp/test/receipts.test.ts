import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Rng } from '@usebag/edge'
import { writeJson } from '@usebag/enterprise-client'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { parseConfig, parseServerConfig, type ServerConfig } from '../src/config.ts'
import { INSTRUCTIONS, RECEIPT_NOTE } from '../src/tools.ts'
import {
  FakeClock,
  ManualTimers,
  P,
  publishAddress,
  RELAY,
  saveKeys,
  seededRng,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// Read receipts through the tools (spec/SPEC.md §10, threat model R23; the edge's half is packages/edge/test/receipts.test.ts):
// two servers on one memory relay. Whether a receipt goes out is the reader's --receipts-to, addresses per peer, off by
// default; no tool sets it, and no pairing can, since it takes no names. The sender asks with send's receipt and reads the answer with the receipts tool. The reader's rng
// gives no jitter, so a test need not wait out the 20 s of real use.

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
const servers: TestServer[] = []

beforeEach(async () => {
  tmp = tempDir('receipts')
  relay = new MemoryRelay()
  clock = new FakeClock()
  for (const p of [P.alice, P.bob]) {
    saveKeys(tmp.dir, p)
    await publishAddress(relay, p)
  }
})

afterEach(async () => {
  for (const s of servers.splice(0)) await s.close()
  tmp.cleanup()
})

/** A seeded rng whose 4-byte draws (the jitters) are all 0. */
function noJitter(label: string): Rng {
  const base = seededRng(label)
  return { bytes: (n) => (n === 4 ? new Uint8Array(4) : base.bytes(n)) }
}

async function start(name: 'alice' | 'bob', args: readonly string[]): Promise<TestServer> {
  const s = await testServer({
    home: tmp.dir,
    name,
    relay,
    clock,
    timers: new ManualTimers(),
    args: ['--trust-root', (name === 'alice' ? P.bob : P.alice).address, ...args],
    pid: 7000 + servers.length,
    rng: noJitter(name),
  })
  servers.push(s)
  return s
}

/** Alice's message to bob, read by bob's wait: its id. */
async function delivered(alice: TestServer, bob: TestServer, receipt: boolean): Promise<string> {
  const waiting = bob.call('wait', { timeout_s: 5 })
  const sent = await alice.call('send', {
    to: [P.bob.address],
    type: 'chat.v1',
    body: { n: 1 },
    ...(receipt ? { receipt } : {}),
  })
  expect(sent.isError).toBe(false)
  expect((await waiting).value.message).toMatchObject({ id: sent.value.id })
  return sent.value.id as string
}

const seen = async (s: TestServer, id: string): Promise<unknown> =>
  (await s.call('receipts', { id })).value.receipts

/** The reader's envelopes at the sender's mailbox: a receipt goes out as one. */
const toAlice = (): number => relay.box(RELAY, P.alice.address).length

describe('read receipts through the tools', () => {
  it('a peer the reader named gets a receipt, seen with the receipts tool; the reader sees no sign of it', async () => {
    const alice = await start('alice', [])
    const bob = await start('bob', ['--receipts-to', P.alice.address])
    const id = await delivered(alice, bob, true)
    await until('the receipt', () => toAlice() === 1)
    await until('its arrival', () => alice.running.opened.edge.receipts(id).length === 1)
    expect((await alice.call('receipts', { id })).value).toEqual({
      id,
      receipts: [{ reader: P.bob.address, at: T0 }],
    })
    // It is a fact about a send: no message, no thread, nothing to answer.
    expect((await alice.call('inbox', {})).value.messages).toEqual([])
    expect((await bob.call('status')).value.receipts_to).toEqual([P.alice.address])
  })

  it('says what a receipt means at the send that asks, and that no tool sends one (the sitting on A and C)', async () => {
    const alice = await start('alice', [])
    const asked = { to: [P.bob.address], type: 'chat.v1', body: { n: 1 } }
    expect((await alice.call('send', { ...asked, receipt: true })).value.receipt_note).toBe(RECEIPT_NOTE)
    expect((await alice.call('send', asked)).value).not.toHaveProperty('receipt_note')
    expect(RECEIPT_NOTE).toContain("the reader's edge accepted the message, not that anyone has read it")
    expect(INSTRUCTIONS).toContain('no tool sends one')
    const { tools } = await alice.client.listTools()
    const text = (name: string) => tools.find((t) => t.name === name)?.description
    expect(text('receipts')).toContain('No tool sends a receipt')
    expect(text('pair_accept')).toContain('your user can try the same code again')
    const send = tools.find((t) => t.name === 'send')?.inputSchema.properties?.receipt as {
      description: string
    }
    expect(send.description).toContain("the recipient's edge accepted the message, not that anyone read it")
  })

  it('is off by default: the sender asks, and nothing comes back', async () => {
    const alice = await start('alice', [])
    const bob = await start('bob', [])
    const id = await delivered(alice, bob, true)
    await new Promise((r) => setTimeout(r, 30))
    expect(await seen(alice, id)).toEqual([])
    expect(toAlice()).toBe(0)
    expect((await bob.call('status')).value.receipts_to).toEqual([])
  })

  it("is off when the reader's organisation turned its agents' receipts off, and on again when it turns them on", async () => {
    // The reader bob is its home's enterprise agent; GET /agent/trust's receipts: false is kept as the session's.
    const dir = join(tmp.dir, 'orgs', 'acme.example', 'enterprise')
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const session = (more: object) => ({ v: 1, domain: 'acme.example', name: 'bob', state: 'live', ...more })
    writeJson(join(dir, 'session.json'), session({ receipts: false }))
    const alice = await start('alice', [])
    const bob = await start('bob', ['--receipts-to', P.alice.address])
    const off = await delivered(alice, bob, true)
    await new Promise((r) => setTimeout(r, 30))
    expect([await seen(alice, off), toAlice()]).toEqual([[], 0])
    writeJson(join(dir, 'session.json'), session({}))
    const on = await delivered(alice, bob, true)
    await until('the receipt', () => toAlice() === 1)
    await until('its arrival', () => alice.running.opened.edge.receipts(on).length === 1)
  })

  it('a peer the reader did not name gets nothing, nor one who did not ask', async () => {
    const alice = await start('alice', [])
    const bob = await start('bob', ['--receipts-to', P.carol.address])
    const id = await delivered(alice, bob, true)
    await new Promise((r) => setTimeout(r, 30))
    expect(await seen(alice, id)).toEqual([])
    expect(toAlice()).toBe(0)
  })

  it('needs an object body to ask: bad-content, and nothing is sent', async () => {
    const alice = await start('alice', [])
    const out = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'hi', receipt: true })
    expect([out.isError, out.value.error]).toEqual([true, 'bad-content'])
    expect(relay.box(RELAY, P.bob.address)).toEqual([])
  })

  it('an id it never sent has none, and no tool can turn receipts on', async () => {
    const alice = await start('alice', [])
    expect(await seen(alice, 'a'.repeat(64))).toEqual([])
    const { tools } = await alice.client.listTools()
    for (const t of tools) {
      const fields = Object.keys(t.inputSchema.properties ?? {})
      expect(fields.filter((f) => /receipts?_?to/i.test(f))).toEqual([])
    }
  })
})

describe('--receipts-to', () => {
  const parse = (...args: string[]) => parseConfig(['--as', 'a', '--relay', RELAY, ...args], { HOME: '/h' })

  it('takes addresses, repeated; none by default', () => {
    expect(parse()).toMatchObject({ receiptsTo: [] })
    expect(parse('--receipts-to', P.bob.address, '--receipts-to', P.carol.address)).toMatchObject({
      receiptsTo: [P.bob.address, P.carol.address],
    })
  })

  it('an identity of an --identities file takes receipts_to, and refuses what is neither', () => {
    const file = join(tmp.dir, 'identities.json')
    const write = (peer: string): void =>
      writeFileSync(
        file,
        JSON.stringify({
          version: 1,
          identities: [{ label: 'a', home: join(tmp.dir, 'a'), relays: [RELAY], receipts_to: [peer] }],
        }),
        { mode: 0o600 },
      )
    write(P.alice.address)
    const server = parseServerConfig(['--identities', file], {}) as ServerConfig
    expect(server.identities[0]?.receiptsTo).toEqual([P.alice.address])
    expect(() => parseServerConfig(['--identities', file, '--receipts-to', P.bob.address], {})).toThrow(
      /receipts-to/,
    )
    write('alice')
    expect(() => parseServerConfig(['--identities', file], {})).toThrow(
      /receipts_to "alice" is not an address/,
    )
  })

  it('refuses a name, which a pairing could add to, and a --session', () => {
    expect(() => parse('--receipts-to', 'alice')).toThrow(/"alice" is not an address/)
    const session = ['--session', 'auto', '--principal', 'p', '--grant-caveat', 'c', '--relay', RELAY]
    expect(() => parseConfig([...session, '--receipts-to', P.bob.address], { HOME: '/h' })).toThrow(
      /does not go with --session/,
    )
  })
})

import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js'
import { type Hop, serializeRecord, signHop, signRecord, toHex } from '@usebag/core'
import { RelayError } from '@usebag/edge'
import { parseConfig } from '../../src/config.ts'
import { type Running, startServer } from '../../src/server.ts'
import {
  acceptFrom,
  FakeClock,
  fakeRecords,
  ManualTimers,
  MemoryLog,
  P,
  type Party,
  publishAddress,
  RELAY,
  saveKeys,
  seededRng,
  sessionChain,
  T0,
  tempDir,
} from './ports.ts'
import { MemoryRelay } from './relay.ts'

// The loaded-set scripted session: run as `node --import loaded-hook.ts loaded-session.ts` by
// test/loaded-set.test.ts, so that the hook sees every package the servers load. It runs servers in this process on
// the memory relay, over an in-memory transport of its own and a JSON-RPC client of its own, so that no MCP client
// and no test framework loads here: only the SDK's server side and what it brings. It drives initialize, tools/list,
// every tool, the refusals the unit tests reach, a schema error, an unknown tool and a ping, a window and a resume, a
// chain re-read (by a timer, on a refusal, from a file and from a command under /bin/sh), a resubscription and a
// keep-alive re-sign. It prints one JSON line, the calls, the tool errors and every mismatch with the script, and exits
// 1 on a mismatch.

/** One end of an in-memory transport pair: what one end sends, the other receives, a microtask later. */
class End implements Transport {
  other: End | null = null
  onmessage?: (message: JSONRPCMessage) => void
  onclose?: () => void
  onerror?: (error: Error) => void

  async start(): Promise<void> {}

  async send(message: JSONRPCMessage): Promise<void> {
    const other = this.other
    queueMicrotask(() => other?.onmessage?.(message))
  }

  async close(): Promise<void> {
    this.onclose?.()
  }
}

function pair(): [End, End] {
  const a = new End()
  const b = new End()
  a.other = b
  b.other = a
  return [a, b]
}

type Json = Record<string, unknown>

/** A JSON-RPC client over one end. */
class Rpc {
  readonly #end: End
  readonly #pending = new Map<number, (message: Json) => void>()
  #id = 1

  constructor(end: End) {
    this.#end = end
    end.onmessage = (m) => {
      const id = (m as { id?: unknown }).id
      if (typeof id === 'number') this.#pending.get(id)?.(m as unknown as Json)
    }
  }

  request(method: string, params: Json = {}): Promise<Json> {
    const id = this.#id++
    return new Promise((resolve) => {
      this.#pending.set(id, resolve)
      void this.#end.send({ jsonrpc: '2.0', id, method, params } as JSONRPCMessage)
    })
  }

  notify(method: string): void {
    void this.#end.send({ jsonrpc: '2.0', method } as JSONRPCMessage)
  }
}

const tmp = tempDir('loaded')
const relay = new MemoryRelay()
const clock = new FakeClock()
const timers = new ManualTimers()
const chainFile = join(tmp.dir, 'chain.json')
const mismatches: string[] = []
let calls = 0
let toolErrors = 0

interface Served {
  readonly running: Running
  readonly rpc: Rpc
  readonly log: MemoryLog
  call(tool: string, args?: Json): Promise<{ isError: boolean; value: Json }>
}

async function serve(name: string, home: string, args: readonly string[]): Promise<Served> {
  const config = parseConfig(['--as', name, '--dir', home, '--relay', RELAY, ...args], {})
  if (config === 'help') throw new Error('help')
  const log = new MemoryLog()
  const running = await startServer(config, {
    clock,
    rng: seededRng(name),
    relay,
    records: fakeRecords(new Map()),
    timers,
    pid: calls + 100,
    alive: () => false,
    log,
    env: { PATH: process.env.PATH },
  })
  const [client, server] = pair()
  await running.mcp.connect(server)
  const rpc = new Rpc(client)
  const init = await rpc.request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'loaded-session', version: '0' },
  })
  if (init.result === undefined) mismatches.push(`${name}: initialize answered no result`)
  rpc.notify('notifications/initialized')
  return {
    running,
    rpc,
    log,
    async call(tool, a = {}) {
      calls++
      const answer = await rpc.request('tools/call', { name: tool, arguments: a })
      const result = answer.result as { isError?: boolean; content: { text: string }[] } | undefined
      if (result === undefined) return { isError: true, value: { rpcError: answer.error } }
      const text = result.content[0]?.text ?? ''
      let value: Json
      try {
        value = JSON.parse(text) as Json
      } catch {
        value = { text }
      }
      if (result.isError === true) toolErrors++
      return { isError: result.isError === true, value }
    },
  }
}

/** Checks a call's outcome against the script: ok, or a tool error with the given code ('*' for the SDK's own). */
function expectOutcome(step: string, got: { isError: boolean; value: Json }, want: 'ok' | string): void {
  const code = got.isError ? ((got.value.error as string | undefined) ?? '*') : 'ok'
  if (code !== want) mismatches.push(`${step}: got ${code}, want ${want}`)
}

/** Checks an enterprise tool's {exit, lines}: ok, or a tool error whose last line is "<want>: ...". */
function expectLines(step: string, got: { isError: boolean; value: Json }, want: 'ok' | string): void {
  const lines = got.value.lines
  if (!Array.isArray(lines) || typeof got.value.exit !== 'number') {
    mismatches.push(`${step}: no exit and lines`)
    return
  }
  const code = got.isError ? String(lines.at(-1)).split(':')[0] : 'ok'
  if (code !== want) mismatches.push(`${step}: got ${code}, want ${want}`)
}

/** The give-up of `fire` and `until`: a missed barrier fails here, naming what it waited for. */
const WAIT_MS = 5000

/** Fires the timer of `ms` once it is pending, so the call waiting on it returns; throws if it never is. */
async function fire(ms: number): Promise<void> {
  await until(`the ${ms} ms timer to be pending`, () => timers.live().includes(ms))
  timers.fire((t) => t === ms)
}

/** Polls `test` every 5 ms until it holds; throws naming `what` after WAIT_MS. */
async function until(what: string, test: () => boolean): Promise<void> {
  const end = Date.now() + WAIT_MS
  while (!test()) {
    if (Date.now() > end) throw new Error(`timed out after ${WAIT_MS} ms waiting for ${what}`)
    await new Promise((r) => setTimeout(r, 5))
  }
}

const writeChain = (hops: readonly Hop[]): void => writeFileSync(chainFile, `${JSON.stringify(hops)}\n`)

function addressOf(p: Party, ttl: number): Uint8Array {
  return serializeRecord(
    signRecord(p.keys.signing, {
      kind: 'address',
      key: p.address,
      sealing_key: toHex(p.keys.sealing.publicKey),
      relays: [RELAY],
      rotation_key: null,
      revoked: [],
      ttl,
      iat: T0,
      rotated_from: null,
    }),
  )
}

async function main(): Promise<void> {
  for (const p of [P.org, P.jane, P.bob]) await publishAddress(relay, p)
  await relay.publish(RELAY, addressOf(P.alice, 600))
  await relay.publish(RELAY, serializeRecord(acceptFrom(P.alice, [P.bob.address])))
  for (const p of [P.alice, P.bob]) saveKeys(join(tmp.dir, p.name), p)
  saveKeys(join(tmp.dir, 'session'), P.session, {
    signing: P.session.keys.signing,
    sealing: P.jane.keys.sealing,
  })
  writeChain(sessionChain())

  const alice = await serve('alice', join(tmp.dir, 'alice'), [
    '--trust-root',
    P.bob.address,
    '--keep-alive-records',
    '--allow-delegate',
  ])
  const bob = await serve('bob', join(tmp.dir, 'bob'), [
    '--trust-root',
    P.alice.address,
    '--trust-root',
    P.org.address,
    '--honor',
    'coding',
  ])
  let session = await serve('session', join(tmp.dir, 'session'), [
    '--auth',
    chainFile,
    '--mailbox',
    P.jane.address,
    '--trust-root',
    P.bob.address,
    '--allow-delegate',
  ])
  await alice.running.kept

  const listed = await alice.rpc.request('tools/list')
  const names = ((listed.result as { tools?: { name: string }[] } | undefined)?.tools ?? []).map(
    (t) => t.name,
  )
  if (names.length !== 15) mismatches.push(`tools/list: ${names.length} tools`)
  // bob runs without --allow-delegate: 14 tools, and delegate is the SDK's unknown-tool error.
  const bobs = await bob.rpc.request('tools/list')
  const bobNames = ((bobs.result as { tools?: { name: string }[] } | undefined)?.tools ?? []).map(
    (t) => t.name,
  )
  if (bobNames.length !== 14 || bobNames.includes('delegate'))
    mismatches.push(`tools/list without --allow-delegate: ${bobNames.join(', ')}`)
  expectOutcome(
    'delegate unlisted',
    await bob.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+60' }),
    '*',
  )
  // The pair tools (pairing.ts) load with the rest; this client shows no dialog, so each refuses before any network.
  expectOutcome(
    'pair_invite without a dialog',
    await alice.call('pair_invite', { name: 'bob' }),
    'no-elicitation',
  )
  expectOutcome(
    'pair_accept without a dialog',
    await alice.call('pair_accept', { name: 'bob' }),
    'no-elicitation',
  )
  const listedSession = await session.rpc.request('tools/list')
  const sessionNames = (
    (listedSession.result as { tools?: { name: string }[] } | undefined)?.tools ?? []
  ).map((t) => t.name)
  if (sessionNames.some((n) => n.startsWith('pair_'))) mismatches.push('tools/list of a session: a pair tool')
  for (const n of ['connect', 'sign_in', 'enterprise_status'])
    if (!names.includes(n) || !sessionNames.includes(n)) mismatches.push(`tools/list: no ${n}`)
  // The enterprise tools (enterprise.ts, on @usebag/enterprise-client): their refusals before any network.
  expectLines('enterprise_status signed out', await alice.call('enterprise_status'), 'signed-out')
  expectLines('connect no code', await alice.call('connect', { code: ' ' }), 'usage')
  expectLines('connect bad code', await alice.call('connect', { code: 'bagcode_x.y' }), 'usage')
  expectOutcome('connect schema', await alice.call('connect', {}), '*')
  const origin = 'https://console.acme.example'
  expectLines(
    'sign_in instance',
    await alice.call('sign_in', { domain: 'acme.example', instance: 'http://console.acme.example' }),
    'usage',
  )
  expectLines(
    'sign_in domain',
    await alice.call('sign_in', { domain: 'Not A Domain', instance: origin }),
    'usage',
  )
  expectLines('session enterprise_status', await session.call('enterprise_status'), 'signed-out')
  const pinged = await alice.rpc.request('ping')
  if (pinged.result === undefined) mismatches.push('ping: no result')
  const unknown = await alice.rpc.request('tools/call', { name: 'nope', arguments: {} })
  if (unknown.result === undefined && unknown.error === undefined) mismatches.push('unknown tool: no answer')

  // status, inbox and send, with their refusals
  expectOutcome('status', await alice.call('status'), 'ok')
  expectOutcome('facts', await alice.call('facts'), 'ok')
  expectOutcome('inbox', await alice.call('inbox'), 'ok')
  expectOutcome('inbox since', await alice.call('inbox', { since: 'yesterday' }), 'usage')
  expectOutcome(
    'inbox handed_off',
    await alice.call('inbox', { handed_off: 'exclude', since: 0, limit: 5 }),
    'ok',
  )
  expectOutcome('inbox thread', await alice.call('inbox', { thread: 'abc' }), 'bad-thread')
  expectOutcome(
    'send',
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'hello' }),
    'ok',
  )
  expectOutcome(
    'send address',
    await alice.call('send', { to: ['Bob!'], type: 'chat.v1', body: 1 }),
    'bad-address',
  )
  expectOutcome(
    'send unknown name',
    await alice.call('send', { to: ['bob'], type: 'chat.v1', body: 1 }),
    'name-unknown',
  )
  // The name book, read at each call: a name resolves, and bob's book names alice in what he receives.
  const book = (name: string, address: string): string =>
    `${JSON.stringify({ version: 1, names: { [name]: { address, added_at: T0 } } })}\n`
  writeFileSync(join(tmp.dir, 'alice', 'names.json'), book('bob', P.bob.address))
  writeFileSync(join(tmp.dir, 'bob', 'names.json'), book('alice', P.alice.address))
  expectOutcome('send name', await alice.call('send', { to: ['bob'], type: 'chat.v1', body: 'named' }), 'ok')
  expectOutcome('wait named', await bob.call('wait', { timeout_s: 30 }), 'ok')
  // A recipient no relay holds is kept waiting (first contact), not refused.
  const unresolved = await alice.call('send', { to: [P.carol.address], type: 'chat.v1', body: 1 })
  expectOutcome('send unresolved', unresolved, 'ok')
  if (unresolved.value.waiting !== true) mismatches.push('send unresolved: not waiting')
  expectOutcome('lookup', await alice.call('lookup', { address: P.carol.address }), 'ok')
  expectOutcome('lookup address', await alice.call('lookup', { address: 'carol' }), 'bad-address')
  expectOutcome(
    'send thread',
    await alice.call('send', {
      to: [P.bob.address],
      type: 'chat.v1',
      body: 1,
      thread: { id: 'x', prev: [] },
    }),
    'bad-thread',
  )
  expectOutcome('send schema', await alice.call('send', { to: [P.bob.address] }), '*')
  relay.failPublish.set(RELAY, new RelayError('root-not-accepted', 403, null, 'refused'))
  expectOutcome(
    'send refused',
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 1 }),
    'root-not-accepted',
  )
  relay.failPublish.set(RELAY, new RelayError(null, 0, null, 'connection refused'))
  const unreachable = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 1 })
  expectOutcome('send unreachable', unreachable, 'ok')
  if (unreachable.value.reason !== 'unreachable') mismatches.push('send unreachable: no reason unreachable')
  relay.failPublish.delete(RELAY)

  // wait: unread, the window, a resume, a timeout, and refusals
  expectOutcome('wait unread', await bob.call('wait', { timeout_s: 30 }), 'ok')
  const windowed = bob.call('wait', { timeout_s: 300 })
  await fire(25_000)
  const pending = await windowed
  expectOutcome('wait window', pending, 'ok')
  await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'between' })
  await until('bob has an unread message', () => bob.running.desk.counts().counts.unread > 0)
  const resumed = await bob.call('wait', { resume: pending.value.resume })
  expectOutcome('wait resume', resumed, 'ok')
  if (resumed.value.message === undefined) mismatches.push('wait resume: no message')
  expectOutcome('wait timeout', await bob.call('wait', { timeout_s: 0 }), 'ok')
  expectOutcome('wait thread', await bob.call('wait', { thread: 'nope', timeout_s: 1 }), 'bad-thread')
  expectOutcome('wait token', await bob.call('wait', { resume: 'bad' }), 'usage')
  expectOutcome('wait schema', await bob.call('wait', { timeout_s: 301 }), '*')

  // ask: pending, the answer between calls, a resume, and refusals
  const asking = alice.call('ask', { to: P.bob.address, body: { q: 'ready?' }, timeout_s: 60 })
  await fire(25_000)
  const asked = await asking
  expectOutcome('ask window', asked, 'ok')
  const question = await bob.call('wait', { timeout_s: 5 })
  const reply = (question.value.message as { reply?: Json } | undefined)?.reply ?? {}
  expectOutcome('answer', await bob.call('send', { ...reply, type: 'answer.v1', body: { a: 'yes' } }), 'ok')
  await until('alice has the answer unread', () => alice.running.desk.counts().counts.unread > 0)
  const answered = await alice.call('ask', { resume: asked.value.resume })
  expectOutcome('ask resume', answered, 'ok')
  if (answered.value.answer === undefined) mismatches.push('ask resume: no answer')
  expectOutcome('ask address', await alice.call('ask', { to: 'X', body: 1 }), 'bad-address')
  expectOutcome('ask name', await alice.call('ask', { to: 'carol', body: 1 }), 'name-unknown')
  expectOutcome('ask usage', await alice.call('ask', {}), 'usage')
  expectOutcome('ask wait token', await alice.call('ask', { resume: `r1.0.${T0}.any` }), 'usage')
  relay.failPublish.set(RELAY, new RelayError('too-large-for-mailbox', 403, null, 'big'))
  expectOutcome(
    'ask refused',
    await alice.call('ask', { to: P.bob.address, body: 1 }),
    'too-large-for-mailbox',
  )
  relay.failPublish.delete(RELAY)

  // handoff and delegate
  const thread =
    (asked.value.question as { thread?: { id: string } } | undefined)?.thread?.id ?? 'a'.repeat(64)
  expectOutcome(
    'handoff',
    await alice.call('handoff', { to: P.bob.address, threads: [thread], note: 'yours' }),
    'ok',
  )
  expectOutcome(
    'handoff thread',
    await alice.call('handoff', { to: P.bob.address, threads: ['x'] }),
    'bad-thread',
  )
  expectOutcome(
    'handoff unresolved',
    await alice.call('handoff', { to: P.carol.address, threads: [thread] }),
    'resolve-failed',
  )
  expectOutcome('inbox only', await alice.call('inbox', { handed_off: 'only' }), 'ok')
  expectOutcome(
    'delegate',
    await alice.call('delegate', { to: P.carol.address, caveats: ['type=chat.*'], exp: '+60' }),
    'ok',
  )
  const toBob = [signHop(P.org.keys.signing, P.bob.address, [], T0 + 3600)]
  expectOutcome(
    'delegate broken',
    await alice.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+60', chain: toBob }),
    'chain-broken',
  )
  expectOutcome(
    'delegate exp',
    await alice.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: 'later' }),
    'usage',
  )
  expectOutcome(
    'delegate expired',
    await alice.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: T0 - 1 }),
    'hop-expired',
  )
  expectOutcome(
    'delegate caveat',
    await alice.call('delegate', { to: P.carol.address, caveats: [''], exp: '+60' }),
    'bad-hop',
  )
  expectOutcome(
    'delegate no caveat',
    await alice.call('delegate', { to: P.carol.address, caveats: [], exp: '+60' }),
    '*',
  )
  expectOutcome(
    'delegate cap',
    await alice.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+28801' }),
    'usage',
  )

  // the keep-alive: half the address record's ttl. Its first cycle published epoch 1, which re-signed the
  // record with no sealing key one second past its iat, so the re-sign is due at T0 + 1 + 300.
  clock.t = T0 + 301
  await fire(301_000)
  await until(
    'the keep-alive to re-sign the address record',
    () => alice.running.records?.status().last?.outcome === 're-signed',
  )
  if (alice.running.records?.status().last?.outcome !== 're-signed')
    mismatches.push('keep-alive: not re-signed')

  // a session: delegation refused, a send, then its chain read again on a refusal, by a timer and on a subscription
  expectOutcome('session status', await session.call('status'), 'ok')
  expectOutcome(
    'session delegate',
    await session.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+60' }),
    'usage',
  )
  expectOutcome(
    'session send',
    await session.call('send', { to: [P.bob.address], type: 'chat.v1', body: 's' }),
    'ok',
  )
  relay.checkChains = true
  clock.t = T0 + 3601
  expectOutcome(
    'session expired',
    await session.call('send', { to: [P.bob.address], type: 'chat.v1', body: 1 }),
    'hop-expired',
  )
  writeChain([sessionChain()[0] as Hop, signHop(P.jane.keys.signing, P.session.address, [], T0 + 7200)])
  expectOutcome(
    'session renewed',
    await session.call('send', { to: [P.bob.address], type: 'chat.v1', body: 2 }),
    'hop-expired',
  )
  expectOutcome(
    'session sends',
    await session.call('send', { to: [P.bob.address], type: 'chat.v1', body: 3 }),
    'ok',
  )
  await until('the chain timer is pending', () => timers.live().length > 0)
  timers.fire()
  await until('the session to read its chain again on the timer', () =>
    session.log.lines.some((l) => l.event === 'chain' && l.fields.why === 'timer'),
  )
  relay.failOnce.set(P.jane.address, new RelayError('hop-expired', 0, null, 'expired'))
  relay.wakeAll()
  await until('the session to read its chain again on the subscription', () =>
    session.log.lines.some((l) => l.event === 'chain' && l.fields.why === 'subscription'),
  )

  // the session again, its chain from a command under /bin/sh, allowed to delegate on
  await session.running.stop()
  session = await serve('session', join(tmp.dir, 'session'), [
    '--chain-cmd',
    `cat '${chainFile}'`,
    '--mailbox',
    P.jane.address,
    '--allow-session-delegation',
    '--allow-delegate',
  ])
  const allowed = await session.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+60' })
  expectOutcome('session delegate allowed', allowed, 'ok')
  if (allowed.value.reply_to !== P.jane.address) mismatches.push('session delegate allowed: reply_to')
  expectOutcome('session status command', await session.call('status'), 'ok')

  for (const s of [alice, bob, session]) await s.running.stop()
  process.stdout.write(`${JSON.stringify({ calls, tool_errors: toolErrors, mismatches })}\n`)
  tmp.cleanup()
  process.exitCode = mismatches.length === 0 ? 0 : 1
}

await main()

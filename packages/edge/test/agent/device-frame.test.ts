import { once } from 'node:events'
import { createConnection } from 'node:net'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import {
  type AcRecord,
  codingEvaluator,
  DEFAULT_SKEW,
  DEFAULT_TTL,
  type Hop,
  type RecordKind,
  signHop,
  verifyChain,
} from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import {
  Agent,
  AgentAudit,
  AgentClient,
  type AgentOp,
  AgentServer,
  buildRequest,
  DEVICE_MAX,
  signEntry,
  type Terminal,
} from '../../src/agent/index.ts'
import { parseAuditLine, verifyAuditLog } from '../../src/audit.ts'
import {
  addressRecord,
  DAY,
  FakeClock,
  MemoryAuditSink,
  P,
  seededRng,
  T0,
  tempDir,
} from '../support/fixtures.ts'
import { CAVEAT, EXP, JANE_KEYS, lines } from './support.ts'

// The `device-grant` frame and a device's end path at the socket: the prompt on the agent's own
// terminal, the device hop never in P's dated map, and on D a logout that signs nothing and a resign
// refused. jane is P, carol is D.

const J = P.jane.address
const D = P.carol.address
const S = P.session.address
const CAROL_KEYS = { signing: P.carol.signing, sealing: P.carol.sealing }

const tmp = tempDir('df')
afterAll(() => tmp.cleanup())
let n = 0
const servers: AgentServer[] = []
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()))
})
const quiet = { timers: { set: () => 1, clear: () => {} }, signals: { on: () => 0, off: () => 0 } }

/** jane's agent behind a socket (on carol's device when `device` is given), its window open, `answers` typed in turn. */
async function boot(answers: string[] = [], device: Hop | null = null, expiry = new Map<string, number>()) {
  const printed: string[] = []
  const terminal: Terminal = { print: (l) => void printed.push(l), ask: async () => answers.shift() ?? 'n' }
  const clock = new FakeClock()
  const sink = new MemoryAuditSink()
  const audit = new AgentAudit(sink, clock)
  const agent = new Agent({
    principal: J,
    clock,
    rng: seededRng('df'),
    audit,
    evaluators: [codingEvaluator],
    device,
  })
  const records = new Map<RecordKind, AcRecord>([['address', addressRecord(P.jane)]])
  const home = join(tmp.dir, `d${n++}`)
  const server = new AgentServer({ agent, clock, home, terminal, records, expiry, ended: () => {}, ...quiet })
  servers.push(server)
  await server.listen()
  server.login(device === null ? JANE_KEYS : CAROL_KEYS)
  const closed = once(server.listener, 'close')
  return { agent, sink, printed, records, expiry, server, closed, client: new AgentClient(server.path) }
}

describe('the device-grant frame', () => {
  it('prints the hop on the agent terminal and signs P -> D on a y, the code told first; the log verifies', async () => {
    const m = await boot(['y'])
    const codes: string[] = []
    const reply = await m.client.deviceGrant(D, [], T0 + DAY, (c) => codes.push(c))
    if (!reply.ok) throw new Error(`refused: ${reply.code}`)
    expect(Object.keys(reply)).toEqual(['ok', 'device'])
    expect(reply.device).toMatchObject({ iss: J, sub: D, caveats: [], exp: T0 + DAY })
    expect(verifyChain([reply.device], D, T0).root).toBe(J)
    expect(codes).toHaveLength(1)
    expect(m.printed).toEqual([
      `request ${codes[0]}`,
      `device grant to ${D}`,
      'caveats unrestricted',
      `until ${T0 + DAY} (${new Date((T0 + DAY) * 1000).toISOString()})`,
      'sign this device grant? type y to sign',
    ])
    expect(lines(m.sink)).toMatchObject([{ event: 'device', decision: 'accept', reason: 'ok', root: J }])
    expect(verifyAuditLog(m.sink.lines)).toEqual({ ok: true, lines: 1 })
  })

  it('is declined on anything but y, with one device reject line that the edge parser takes', async () => {
    const m = await boot(['yes'])
    expect(await m.client.deviceGrant(D, ['repo=r'], T0 + DAY)).toEqual({ ok: false, code: 'declined' })
    expect(lines(m.sink)).toMatchObject([{ event: 'device', decision: 'reject', reason: 'declined' }])
    expect(verifyAuditLog(m.sink.lines)).toEqual({ ok: true, lines: 1 })
  })

  it('refuses past now + 30 days and a malformed frame without asking the terminal', async () => {
    const m = await boot(['y', 'y'])
    expect(await m.client.deviceGrant(D, [], T0 + DEVICE_MAX + 1)).toEqual({
      ok: false,
      code: 'exp-not-monotone',
    })
    const raw = (args: unknown) => JSON.stringify({ op: 'device-grant', args })
    const sent = [raw([D, [], 'soon']), raw([D, 'c', T0 + 60]), raw([1, [], T0 + 60]), raw(null)]
    for (const frame of sent)
      expect(await call(m.server.path, () => frame)).toMatchObject({ code: 'bad-shape' })
    expect(m.printed).toEqual([])
  })

  it('takes no session frame: a signed request naming device-grant is bad-shape, and nothing is asked', async () => {
    const m = await boot(['y'])
    const frame = (nonce: string) =>
      buildRequest(P.session.signing, nonce, 0, 'device-grant' as AgentOp, [D, [], EXP])
    expect(await call(m.server.path, frame)).toEqual({ ok: false, code: 'bad-shape' })
    expect(m.printed).toEqual([])
  })
})

describe("a device grant: P's logout after a device grant does not revoke D", () => {
  it('revokes the session P granted and never D, whose hop is in no dated map', async () => {
    const m = await boot(['y', 'y'])
    expect(await m.client.grant(S, [CAVEAT], EXP)).toMatchObject({ ok: true })
    expect(await m.client.deviceGrant(D, [], T0 + DAY)).toMatchObject({ ok: true })
    expect([...m.expiry.keys()]).toEqual([S])
    const reply = await m.client.logout()
    expect(reply).toMatchObject({ ok: true, record: { revoked: [S] } })
    expect(JSON.stringify(reply)).not.toContain(D)
    await m.closed
  })

  it('has nothing to revoke when the device grant is the only thing signed', async () => {
    const m = await boot(['y'])
    expect(await m.client.deviceGrant(D, [], T0 + DAY)).toMatchObject({ ok: true })
    expect(await m.client.logout()).toEqual({ ok: true, record: null })
    expect(m.expiry.size).toBe(0)
  })
})

describe("a device's agent at the socket", () => {
  const device = () => signHop(P.jane.signing, D, [], T0 + DAY)

  it('signs no record at logout: record null, each live subject with its exp + TTL + skew', async () => {
    const m = await boot(['y'], device())
    const held = m.records.get('address')
    expect(await m.client.grant(S, [CAVEAT], EXP)).toMatchObject({ ok: true, hop: { iss: D, sub: S } })
    const reply = await m.client.logout()
    expect(reply).toEqual({
      ok: true,
      record: null,
      unrevoked: [{ sub: S, until: EXP + DEFAULT_TTL + DEFAULT_SKEW }],
    })
    expect(m.records.get('address')).toBe(held)
    expect(m.agent.windowEnd()).toBeNull()
    await m.closed
  })

  it("prunes the dated map past its bound, and dates a subject it never saw by the device hop's exp", async () => {
    const old = P.bob.address
    const expiry = new Map([[old, T0 - DEFAULT_TTL - DEFAULT_SKEW - 1]])
    const m = await boot(['y'], device(), expiry)
    expect(await m.client.grant(S, [CAVEAT], EXP)).toMatchObject({ ok: true })
    expiry.delete(S)
    const reply = await m.client.logout()
    expect(reply).toEqual({
      ok: true,
      record: null,
      unrevoked: [{ sub: S, until: T0 + DAY + DEFAULT_TTL + DEFAULT_SKEW }],
    })
    expect(expiry.size).toBe(0)
    await m.closed
  })

  it('refuses resign not-authorized and device-grant not-authorized, without asking', async () => {
    const m = await boot(['y'], device())
    await expect(m.client.resign('address')).rejects.toMatchObject({ code: 'not-authorized' })
    expect(await m.client.deviceGrant(P.bob.address, [], T0 + DAY)).toEqual({
      ok: false,
      code: 'not-authorized',
    })
    expect(m.printed).toEqual([])
  })
})

describe("the edge's audit parser on the agent's device and rotate lines", () => {
  it('takes declined on a device line and an agent code on device and rotate lines; declined nowhere else', () => {
    const audit = new AgentAudit(new MemoryAuditSink(), new FakeClock())
    const hop = { iss: J, sub: D, caveats: [], exp: T0 + DAY }
    const at = (event: 'device' | 'rotate' | 'sign', reason: 'declined' | 'agent-locked' | 'not-in-grant') =>
      audit.record({ ...signEntry(reason, hop, null), event })
    expect(parseAuditLine(at('device', 'declined'))).toMatchObject({ event: 'device', reason: 'declined' })
    expect(parseAuditLine(at('device', 'agent-locked'))).toMatchObject({ reason: 'agent-locked' })
    expect(parseAuditLine(at('rotate', 'agent-locked'))).toMatchObject({ event: 'rotate' })
    expect(parseAuditLine(at('sign', 'not-in-grant'))).toMatchObject({ reason: 'not-in-grant' })
    const refused = [at('rotate', 'declined'), at('sign', 'declined'), at('rotate', 'not-in-grant')]
    for (const line of [...refused, at('device', 'not-in-grant')])
      expect(() => parseAuditLine(line)).toThrow()
  })
})

/** One frame on a raw connection, after the nonce line; the socket and its reader each have an error listener. */
async function call(path: string, frame: (nonce: string) => string): Promise<unknown> {
  const socket = createConnection(path).on('error', () => {})
  const reader = createInterface({ input: socket }).on('error', () => {})
  const it = reader[Symbol.asyncIterator]()
  try {
    const { nonce } = JSON.parse(String((await it.next()).value)) as { nonce: string }
    socket.write(`${frame(nonce)}\n`)
    return JSON.parse(String((await it.next()).value))
  } finally {
    reader.close()
    socket.destroy()
  }
}

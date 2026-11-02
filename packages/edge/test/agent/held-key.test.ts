import {
  codingEvaluator,
  groupCaveat,
  type Hop,
  sealGroupKey,
  sealingKeyFromSeed,
  signHop,
  signMembership,
  verifyChain,
} from '@usebag/core'
import { describe, expect, it } from 'vitest'
import {
  Agent,
  AgentAudit,
  type AgentOp,
  checkDeviceGrant,
  DEVICE_MAX,
  grantLines,
  hopDigest,
  rootRule,
  WINDOW_MAX,
} from '../../src/agent/index.ts'
import { FakeClock, MemoryAuditSink, P, seededRng, T0 } from '../support/fixtures.ts'
import { CAVEAT, EXP, envelope, grant, hopOf, JANE_KEYS, lines, refusal, Session, setup } from './support.ts'

// The agent core's held key: the root rule, the device-grant
// op on P's agent, and a device's agent that holds D, answers for P and signs only. jane is P, carol is the device D,
// org a group. Unit tests of the core.

const J = P.jane.address
const D = P.carol.address
const S = P.session.address
const B = P.bob.address
const G = P.org.address
const CAROL_KEYS = { signing: P.carol.signing, sealing: P.carol.sealing }

/** The device hop P -> D, a day long unless told otherwise. */
const deviceHop = (exp: number = T0 + 86_400, caveats: readonly string[] = []): Hop =>
  signHop(P.jane.signing, D, caveats, exp)

/** A device's agent for jane holding carol's key, logged in unless `login` is false. */
function deviceAgent(device: Hop = deviceHop(), login = true) {
  const clock = new FakeClock()
  const sink = new MemoryAuditSink()
  const audit = new AgentAudit(sink, clock)
  const agent = new Agent({
    principal: J,
    clock,
    rng: seededRng('device'),
    audit,
    evaluators: [codingEvaluator],
    device,
  })
  if (login) agent.login(CAROL_KEYS)
  return { agent, sink, clock }
}

describe('rootRule', () => {
  const pHop = signHop(P.jane.signing, S, [CAVEAT], EXP)
  const dev = deviceHop()
  const dHop = signHop(P.carol.signing, S, [CAVEAT], EXP)
  const member = signMembership(P.org.signing, J, EXP)
  const none = () => false
  const org = (g: string) => g === G

  it("takes P's own hop at index 0, and on a device the held device hop's next hop at index 1", () => {
    expect(rootRule([pHop], J, null, none)).toEqual({ at: 0, group: null })
    expect(rootRule([dev, dHop], J, dev, none)).toEqual({ at: 1, group: null })
  })

  it("refuses on a device a chain whose first hop is not the held device hop, and a group's chain", () => {
    expect(() => rootRule([pHop], J, dev, none)).toThrow(/not-authorized/)
    expect(() => rootRule([deviceHop(T0 + 99), dHop], J, dev, none)).toThrow(/not-authorized/)
    expect(() => rootRule([member, pHop], J, dev, org)).toThrow(/not-authorized/)
  })

  it("takes a held group's membership of P carrying group=<G>, and nothing else rooted elsewhere", () => {
    expect(rootRule([member, pHop], J, null, org)).toEqual({ at: 1, group: G })
    expect(() => rootRule([member, pHop], J, null, none)).toThrow(/not-authorized/)
    const bare = signHop(P.org.signing, J, ['repo=r'], EXP)
    expect(() => rootRule([bare, pHop], J, null, org)).toThrow(/not-authorized/)
    const toBob = signHop(P.org.signing, B, [groupCaveat(G)], EXP)
    expect(() => rootRule([toBob], J, null, org)).toThrow(/not-authorized/)
    expect(() => rootRule([], J, null, org)).toThrow(/not-authorized/)
  })
})

describe('checkDeviceGrant and its lines', () => {
  it('admits no caveat and an exp up to now + 30 days, shown unrestricted', () => {
    const hop = checkDeviceGrant(J, { device: D, caveats: [], exp: T0 + DEVICE_MAX }, T0)
    expect(hop).toEqual({ iss: J, sub: D, caveats: [], exp: T0 + DEVICE_MAX })
    const shown = grantLines(hop, 'device grant')
    expect(shown[0]).toBe(`device grant to ${D}`)
    expect(shown[1]).toBe('caveats unrestricted')
    expect(shown[3]).toBe('sign this device grant? type y to sign')
    expect(grantLines({ ...hop, caveats: [CAVEAT] })[0]).toBe(`grant to session ${D}`)
  })

  it('refuses a bad device address, caveats past the bounds and an exp past 30 days, in that order', () => {
    expect(() => checkDeviceGrant(J, { device: 'x', caveats: [], exp: T0 }, T0)).toThrow(/^bad-address/)
    expect(() => checkDeviceGrant(J, { device: J, caveats: [], exp: T0 }, T0)).toThrow(/^bad-address/)
    const many = Array.from({ length: 33 }, (_, i) => `c${i}`)
    expect(() => checkDeviceGrant(J, { device: D, caveats: many, exp: T0 }, T0)).toThrow(/^bad-shape/)
    expect(() => checkDeviceGrant(J, { device: D, caveats: [''], exp: T0 }, T0)).toThrow(/^bad-shape/)
    const late = { device: D, caveats: [], exp: T0 + DEVICE_MAX + 1 }
    expect(() => checkDeviceGrant(J, late, T0)).toThrow(/^exp-not-monotone/)
  })
})

describe("device-grant on P's agent (S1)", () => {
  it('signs on y one hop P -> D that verifies, audits device accept, and never enters the grant-set', () => {
    const { agent, sink } = setup()
    const pending = agent.prepareDeviceGrant({ device: D, caveats: [], exp: T0 + 7 * 86_400 })
    if (!pending.ok) throw new Error(pending.code)
    expect(pending.lines[0]).toBe(`device grant to ${D}`)
    const reply = agent.confirmDeviceGrant(pending, 'y')
    if (!reply.ok) throw new Error(reply.code)
    expect(verifyChain([reply.device], D, T0).root).toBe(J)
    expect(lines(sink).at(-1)).toMatchObject({
      event: 'device',
      decision: 'accept',
      reason: 'ok',
      id: hopDigest(reply.device),
      from: null,
      root: J,
      detail: JSON.stringify({ tag: 'ac/hop/1', sub: D, exp: T0 + 7 * 86_400, caveats: 0 }),
    })
    // Not a grant of the window: D presenting it as a session chain is not-in-grant, and logout names no D.
    const asD = new Session(agent, P.carol.signing, [reply.device])
    expect(asD.register('00'.repeat(32))).toEqual(refusal('not-in-grant'))
    grant(agent)
    expect(agent.logout()).toEqual([S])
  })

  it('signs nothing on n or no answer, a device reject declined line each', () => {
    const { agent, sink } = setup()
    for (const answer of ['n', '']) {
      const pending = agent.prepareDeviceGrant({ device: D, caveats: [CAVEAT], exp: T0 + 60 })
      if (!pending.ok) throw new Error(pending.code)
      expect(agent.confirmDeviceGrant(pending, answer)).toEqual({ ok: false, code: 'declined' })
      expect(lines(sink).at(-1)).toMatchObject({ event: 'device', decision: 'reject', reason: 'declined' })
    }
    expect(agent.logout()).toEqual([])
  })

  it('refuses 31 days, a closed window and a mixed-up confirm; a malformed ask writes no line', () => {
    const { agent, sink } = setup()
    const late = agent.prepareDeviceGrant({ device: D, caveats: [], exp: T0 + DEVICE_MAX + 1 })
    expect(late).toEqual(refusal('exp-not-monotone'))
    expect(lines(sink).at(-1)).toMatchObject({
      event: 'device',
      decision: 'reject',
      reason: 'exp-not-monotone',
    })
    const n = sink.lines.length
    expect(agent.prepareDeviceGrant({ device: 'x', caveats: [], exp: T0 })).toEqual(refusal('bad-address'))
    expect(sink.lines.length).toBe(n)
    const asGrant = agent.prepareGrant({ session: S, caveats: [CAVEAT], exp: EXP })
    const asDevice = agent.prepareDeviceGrant({ device: D, caveats: [], exp: EXP })
    if (!asGrant.ok || !asDevice.ok) throw new Error('prepare refused')
    expect(agent.confirmDeviceGrant(asGrant, 'y')).toEqual(refusal('bad-shape'))
    expect(agent.confirmGrant(asDevice, 'y')).toEqual(refusal('bad-shape'))
    agent.logout()
    expect(agent.prepareDeviceGrant({ device: D, caveats: [], exp: EXP })).toEqual(refusal('agent-locked'))
  })

  it('refuses a confirm after the window it was asked in has closed and another opened: agent-locked', () => {
    const { agent } = setup()
    const pending = agent.prepareDeviceGrant({ device: D, caveats: [], exp: EXP })
    if (!pending.ok) throw new Error(pending.code)
    agent.logout()
    agent.login(JANE_KEYS)
    expect(agent.confirmDeviceGrant(pending, 'y')).toEqual(refusal('agent-locked'))
  })

  it("refuses the group's own copy of a generation, whose hop is null: the admin's, not a member's", () => {
    const clock = new FakeClock()
    const org = new Agent({
      principal: G,
      clock,
      rng: seededRng('org'),
      audit: new AgentAudit(new MemoryAuditSink(), clock),
      evaluators: [codingEvaluator],
    })
    org.login({ signing: P.org.signing, sealing: P.org.sealing })
    const own = sealGroupKey({
      group: P.org.signing,
      generation: 1,
      key: sealingKeyFromSeed(new Uint8Array(32).fill(4)),
      holder: { address: G, sealingKey: P.org.sealing.publicKey },
      hop: null,
      iat: T0,
      rng: (n) => seededRng('own copy').bytes(n),
    })
    expect(org.takeGroupKey({ body: own })).toEqual(refusal('not-authorized'))
  })

  it('is no session op: a session frame naming device-grant or group-key is bad-shape', () => {
    const { agent } = setup()
    const s = new Session(agent, P.session.signing, [grant(agent)])
    for (const op of ['device-grant', 'group-key']) {
      expect(s.send(op as unknown as AgentOp, [D, [], EXP])).toEqual(refusal('bad-shape'))
    }
  })
})

describe("a device's agent (S2: holds D, answers for P, signs only)", () => {
  it("logs in with D's keys only, while the device hop is live, and ends the window by its exp", () => {
    const { agent } = deviceAgent(deviceHop(T0 + 3600), false)
    expect(agent.held).toBe(D)
    expect(agent.principal).toBe(J)
    expect(() => agent.login(JANE_KEYS)).toThrow("the keys are not the device's")
    expect(agent.login(CAROL_KEYS)).toBe(T0 + 3600)
    const stale = deviceAgent(deviceHop(T0 - 1), false).agent
    expect(() => stale.login(CAROL_KEYS)).toThrow(/^hop-expired/)
    expect(() => deviceAgent(signHop(P.bob.signing, D, [], T0 + 60))).toThrow("not P's device hop")
    expect(deviceAgent(deviceHop(T0 + 10 * WINDOW_MAX), false).agent.login(CAROL_KEYS)).toBe(T0 + WINDOW_MAX)
  })

  it('signs first grants and derived hops under D for the chain [P -> D, D -> S], root P in the lines', () => {
    const { agent, sink } = deviceAgent()
    const dev = agent.device as Hop
    const first = grant(agent)
    expect(first.iss).toBe(D)
    const s = new Session(agent, P.session.signing, [dev, first])
    const derived = hopOf(s.sign(B, [CAVEAT, 'repo=r'], EXP))
    expect(derived.iss).toBe(D)
    expect(verifyChain([dev, derived], B, T0).root).toBe(J)
    expect(lines(sink).at(-1)).toMatchObject({ event: 'sign', decision: 'accept', root: J, from: S })
    expect(s.sign(S, [CAVEAT], EXP + 60)).toMatchObject({ ok: true, renewal: true })
    expect(s.sign(B, ['repo=r'], EXP)).toEqual(refusal('not-in-grant'))
  })

  it('refuses a chain of the device hop alone: no hop of it is from the held key', () => {
    const { agent } = deviceAgent()
    const s = new Session(agent, P.carol.signing, [agent.device as Hop])
    expect(s.register('00'.repeat(32))).toEqual(refusal('not-authorized'))
  })

  it("refuses P's own chain, any open, a device-grant and a group-key; a first grant past the hop is refused", () => {
    const { agent, sink } = deviceAgent(deviceHop(T0 + 3600))
    const pFirst = signHop(P.jane.signing, S, [CAVEAT], EXP)
    expect(new Session(agent, P.session.signing, [pFirst]).register('00'.repeat(32))).toEqual(
      refusal('not-authorized'),
    )
    const s = new Session(agent, P.session.signing, [agent.device as Hop, grant(agent)])
    expect(s.open(envelope())).toEqual(refusal('not-authorized'))
    expect(lines(sink).at(-1)).toMatchObject({ event: 'open', decision: 'reject', reason: 'not-authorized' })
    expect(agent.prepareDeviceGrant({ device: B, caveats: [], exp: EXP })).toEqual(refusal('not-authorized'))
    expect(agent.takeGroupKey({ body: {} })).toEqual(refusal('not-authorized'))
    expect(agent.prepareGrant({ session: S, caveats: [CAVEAT], exp: T0 + 3601 })).toEqual(
      refusal('exp-not-monotone'),
    )
  })

  it("closes the window at the device hop's exp (sessions agent-locked); its logout names session subjects only", () => {
    const { agent, clock } = deviceAgent(deviceHop(T0 + 3600))
    const s = new Session(agent, P.session.signing, [
      agent.device as Hop,
      grant(agent, S, [CAVEAT], T0 + 3600),
    ])
    expect(s.register('00'.repeat(32))).toEqual({ ok: true, op: 'register' })
    clock.advance(3600)
    expect(s.register('00'.repeat(32))).toEqual(refusal('agent-locked'))
    expect(agent.logout()).toEqual([])
    const again = deviceAgent().agent
    grant(again)
    expect(again.logout()).toEqual([S])
  })
})

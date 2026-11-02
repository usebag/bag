import { type Hop, signHop, verifyChain } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { buildRequest, hopDigest, SEQ_MAX, SIGNS_PER_MINUTE, WINDOW_MAX } from '../../src/agent/index.ts'
import { P, T0 } from '../support/fixtures.ts'
import {
  CAVEAT,
  EXP,
  grant,
  hopOf,
  JANE_KEYS,
  lines,
  refusal,
  Session,
  session,
  setup,
  threadId,
} from './support.ts'

// The agent's session side: the window and logout, the connection ledger, authority
// at the agent's clock and the grant-set, the one derived hop, silent renewals, the first grant's terminal y, and the
// per-minute cap on signatures. Each refusal is checked by its code.

const J = P.jane.address
const S = P.session.address
const B = P.bob.address
const T = threadId(1)

describe('login and logout', () => {
  it('opens a window of at most 8 hours, which ends by itself at its end', () => {
    const { agent, clock } = setup({ login: false })
    expect(agent.windowEnd()).toBeNull()
    expect(agent.login(JANE_KEYS, 60)).toBe(T0 + 60)
    expect(agent.windowEnd()).toBe(T0 + 60)
    clock.advance(60)
    expect(agent.windowEnd()).toBeNull()
    expect(agent.login(JANE_KEYS, 10 * WINDOW_MAX)).toBe(T0 + 60 + WINDOW_MAX)
  })

  it("refuses keys not the principal's, a window not in whole seconds, and a second window", () => {
    const { agent } = setup({ login: false })
    const bobs = { signing: P.bob.signing, sealing: P.bob.sealing }
    expect(() => agent.login(bobs)).toThrow("the keys are not the principal's")
    for (const s of [0, 1.5, -1]) expect(() => agent.login(JANE_KEYS, s)).toThrow('a window is whole seconds')
    agent.login(JANE_KEYS)
    expect(agent.windowEnd()).toBe(T0 + WINDOW_MAX)
    expect(() => agent.login(JANE_KEYS)).toThrow('a login window is open')
  })

  it("returns the live grants' subjects once each, sorted, and locks every later request", () => {
    const { agent, clock } = setup()
    const s = session(agent)
    expect(s.sign(B, [CAVEAT, 'repo=r'], EXP)).toMatchObject({ ok: true, renewal: false })
    expect(s.sign(S, [CAVEAT], EXP + 60)).toMatchObject({ ok: true, renewal: true })
    grant(agent, P.mallory.address, [CAVEAT], T0 + 100)
    clock.advance(200)
    expect(agent.logout()).toEqual([B, S].sort())
    expect(agent.windowEnd()).toBeNull()
    expect(s.sign(B, [CAVEAT], EXP)).toEqual(refusal('agent-locked'))
    expect(agent.logout()).toEqual([])
  })

  it('locks at the window end', () => {
    const { agent, clock } = setup()
    const s = session(agent)
    expect(s.register(T)).toEqual({ ok: true, op: 'register' })
    clock.advance(WINDOW_MAX)
    expect(s.register(T)).toEqual(refusal('agent-locked'))
  })
})

describe('the request and the connection ledger', () => {
  it('draws a fresh 32-byte nonce for each connection', () => {
    const { agent } = setup()
    const a = agent.connect()
    const b = agent.connect()
    expect(a.nonce).toMatch(/^[0-9a-f]{64}$/)
    expect(a.nonce).not.toBe(b.nonce)
  })

  it('takes seq 0 first and then one more each time, and refuses a replayed or skipped seq bad-shape', () => {
    const { agent } = setup()
    const s = session(agent)
    expect(s.register(T)).toEqual({ ok: true, op: 'register' })
    const replay = buildRequest(P.session.signing, s.conn.nonce, 0, 'register', [T])
    expect(agent.handle(s.conn, replay)).toEqual(refusal('bad-shape'))
    const skip = buildRequest(P.session.signing, s.conn.nonce, 2, 'register', [T])
    expect(agent.handle(s.conn, skip)).toEqual(refusal('bad-shape'))
    expect(s.register(T)).toEqual({ ok: true, op: 'register' })
  })

  it('refuses a seq from SEQ_MAX rate-limited, so the connection is made again', () => {
    const { agent } = setup()
    const conn = agent.connect()
    const spent = buildRequest(P.session.signing, conn.nonce, SEQ_MAX, 'register', [T])
    expect(agent.handle(conn, spent)).toEqual(refusal('rate-limited'))
  })

  it('refuses a request signed for another connection or by another key bad-sig, and spends no seq on it', () => {
    const { agent } = setup()
    const chain = [grant(agent)]
    const s = new Session(agent, P.session.signing, chain)
    const elsewhere = buildRequest(P.session.signing, agent.connect().nonce, 0, 'register', [T], { chain })
    expect(agent.handle(s.conn, elsewhere)).toEqual(refusal('bad-sig'))
    const forged = JSON.parse(buildRequest(P.mallory.signing, s.conn.nonce, 0, 'register', [T], { chain }))
    forged.session = S
    expect(agent.handle(s.conn, JSON.stringify(forged))).toEqual(refusal('bad-sig'))
    expect(s.register(T)).toEqual({ ok: true, op: 'register' })
  })

  it('writes no audit line for a sign or open whose signature does not verify, so none names an unproven session', () => {
    const { agent, sink } = setup()
    const s = session(agent)
    expect(s.register(T)).toEqual({ ok: true, op: 'register' })
    const before = sink.lines.length
    for (const [op, args] of [
      ['sign', [B, [CAVEAT], EXP]],
      ['open', [J, T]],
    ] as const) {
      const extras = op === 'open' ? { envelope: '{}' } : {}
      const claimed = JSON.parse(buildRequest(P.mallory.signing, s.conn.nonce, 1, op, args, extras))
      claimed.session = S
      expect(agent.handle(s.conn, JSON.stringify(claimed))).toEqual(refusal('bad-sig'))
    }
    expect(sink.lines.length).toBe(before)
  })

  it('refuses a dropped connection and unparsable input bad-shape, with no audit line', () => {
    const { agent, sink } = setup()
    const s = session(agent)
    agent.disconnect(s.conn)
    expect(s.register(T)).toEqual(refusal('bad-shape'))
    expect(agent.handle(agent.connect(), 'not json')).toEqual(refusal('bad-shape'))
    expect(agent.handle(agent.connect(), JSON.stringify({ op: 'resign' }))).toEqual(refusal('bad-shape'))
    expect(sink.steps()).toEqual(['sign accept ok'])
  })

  it('refuses agent-locked with no window, before any signature is checked, so with no audit line', () => {
    const { agent, sink } = setup({ login: false })
    const conn = agent.connect()
    const sign = buildRequest(P.session.signing, conn.nonce, 0, 'sign', [B, [CAVEAT], EXP])
    expect(agent.handle(conn, sign)).toEqual(refusal('agent-locked'))
    const register = buildRequest(P.session.signing, conn.nonce, 0, 'register', [T])
    expect(agent.handle(conn, register)).toEqual(refusal('agent-locked'))
    expect(sink.lines).toEqual([])
  })

  it('audits a sign refused after its signature verified, by the hop digest and the proven session', () => {
    const { agent, sink } = setup()
    expect(session(agent).sign(B, [CAVEAT], EXP + 1)).toEqual(refusal('exp-not-monotone'))
    const id = hopDigest({ iss: J, sub: B, caveats: [CAVEAT], exp: EXP + 1 })
    expect(lines(sink)[1]).toMatchObject({ event: 'sign', decision: 'reject', id, from: S, root: J })
  })
})

describe("authority at the agent's clock", () => {
  it('needs the chain with the first request on a connection, bad-shape without', () => {
    const { agent } = setup()
    grant(agent)
    expect(new Session(agent, P.session.signing, null).register(T)).toEqual(refusal('bad-shape'))
  })

  it('refuses a chain not to the session, one not rooted at the principal, and an expired one', () => {
    const { agent, clock } = setup()
    const g = grant(agent)
    expect(new Session(agent, P.mallory.signing, [g]).register(T)).toEqual(refusal('chain-not-to-sender'))
    const bobs = signHop(P.bob.signing, S, [CAVEAT], EXP)
    expect(new Session(agent, P.session.signing, [bobs]).register(T)).toEqual(refusal('not-authorized'))
    expect(new Session(agent, P.session.signing, []).register(T)).toEqual(refusal('not-authorized'))
    expect(new Session(agent, P.jane.signing, []).register(T)).toEqual(refusal('not-authorized'))
    clock.advance(3601)
    expect(new Session(agent, P.session.signing, [g]).register(T)).toEqual(refusal('hop-expired'))
  })

  it('refuses a principal hop that is not a grant of this window not-in-grant, the replay across logout', () => {
    const { agent } = setup()
    const direct = signHop(P.jane.signing, S, [CAVEAT, 'repo=r'], EXP)
    expect(new Session(agent, P.session.signing, [direct]).register(T)).toEqual(refusal('not-in-grant'))
    const g = grant(agent)
    const s = new Session(agent, P.session.signing, [g])
    expect(s.register(T)).toEqual({ ok: true, op: 'register' })
    agent.logout()
    agent.login(JANE_KEYS)
    expect(s.register(T)).toEqual(refusal('not-in-grant'))
    expect(new Session(agent, P.session.signing, [g]).register(T)).toEqual(refusal('not-in-grant'))
  })

  it('judges every request: another session on the connection, then the chain expiring', () => {
    const { agent, clock } = setup()
    const s = session(agent)
    expect(s.register(T)).toEqual({ ok: true, op: 'register' })
    const intruder = buildRequest(P.mallory.signing, s.conn.nonce, 1, 'register', [T])
    expect(agent.handle(s.conn, intruder)).toEqual(refusal('not-authorized'))
    s.seq = 2
    clock.advance(3601)
    expect(s.register(T)).toEqual(refusal('hop-expired'))
  })

  it('takes a later chain in place of the first, and keeps none when that chain fails', () => {
    const { agent } = setup()
    const s = session(agent)
    const renewed = hopOf(s.sign(S, [CAVEAT], EXP + 600))
    expect(s.send('register', [T], { chain: [renewed] })).toEqual({ ok: true, op: 'register' })
    const bobs = signHop(P.bob.signing, S, [CAVEAT], EXP)
    expect(s.send('register', [T], { chain: [bobs] })).toEqual(refusal('not-authorized'))
    expect(s.register(T)).toEqual(refusal('bad-shape'))
  })
})

describe('the one derived hop', () => {
  it('signs exactly the derived hop under the principal, and the hop admits its subject', () => {
    const { agent, sink } = setup()
    const s = session(agent)
    const hop = hopOf(s.sign(B, [CAVEAT, 'repo=r'], EXP - 60))
    expect(hop).toMatchObject({ iss: J, sub: B, caveats: [CAVEAT, 'repo=r'], exp: EXP - 60 })
    expect(verifyChain([hop], B, T0)).toEqual({ root: J, principal: J, caveats: [CAVEAT, 'repo=r'] })
    expect(new Session(agent, P.bob.signing, [hop]).register(T)).toEqual({ ok: true, op: 'register' })
    expect(sink.steps()).toEqual(['sign accept ok', 'sign accept ok'])
    expect(lines(sink)[1]).toMatchObject({ id: hopDigest(hop), from: S, root: J })
  })

  it('refuses in its fixed order with one code each, and audits each refusal', () => {
    const { agent, sink } = setup()
    const s = session(agent)
    const many = Array.from({ length: 33 }, (_, i) => `c${i}`)
    expect(s.sign(B, [''], EXP + 1)).toEqual(refusal('bad-hop'))
    expect(s.sign(B, many, EXP)).toEqual(refusal('too-many-caveats'))
    expect(s.sign(B, [CAVEAT, 'x'.repeat(257)], EXP)).toEqual(refusal('caveat-too-long'))
    expect(s.sign(B, [], EXP)).toEqual(refusal('not-in-grant'))
    expect(s.sign(B, ['repo=r', CAVEAT], EXP)).toEqual(refusal('not-in-grant'))
    expect(s.sign(B, ['type=coding.task.v1'], EXP)).toEqual(refusal('not-in-grant'))
    expect(s.sign(B, [CAVEAT], EXP + 1)).toEqual(refusal('exp-not-monotone'))
    expect(sink.steps().slice(1)).toEqual([
      'sign reject bad-hop',
      'sign reject too-many-caveats',
      'sign reject caveat-too-long',
      'sign reject not-in-grant',
      'sign reject not-in-grant',
      'sign reject not-in-grant',
      'sign reject exp-not-monotone',
    ])
    expect(sink.lines.join('\n')).not.toContain('repo=r')
  })
})

describe('renewals', () => {
  it('renews a first grant silently up to the window end, and a renewal again', () => {
    const { agent } = setup()
    const s = session(agent)
    const renewed = hopOf(s.sign(S, [CAVEAT], EXP + 3600))
    const again = new Session(agent, P.session.signing, [renewed])
    expect(again.sign(S, [CAVEAT, 'repo=r'], T0 + WINDOW_MAX)).toMatchObject({ ok: true, renewal: true })
    expect(again.sign(S, [CAVEAT], T0 + WINDOW_MAX + 1)).toEqual(refusal('exp-not-monotone'))
    expect(again.sign(S, ['repo=r'], EXP)).toEqual(refusal('not-in-grant'))
  })

  it('keeps a first grant renewable when another session signs the same preimage as a derived hop', () => {
    const { agent } = setup()
    const s = session(agent)
    const other = session(agent, P.mallory.signing)
    expect(other.sign(S, [CAVEAT], EXP)).toMatchObject({ ok: true, renewal: false, hop: { sub: S } })
    expect(s.sign(S, [CAVEAT], EXP + 3600)).toMatchObject({ ok: true, renewal: true })
  })

  it('judges anything wider as an ordinary derived hop: another sub, a derived grant, a longer chain', () => {
    const { agent } = setup()
    const g = grant(agent)
    const s = new Session(agent, P.session.signing, [g])
    expect(s.sign(B, [CAVEAT], EXP + 1)).toEqual(refusal('exp-not-monotone'))
    const bob = new Session(agent, P.bob.signing, [hopOf(s.sign(B, [CAVEAT], EXP))])
    expect(bob.sign(B, [CAVEAT], EXP + 1)).toEqual(refusal('exp-not-monotone'))
    const onward: Hop = signHop(P.session.signing, B, ['repo=r'], EXP)
    const long = new Session(agent, P.bob.signing, [g, onward])
    expect(long.sign(B, [CAVEAT, 'repo=r'], EXP + 1)).toEqual(refusal('exp-not-monotone'))
    expect(long.sign(B, [CAVEAT, 'repo=r', 'x=1'], EXP)).toMatchObject({ ok: true, renewal: false })
  })
})

describe('the first grant', () => {
  it("prints the grant and signs it only after a y typed on the agent's terminal", () => {
    const { agent, sink } = setup()
    const pending = agent.prepareGrant({ session: S, caveats: [CAVEAT], exp: EXP })
    if (!pending.ok) throw new Error(pending.code)
    expect(pending.lines[0]).toBe(`grant to session ${S}`)
    expect(sink.lines).toEqual([])
    const reply = agent.confirmGrant(pending, ' y\n')
    expect(reply).toMatchObject({ ok: true, hop: { iss: J, sub: S, caveats: [CAVEAT], exp: EXP } })
    expect(lines(sink)[0]).toMatchObject({ event: 'sign', decision: 'accept', from: null, root: J })
    if (!reply.ok) throw new Error(reply.code)
    const granted = new Session(agent, P.session.signing, [reply.hop])
    expect(granted.register(T)).toEqual({ ok: true, op: 'register' })
  })

  it('declines any other answer with one declined line each, and a pending grant answers once', () => {
    const { agent, sink } = setup()
    for (const answer of ['n', '', 'yes', 'Y', 'y y']) {
      const pending = agent.prepareGrant({ session: S, caveats: [CAVEAT], exp: EXP })
      if (!pending.ok) throw new Error(pending.code)
      expect(agent.confirmGrant(pending, answer)).toEqual({ ok: false, code: 'declined' })
      expect(agent.confirmGrant(pending, 'y')).toEqual(refusal('bad-shape'))
    }
    // The agent logs a refused grant prompt; this line read [] before the build.
    expect(lines(sink).map((l) => l.event)).toEqual(Array(5).fill('declined'))
  })

  it('signs the grant as it was printed, whatever is done to the object after', () => {
    const { agent } = setup()
    const pending = agent.prepareGrant({ session: S, caveats: [CAVEAT], exp: EXP })
    if (!pending.ok) throw new Error(pending.code)
    const caveats = pending.hop.caveats as string[]
    caveats.push('wider')
    expect(agent.confirmGrant(pending, 'y')).toMatchObject({ ok: true, hop: { caveats: [CAVEAT] } })
    const forged = { ok: true as const, hop: { iss: J, sub: S, caveats: [CAVEAT], exp: EXP }, lines: [] }
    expect(agent.confirmGrant(forged, 'y')).toEqual(refusal('bad-shape'))
  })

  it('refuses with no window, no caveat, a bad session or an exp past the window', () => {
    const locked = setup({ login: false }).agent
    expect(locked.prepareGrant({ session: S, caveats: [CAVEAT], exp: EXP })).toEqual(refusal('agent-locked'))
    const { agent, sink } = setup()
    expect(agent.prepareGrant({ session: S, caveats: [], exp: EXP })).toEqual(refusal('bad-shape'))
    expect(agent.prepareGrant({ session: 'x', caveats: [CAVEAT], exp: EXP })).toEqual(refusal('bad-hop'))
    const late = { session: S, caveats: [CAVEAT], exp: T0 + WINDOW_MAX + 1 }
    expect(agent.prepareGrant(late)).toEqual(refusal('exp-not-monotone'))
    expect(sink.lines).toEqual([])
  })

  it('answers only in the window it was checked in', () => {
    const { agent } = setup()
    const first = agent.prepareGrant({ session: S, caveats: [CAVEAT], exp: EXP })
    const second = agent.prepareGrant({ session: S, caveats: [CAVEAT], exp: EXP })
    if (!first.ok || !second.ok) throw new Error('prepareGrant')
    agent.logout()
    expect(agent.confirmGrant(first, 'y')).toEqual(refusal('agent-locked'))
    agent.login(JANE_KEYS)
    expect(agent.confirmGrant(second, 'y')).toEqual(refusal('agent-locked'))
  })
})

describe('the signature cap', () => {
  it('signs 60 a minute per session and refuses the 61st rate-limited until the next minute', () => {
    const { agent, clock } = setup()
    const s = session(agent)
    for (let i = 0; i < SIGNS_PER_MINUTE; i++) expect(s.sign(B, [CAVEAT], EXP).ok).toBe(true)
    expect(s.sign(B, [CAVEAT], EXP)).toEqual(refusal('rate-limited'))
    expect(session(agent, P.mallory.signing).sign(B, [CAVEAT], EXP).ok).toBe(true)
    clock.advance(60)
    expect(s.sign(B, [CAVEAT], EXP).ok).toBe(true)
  })
})

import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { generateEdgeKeys, HomeCustody } from '@usebag/edge'
import { GRANT_ACTS, grantAuditEntry, NOTE_MAX, type RevokeReply } from '@usebag/edge/agent'
import { afterEach, describe, expect, it } from 'vitest'
import { ConfigError } from '../src/config.ts'
import {
  AGAIN_DIALOG,
  AGAIN_TYPED,
  type Audit,
  againFor,
  GrantSlot,
  holdFile,
  hostKindOf,
  type IntentOutcome,
  intentsPath,
  NOT_SENT,
  narrows,
  RENEW_MARGIN_S,
  type RevokeIntent,
  readIntents,
  regrantLine,
  regrantNote,
  renewDue,
  retireUnitKey,
  revokeIntent,
  SlotKeeper,
  type SlotPorts,
  sendIntents,
  withNotSent,
} from '../src/regrant.ts'
import { seededRng, tempDir } from './support/ports.ts'

// Regrant in place, the rules module (packages/mcp/src/regrant.ts), against a fake agent and a fake clock, at the
// module's level; the service's own cases (a restart, a unit reopened under a fresh key) are in
// service-agent-regrant.test.ts.

interface G {
  readonly iss: string
  readonly sub: string
  readonly caveats: readonly string[]
  readonly exp: number
}

const ISS = 'ed25519:jane'
const grant = (sub: string, exp: number): G => ({ iss: ISS, sub, caveats: CAVEATS, exp })

const CAVEATS = ['type=chat.v1']
const START = 1_800_000_000

class Rig {
  now = START
  renews = 0
  grants = 0
  keys = 0
  renewAnswer: (g: G) => Promise<G> = async (g) => ({ ...g, exp: this.now + 3600 })
  grantAnswer: () => Promise<G> = async () => grant(this.fresh(), this.now + 3600)
  codes = 0
  events: Array<[string, object]> = []
  held = false

  fresh(): string {
    this.keys += 1
    return `key-${this.keys}`
  }

  ports(hold = true): SlotPorts<G> {
    const audit: Audit = (e, f) => this.events.push([e, f])
    return {
      now: () => this.now,
      renew: (g) => {
        this.renews += 1
        return this.renewAnswer(g)
      },
      regrant: (onCode) => {
        this.grants += 1
        this.codes += 1
        onCode(`code-${this.codes}`)
        return this.grantAnswer()
      },
      windowEnd: () => this.now + 8 * 3600,
      audit,
      ...(hold ? { hold: { get: () => this.held, set: (on: boolean) => (this.held = on) } } : {}),
      words: (code) => regrantLine({ label: 'jane', host: 'omp', connection: 'c1', code }),
    }
  }

  slot(exp = START + 3600, hold = true): GrantSlot<G> {
    return new GrantSlot<G>(grant(this.fresh(), exp), this.ports(hold))
  }
}

const codeOf = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p
    return 'ok'
  } catch (e) {
    return (e as ConfigError).code
  }
}

const settle = (): Promise<void> => new Promise((r) => setImmediate(r))

describe('renewal rules', () => {
  it('renews only under the margin and before exp', () => {
    expect(renewDue(START + RENEW_MARGIN_S + 1, START)).toBe(false)
    expect(renewDue(START + RENEW_MARGIN_S - 1, START)).toBe(true)
    expect(renewDue(START, START)).toBe(false)
  })

  it('a renewal keeps or narrows and never passes the window', () => {
    const old = grant('ed25519:s1', START + 100)
    expect(narrows(old, { ...old, caveats: [...CAVEATS, 'to=x'], exp: START + 200 }, START + 300)).toBe(true)
    expect(narrows(old, { ...old, caveats: ['type=any'], exp: START + 200 }, null)).toBe(false)
    expect(narrows(old, { ...old, exp: START + 400 }, START + 300)).toBe(false)
    expect(narrows(old, { ...old, exp: START + 100 }, null)).toBe(false)
    // An answer for another key, or from another issuer, is never a renewal of this one
    expect(narrows(old, { ...old, sub: 'ed25519:s2', exp: START + 200 }, null)).toBe(false)
    expect(narrows(old, { ...old, iss: 'ed25519:john', exp: START + 200 }, null)).toBe(false)
  })
})

describe('GrantSlot', () => {
  it('a silent renewal at the margin keeps the key and asks no y', async () => {
    const r = new Rig()
    const s = r.slot(START + 300)
    const before = s.current.sub
    const g = await s.forAct()
    expect(r.renews).toBe(1)
    expect(r.grants).toBe(0)
    expect(g.sub).toBe(before)
    expect(g.exp).toBe(START + 3600)
    expect(r.events.map(([e]) => e)).toEqual(['grant-renewed'])
  })

  it('a wider renewal is never taken; the live grant stands to its exp and nothing is asked', async () => {
    const r = new Rig()
    r.renewAnswer = async (g) => ({ ...g, caveats: ['type=any'], exp: r.now + 3600 })
    const s = r.slot(START + 300)
    expect((await s.forAct()).caveats).toEqual(CAVEATS)
    expect([r.renews, r.grants]).toEqual([1, 0])
  })

  it('two acts under the margin make one renewal', async () => {
    const r = new Rig()
    let release: () => void = () => {}
    r.renewAnswer = (g) => new Promise((done) => (release = () => done({ ...g, exp: r.now + 3600 })))
    const s = r.slot(START + 300)
    const a = s.forAct()
    const b = s.forAct()
    release()
    const [ga, gb] = await Promise.all([a, b])
    expect(r.renews).toBe(1)
    expect(ga).toBe(gb)
    await s.forAct()
    expect(r.renews).toBe(1)
  })

  it('the window ended: grant-pending with the code, one fresh key, the next act signs under it', async () => {
    const r = new Rig()
    r.renewAnswer = async () => {
      throw new ConfigError('revoked', 'logged out')
    }
    const s = r.slot(START + 300)
    const old = s.current.sub
    const e = await s.forAct().catch((x: ConfigError) => x)
    expect((e as ConfigError).code).toBe('grant-pending')
    expect((e as ConfigError).message).toContain('code-1')
    await settle()
    const g = await s.forAct()
    expect(r.grants).toBe(1)
    expect(g.sub).not.toBe(old)
    expect(r.events.map(([ev]) => ev)).toEqual(['regrant-asked', 'regrant-granted'])
  })

  it('an act holding the old grant fails after the swap, never re-signs', async () => {
    const r = new Rig()
    const s = r.slot(START + 10)
    const held = s.current
    r.now = START + 20 // past exp
    expect(await codeOf(s.forAct())).toBe('grant-pending')
    await settle()
    expect(() => s.assertCurrent(held)).toThrow(/grant-replaced/)
    expect(() => s.assertCurrent(s.current)).not.toThrow()
  })

  it('the words name the label, the host, the window and "after the grant ended", with the code', () => {
    const line = regrantLine({ label: 'jane', host: 'omp', connection: 'c1', code: 'code-7' })
    for (const w of ['jane', 'omp', 'window c1', 'after the grant ended', 'request code-7'])
      expect(line).toContain(w)
    // a refused send never reads as sent, and the agent's note has no such words
    expect(
      line.endsWith('request code-7; nothing was sent: once your user answers y at the agent, send it again'),
    ).toBe(true)
    expect(regrantNote({ label: 'jane', host: 'omp' })).not.toContain('nothing was sent')
  })

  it('the words that say nothing was sent end either answer exactly once', () => {
    const count = (t: string) => t.split('nothing was sent').length - 1
    // the unit's two answers: the session's waiting line, and the regrant line when no session waits
    const waitingLine = withNotSent('jane: waiting for the agent of ed25519:aa')
    const unitLine = withNotSent(
      regrantLine({ label: 'jane', host: 'service', connection: 'unit', code: null }),
    )
    for (const t of [waitingLine, unitLine, withNotSent(waitingLine)]) {
      expect(count(t)).toBe(1)
      expect(t.endsWith(NOT_SENT)).toBe(true)
    }
  })

  it('declined holds: tool calls ask nothing more', async () => {
    const r = new Rig()
    r.grantAnswer = async () => {
      throw new ConfigError('declined', 'n')
    }
    const s = r.slot(START + 10)
    r.now = START + 20
    expect(await codeOf(s.forAct())).toBe('grant-pending')
    await settle()
    for (let i = 0; i < 10; i++) expect(await codeOf(s.forAct())).toBe('declined')
    expect(r.grants).toBe(1)
    expect(r.held).toBe(true)
  })

  it('declined holds in memory with no hold file too', async () => {
    const r = new Rig()
    r.grantAnswer = async () => {
      throw new ConfigError('declined', 'n')
    }
    const s = r.slot(START + 10, false)
    r.now = START + 20
    await codeOf(s.forAct())
    await settle()
    for (let i = 0; i < 5; i++) expect(await codeOf(s.forAct())).toBe('declined')
    expect(r.grants).toBe(1)
  })

  it('only the person channel resets the hold, and it asks once', async () => {
    const r = new Rig()
    r.held = true
    const s = r.slot(START + 10)
    r.now = START + 20 // past exp: the act must ask, and the hold refuses it
    expect(await codeOf(s.forAct())).toBe('declined')
    expect(() => s.person('tool' as 'use')).toThrow(/not-authorized/)
    expect(r.held).toBe(true)
    const g = await s.person('use')
    expect(r.grants).toBe(1)
    expect(r.held).toBe(false)
    expect(g.sub).toBe('key-2')
  })

  it('one slot regranting leaves another alone', async () => {
    const r = new Rig()
    const a = r.slot(START + 10)
    const b = r.slot(START + 3600)
    const bKey = b.current.sub
    r.now = START + 20
    await codeOf(a.forAct())
    await settle()
    expect((await b.forAct()).sub).toBe(bKey)
    expect(r.grants).toBe(1)
  })

  it('a background failure marks lost and asks nothing', async () => {
    const r = new Rig()
    const s = r.slot()
    s.markLost('hop-expired')
    r.now += 600
    await settle()
    expect(r.grants).toBe(0)
  })

  it('the first act after lost asks once; a second act gets the same code', async () => {
    const r = new Rig()
    let release: () => void = () => {}
    r.grantAnswer = () => new Promise((done) => (release = () => done(grant(r.fresh(), r.now + 3600))))
    const s = r.slot()
    s.markLost('revoked')
    const first = await s.forAct().catch((x: ConfigError) => x)
    const second = await s.forAct().catch((x: ConfigError) => x)
    expect([(first as ConfigError).code, (second as ConfigError).code]).toEqual([
      'grant-pending',
      'grant-pending',
    ])
    expect((second as ConfigError).message).toContain('code-1')
    expect(r.grants).toBe(1)
    release()
    await settle()
    expect((await s.forAct()).sub).toBe('key-2')
  })

  it('one refused renewal under two waiting acts makes one request', async () => {
    const r = new Rig()
    let refuse: () => void = () => {}
    r.renewAnswer = () => new Promise((_, no) => (refuse = () => no(new ConfigError('revoked', 'ended'))))
    const s = r.slot(START + 300)
    const a = s.forAct()
    const b = s.forAct()
    refuse()
    expect([await codeOf(a), await codeOf(b)]).toEqual(['grant-pending', 'grant-pending'])
    expect(r.grants).toBe(1)
  })

  it('the hold stops only asking: a live grant keeps signing and renews silently', async () => {
    const r = new Rig()
    r.held = true
    const s = r.slot(START + 3600)
    expect((await s.forAct()).sub).toBe('key-1')
    r.now = START + 3300 // under the margin: a silent renewal, still no y
    expect((await s.forAct()).exp).toBe(START + 3300 + 3600)
    expect([r.renews, r.grants]).toEqual([1, 0])
  })

  it('a typed use on a live slot asks nothing', async () => {
    const r = new Rig()
    const s = r.slot(START + 3600)
    expect((await s.person('use')).sub).toBe('key-1')
    expect(r.grants).toBe(0)
  })

  it('no audit line carries more than addresses, exps, codes and reasons', async () => {
    const r = new Rig()
    r.renewAnswer = async () => {
      throw new ConfigError('revoked', 'ended')
    }
    const s = r.slot(START + 300)
    await codeOf(s.forAct())
    await settle()
    expect(r.events.map(([e]) => e)).toEqual(['regrant-asked', 'regrant-granted'])
    for (const [, f] of r.events)
      for (const v of Object.values(f)) expect(['string', 'number']).toContain(typeof v)
    expect(r.events[1]?.[1]).toEqual({ from: 'key-1', to: 'key-2', exp: START + 3600 })
  })

  it('a renewal answered for another key is never taken; the live grant stands', async () => {
    const r = new Rig()
    r.renewAnswer = async (g) => ({ ...g, sub: 'ed25519:other', exp: r.now + 3600 })
    const s = r.slot(START + 300)
    expect((await s.forAct()).sub).toBe('key-1')
    expect([r.renews, r.grants]).toEqual([1, 0])
  })

  it('T7b: a refused new grant (agent-locked) is never asked again by itself; the next act asks', async () => {
    const r = new Rig()
    r.grantAnswer = async () => {
      throw new ConfigError('agent-locked', 'no window')
    }
    const s = r.slot(START + 10)
    r.now = START + 20
    expect(await codeOf(s.forAct())).toBe('grant-pending')
    for (let i = 0; i < 5; i++) await settle()
    expect(r.grants).toBe(1)
    expect(await codeOf(s.forAct())).toBe('grant-pending')
    expect(r.grants).toBe(2)
  })

  it('a renewal that keeps the exp (the window end) keeps the grant, asks nothing and is not tried again', async () => {
    const r = new Rig()
    r.renewAnswer = async (g) => g
    const s = r.slot(START + 300)
    expect((await s.forAct()).sub).toBe('key-1')
    expect((await s.forAct()).sub).toBe('key-1')
    expect([r.renews, r.grants]).toEqual([1, 0])
    r.now = START + 400 // past exp: then, and only then, a new grant is asked
    expect(await codeOf(s.forAct())).toBe('grant-pending')
    expect(r.grants).toBe(1)
  })

  it('a renewal with an earlier exp (the window end near) keeps the grant to its exp and asks nothing', async () => {
    const r = new Rig()
    r.renewAnswer = async (g) => ({ ...g, exp: g.exp - 100 })
    const s = r.slot(START + 300)
    expect((await s.forAct()).exp).toBe(START + 300)
    expect([r.renews, r.grants]).toEqual([1, 0])
  })

  it('a refusal that ends nothing (rate-limited) leaves the live grant signing', async () => {
    const r = new Rig()
    r.renewAnswer = async () => {
      throw new ConfigError('rate-limited', 'too soon')
    }
    const s = r.slot(START + 300)
    expect((await s.forAct()).sub).toBe('key-1')
    expect(r.grants).toBe(0)
  })

  it('a drain cancels: no request asked after it', async () => {
    const r = new Rig()
    const s = r.slot(START + 10)
    s.cancel()
    r.now = START + 20
    expect(await codeOf(s.forAct())).toBe('draining')
    expect(r.grants).toBe(0)
  })
})

describe('the files', () => {
  let t: { dir: string; cleanup(): void } | null = null
  afterEach(() => {
    t?.cleanup()
    t = null
  })

  it('the declined hold survives a new reader (a reconnect or a restart), 0600 under run/', () => {
    t = tempDir('regrant-hold-')
    holdFile(t.dir, 'jane').set(true)
    holdFile(t.dir, 'john').set(true)
    expect(holdFile(t.dir, 'jane').get()).toBe(true)
    const file = join(t.dir, 'run', 'regrant-holds.json')
    expect(statSync(file).mode & 0o777).toBe(0o600)
    holdFile(t.dir, 'jane').set(false)
    expect(holdFile(t.dir, 'jane').get()).toBe(false)
    expect(holdFile(t.dir, 'john').get()).toBe(true)
  })

  it('the old marked unit key is deleted, not moved, and its address returned for the revoke', () => {
    t = tempDir('regrant-key-')
    const custody = new HomeCustody(t.dir)
    const address = custody.create('jane.service', generateEdgeKeys(seededRng('regrant')), {
      custody: 'file',
    }).address
    const file = join(t.dir, 'keys', 'jane.service.json')
    writeFileSync(
      file,
      JSON.stringify({ ...JSON.parse(readFileSync(file, 'utf8')), kind: 'session-key', principal: 'jane' }),
    )
    expect(retireUnitKey(t.dir, 'jane.service', { principal: 'jane', address })).toEqual({
      deleted: true,
      revoke: address,
    })
    expect(existsSync(file)).toBe(false)
    expect(existsSync(join(t.dir, 'run', '.gone'))).toBe(false)
  })

  it('a key that is not the marked session key at that address is left', () => {
    t = tempDir('regrant-key-')
    const custody = new HomeCustody(t.dir)
    const address = custody.create('jane.service', generateEdgeKeys(seededRng('regrant-2')), {
      custody: 'file',
    }).address
    const file = join(t.dir, 'keys', 'jane.service.json')
    expect(retireUnitKey(t.dir, 'jane.service', { principal: 'jane', address }).deleted).toBe(false)
    writeFileSync(
      file,
      JSON.stringify({ ...JSON.parse(readFileSync(file, 'utf8')), kind: 'session-key', principal: 'jane' }),
    )
    expect(
      retireUnitKey(t.dir, 'jane.service', { principal: 'jane', address: 'ed25519:other' }).deleted,
    ).toBe(false)
    expect(existsSync(file)).toBe(true)
  })
})

/** Timers in the rig's time: `to(t)` runs each timer due by t in order, the clock moved to it. */
class Timeline {
  readonly q: { at: number; fn: () => void; off: boolean }[] = []
  readonly r: Rig
  constructor(r: Rig) {
    this.r = r
  }

  after(ms: number, fn: () => void): () => void {
    const t = { at: this.r.now + ms / 1000, fn, off: false }
    this.q.push(t)
    return () => {
      t.off = true
    }
  }

  live(): number[] {
    return this.q.filter((t) => !t.off).map((t) => t.at)
  }

  async to(at: number): Promise<void> {
    for (;;) {
      const next = this.q.filter((t) => !t.off && t.at <= at).sort((x, y) => x.at - y.at)[0]
      if (next === undefined) break
      next.off = true
      this.r.now = Math.max(this.r.now, next.at)
      next.fn()
      await settle()
      await settle()
    }
    this.r.now = Math.max(this.r.now, at)
  }
}

function kept(r: Rig, exp = START + 3600) {
  const s = r.slot(exp)
  const tl = new Timeline(r)
  const hold = { on: false }
  const k = new SlotKeeper(s, { now: () => r.now, timers: tl, held: () => hold.on })
  k.start()
  return { s, tl, hold, k }
}

describe('SlotKeeper: a window grant renewed while bound', () => {
  it('an idle window across its exp sends with no y: one silent renewal before each exp', async () => {
    const r = new Rig()
    const { s, tl } = kept(r)
    await tl.to(START + 3 * 3600)
    expect(r.grants).toBe(0)
    expect(r.renews).toBeGreaterThanOrEqual(3)
    expect(s.current.exp).toBeGreaterThan(r.now)
    const g = await s.forAct()
    expect(r.grants).toBe(0)
    expect(g).toBe(s.current)
    // each renewal ran inside the margin, never earlier
    expect(r.events.filter(([e]) => e === 'grant-renewed')).toHaveLength(r.renews)
  })

  it('pauses while the identity is held, and makes one attempt at once at the give-back', async () => {
    const r = new Rig()
    const { s, tl, hold, k } = kept(r)
    hold.on = true
    await tl.to(START + 3500)
    expect([r.renews, k.paused]).toEqual([0, true])
    hold.on = false
    k.resume()
    await settle()
    expect(r.renews).toBe(1)
    expect(s.current.exp).toBe(START + 3500 + 3600)
    expect(k.paused).toBe(false)
  })

  it('a grant that lapsed in a long hold is not asked by the keeper; the next act asks its y', async () => {
    const r = new Rig()
    const { s, tl, hold, k } = kept(r)
    hold.on = true
    await tl.to(START + 4000)
    hold.on = false
    k.resume()
    await settle()
    expect([r.renews, r.grants]).toEqual([0, 0])
    expect(tl.live()).toEqual([])
    expect(await codeOf(s.forAct())).toBe('grant-pending')
    expect(r.grants).toBe(1)
  })

  it('stops at the unbind or the close (the slot cancelled) and at the drain (stop)', async () => {
    for (const end of ['cancel', 'stop'] as const) {
      const r = new Rig()
      const { s, tl, k } = kept(r)
      if (end === 'cancel') s.cancel()
      else k.stop()
      expect(k.stopped).toBe(true)
      expect(tl.live()).toEqual([])
      k.resume()
      await tl.to(START + 2 * 3600)
      expect([r.renews, r.grants]).toEqual([0, 0])
    }
  })

  it('a failed renewal keeps the live grant to its exp, asks nothing and is not tried again', async () => {
    const r = new Rig()
    r.renewAnswer = async () => {
      throw new ConfigError('rate-limited', 'later')
    }
    const { s, tl } = kept(r)
    await tl.to(START + 3599)
    expect([r.renews, r.grants]).toEqual([1, 0])
    expect(tl.live()).toEqual([])
    expect((await s.forAct()).exp).toBe(START + 3600)
  })
})

describe('the grant note and the grant lines', () => {
  it('the note names the label, the host kind and the reason, and nothing else', () => {
    expect(regrantNote({ label: 'jane', host: hostKindOf('omp') })).toBe(
      'jane in omp asks for a new grant after the grant ended',
    )
    expect(regrantNote({ label: 'jane', host: hostKindOf('/Users/x/repo; rm -rf') })).toBe(
      'jane in other asks for a new grant after the grant ended',
    )
    expect(regrantNote({ label: 'jane', host: 'service' })).toContain('in the bag service asks')
    const long = regrantNote({ label: 'j'.repeat(400), host: 'codex' })
    expect(long.length).toBe(NOTE_MAX)
    expect(long.endsWith('after the grant ended')).toBe(true)
  })

  it('four lines, each once per grant: a policy entry of labels, subjects, exp and a code', async () => {
    const r = new Rig()
    const s = r.slot(START + 300)
    await s.forAct() // renewed
    r.renewAnswer = async () => {
      throw new ConfigError('revoked', 'ended')
    }
    r.now = START + 3600 - 100
    expect(await codeOf(s.forAct())).toBe('grant-pending')
    await settle()
    await s.forAct()
    const s2 = r.slot(START + 10)
    r.grantAnswer = async () => {
      throw new ConfigError('declined', 'no')
    }
    r.now = START + 3600 + 20
    expect(await codeOf(s2.forAct())).toBe('grant-pending')
    await settle()
    const acts = r.events.map(([e]) => e)
    for (const act of GRANT_ACTS)
      expect(acts.filter((e) => e === act)).toHaveLength(act === 'regrant-asked' ? 2 : 1)
    for (const [act, f] of r.events) {
      const e = grantAuditEntry(act as (typeof GRANT_ACTS)[number], { ...f, label: 'jane' })
      expect(e.event).toBe('policy')
      for (const k of Object.keys(e.detail ?? {}))
        expect(['step', 'act', 'label', 'from', 'to', 'exp', 'code']).toContain(k)
    }
  })
})

describe('the revoke intents', () => {
  let t: { dir: string; cleanup(): void } | null = null
  afterEach(() => {
    t?.cleanup()
    t = null
  })

  function seed(intents: RevokeIntent[]): string {
    t = tempDir('regrant-intents-')
    mkdirSync(join(t.dir, 'run'), { mode: 0o700 })
    writeFileSync(intentsPath(t.dir), JSON.stringify({ v: 1, intents }), { mode: 0o600 })
    return t.dir
  }

  function agent(answer: (session: string) => RevokeReply | Error) {
    const sent: string[] = []
    return {
      sent,
      connect: () => ({
        revoke: async (session: string) => {
          sent.push(session)
          const a = answer(session)
          if (a instanceof Error) throw a
          return a
        },
        close: () => {},
      }),
    }
  }

  async function send(home: string, a: ReturnType<typeof agent>, now = START) {
    const outcomes: [string, IntentOutcome][] = []
    const refused: string[] = []
    await sendIntents(home, {
      now,
      connect: a.connect,
      outcome: (i, what) => outcomes.push([i.address, what]),
      refused: (why) => refused.push(why),
    })
    return { outcomes, refused }
  }

  it('an intent is sent once and dropped on ok', async () => {
    const home = seed([{ address: 'ed25519:old', at: START, label: 'jane', exp: START + 600 }])
    const a = agent(() => ({ ok: true, op: 'revoke', grants: 1 }))
    expect((await send(home, a)).outcomes).toEqual([['ed25519:old', 'revoked']])
    expect(readIntents(home)).toEqual([])
    await send(home, a)
    expect(a.sent).toEqual(['ed25519:old'])
  })

  it('kept with its reason on bad-shape or agent-locked, kept as it is when no agent answers', async () => {
    const home = seed([
      { address: 'ed25519:a', at: START, exp: START + 600 },
      { address: 'ed25519:b', at: START, exp: START + 600 },
      { address: 'ed25519:c', at: START, exp: START + 600 },
    ])
    const a = agent((s) =>
      s === 'ed25519:a'
        ? { ok: false, code: 'bad-shape' }
        : s === 'ed25519:b'
          ? { ok: false, code: 'agent-locked' }
          : new Error('agent: the socket closed'),
    )
    await send(home, a)
    expect(readIntents(home)).toEqual([
      { address: 'ed25519:a', at: START, exp: START + 600, reason: 'bad-shape' },
      { address: 'ed25519:b', at: START, exp: START + 600, reason: 'agent-locked' },
      { address: 'ed25519:c', at: START, exp: START + 600 },
    ])
  })

  it('pruned past its exp, never sent, and reported once as pruned', async () => {
    const home = seed([
      { address: 'ed25519:gone', at: START, exp: START + 600, reason: 'bad-shape' },
      { address: 'ed25519:old', at: START - 9 * 3600 },
    ])
    const a = agent(() => ({ ok: true, op: 'revoke', grants: 0 }))
    const { outcomes } = await send(home, a, START + 601)
    expect(outcomes).toEqual([
      ['ed25519:gone', 'pruned'],
      ['ed25519:old', 'pruned'],
    ])
    expect(a.sent).toEqual([])
    expect(readIntents(home)).toEqual([])
  })

  it('a revoke-intents.json that is a link or 0644 is refused: nothing read, sent or written', async () => {
    const home = seed([{ address: 'ed25519:x', at: START }])
    chmodSync(intentsPath(home), 0o644)
    const a = agent(() => ({ ok: true, op: 'revoke', grants: 1 }))
    expect((await send(home, a)).refused).toEqual([
      'run/revoke-intents.json is not a 0600 regular file of this user',
    ])
    expect(revokeIntent(home, 'ed25519:y', START)).toBe(false)
    expect(statSync(intentsPath(home)).mode & 0o777).toBe(0o644)
    expect(a.sent).toEqual([])
  })

  it('a revoke-intents.json that is a link to a 0600 file of intents is refused the same way', async () => {
    t = tempDir('regrant-intents-')
    const home = t.dir
    mkdirSync(join(home, 'run'), { mode: 0o700 })
    const other = join(home, 'elsewhere.json')
    writeFileSync(other, JSON.stringify({ v: 1, intents: [{ address: 'ed25519:z', at: START }] }), {
      mode: 0o600,
    })
    symlinkSync(other, intentsPath(home))
    const a = agent(() => ({ ok: true, op: 'revoke', grants: 1 }))
    expect((await send(home, a)).refused).toEqual([
      'run/revoke-intents.json is not a 0600 regular file of this user',
    ])
    expect(a.sent).toEqual([])
    expect(readIntents(home)).toEqual([])
    expect(readFileSync(other, 'utf8')).toContain('ed25519:z')
  })

  it('revokeIntent keeps the label and the exp beside the address (0600)', () => {
    t = tempDir('regrant-intents-')
    expect(revokeIntent(t.dir, 'ed25519:old', START, { label: 'jane', exp: START + 900 })).toBe(true)
    expect(readIntents(t.dir)).toEqual([
      { address: 'ed25519:old', at: START, label: 'jane', exp: START + 900 },
    ])
    expect(statSync(intentsPath(t.dir)).mode & 0o777).toBe(0o600)
    expect(JSON.parse(readFileSync(intentsPath(t.dir), 'utf8')).v).toBe(1)
  })
})

describe('what a declined grant tells the person to do, by the window it serves', () => {
  /** A slot whose grant was declined, with `again` as the service gives it for a window of that host. */
  const declined = async (typed: boolean): Promise<string[]> => {
    const r = new Rig()
    r.grantAnswer = async () => {
      throw new ConfigError('declined', 'n')
    }
    const s = new GrantSlot<G>(grant(r.fresh(), START + 10), { ...r.ports(), again: againFor(typed) })
    r.now = START + 20
    await codeOf(s.forAct())
    await settle()
    const said = await s.forAct().then(
      () => 'ok',
      (e: unknown) => String((e as Error).message),
    )
    let guard = ''
    try {
      s.person('tool' as 'use')
    } catch (e) {
      guard = String((e as Error).message)
    }
    return [said, guard]
  }

  it('with an input hook (Claude Code, omp): type use and the name', async () => {
    expect(await declined(true)).toEqual([
      `declined: the agent said no to a new grant: ${AGAIN_TYPED} to ask again`,
      `not-authorized: only the person resets a declined grant: ${AGAIN_TYPED}`,
    ])
    expect(AGAIN_TYPED).toBe('type use and the name')
  })

  it('with none (Codex, opencode): the bind dialog, and never the typed use', async () => {
    const said = await declined(false)
    expect(said).toEqual([
      `declined: the agent said no to a new grant: ${AGAIN_DIALOG} to ask again`,
      `not-authorized: only the person resets a declined grant: ${AGAIN_DIALOG}`,
    ])
    expect(AGAIN_DIALOG).toBe('answer Yes in the bind dialog (the use tool opens it)')
    for (const line of said) for (const typed of ['type use', 'typing use']) expect(line).not.toContain(typed)
  })
})

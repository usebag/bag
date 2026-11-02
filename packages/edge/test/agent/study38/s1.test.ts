import { existsSync } from 'node:fs'
import { join } from 'node:path'
import type { BuiltEnvelope, Hop } from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { addressRecord, P, T0, tempDir } from '../../support/fixtures.ts'
import { envelope, JANE_KEYS, text, threadId } from '../support.ts'
import { S1_GRANT, S1_REGISTERED, S1_REQUESTS, S1_UNREGISTERED, type S1Request } from './requests-s1.ts'
import {
  type Booted,
  boot,
  closeAll,
  codes,
  Driver,
  gone,
  granted,
  measure,
  type Outcome,
  SessionWire,
  Wire,
} from './support-a.ts'

// S1, a stolen session opens only its grant: a client holding the session's key and
// chain sends the pre-registered 100 (requests-s1.ts) (a) in the window, (b) after `ac logout`, (c) after the window's
// end, (d) after SIGHUP of the agent's terminal, (e) after the agent process dies, and after a re-login on the same
// keys. Counted per request: the code, and the content bytes that left the agent. Pass: 0 content bytes released
// outside the read rule in (a); 0 requests served in (b) to (e) and in the re-login arm.

const tmp = tempDir('s38-s1')
afterAll(() => tmp.cleanup())
afterEach(closeAll)
let homes = 0
const home = (): string => join(tmp.dir, `h${homes++}`)

const J = P.jane.address
const S = P.session.address
const EXP1 = T0 + S1_GRANT.expAfterT0
const NAMES = {
  bob: P.bob.address,
  carol: P.carol.address,
  mallory: P.mallory.address,
  other: P.other.address,
  org: P.org.address,
} as const
const REGISTERED = Array.from({ length: S1_REGISTERED }, (_, k) => threadId(0x5100 + k))
const UNREGISTERED = Array.from({ length: S1_UNREGISTERED }, (_, k) => threadId(0x5200 + k))

/** The mailbox: one envelope to jane from bob for each open of the set, built once with the core's builders. */
const MAIL = new Map<number, BuiltEnvelope>()
for (const r of S1_REQUESTS) {
  if (r.op !== 'open') continue
  const id =
    r.thread.set === 'new'
      ? threadId(0x5000 + r.n)
      : ((r.thread.set === 'registered' ? REGISTERED : UNREGISTERED)[r.thread.k] as string)
  MAIL.set(r.n, envelope({ type: r.type, thread: { id, prev: r.reply ? [threadId(0x5300 + r.n)] : [] } }))
}

function send(d: Driver, r: S1Request): Promise<Outcome> {
  if (r.op === 'sign')
    return d.request('sign', [NAMES[r.sub], [...S1_GRANT.caveats, ...r.append], EXP1 + r.past])
  const env = MAIL.get(r.n) as BuiltEnvelope
  return d.request('open', [J, env.envelope.id], { envelope: text(env) })
}

async function sendAll(d: Driver): Promise<Outcome[]> {
  const out: Outcome[] = []
  for (const r of S1_REQUESTS) out.push(await send(d, r))
  return out
}

interface Window {
  readonly m: Booted
  readonly first: Hop
  /** The stolen session's connection, opened and used in the window. */
  readonly open: SessionWire
}

/** The window as the session lived it: a first grant, its threads registered, one connection in use. */
async function lived(): Promise<Window> {
  const m = await boot({ home: home(), answers: ['y'] })
  m.records.set('address', addressRecord(P.jane))
  const first = await granted(m, S, S1_GRANT.caveats, EXP1)
  const open = await SessionWire.open(m.path, P.session.signing, [first])
  for (const t of REGISTERED) expect((await open.request('register', [t]))?.ok).toBe(true)
  return { m, first, open }
}

/** The connections the last run opened beyond the session's own. */
let connections = 0

/** The thief's run of the 100 with the session's key file and chain, starting on the session's own connection. */
async function stolen(w: Window): Promise<Outcome[]> {
  const d = new Driver(w.m.path, P.session.signing, [w.first])
  d.adopt(w.open)
  const out = await sendAll(d)
  connections = d.opened.length
  return out
}

function after(arm: string, out: readonly Outcome[]): void {
  const served = out.filter((o) => o.served).length
  const bytes = out.reduce((n, o) => n + o.bytes + o.leak, 0)
  const locked = out.every(
    (o) => o.code === 'agent-locked' || o.code.startsWith('refused-') || o.code === 'closed',
  )
  measure(
    'S1',
    arm,
    `${out.length} requests; served ${served}; content bytes released ${bytes}; codes ${codes(out)}; ` +
      `predicted (each agent-locked or a refused connection) met: ${locked ? 'yes' : 'no'}`,
  )
  expect(out).toHaveLength(100)
  expect(served).toBe(0)
  expect(bytes).toBe(0)
}

describe('S1: a stolen session opens only its grant', () => {
  it('V3: the request set holds 100, of the four kinds', () => {
    const kinds = codes(S1_REQUESTS.map((r) => ({ code: r.kind })))
    measure('S1', 'set', `${S1_REQUESTS.length} requests: ${kinds}`)
    expect(S1_REQUESTS).toHaveLength(100)
  })

  it('(a) in the window: exactly what the read rule and the caveats say, nothing else opened', async () => {
    const w = await lived()
    const out = await stolen(w)
    const lines = w.m.sink.lines.map((l) => JSON.parse(l) as { event: string; id: string; detail: string })
    const ruleOf = (id: string): string | undefined => {
      const line = lines.find((l) => l.event === 'open' && l.id === id)
      return line === undefined ? undefined : (JSON.parse(line.detail) as { rule?: string }).rule
    }
    let outside = 0
    let inside = 0
    let asPredicted = 0
    const by = new Map<string, Outcome[]>()
    S1_REQUESTS.forEach((r, i) => {
      const o = out[i] as Outcome
      by.set(r.expect, [...(by.get(r.expect) ?? []), o])
      if (r.expect === 'release-root' || r.expect === 'release-thread') {
        inside += o.bytes
        const env = MAIL.get(r.n) as BuiltEnvelope
        const rule = r.expect === 'release-root' ? 'root' : 'thread'
        const content = o.reply?.content as { type?: unknown } | undefined
        if (o.served && content?.type === r.type && ruleOf(env.envelope.id) === rule) asPredicted++
        outside += o.leak
      } else {
        outside += o.bytes + o.leak + (o.served ? 1 : 0)
        const code = r.expect === 'withhold' ? 'not-in-grant' : 'exp-not-monotone'
        if (!o.served && o.code === code) asPredicted++
      }
    })
    for (const [kind, os] of by) {
      measure(
        'S1',
        `a ${kind}`,
        `${os.length} requests; served ${os.filter((o) => o.served).length}; codes ${codes(os)}`,
      )
    }
    measure(
      'S1',
      'a',
      `100 requests in the window; content bytes released under the read rule ${inside}; bytes or signatures ` +
        `released outside it ${outside}; requests exactly as predicted (released by the predicted limb, or ` +
        `refused with the predicted code) ${asPredicted} of 100; new connections after refusals ${connections}`,
    )
    expect(outside).toBe(0)
  })

  it('(b) after ac logout: 0 of 100 served', async () => {
    const w = await lived()
    const plain = new Wire(w.m.path)
    await plain.next()
    const r = await plain.ask('{"op":"logout"}')
    measure(
      'S1',
      'b logout',
      `the logout frame answered ok ${r?.ok === true}; socket gone ${await gone(w.m.path)}`,
    )
    after('b', await stolen(w))
  })

  it("(c) after the window's end on the fake clock: 0 of 100 served", async () => {
    const w = await lived()
    w.m.clock.t = w.m.agent.windowEnd() as number
    w.m.timers.fn?.()
    measure(
      'S1',
      'c end',
      `the timer fired; zeroed ${w.m.zeroed.n}; the agent still listens ${existsSync(w.m.path)}`,
    )
    after('c', await stolen(w))
  })

  it("(d) after SIGHUP of the agent's terminal: 0 of 100 served", async () => {
    const w = await lived()
    w.m.signals.emit('SIGHUP')
    measure('S1', 'd hangup', `socket gone ${await gone(w.m.path)}`)
    after('d', await stolen(w))
  })

  it('(e) after the agent process dies: 0 of 100 served', async () => {
    const w = await lived()
    await w.m.server.close()
    measure(
      'S1',
      'e death',
      `simulated in process: the listener and every connection closed (a real kill is not run: the agent shares ` +
        `the test's process); socket gone ${await gone(w.m.path)}`,
    )
    after('e', await stolen(w))
  })

  it("re-login on the same keys: the earlier window's hops are not-in-grant, 0 of 100 served", async () => {
    const w = await lived()
    const derived = await w.open.request('sign', [P.bob.address, [...S1_GRANT.caveats, 'repo=r'], EXP1])
    const bobs = derived?.hop as Hop
    w.m.server.logout()
    w.m.server.login(JANE_KEYS)
    const out = await stolen(w)
    const d = new Driver(w.m.path, P.bob.signing, [bobs])
    const bob = [
      await d.request('register', [threadId(0x5400)]),
      await d.request('sign', [P.carol.address, [...S1_GRANT.caveats, 'repo=r'], EXP1]),
    ]
    const all = [...out, ...bob]
    const served = all.filter((o) => o.served).length
    const nig = all.filter((o) => o.code === 'not-in-grant').length
    measure(
      'S1',
      're-login',
      `the session's first grant over 100 requests and a derived hop of the earlier window over 2: served ${served}; ` +
        `codes ${codes(all)}; predicted not-in-grant ${nig} of ${all.length}; the derived hop signed in the window ` +
        `${derived?.ok === true}`,
    )
    expect(derived?.ok).toBe(true)
    expect(served).toBe(0)
  })
})

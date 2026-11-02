import { randomBytes } from 'node:crypto'
import { existsSync, readFileSync, statSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { writeHeapSnapshot } from 'node:v8'
import { type BuiltEnvelope, buildEnvelope, fromHex, type Hop, newThread, SigningKey } from '@usebag/core'
import { AgentClient, buildRequest } from '@usebag/edge/agent'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { tempDir } from '../support/io.ts'
import { forms } from '../support/security.ts'
import { auditedAt, LoginChild, type Made, makeHome, RecordRelay } from './c31-support.ts'
import { measure, notRun, RawWire, type Reply } from './support-a.ts'

// The addendum's helper half: the arms the first run printed as not
// run or simulated, with the agent as a real child process (`node packages/cli/src/main.ts login`, a test home made by
// another child, a fake terminal on the child's stdin that types the `y`):
//   G3 (e), a real kill: SIGKILL of the child mid-window, then the 23 requests of g3's arms (10 signs, 10 opens, a
//     register, a `grant`, a `resign`); signatures and openings served after it counted (gate 70d4165, line 502).
//   G3 (d), the real clock: a 5-second window ended by login's own timer, read past its end by the wall clock, then the
//     same 23 (`--window 60` was named; the file stays under about 20 s; 5 s, not 3, so the in-window
//     steps finish well before the end).
// An arm whose window did not serve its in-window steps (register, sign, open, each ok) prints "not run" and asserts
// nothing, so 0 after the end is never trivial; S8's heap arm runs only after such a real exchange.
//   S8, the memory: with the agent out of the test's process, a heap snapshot of the test's process (the session side)
//     searched for the principal's seeds, in the six text forms and the raw bytes (gate line 728).
//   S8 (b), another uid: not run again, and why (gate line 717).
// Pass, as pre-registered: G3, 0 signatures and 0 openings after any end; S8, 0 seeds. A child the lane cannot spawn
// prints "not run: <reason>" and asserts nothing (the arm stays not run).

const tmp = tempDir('c31')
const home = join(tmp.dir, 'h')
const sock = join(home, 'agent.sock')
const CAVEAT = 'type=coding.*'
const THREAD = `${'0'.repeat(63)}1`
const relay = new RecordRelay()
const children: LoginChild[] = []
/** What the session side holds, kept alive so the heap snapshot holds it. */
const held: unknown[] = []
let made: Made | null = null
let setupError = ''
/** Set when a window served its in-window steps: a real exchange with a child agent happened. */
let exchanged = false
const IN_WINDOW = 'register ok, sign ok, open ok'

beforeAll(async () => {
  const url = await relay.listen()
  try {
    // The home holds a live epoch (c31-support.ts setup), so ac login rotates nothing and the relay sees only fetches.
    made = makeHome(home, url, tmp.dir)
    relay.records.set(`${made.address} address`, made.record)
  } catch (e) {
    setupError = String((e as Error).message).split('\n')[0] ?? 'the setup child failed'
  }
}, 30_000)
afterEach(() => {
  for (const c of children) c.kill()
})
afterAll(async () => {
  for (const c of children) c.kill()
  // Each child's exit is awaited (bounded) before the temp directory goes.
  await Promise.race([
    Promise.all(children.map((c) => c.exited)),
    new Promise((done) => setTimeout(done, 5_000)),
  ])
  await relay.close()
  tmp.cleanup()
})

const now = (): number => Math.floor(Date.now() / 1000)
const rng = (n: number): Uint8Array => Uint8Array.from(randomBytes(n))

interface Window {
  readonly m: Made
  readonly child: LoginChild
  readonly end: number
  readonly key: SigningKey
  readonly hop: Hop
  readonly mail: readonly BuiltEnvelope[]
  /** What the session got in the window: proof the arm could be served before its end. */
  readonly before: string
  /** Seconds from the last in-window step to the window's end. */
  readonly margin: number
}

/** A child `ac login` with a window of `seconds`, a first grant typed `y` on its terminal, a session that used it. */
async function windowOf(seconds: number): Promise<Window | string> {
  const m = made
  if (m === null) return `the test home could not be made in a child process (${setupError})`
  const child = new LoginChild(home, relay.url, seconds, tmp.dir)
  children.push(child)
  const end = await child.opened(10_000)
  if (end === null) {
    const last = child.err.filter((l) => l.startsWith('bag:')).at(-1) ?? 'no error line'
    return `ac login did not open a window as a child process (exit ${JSON.stringify(child.exit)}; ${last})`
  }
  const key = new SigningKey(rng(32))
  const granter = new AgentClient(sock)
  const g = await granter.grant(key.address, [CAVEAT], end, () => child.type('y'))
  granter.close()
  if (!g.ok) return `the first grant was refused (${g.code})`
  const to = [{ address: m.address, sealingKey: fromHex(m.sealing, 32) }]
  const sender = new SigningKey(rng(32))
  const mail = [0, 1, 2].map(() =>
    buildEnvelope({
      from: sender,
      to,
      auth: [],
      type: 'coding.task.v1',
      thread: newThread(rng),
      body: { repo: 'r' },
      ts: now(),
      rng,
    }),
  )
  const session = new AgentClient(sock, { key, chain: [g.hop] })
  const got: string[] = []
  const step = async (name: string, f: () => Promise<unknown>): Promise<void> => {
    got.push(
      await f().then(
        (v) => {
          held.push(v)
          return `${name} ok`
        },
        (e: { code?: unknown }) => `${name} ${String(e.code)}`,
      ),
    )
  }
  await step('register', () => session.register(THREAD))
  await step('sign', () => session.sign(sender.address, [CAVEAT], end))
  const first = mail[0] as BuiltEnvelope
  await step('open', () => session.open(m.address, first.envelope.id, new TextDecoder().decode(first.bytes)))
  session.close()
  held.push(session, g, mail)
  const before = got.join(', ')
  if (before === IN_WINDOW) exchanged = true
  return { m, child, end, key, hop: g.hop, mail, before, margin: end - Date.now() / 1000 }
}

/** One request on a new connection: the code it met, past a grant's pending line. */
async function attempt(frame: (nonce: string) => string): Promise<string> {
  const w = new RawWire(sock)
  held.push(w)
  const first = await w.next()
  if (first === null) return `refused-${w.error ?? 'closed'}`
  if (typeof first.nonce !== 'string') {
    w.close()
    return String(first.code)
  }
  w.write(`${frame(first.nonce)}\n`)
  let r: Reply | null = await w.next()
  while (r !== null && r.pending !== undefined) r = await w.next()
  w.close()
  return r === null ? 'closed' : r.ok === true ? 'ok' : String(r.code)
}

interface After {
  readonly codes: string
  /** Signatures served: the ok replies to the 10 signs, the grant and the resign. */
  readonly signatures: number
  /** Openings served: the ok replies to the 10 opens. */
  readonly openings: number
  /** Printed beside, not added: the agent's sign-accept and open-accept audit lines gained after the end. */
  readonly audit: string
}

/** The 23 of g3's arms after an end: what was served, and what the agent's audit and the relay gained. */
async function afterEnd(w: Window): Promise<After> {
  const [signs, opens] = [auditedAt(home, 'sign', 'accept'), auditedAt(home, 'open', 'accept')]
  const session =
    (
      op: 'sign' | 'open' | 'register',
      args: readonly (string | number | readonly string[])[],
      envelope?: string,
    ) =>
    (nonce: string): string =>
      buildRequest(w.key, nonce, 0, op, args, {
        chain: [w.hop],
        ...(envelope === undefined ? {} : { envelope }),
      })
  const codes: string[] = []
  for (let i = 0; i < 10; i++) codes.push(await attempt(session('sign', [w.m.address, [CAVEAT], w.end])))
  for (let i = 0; i < 10; i++) {
    const env = w.mail[i % w.mail.length] as BuiltEnvelope
    codes.push(
      await attempt(session('open', [w.m.address, env.envelope.id], new TextDecoder().decode(env.bytes))),
    )
  }
  codes.push(await attempt(session('register', [THREAD])))
  const stranger = new SigningKey(rng(32)).address
  codes.push(await attempt(() => JSON.stringify({ op: 'grant', args: [stranger, [CAVEAT], w.end] })))
  codes.push(await attempt(() => '{"op":"resign","args":["address"]}'))
  const ok = (from: number, to: number): number => codes.slice(from, to).filter((c) => c === 'ok').length
  const tally = new Map<string, number>()
  for (const c of codes) tally.set(c, (tally.get(c) ?? 0) + 1)
  return {
    codes: [...tally].map(([c, n]) => `${c} ${n}`).join(', '),
    signatures: ok(0, 10) + ok(21, 23),
    openings: ok(10, 20),
    audit:
      `sign accept +${auditedAt(home, 'sign', 'accept') - signs}, ` +
      `open accept +${auditedAt(home, 'open', 'accept') - opens}`,
  }
}

describe('the addendum (helper half): a real kill, a real clock, the session side heap', () => {
  it('G3 (e), a real kill: SIGKILL of the agent process, then 0 signatures and 0 openings served', async () => {
    const other = relay.other.length
    const w = await windowOf(60)
    if (typeof w === 'string') return notRun('G3', 'e real kill', w)
    if (w.before !== IN_WINDOW) {
      return notRun('G3', 'e real kill', `the window did not serve its in-window steps (${w.before})`)
    }
    w.child.kill()
    await w.child.exited
    const stale = existsSync(sock)
    const a = await afterEnd(w)
    measure(
      'G3',
      'e real kill',
      `in the window: ${w.before}; the child killed (${JSON.stringify(w.child.exit)}); the socket file left ${stale}; ` +
        `after the kill: 23 requests; signatures ${a.signatures}; openings ${a.openings}; codes ${a.codes} (the ` +
        'stale socket file refuses the connect, ECONNREFUSED: no request reaches a live agent refusing ' +
        `agent-locked, which s8.test.ts and the server tests cover); audit after it ${a.audit}; publishes at the ` +
        `relay ${relay.other.length - other}; predicted 0 and 0, a refused connection: ` +
        `${a.signatures + a.openings === 0 ? 'met' : 'NOT met'}. Stated, not measured: the keys leave with the ` +
        'process, and no zeroing code runs at a SIGKILL',
    )
    expect([a.signatures, a.openings]).toEqual([0, 0])
    expect(relay.other.slice(other)).toEqual([])
  }, 30_000)

  it("G3 (d), the real clock: a 5 s window ended by login's own timer, then 0 signatures and 0 openings", async () => {
    const other = relay.other.length
    const w = await windowOf(5)
    if (typeof w === 'string') return notRun('G3', 'd real clock', w)
    if (w.before !== IN_WINDOW || w.margin < 1) {
      const why = `${w.before}; ${w.margin.toFixed(2)} s before the end, under 1 s`
      return notRun(
        'G3',
        'd real clock',
        `the window did not serve its in-window steps well before its end (${why})`,
      )
    }
    while (Date.now() / 1000 < w.end + 0.5) await new Promise((done) => setTimeout(done, 50))
    const read = new Date().toISOString()
    const a = await afterEnd(w)
    const exited = await Promise.race([
      w.child.exited.then(() => true),
      new Promise<boolean>((done) => setTimeout(() => done(false), 5_000)),
    ])
    measure(
      'G3',
      'd real clock',
      `in the window: ${w.before}, ${w.margin.toFixed(2)} s before its end; the window's end ` +
        `${new Date(w.end * 1000).toISOString()}, read past it at ${read} (wall clock); after the end: 23 requests; ` +
        `signatures ${a.signatures}; openings ${a.openings}; codes ${a.codes} (ENOENT once the agent closed its ` +
        'socket at the clean end; a request that met the agent still listening would read agent-locked; no request ' +
        `reaches a live agent refusing agent-locked by design here, which s8.test.ts and the server tests cover); ` +
        `audit after it ${a.audit}; login exited by itself ${exited} (${JSON.stringify(w.child.exit)}; its last ` +
        `line ${JSON.stringify(w.child.out.at(-1) ?? '')}); publishes at the relay from before the wait ` +
        `${JSON.stringify(relay.other.slice(other))} (the timer re-signs nothing at a clean end)`,
    )
    expect([a.signatures, a.openings]).toEqual([0, 0])
    expect(relay.other.slice(other)).toEqual([])
  }, 30_000)

  it("S8, the memory: a heap snapshot of the session side's process holds no seed of the principal", () => {
    if (made === null) return notRun('S8', 'memory dump', `no test home (${setupError})`)
    if (!exchanged) {
      return notRun(
        'S8',
        'memory dump',
        'no window served its in-window steps: no real exchange with a child agent',
      )
    }
    const file = writeHeapSnapshot(join(tmp.dir, 'session.heapsnapshot'))
    const size = statSync(file).size
    // Only now are the seeds read, from the key file the setup child wrote: the test's process never held them before.
    const keyFile = JSON.parse(readFileSync(join(home, 'keys', 'jane-keys.json'), 'utf8')) as {
      sign_seed: string
      seal_priv: string
    }
    const seeds = [Buffer.from(keyFile.sign_seed, 'hex'), Buffer.from(keyFile.seal_priv, 'hex')]
    const needles = [...seeds.flatMap((s) => forms(s).map((f) => Buffer.from(f, 'utf8'))), ...seeds]
    const snap = readFileSync(file)
    let found = 0
    for (const n of needles) for (let i = snap.indexOf(n); i >= 0; i = snap.indexOf(n, i + 1)) found++
    unlinkSync(file)
    measure(
      'S8',
      'memory dump',
      `the agent out of the test's process (${children.length} child agents ran, a real exchange with one); a V8 heap snapshot of the test's ` +
        `process, the session side (${size} bytes, ${held.length} session-side objects held alive), searched for ` +
        `the 6 text forms of each of the principal's 2 seeds and their raw bytes: ${found} found; a heap snapshot ` +
        'records strings and object shapes, not the bytes inside typed arrays, so the raw-byte search covers only ' +
        'what a string would hold',
    )
    expect(found).toBe(0)
  }, 60_000)

  it('S8 (b), another uid: not run', () => {
    notRun(
      'S8',
      'b another uid',
      'a client running as a second uid needs a second account (root to make it); the agent-side check, the socket ' +
        "file's owner and mode, is measured in s8.test.ts; a real second uid's connect is measured by hand",
    )
  })
})

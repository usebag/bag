import { randomBytes } from 'node:crypto'
import { join } from 'node:path'
import { type Hop, SigningKey, signHop } from '@usebag/core'
import { AgentClient, buildRequest } from '@usebag/edge/agent'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { type AgentHome, agentHome, loggedIn, publishRecord } from '../support/agent.ts'
import { T0, type TestIo, tempDir, testIo } from '../support/io.ts'
import { MemoryRelay } from '../support/relay.ts'
import { cli, type Ran } from '../support/run.ts'
import { G1_ARMS, G1_CONFIRMED, G1_REQUESTS, type G1Request } from './requests-g1.ts'
import { audited, measure, RawWire, type Reply } from './support-a.ts'

// G1, the grant surface (`ac grant`'s first grants). A real `ac login` agent
// whose own terminal is the login run's io; no `y` is typed on it for the 40 pre-registered first-grant requests
// (requests-g1.ts) from clients that are not that terminal: `ac grant` with no TTY, `ac grant` with a TTY of its own
// (the pty arm, the stated limit), a raw client that sets the confirmation itself, and an MCP-style call with no TTY.
// Then the 10 confirmed, each with one `y` typed on the agent's terminal. Counted: first grants signed (the replies,
// and the agent's own `sign accept` audit lines), the prompts the agent's terminal showed. Pass: 0 first grants
// signed in the non-pty arms; the pty arm is recorded as the limit, not a pass or fail.

const tmp = tempDir('s38-g1')
afterAll(() => tmp.cleanup())
// A test that fails with a window open leaves no agent behind (login.test.ts's rule).
afterEach(() => {
  process.emit('SIGHUP')
})
let homes = 0
const dir = (): string => join(tmp.dir, `h${homes++}`)
const fresh = (): SigningKey => new SigningKey(Uint8Array.from(randomBytes(32)))
const THREAD = `${'0'.repeat(63)}1`

interface Up {
  readonly relay: MemoryRelay
  readonly h: AgentHome
  readonly login: { readonly io: TestIo; readonly ran: Promise<Ran> }
  readonly sock: string
}

async function up(): Promise<Up> {
  const relay = new MemoryRelay()
  const h = agentHome(dir())
  publishRecord(relay, h)
  const login = await loggedIn(relay, h)
  return { relay, h, login, sock: join(h.dir, 'agent.sock') }
}

const prompts = (a: Up): number => a.login.io.stderr.filter((l) => l.startsWith('request ')).length

interface Tried {
  readonly r: G1Request
  readonly signed: number
  readonly audited: number
  readonly prompted: number
  readonly code: string
}

/** What a raw client writes first, and what it writes when the agent sends it a prompt's code. */
function script(
  r: G1Request,
  k: SigningKey,
  nonce: string,
  exp: number,
): { first: string; onCode?: (c: string) => string } {
  const S = k.address
  const base = { op: 'grant', args: [S, r.caveats, exp] }
  const line = (o: unknown): string => `${JSON.stringify(o)}\n`
  const signed = (extras: { chain?: readonly Hop[] } = {}): string =>
    `${buildRequest(k, nonce, 0, 'sign', [S, r.caveats, exp], extras)}\n`
  switch (r.frame) {
    case 'answer-field':
      return { first: line({ ...base, answer: 'y' }) }
    case 'confirm-field':
      return { first: line({ ...base, confirm: 'y' }) }
    case 'confirmed-true':
      return { first: line({ ...base, confirmed: true }) }
    case 'fourth-arg-y':
      return { first: line({ op: 'grant', args: [S, r.caveats, exp, 'y'] }) }
    case 'y-key':
      return { first: line({ ...base, y: true }) }
    case 'y-line-after':
      return { first: line(base), onCode: () => 'y\n' }
    case 'echo-code':
      return { first: line(base), onCode: (c) => line({ op: 'grant', code: c, answer: 'y' }) }
    case 'tty-field':
      return { first: line({ ...base, tty: true, answer: 'y\n' }) }
    case 'pipelined-y':
      return { first: `${JSON.stringify(base)}\ny\ny\n` }
    case 'terminal-field':
      return { first: line({ ...base, terminal: 'y' }) }
    case 'signed-grant':
      return { first: line({ ...JSON.parse(signed()), op: 'grant', args: [S, r.caveats, exp] }) }
    case 'sign-self-no-chain':
      return { first: signed() }
    case 'sign-self-empty-chain':
      return { first: signed({ chain: [] }) }
    case 'sign-self-own-hop':
      return { first: signed({ chain: [signHop(k, S, r.caveats, exp)] }) }
    case 'register-no-chain':
      return { first: `${buildRequest(k, nonce, 0, 'register', [THREAD])}\n` }
    case 'cli':
      throw new Error('a cli request has no frame')
  }
}

/** A raw client's run: every frame written is answered once; a prompt's code may make it write one more. */
async function raw(a: Up, r: G1Request, k: SigningKey, exp: number): Promise<Reply[]> {
  const w = new RawWire(a.sock)
  const first = await w.next()
  const s = script(r, k, String(first?.nonce), exp)
  let frames = s.first.split('\n').length - 1
  w.write(s.first)
  const replies: Reply[] = []
  while (replies.length < frames) {
    const reply = await w.next()
    if (reply === null) break
    if (typeof reply.pending === 'string') {
      if (s.onCode !== undefined) {
        w.write(s.onCode(reply.pending))
        frames++
      }
      continue
    }
    replies.push(reply)
  }
  w.close()
  return replies
}

async function attempt(a: Up, r: G1Request): Promise<Tried> {
  const k = fresh()
  const exp = T0 + r.expAfterT0
  const [p0, s0] = [prompts(a), audited(a.h, 'sign', 'accept')]
  let signed = 0
  let code: string
  if (r.frame === 'cli') {
    const io = testIo(a.relay)
    io.tty = r.arm === 'pty'
    const caveats = r.caveats.flatMap((c) => ['--caveat', c])
    const ran = await cli(
      io,
      'grant',
      '--as',
      'jane',
      '--session',
      k.address,
      ...caveats,
      '--exp',
      String(exp),
      '--dir',
      a.h.dir,
    )
    signed = ran.code === 0 ? 1 : 0
    code = signed === 1 ? 'ok' : (/^bag: ([a-z-]+):/.exec(ran.err.at(-1) ?? '')?.[1] ?? `exit ${ran.code}`)
  } else {
    const replies = await raw(a, r, k, exp)
    signed = replies.filter((x) => x.ok === true && 'hop' in x).length
    code = replies.map((x) => (x.ok === true ? 'ok' : String(x.code))).join('+') || 'closed'
  }
  return { r, signed, audited: audited(a.h, 'sign', 'accept') - s0, prompted: prompts(a) - p0, code }
}

function tally(xs: readonly Tried[]): string {
  const n = new Map<string, number>()
  for (const x of xs) n.set(`${x.r.frame}:${x.code}`, (n.get(`${x.r.frame}:${x.code}`) ?? 0) + 1)
  return [...n].map(([c, k]) => `${c} ${k}`).join(', ')
}

describe('G1: the grant surface', () => {
  it('V3: 40 first-grant requests, 10 in each arm, and 10 confirmed', () => {
    measure(
      'G1',
      'set',
      `${G1_REQUESTS.length} requests (${G1_ARMS.map((arm) => `${arm} ${G1_REQUESTS.filter((r) => r.arm === arm).length}`).join(', ')}); confirmed ${G1_CONFIRMED.length}`,
    )
    expect(G1_REQUESTS).toHaveLength(40)
    expect(G1_CONFIRMED).toHaveLength(10)
  })

  it("the 40: 0 first grants signed without a y on the agent's own terminal", async () => {
    const a = await up()
    const tried: Tried[] = []
    for (const r of G1_REQUESTS) tried.push(await attempt(a, r))
    for (const arm of G1_ARMS) {
      const xs = tried.filter((x) => x.r.arm === arm)
      const limit =
        arm === 'pty'
          ? "; the stated limit: a same-uid process that can type on the agent's OWN " +
            'terminal (TIOCSTI, or the master of the pty ac login runs on) types the y; that is not modelled in ' +
            'process, so this arm is recorded as the limit, not a pass or fail'
          : ''
      measure(
        'G1',
        arm,
        `${xs.length} requests; first grants signed ${xs.reduce((n, x) => n + x.signed, 0)}; agent sign-accept ` +
          `audit lines ${xs.reduce((n, x) => n + x.audited, 0)}; prompts on the agent's terminal ` +
          `${xs.reduce((n, x) => n + x.prompted, 0)} (each answered by no y); outcomes ${tally(xs)}${limit}`,
      )
    }
    const nonPty = tried.filter((x) => x.r.arm !== 'pty')
    const signedNonPty = nonPty.reduce((n, x) => n + x.signed + x.audited, 0)
    measure(
      'G1',
      '40',
      `first grants signed without a y in the 30 non-pty requests ${signedNonPty}; in all 40 ${tried.reduce((n, x) => n + x.signed + x.audited, 0)}`,
    )
    expect(tried).toHaveLength(40)
    expect(signedNonPty).toBe(0)
    a.login.io.lines.length = 0
  })

  it('the 10 confirmed: each signed after a y, its line naming session, caveats and exp, then admitted', async () => {
    const a = await up()
    let refusedBefore = 0
    let signed = 0
    let named = 0
    let admitted = 0
    const codes: string[] = []
    for (const c of G1_CONFIRMED) {
      const k = fresh()
      const S = k.address
      const exp = T0 + c.expAfterT0
      // Before any ac grant: the very hop the grant will be (Ed25519 is deterministic), not yet in the grant-set.
      const early = new AgentClient(a.sock, { key: k, chain: [signHop(a.h.keys.signing, S, c.caveats, exp)] })
      const before = await early.register(THREAD).then(
        () => 'ok',
        (e: { code?: unknown }) => String(e.code),
      )
      early.close()
      codes.push(before)
      if (before === 'not-in-grant') refusedBefore++
      const shown0 = a.login.io.stderr.length
      a.login.io.lines.push('y')
      const caveats = c.caveats.flatMap((x) => ['--caveat', x])
      const ran = await cli(
        testIo(a.relay),
        'grant',
        '--as',
        'jane',
        '--session',
        S,
        ...caveats,
        '--exp',
        String(exp),
        '--dir',
        a.h.dir,
      )
      if (ran.code !== 0) continue
      signed++
      const [hop] = JSON.parse(ran.out[0] as string) as Hop[]
      const shown = a.login.io.stderr.slice(shown0)
      if (
        shown.includes(`grant to session ${S}`) &&
        shown.includes(`caveats ${c.caveats.map((x) => JSON.stringify(x)).join(' ')}`) &&
        shown.some((l) => l.startsWith(`until ${exp} (`))
      ) {
        named++
      }
      const session = new AgentClient(a.sock, { key: k, chain: [hop as Hop] })
      if (
        await session.register(THREAD).then(
          () => true,
          () => false,
        )
      )
        admitted++
      session.close()
    }
    measure(
      'G1',
      '10 confirmed',
      `signed after a y ${signed} of 10; the terminal's lines naming session, caveats and exp ${named} of 10; the ` +
        `session's first request admitted after ${admitted} of 10; the same hop refused before the grant ` +
        `not-in-grant ${refusedBefore} of 10 (${[...new Set(codes)].join(', ')}); predicted 10, 10, 10, 10: ` +
        `${signed === 10 && named === 10 && admitted === 10 && refusedBefore === 10 ? 'met' : 'not met'}`,
    )
  })
})

import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { liveSession, withSession } from '../src/defaults.ts'
import {
  chainAt,
  chainPath,
  profileHome,
  type Session,
  setCurrent,
  write,
  writeJson,
} from '../src/session.ts'
import { DAY, T0, tempDir } from './support/fixtures.ts'

// send's and inbox's flags filled in from a faked live session (a session file and a chain file in a temporary home):
// each default, the precedence of every flag given, and the path with no session, which changes nothing.

const tmp = tempDir('defaults')
afterAll(() => tmp.cleanup())
let n = 0
const ROOT = `ed25519:${'a'.repeat(64)}`
const [A, K] = [`ed25519:${'b'.repeat(64)}`, `ed25519:${'c'.repeat(64)}`]
const RELAYS = ['http://127.0.0.1:47713', 'https://relay-2.example.test']
const hop = (iss: string, sub: string, exp: number) => ({ iss, sub, caveats: [], exp, sig: 'x' })

/** A session of acme.example for the agent `acme`, live unless `over` says otherwise. */
function session(over: Partial<Session> = {}): Session {
  return {
    v: 1,
    domain: 'acme.example',
    instance: 'http://127.0.0.1:8788',
    name: 'acme',
    agent_address: A,
    session_address: K,
    access_token: 'redacted',
    token_exp: T0 + 3600,
    generation: 1,
    org: { domain: 'acme.example', root: ROOT, relays: RELAYS },
    hop: hop(ROOT, A, T0 + 7 * DAY),
    hop_got_at: T0,
    local_hop: hop(A, K, T0 + DAY),
    trust_etag: 't1',
    trust_applied: 't1',
    state: 'live',
    reason: null,
    refreshed_at: T0,
    state_call_at: null,
    ...over,
  }
}

/** A home with the session written (and its chain, unless `chain` is false), or an empty one for `null`. */
function home(s: Session | null = session(), chain = true, dir = join(tmp.dir, `h${n++}`)): string {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  if (s !== null) write(profileHome(dir, s.domain), 'session', s)
  if (s !== null && chain) writeJson(chainAt(profileHome(dir, s.domain)), [s.hop, s.local_hop])
  return dir
}

class Usage extends Error {}
const said: string[] = []
const io = { clock: { now: () => T0 }, err: (line: string) => said.push(line) }
const run = (h: string, command: 'send' | 'inbox', values: Record<string, unknown>) =>
  withSession({ positionals: [], values }, command, io, (d) => d ?? h, Usage)
const SEND = { to: ['bob'], type: 'note', body: '{}' }

describe('send with a live session', () => {
  it('defaults --as to the session key, --relay to the first relay and --auth to the chain', () => {
    const h = home()
    expect(run(h, 'send', SEND).values).toEqual({
      ...SEND,
      as: 'acme.session',
      relay: RELAYS[0],
      auth: chainPath(h),
    })
  })

  it('keeps every flag given: --relay and --auth win, and another --as takes neither relay nor chain', () => {
    const h = home()
    const given = { ...SEND, relay: 'https://mine.example', auth: '/tmp/c.json' }
    expect(run(h, 'send', given).values).toEqual({ ...given, as: 'acme.session' })
    expect(() => run(h, 'send', { ...SEND, as: 'alice' })).toThrow(new Usage('--relay is required'))
    const own = run(h, 'send', { ...SEND, as: 'alice', relay: 'https://r.example' }).values
    expect(own).toEqual({ ...SEND, as: 'alice', relay: 'https://r.example' })
  })

  it('reads the home under --dir, and still requires what no session knows', () => {
    const h = home()
    const p = withSession(
      { positionals: [], values: { ...SEND, dir: h } },
      'send',
      io,
      (d) => d as string,
      Usage,
    )
    expect((p.values as Record<string, unknown>).auth).toBe(chainPath(h))
    expect(() => run(h, 'send', { to: ['bob'], type: 'note' })).toThrow(new Usage('--body is required'))
    // --type is not required: send defaults it (chat.v1).
    expect(run(h, 'send', { to: ['bob'], body: '{}' }).values).toMatchObject({ as: 'acme.session' })
  })
})

describe('inbox with a live session', () => {
  it('defaults --as to the agent, --relay to every relay and --trust-root to the root address', () => {
    const p = run(home(), 'inbox', { once: true })
    expect(p.values).toEqual({ once: true, as: 'acme', relay: RELAYS, 'trust-root': [ROOT] })
  })

  it('keeps every flag given: --relay and --trust-root win, and another --as takes neither', () => {
    const h = home()
    const given = { relay: ['https://mine.example'], 'trust-root': ['friend.example'] }
    expect(run(h, 'inbox', given).values).toEqual({ ...given, as: 'acme' })
    expect(() => run(h, 'inbox', { as: 'alice' })).toThrow(new Usage('--relay is required'))
    expect(run(h, 'inbox', { as: 'alice', relay: ['https://r.example'] }).values).toEqual({
      as: 'alice',
      relay: ['https://r.example'],
    })
  })

  it("reads the session's domain as its root address, with no lookup; any other root stays as given", () => {
    const { root } = run(home(), 'inbox', { 'trust-root': ['acme.example'] })
    expect(['acme.example', 'friend.example', ROOT].map(root)).toEqual([ROOT, 'friend.example', ROOT])
  })
})

describe('no session, or none live', () => {
  it('with no session fills in nothing: the values as given, every root as given, the same required errors', () => {
    const h = home(null)
    const all = { ...SEND, as: 'alice', relay: 'https://r.example' }
    const p = run(h, 'send', all)
    expect(p.values).toEqual(all)
    expect(p.root('acme.example')).toBe('acme.example')
    expect(() => run(h, 'send', SEND)).toThrow(new Usage('--as is required'))
    expect(() => run(h, 'inbox', { as: 'alice' })).toThrow(new Usage('--relay is required'))
    expect(liveSession(() => h, T0)).toBeNull()
  })

  it('reads no session when every flag is given, and treats a home that cannot be named as none', () => {
    const all = { ...SEND, as: 'alice', relay: 'https://r.example', auth: '/c.json' }
    const asked = () => {
      throw new Error('the home was asked for')
    }
    expect(withSession({ positionals: [], values: all }, 'send', io, asked, Usage).values).toEqual(all)
    const none = () => {
      throw new Error('no home directory')
    }
    expect(liveSession(none, T0)).toBeNull()
    expect(() => withSession({ positionals: [], values: SEND }, 'send', io, none, Usage)).toThrow(
      new Usage('--as is required'),
    )
  })

  it('names why a session filled nothing in: not live, no chain, a chain run out, no relays, a file that does not read', () => {
    const why = (h: string) => liveSession(() => h, T0)
    expect(why(home(session({ state: 'frozen' })))).toBe(
      'the enterprise session of acme.example is frozen: bag status',
    )
    const noChain = 'the enterprise session of acme.example is live, without a live chain: bag status'
    expect(why(home(session(), false))).toBe(noChain)
    expect(why(home(session({ local_hop: hop(A, K, T0) })))).toBe(noChain)
    expect(why(home(session({ hop: null })))).toBe(noChain)
    const noRelays = 'the enterprise session of acme.example is live, with no relays: bag status'
    expect(why(home(session({ org: { domain: 'acme.example', root: ROOT, relays: [] } })))).toBe(noRelays)
    expect(() => run(home(session({ state: 'paused' })), 'inbox', {})).toThrow(
      new Usage('--as is required (the enterprise session of acme.example is paused: bag status)'),
    )
    const bad = home(null)
    mkdirSync(join(bad, 'enterprise'), { mode: 0o700 })
    writeFileSync(join(bad, 'enterprise', 'session.json'), '{"v":2}', { mode: 0o600 })
    expect(why(bad)).toBe('the enterprise session file does not read')
  })
})

describe('a home with several organisations', () => {
  const ROOT2 = `ed25519:${'d'.repeat(64)}`
  const walk2 = session({
    domain: 'walk2.example',
    name: 'walk2',
    org: { domain: 'walk2.example', root: ROOT2, relays: ['https://relay.walk2.example'] },
  })
  const two = (): string => {
    const h = home(walk2)
    home(session(), true, h)
    setCurrent(h, 'acme.example')
    return h
  }

  it('uses the most recently connected and names it and the others on stderr, as status does', () => {
    const h = two()
    said.splice(0)
    expect(run(h, 'inbox', {}).values).toEqual({ as: 'acme', relay: RELAYS, 'trust-root': [ROOT] })
    expect(said).toEqual([
      'bag: using acme.example, the most recently connected; also signed in to walk2.example (--org)',
    ])
  })

  it("--org picks that profile's session, chain and root, with no line; an organisation not held fills nothing", () => {
    const h = two()
    said.splice(0)
    const p = run(h, 'send', { ...SEND, org: 'walk2.example' })
    expect(p.values).toMatchObject({
      as: 'walk2.session',
      relay: 'https://relay.walk2.example',
      auth: chainAt(profileHome(h, 'walk2.example')),
    })
    expect([p.root('walk2.example'), p.root('acme.example'), said]).toEqual([ROOT2, 'acme.example', []])
    expect(() => run(h, 'send', { ...SEND, org: 'other.example' })).toThrow(
      new Usage('--as is required (no enterprise session of other.example in this home)'),
    )
  })

  it('prints no line when every flag is given, nor with one profile', () => {
    const h = two()
    said.splice(0)
    run(h, 'send', { ...SEND, as: 'alice', relay: 'https://r.example', auth: '/c.json' })
    run(home(), 'inbox', {})
    expect(said).toEqual([])
  })
})

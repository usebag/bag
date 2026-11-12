import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { ElicitRequestFormParams, ElicitResult } from '@modelcontextprotocol/sdk/types.js'
import { describe, expect, it } from 'vitest'
import {
  Bindings,
  BRIDGE_CAPABILITY,
  bridgeOf,
  CANNOT_BIND,
  type Custody,
  GONE_KEEP_MS,
  type HomeIdentity,
  NO_AGAIN_MS,
  NOT_BOUND,
  NOT_REACHED,
  type ServiceConnection,
  serviceCustody,
  serviceMethods,
  servicePairings,
  sweepGone,
  TOOLS_BY_CUSTODY,
  toolAllowed,
  withAs,
} from '../src/binding.ts'
import { connectionGrant } from '../src/session.ts'
import { type ToolContext, ToolError } from '../src/tools.ts'
import { FakeClock, seededRng } from './support/fixtures.ts'

// The binding table (binding.ts) over fake connections and a fake service home: the ways into bound (typed word,
// dialog Yes), never silent, proposals that only preset, no re-attach, custody per call, the close, the lend.

type Answer = ElicitResult | Error | 'hang'

interface Fake extends ServiceConnection {
  readonly dialogs: ElicitRequestFormParams[]
  readonly notices: [string, Readonly<Record<string, unknown>>][]
  readonly person: Answer[]
  close(): void
}

let n = 0
function conn(
  o: { elicit?: boolean; hook?: boolean; host?: string; cwd?: string; person?: Answer[] } = {},
): Fake {
  const closers = new Set<() => void>()
  const c = {
    handle: `h${(n++).toString(16).padStart(32, '0')}`,
    host: o.host ?? 'claude-code',
    cwd: o.cwd ?? '/work/a',
    capabilities: { elicitation: o.elicit ?? true, inputHook: o.hook ?? false, raw: {} },
    closed: false,
    dialogs: [] as ElicitRequestFormParams[],
    notices: [] as [string, Readonly<Record<string, unknown>>][],
    person: o.person ?? [],
    onClose(fn: () => void) {
      closers.add(fn)
      return () => closers.delete(fn)
    },
    async elicit(params: ElicitRequestFormParams) {
      c.dialogs.push(params)
      const a = c.person.shift() ?? { action: 'cancel' }
      if (a === 'hang') return new Promise<ElicitResult>(() => {})
      if (a instanceof Error) throw a
      return a
    },
    notify(method: string, params: Readonly<Record<string, unknown>>) {
      c.notices.push([method, params])
    },
    close() {
      c.closed = true
      for (const f of [...closers]) f()
    },
  }
  return c
}

const ids = (...l: [string, Custody][]): HomeIdentity[] =>
  l.map(([label, custody]) => ({ label, address: `ed25519:${label}`, custody }))

function table(
  identities: HomeIdentity[],
  o: { draining?: boolean; custody?: (l: string) => Custody | null } = {},
) {
  // A person's pace: each mono read moves a second, so a dialog never reads as answered at once.
  let t = 0
  const home = { home: '/h', identities: () => identities, draining: o.draining ?? false }
  const record = (l: string) => identities.find((i) => i.label === l)?.custody ?? null
  return new Bindings(home, {
    mono: () => (t += 1000),
    now: () => 1_800_000_000,
    custody: o.custody ?? record,
  })
}

const yes = { action: 'accept', content: { bind: true } } as const
const code = async (p: Promise<unknown> | (() => unknown)): Promise<string> => {
  try {
    await (typeof p === 'function' ? p() : p)
    return 'ok'
  } catch (e) {
    return e instanceof ToolError ? e.code : String(e)
  }
}

describe('the ways into bound', () => {
  it('never silent: a one-identity home leaves a new connection unbound, and an act answers not-bound naming no label', () => {
    const t = table(ids(['solo', 'home-key']))
    const c = conn()
    expect(t.state(c)).toBe('unbound')
    expect(() => t.require(c, 'send')).toThrow(NOT_BOUND)
    expect(NOT_BOUND).not.toContain('solo')
  })

  it('the typed word binds only on a connection whose hello declared an input hook, with no dialog', async () => {
    const t = table(ids(['omp', 'home-key']))
    const plain = conn()
    expect(await code(() => t.bindByWord(plain, 'omp'))).toBe('usage')
    expect(t.state(plain)).toBe('unbound')
    const hooked = conn({ hook: true })
    expect(t.bindByWord(hooked, 'omp').granted).toBe('typed')
    expect(hooked.dialogs).toEqual([])
    expect(t.require(hooked, 'send').label).toBe('omp')
    expect(hooked.notices[0]?.[0]).toBe('service/bound')
  })

  it('a dialog binds only on an explicit Yes; an explicit No is declined', async () => {
    const t = table(ids(['omp', 'home-key']))
    const no = conn({ person: [{ action: 'accept', content: { bind: false } }] })
    expect(await code(t.bindByDialog(no, 'omp'))).toBe('declined')
    expect(t.state(no)).toBe('unbound')
    const ok = conn({ person: [yes] })
    expect((await t.bindByDialog(ok, 'omp')).granted).toBe('dialog')
    expect(t.state(ok)).toBe('bound')
  })

  it("a host's decline, a close, a failure or a timeout did not reach the person: cancelled, never declined", async () => {
    const t = table(ids(['omp', 'home-key']))
    for (const a of [{ action: 'decline' }, { action: 'cancel' }, new Error('timeout')] as Answer[]) {
      const c = conn({ person: [a] })
      await expect(t.bindByDialog(c, 'omp')).rejects.toThrow(NOT_REACHED)
      expect(t.state(c)).toBe('unbound')
    }
  })

  it('a dialog answered at once was never seen: no-elicitation', async () => {
    const home = { home: '/h', identities: () => ids(['omp', 'home-key']), draining: false }
    const t = new Bindings(home, { mono: () => 0, custody: () => 'home-key' })
    expect(await code(t.bindByDialog(conn({ person: [{ action: 'decline' }] }), 'omp'))).toBe(
      'no-elicitation',
    )
  })

  it('a connection with neither a dialog nor a hook cannot bind, and the refusal names what the person can do', async () => {
    const t = table(ids(['omp', 'home-key']))
    await expect(t.bindByDialog(conn({ elicit: false }), 'omp')).rejects.toThrow(CANNOT_BIND)
  })

  it('a second bind dialog while one is open on the connection is busy', async () => {
    const t = table(ids(['omp', 'home-key']))
    const c = conn({ person: ['hang'] })
    void t.bindByDialog(c, 'omp')
    expect(t.state(c)).toBe('asking')
    expect(await code(t.bindByDialog(c, 'omp'))).toBe('busy')
  })
})

describe('proposals and no re-attach', () => {
  it('a marker presets the choice dialog and binds nothing by itself', async () => {
    const t = table(ids(['a', 'home-key'], ['b', 'home-key']))
    t.mark('/work/a', 'b')
    const c = conn()
    expect(await code(t.bindByDialog(c))).toBe('cancelled')
    const field = (
      (c.dialogs[0] as ElicitRequestFormParams).requestedSchema.properties as Record<
        string,
        { default?: string }
      >
    ).identity
    expect(field?.default).toBe('b')
    expect(t.state(c)).toBe('unbound')
  })

  it('a new connection with the same host kind and cwd starts unbound; the last bind only proposes', async () => {
    const t = table(ids(['a', 'home-key'], ['b', 'home-key']))
    const first = conn({ hook: true })
    t.bindByWord(first, 'b')
    first.close()
    const again = conn({ hook: true })
    expect(t.state(again)).toBe('unbound')
    expect(() => t.require(again, 'send')).toThrow(NOT_BOUND)
    expect(t.propose(again)).toBe('b')
    expect(t.propose(conn({ host: 'codex' }))).toBeNull()
  })

  it("a connection's close drops its bindings and tells the pair tools", () => {
    const t = table(ids(['a', 'home-key']))
    const ended: string[] = []
    t.onEnd((label, c) => ended.push(`${label} ${c.cwd}`))
    const c = conn({ hook: true })
    t.bindByWord(c, 'a')
    c.close()
    expect(t.state(c)).toBe('unbound')
    expect(ended).toEqual(['a /work/a'])
  })
})

describe('custody per call', () => {
  it("follows the contract's tool table for each class", () => {
    const rows = ['status', 'send', 'pair_invite', 'pair_cancel', 'delegate', 'sign_in', 'enterprise_status']
    const allowed = (c: Custody) => rows.filter((t) => toolAllowed(c, t))
    expect(allowed('home-key')).toEqual(rows)
    expect(allowed('keychain')).toEqual(rows)
    expect(allowed('agent')).toEqual(['status', 'send'])
    expect(allowed('grant')).toEqual(['status', 'send', 'enterprise_status'])
  })

  it('a tool the table does not name is refused for every class: an allow-list, not a deny-list', () => {
    for (const c of ['home-key', 'keychain', 'agent', 'grant'] as Custody[]) {
      expect(toolAllowed(c, 'a_tool_added_later')).toBe(false)
      expect(toolAllowed(c, 'lookup')).toBe(true)
      expect(TOOLS_BY_CUSTODY[c].every((t) => toolAllowed(c, t))).toBe(true)
    }
    const t = table(ids(['g', 'agent']))
    const c = conn({ hook: true })
    t.bindByWord(c, 'g')
    expect(() => t.require(c, 'a_tool_added_later')).toThrow(/not-authorized/)
  })

  it('by default takes the class per call from the in-memory record, and the pointers only where it gives none', () => {
    const dir = mkdtempSync(join(tmpdir(), 'binding-'))
    try {
      mkdirSync(join(dir, 'agent'))
      writeFileSync(join(dir, 'agent', 'k.json'), '{}')
      writeFileSync(join(dir, 'agent', 'bare.json'), '{}')
      let k: Custody = 'home-key'
      const home = {
        home: dir,
        identities: () => [
          { label: 'k', address: null, custody: k },
          { label: 'bare', address: null } as unknown as HomeIdentity,
        ],
        draining: false,
      }
      const t = new Bindings(home)
      const c = conn({ hook: true })
      t.bindByWord(c, 'k')
      // The pointer on disk says agent; the record says home-key, and the record is what counts.
      expect(t.require(c, 'pair_invite').custody).toBe('home-key')
      k = 'agent'
      expect(() => t.require(c, 'pair_invite')).toThrow(/not-authorized/)
      const d = conn({ hook: true })
      t.bindByWord(d, 'bare')
      expect(serviceCustody(dir, 'bare')).toBe('agent')
      expect(t.require(d, 'send').custody).toBe('agent')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('a grant binding sends but gets no pair tool: not-authorized, checked on every call', () => {
    let custody: Custody = 'home-key'
    const t = table(ids(['g', 'home-key']), { custody: () => custody })
    const c = conn({ hook: true })
    t.bindByWord(c, 'g')
    expect(t.require(c, 'pair_invite').custody).toBe('home-key')
    custody = 'grant'
    expect(() => t.require(c, 'pair_invite')).toThrow(/not-authorized/)
    expect(t.require(c, 'send').custody).toBe('grant')
  })

  it('a principal is never bindable: unknown-identity, as for a label the home lacks', async () => {
    const t = table(ids(['p', 'home-key']), { custody: (l) => (l === 'p' ? null : 'home-key') })
    expect(await code(() => t.bindByWord(conn({ hook: true }), 'p'))).toBe('unknown-identity')
    expect(await code(() => t.bindByWord(conn({ hook: true }), 'nobody'))).toBe('unknown-identity')
  })

  it('an identity gone since the bind answers not-bound and drops the binding', () => {
    let have = true
    const t = table(ids(['a', 'home-key']), { custody: () => (have ? 'home-key' : null) })
    const c = conn({ hook: true })
    t.bindByWord(c, 'a')
    have = false
    expect(() => t.require(c, 'send')).toThrow(/not-bound/)
    expect(t.state(c)).toBe('unbound')
  })

  it('several bindings and no as is usage; as picks one; an unbound as is not-bound', () => {
    const t = table(ids(['a', 'home-key'], ['b', 'home-key']))
    const c = conn({ hook: true })
    t.bindByWord(c, 'a')
    t.bindByWord(c, 'b')
    expect(() => t.require(c, 'send')).toThrow(/usage/)
    expect(t.require(c, 'send', 'b').label).toBe('b')
    expect(t.as(c)).toBeNull()
    t.unbind(c, 'a')
    expect(t.as(c)).toBe('b')
    expect(() => t.require(c, 'send', 'a')).toThrow(/not-bound/)
  })
})

describe('the lend and the service methods', () => {
  it('service/use of a lent identity answers busy naming the verb and the CLI, never a handle', async () => {
    const t = table(ids(['omp', 'home-key']))
    const use = serviceMethods(t)['service/use'] as (c: ServiceConnection, p: object) => Promise<object>
    const c = conn({ hook: true })
    t.lend('omp', 'identity remove')
    const e = await use(c, { label: 'omp', via: 'typed' }).catch((x: unknown) => x as ToolError)
    expect((e as ToolError).code).toBe('busy')
    expect((e as ToolError).message).toContain('bag command line (identity remove)')
    expect((e as ToolError).message).not.toContain(c.handle)
    t.returned('omp')
    expect(await use(c, { label: 'omp', via: 'typed' })).toMatchObject({
      bound: true,
      as: 'omp',
      granted: 'typed',
    })
  })

  it('service/identities lists bindable labels only on a dialog-capable connection; unknown params are usage', async () => {
    const t = table(ids(['a', 'home-key'], ['p', 'home-key']), {
      custody: (l) => (l === 'p' ? null : 'home-key'),
    })
    const m = serviceMethods(t)
    const list = m['service/identities'] as (c: ServiceConnection, p: object) => Promise<object>
    expect(await list(conn(), {})).toEqual({ identities: [{ label: 'a' }], proposed: null })
    expect(await code(list(conn({ elicit: false }), {}))).toBe('no-elicitation')
    expect(await code(list(conn(), { x: 1 }))).toBe('usage')
    const unbind = m['service/unbind'] as (c: ServiceConnection, p: object) => Promise<object>
    const c = conn({ hook: true })
    t.bindByWord(c, 'a')
    expect(await unbind(c, {})).toEqual({ unbound: ['a'] })
  })

  it('withAs carries as in both the structured content and the text', () => {
    const r = withAs({ content: [{ type: 'text', text: '{"x":1}' }], structuredContent: { x: 1 } }, 'a')
    expect([r.structuredContent, JSON.parse((r.content[0] as { text: string }).text)]).toEqual([
      { x: 1, as: 'a' },
      { x: 1, as: 'a' },
    ])
  })
})

describe('the wake router and markUsed (svc-mail)', () => {
  function routed() {
    const calls: string[] = []
    const home = { home: '/h', identities: () => ids(['a', 'home-key'], ['b', 'home-key']), draining: false }
    const t = new Bindings(home, {
      mono: (
        (x) => () =>
          (x += 1000)
      )(0),
      now: () => 7,
      custody: () => 'home-key',
      router: {
        bind: (label, c) => calls.push(`bind ${label} ${c.handle}`),
        unbind: (handle, label) => calls.push(`unbind ${handle} ${label}`),
      },
      markUsed: async (h, name, now) => {
        calls.push(`used ${h} ${name} ${now}`)
      },
    })
    return { t, calls }
  }

  it('a bind, typed or by dialog, calls router.bind once and markUsed not at all', async () => {
    const { t, calls } = routed()
    const c = conn({ hook: true, person: [yes] })
    t.bindByWord(c, 'a')
    await t.bindByDialog(c, 'b')
    expect(calls).toEqual([`bind a ${c.handle}`, `bind b ${c.handle}`])
  })

  it('unbind and close call router.unbind and markUsed once for each label they end', async () => {
    const { t, calls } = routed()
    const c = conn({ hook: true })
    t.bindByWord(c, 'a')
    t.bindByWord(c, 'b')
    calls.length = 0
    t.unbind(c, 'a')
    c.close()
    await new Promise((s) => setTimeout(s, 0))
    expect(calls).toEqual([`unbind ${c.handle} a`, `unbind ${c.handle} b`, 'used /h a 7', 'used /h b 7'])
  })

  it('a markUsed that rejects or never settles does not throw out of unbind or close, and close still finishes', async () => {
    const warned: string[] = []
    const ended: string[] = []
    const home = { home: '/h', identities: () => ids(['a', 'home-key'], ['b', 'home-key']), draining: false }
    let n = 0
    const t = new Bindings(home, {
      custody: () => 'home-key',
      markUsed: () => (n++ === 0 ? Promise.reject(new Error('busy')) : new Promise<void>(() => {})),
      log: { log: (_l, event, f) => warned.push(`${event} ${String(f?.outcome)}`) },
    })
    t.onEnd((l) => ended.push(l))
    const c = conn({ hook: true })
    t.bindByWord(c, 'a')
    t.bindByWord(c, 'b')
    expect(t.unbind(c, 'a')).toEqual(['a'])
    c.close()
    expect([t.state(c), ended]).toEqual(['unbound', ['a', 'b']])
    await new Promise((s) => setTimeout(s, 0))
    expect(warned).toEqual(['keep-alive busy'])
  })

  it('a refused, declined or unreached bind calls neither', async () => {
    const { t, calls } = routed()
    await code(() => t.bindByWord(conn(), 'a'))
    await code(() => t.bindByWord(conn({ hook: true }), 'nobody'))
    await code(t.bindByDialog(conn({ person: [{ action: 'accept', content: { bind: false } }] }), 'a'))
    await code(t.bindByDialog(conn({ person: [{ action: 'decline' }] }), 'a'))
    expect(calls).toEqual([])
  })
})

describe('after an explicit No, and a pairing with no table', () => {
  it('refuses use of that label on that connection for NO_AGAIN_MS with no dialog; the typed word still binds', async () => {
    let now = 0
    const home = { home: '/h', identities: () => ids(['omp', 'home-key']), draining: false }
    const t = new Bindings(home, { mono: () => (now += 1000), custody: () => 'home-key' })
    const c = conn({ hook: true, person: [{ action: 'accept', content: { bind: false } }, yes] })
    expect(await code(t.bindByDialog(c, 'omp'))).toBe('declined')
    const again = await t.bindByDialog(c, 'omp').catch((e: unknown) => e as ToolError)
    expect((again as ToolError).message).toContain('your user said No to omp in this window')
    expect(c.dialogs).toHaveLength(1)
    expect(await code(t.bindByDialog(conn({ person: [yes] }), 'omp'))).toBe('ok')
    now += NO_AGAIN_MS
    expect(await code(t.bindByDialog(c, 'omp'))).toBe('ok')
    const d = conn({ hook: true, person: [{ action: 'accept', content: { bind: false } }] })
    await code(t.bindByDialog(d, 'omp'))
    expect(t.bindByWord(d, 'omp').granted).toBe('typed')
  })

  it('servicePairings without a binding table refuses not-bound and makes nothing', () => {
    let made = 0
    const ctx = { config: { home: '/h', label: 'a' } } as unknown as ToolContext
    const make = (): never => {
      made++
      return {} as never
    }
    expect(() => servicePairings(ctx, null, make)).toThrow(/not-bound/)
    expect(made).toBe(0)
  })
})

describe('the omp consent bridge folder, service-derived', () => {
  const uid = process.getuid?.() ?? -1
  const announcing = (o: { handle?: string } = {}): Fake => {
    const c = conn({ elicit: false, host: 'omp', hook: true })
    ;(c as { raw?: unknown; capabilities: { raw: object } }).capabilities.raw = {
      experimental: { [BRIDGE_CAPABILITY]: { dir: '/tmp/evil' } },
    }
    if (o.handle !== undefined) (c as { handle: string }).handle = o.handle
    return c
  }
  const withHome = (fn: (home: string) => void) => {
    const home = mkdtempSync(join(tmpdir(), 'bridge-'))
    try {
      fn(home)
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  }

  it('makes <home>/run/shim/<handle>.consent, 0700, ignoring any path the shim sent; none without the capability', () =>
    withHome((home) => {
      const c = announcing()
      const dir = bridgeOf(c, home, uid) as string
      expect(dir).toBe(join(home, 'run', 'shim', `${c.handle}.consent`))
      expect(statSync(dir).mode & 0o777).toBe(0o700)
      expect(bridgeOf(conn({ elicit: false }), home, uid)).toBeNull()
    }))

  it('moves the folder away on the unbind of the last binding and on close, never deleting it', () =>
    withHome((home) => {
      const t = new Bindings({
        home,
        identities: () => ids(['a', 'home-key'], ['b', 'home-key']),
        draining: false,
      })
      const c = announcing()
      const dir = bridgeOf(c, home, uid) as string
      t.bindByWord(c, 'a')
      t.bindByWord(c, 'b')
      t.unbind(c, 'a')
      expect(existsSync(dir)).toBe(true)
      t.unbind(c, 'b')
      expect(existsSync(dir)).toBe(false)
      expect(readdirSync(join(home, 'run', 'shim', '.gone'))).toHaveLength(1)
      const d = announcing()
      const other = bridgeOf(d, home, uid) as string
      d.close()
      expect(existsSync(other)).toBe(false)
      expect(readdirSync(join(home, 'run', 'shim', '.gone'))).toHaveLength(2)
    }))

  it('as defence refuses a folder of another uid, a mode not 0700, a symlinked run/shim, a handle unfit for a name', () =>
    withHome((home) => {
      expect(bridgeOf(announcing(), home, uid + 1)).toBeNull()
      const loose = announcing()
      mkdirSync(join(home, 'run', 'shim', `${loose.handle}.consent`), { recursive: true })
      chmodSync(join(home, 'run', 'shim', `${loose.handle}.consent`), 0o755)
      expect(bridgeOf(loose, home, uid)).toBeNull()
      expect(bridgeOf(announcing({ handle: '../x' }), home, uid)).toBeNull()
      withHome((other) => {
        mkdirSync(join(other, 'run'))
        symlinkSync(join(home, 'run', 'shim'), join(other, 'run', 'shim'))
        expect(bridgeOf(announcing(), other, uid)).toBeNull()
      })
      expect(bridgeOf(announcing(), home, uid)).not.toBeNull()
    }))
})

describe("an agent-class binding's own grant (M3)", () => {
  it('two connections binding one agent-class identity each ask the agent, and one grant never serves the other', async () => {
    const asked: string[] = []
    const home = { home: '/h', identities: () => ids(['ag', 'agent']), draining: false }
    const t = new Bindings(home, {
      custody: () => 'agent',
      grant: async (c, label) => {
        asked.push(`${label} ${c.handle}`)
        return { for: c.handle } as never
      },
    })
    const one = conn({ hook: true })
    const two = conn({ hook: true })
    t.bindByWord(one, 'ag')
    t.bindByWord(two, 'ag')
    expect(asked).toEqual([`ag ${one.handle}`, `ag ${two.handle}`])
    expect(await t.grantOf(one, 'ag')).toEqual({ for: one.handle })
    expect(await t.grantOf(two, 'ag')).toEqual({ for: two.handle })
    two.close()
    expect(await code(t.grantOf(two, 'ag'))).toBe('not-bound')
    expect(await t.grantOf(one, 'ag')).toEqual({ for: one.handle })
  })

  it('connectionGrant makes a fresh key per connection and asks the agent for a grant to that key', async () => {
    const sessions: string[] = []
    const connect = () => ({
      grant: async (session: string) => {
        sessions.push(session)
        return { ok: true as const, hop: { sub: session } as never }
      },
      close: () => {},
    })
    const o = { rng: seededRng('grant'), clock: new FakeClock(), connect, caveats: ['type == "chat.v1"'] }
    const a = await connectionGrant('/h', o)
    const b = await connectionGrant('/h', o)
    expect(sessions).toEqual([a.keys.signing.address, b.keys.signing.address])
    expect(a.keys.signing.address).not.toBe(b.keys.signing.address)
    expect([a.hop, b.hop]).toEqual([{ sub: sessions[0] }, { sub: sessions[1] }])
  })

  it('connectionGrant refuses an empty caveat list before it asks the agent', async () => {
    let asked = 0
    const connect = () => ({
      grant: async () => {
        asked++
        return { ok: true as const, hop: {} as never }
      },
      close: () => {},
    })
    const o = { rng: seededRng('grant'), clock: new FakeClock(), connect }
    await expect(connectionGrant('/h', o)).rejects.toThrow(/caveat list/)
    await expect(connectionGrant('/h', { ...o, caveats: [] })).rejects.toThrow(/caveat list/)
    expect(asked).toBe(0)
  })
})

describe('the bridge folder: an existing one, and the sweep of run/shim/.gone', () => {
  const uid = process.getuid?.() ?? -1
  it('refuses a folder that already holds anything, and takes an empty one', () => {
    const home = mkdtempSync(join(tmpdir(), 'bridge-'))
    try {
      const c = conn({ elicit: false, host: 'omp' })
      ;(c as { capabilities: { raw: object } }).capabilities.raw = {
        experimental: { [BRIDGE_CAPABILITY]: {} },
      }
      const dir = join(home, 'run', 'shim', `${c.handle}.consent`)
      mkdirSync(dir, { recursive: true, mode: 0o700 })
      writeFileSync(join(dir, 'planted.json'), '{}')
      expect(bridgeOf(c, home, uid)).toBeNull()
      rmSync(join(dir, 'planted.json'))
      const d = conn({ elicit: false, host: 'omp' })
      ;(d as { capabilities: { raw: object } }).capabilities.raw = {
        experimental: { [BRIDGE_CAPABILITY]: {} },
      }
      mkdirSync(join(home, 'run', 'shim', `${d.handle}.consent`), { mode: 0o700 })
      expect(bridgeOf(d, home, uid)).not.toBeNull()
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })

  it('sweepGone removes a day-old folder holding only the known bridge files, and nothing else', () => {
    const home = mkdtempSync(join(tmpdir(), 'gone-'))
    try {
      const gone = join(home, 'run', 'shim', '.gone')
      const now = 10 * GONE_KEEP_MS
      const old = join(gone, `h1.consent.${now - GONE_KEEP_MS - 1}`)
      const kept = join(gone, `h2.consent.${now - GONE_KEEP_MS - 1}`)
      const fresh = join(gone, `h3.consent.${now - 1000}`)
      const odd = join(gone, 'no-stamp')
      for (const d of [old, kept, fresh, odd]) mkdirSync(d, { recursive: true })
      // a request, the answer a dialog cut mid-way left, and the extension's presence file: all known, all go
      writeFileSync(join(old, '0123456789abcdef.json'), '{}')
      writeFileSync(join(old, '0123456789abcdef.answer.json'), '{}')
      writeFileSync(join(old, '.bridge'), '{}')
      writeFileSync(join(kept, '0123456789abcdef.json'), '{}')
      writeFileSync(join(kept, 'unknown.txt'), 'x')
      writeFileSync(join(fresh, '0123456789abcdef.json'), '{}')
      expect(sweepGone(home, now)).toBe(1)
      expect(existsSync(old)).toBe(false)
      expect(readdirSync(kept)).toEqual(['unknown.txt'])
      expect(readdirSync(fresh)).toEqual(['0123456789abcdef.json'])
      expect(existsSync(odd)).toBe(true)
      expect(sweepGone(join(home, 'nothing'), now)).toBe(0)
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })
})

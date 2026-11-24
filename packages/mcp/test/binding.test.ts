import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { ElicitRequestFormParams, ElicitResult } from '@modelcontextprotocol/sdk/types.js'
import { describe, expect, it } from 'vitest'
import { ASK_EVERY_S, UNANSWERED_PER_WINDOW } from '../src/ask.ts'
import {
  BIND_CLOSED,
  Bindings,
  CANNOT_BIND,
  type Custody,
  GONE_KEEP_MS,
  type HomeIdentity,
  NO_AGAIN_MS,
  NOT_BOUND,
  NOT_BOUND_ANY,
  NOT_BOUND_DIALOG,
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
import { NO_ANSWER_IN_TIME, TIMED_OUT, type ToolContext, ToolError } from '../src/tools.ts'
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
  o: {
    elicit?: boolean
    hook?: boolean
    host?: string
    cwd?: string
    person?: Answer[]
    surface?: string
  } = {},
): Fake {
  const closers = new Set<() => void>()
  const c = {
    handle: `h${(n++).toString(16).padStart(32, '0')}`,
    host: o.host ?? 'claude-code',
    cwd: o.cwd ?? '/work/a',
    capabilities: { elicitation: o.elicit ?? true, inputHook: o.hook ?? false, raw: {} },
    ...(o.surface === undefined ? {} : { surface: o.surface }),
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

let homes = 0
function table(
  identities: HomeIdentity[],
  o: { draining?: boolean; custody?: (l: string) => Custody | null } = {},
) {
  // A person's pace: each mono read moves a second, so a dialog never reads as answered at once.
  let t = 0
  // A home of its own: the bind dialog's unanswered allowances count per home, and this clock never moves.
  const home = { home: `/h${homes++}`, identities: () => identities, draining: o.draining ?? false }
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
    const c = conn({ hook: true })
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
    const no = conn({ person: [{ action: 'decline' }] })
    expect(await code(t.bindByDialog(no, 'omp'))).toBe('declined')
    expect(t.state(no)).toBe('unbound')
    const ok = conn({ person: [yes] })
    expect((await t.bindByDialog(ok, 'omp')).granted).toBe('dialog')
    expect(t.state(ok)).toBe('bound')
  })

  it('a close, a failure or a timeout did not reach the person: cancelled, never declined', async () => {
    const t = table(ids(['omp', 'home-key']))
    for (const a of [{ action: 'cancel' }, new Error('timeout')] as Answer[]) {
      const c = conn({ person: [a] })
      await expect(t.bindByDialog(c, 'omp')).rejects.toThrow(NOT_REACHED)
      expect(t.state(c)).toBe('unbound')
    }
  })

  it('a dialog answered at once was never seen: no-elicitation', async () => {
    const home = { home: `/h${homes++}`, identities: () => ids(['omp', 'home-key']), draining: false }
    const t = new Bindings(home, { mono: () => 0, custody: () => 'home-key' })
    expect(await code(t.bindByDialog(conn({ person: [{ action: 'decline' }] }), 'omp'))).toBe(
      'no-elicitation',
    )
  })

  it('any answer within 250 ms, a Yes or a No included, is no-elicitation: nothing bound, no refusal remembered (0.4.4)', async () => {
    // A clock whose step is the time each dialog takes: 10 ms (unseen) or 300 ms (a person).
    let [t, step] = [0, 10]
    const home = { home: `/h${homes++}`, identities: () => ids(['omp', 'home-key']), draining: false }
    const b = new Bindings(home, { mono: () => (t += step), custody: () => 'home-key' })
    for (const a of [{ action: 'decline' }, { action: 'cancel' }, new Error('gone'), yes] as Answer[]) {
      const c = conn({ person: [a] })
      expect(await code(b.bindByDialog(c, 'omp'))).toBe('no-elicitation')
      expect(b.state(c)).toBe('unbound')
    }
    // An instant accept carrying No leaves no refusal: the person's slow Yes on the same connection binds at once after.
    const c = conn({ person: [{ action: 'accept', content: { bind: false } }, yes] })
    expect(await code(b.bindByDialog(c, 'omp'))).toBe('no-elicitation')
    step = 300
    expect((await b.bindByDialog(c, 'omp')).granted).toBe('dialog')
    expect(c.dialogs).toHaveLength(2)
    // At 300 ms a decline is the person's No, and it is remembered: the next use asks no dialog.
    const d = conn({ person: [{ action: 'decline' }, yes] })
    expect(await code(b.bindByDialog(d, 'omp'))).toBe('declined')
    expect(await code(b.bindByDialog(d, 'omp'))).not.toBe('ok')
    expect(d.dialogs).toHaveLength(1)
  })

  it('a decline in 10 ms is no-elicitation on cli, claude-vscode, claude-desktop and none; the surface changes the words', async () => {
    const texts: Record<string, string> = {}
    for (const surface of ['cli', 'claude-vscode', 'claude-desktop', undefined]) {
      let [t, step] = [0, 10]
      const home = { home: `/h${homes++}`, identities: () => ids(['omp', 'home-key']), draining: false }
      const b = new Bindings(home, { mono: () => (t += step), custody: () => 'home-key' })
      const c = conn({ person: [{ action: 'decline' }, yes], ...(surface ? { surface } : {}) })
      const e = await b.bindByDialog(c, 'omp').catch((x: unknown) => x)
      expect((e as ToolError).code).toBe('no-elicitation')
      texts[surface ?? 'none'] = (e as ToolError).message
      step = 300
      expect((await b.bindByDialog(c, 'omp')).granted).toBe('dialog')
    }
    expect(texts.cli).toBe(texts.none)
    expect(texts.cli).toContain('this host answered the bind dialog at once, without showing it')
    expect(texts['claude-vscode']).toContain("Claude Code's VS Code extension does this with every dialog")
    expect(texts['claude-vscode']).toContain(
      'Your user binds this window by typing use and the identity name in it.',
    )
    expect(texts['claude-desktop']).toContain('Claude Desktop does this with every dialog')
  })

  // 2026-11-23, live on 0.4.5: the VS Code extension's own decline of a dialog it never showed took longer than 250 ms
  // on a loaded machine. On a surface that answers every dialog itself, a decline or a cancel of the bind dialog is
  // unseen however long it took; an accept still binds; every other surface keeps the timing rule.
  for (const surface of ['claude-vscode', 'claude-desktop']) {
    it(`${surface}: a decline, a cancel or a failure after 300 ms or 5 s is no-elicitation, telling the person to type use; nothing bound or refused`, async () => {
      const name = surface === 'claude-vscode' ? "Claude Code's VS Code extension" : 'Claude Desktop'
      for (const step of [300, 5000]) {
        for (const a of [{ action: 'decline' }, { action: 'cancel' }, new Error('gone')] as Answer[]) {
          let t = 0
          const home = { home: `/h${homes++}`, identities: () => ids(['omp', 'home-key']), draining: false }
          const b = new Bindings(home, { mono: () => (t += step), custody: () => 'home-key' })
          // Then a slow Yes: no refusal was remembered, so it binds at once.
          const c = conn({ person: [a, yes], surface })
          const e = await b.bindByDialog(c, 'omp').catch((x: unknown) => x)
          expect([(e as ToolError).code, step]).toEqual(['no-elicitation', step])
          expect((e as ToolError).message).toContain(`${name} does this with every dialog`)
          expect((e as ToolError).message).toContain(
            'Your user binds this window by typing use and the identity name in it.',
          )
          expect(b.state(c)).toBe('unbound')
          expect((await b.bindByDialog(c, 'omp')).granted).toBe('dialog')
        }
      }
    })

    it(`${surface}: an accept after 300 ms binds, and the choice dialog's pick binds too`, async () => {
      let t = 0
      const home = { home: `/h${homes++}`, identities: () => ids(['omp', 'home-key']), draining: false }
      const b = new Bindings(home, { mono: () => (t += 300), custody: () => 'home-key' })
      expect((await b.bindByDialog(conn({ person: [yes], surface }), 'omp')).granted).toBe('dialog')
      const pick = conn({ person: [{ action: 'accept', content: { identity: 'omp' } }], surface })
      expect((await b.bindByDialog(pick)).label).toBe('omp')
    })
  }

  it("on cli and with no surface a decline after 300 ms is the person's No: declined and remembered (2026-11-24)", async () => {
    for (const surface of ['cli', undefined]) {
      let t = 0
      const home = { home: `/h${homes++}`, identities: () => ids(['omp', 'home-key']), draining: false }
      const b = new Bindings(home, { mono: () => (t += 300), custody: () => 'home-key' })
      const c = conn({ person: [{ action: 'decline' }, yes], ...(surface ? { surface } : {}) })
      expect(await code(b.bindByDialog(c, 'omp'))).toBe('declined')
      expect(await code(b.bindByDialog(c, 'omp'))).toBe('declined')
      expect(c.dialogs).toHaveLength(1)
    }
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
  it('follows the tool table (TOOLS_BY_CUSTODY) for each class', () => {
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
      // telemetry is the machine's setting: every class runs it; identity_create only a window bound to none.
      expect([c, toolAllowed(c, 'telemetry'), toolAllowed(c, 'identity_create')]).toEqual([c, true, false])
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

describe('the wake router and markUsed', () => {
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

describe("the bind dialog ended by bag's own bound (BIND_TIMEOUT_MS)", () => {
  it.each(['claude-vscode', 'claude-desktop', 'cli', undefined])(
    'on %s: cancelled, no answer in time; never no-elicitation, a No or a bind, and not remembered',
    async (surface) => {
      const home = { home: `/h${homes++}`, identities: () => ids(['omp', 'home-key']), draining: false }
      // Each read a millisecond: under the unseen rule this cancel would read as not shown.
      let [now, step] = [0, 1]
      const t = new Bindings(home, { mono: () => (now += step), custody: () => 'home-key' })
      const timedOut = new ToolError('cancelled', TIMED_OUT)
      const c = conn({ person: [timedOut, timedOut, yes], ...(surface === undefined ? {} : { surface }) })
      for (const label of ['omp', undefined]) {
        const e = await t.bindByDialog(c, label).catch((x: unknown) => x as ToolError)
        expect([(e as ToolError).code, (e as ToolError).message]).toEqual([
          'cancelled',
          `cancelled: ${NO_ANSWER_IN_TIME}`,
        ])
      }
      // Not remembered as a No: the next dialog is asked, and its Yes, at a person's pace, binds.
      step = 1000
      expect(await code(t.bindByDialog(c, 'omp'))).toBe('ok')
      expect(c.dialogs).toHaveLength(3)
    },
  )
})

describe('after an explicit No, and a pairing with no table', () => {
  it('refuses use of that label on that connection for NO_AGAIN_MS with no dialog; the typed word still binds', async () => {
    let now = 0
    const home = { home: `/h${homes++}`, identities: () => ids(['omp', 'home-key']), draining: false }
    const t = new Bindings(home, { mono: () => (now += 1000), custody: () => 'home-key' })
    const c = conn({ hook: true, person: [{ action: 'decline' }, yes] })
    expect(await code(t.bindByDialog(c, 'omp'))).toBe('declined')
    const again = await t.bindByDialog(c, 'omp').catch((e: unknown) => e as ToolError)
    expect((again as ToolError).message).toContain('your user said No to omp in this window')
    expect(c.dialogs).toHaveLength(1)
    // The question states what its No does, in words true on every host.
    expect(c.dialogs[0]?.message).toBe(
      'Act as omp in this window?\nIts tools then act as omp until it closes.\n' +
        'No: not asked again in this window for 5 minutes; typing use omp binds it at any time.',
    )
    expect(await code(t.bindByDialog(conn({ person: [yes] }), 'omp'))).toBe('ok')
    now += NO_AGAIN_MS
    expect(await code(t.bindByDialog(c, 'omp'))).toBe('ok')
    const d = conn({ hook: true, person: [{ action: 'decline' }] })
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

describe('no omp consent bridge folder (0.4.2)', () => {
  it('a window announcing the capability binds, unbinds and closes with no folder made or moved', () => {
    const home = mkdtempSync(join(tmpdir(), 'bridge-'))
    try {
      const t = new Bindings({ home, identities: () => ids(['a', 'home-key']), draining: false })
      const c = conn({ elicit: false, host: 'omp', hook: true })
      ;(c as { capabilities: { raw: object } }).capabilities.raw = {
        experimental: { 'bag.dev/consent-bridge': { pid: 4242 } },
      }
      t.bindByWord(c, 'a')
      t.unbind(c, 'a')
      c.close()
      expect(existsSync(join(home, 'run', 'shim'))).toBe(false)
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })
})

describe("an agent-class binding's own grant (M3)", () => {
  it('two connections binding one agent-class identity each ask the agent, and one grant never serves the other', async () => {
    const asked: string[] = []
    const home = { home: `/h${homes++}`, identities: () => ids(['ag', 'agent']), draining: false }
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

describe("the sweep of a 0.4.1 service's run/shim/.gone (0.4.2 only)", () => {
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

describe('a restore after a service restart (via restored)', () => {
  const restoring = (identities: HomeIdentity[], more: { draining?: boolean } = {}) => {
    const calls: string[] = []
    const home = { home: `/h${homes++}`, identities: () => identities, draining: more.draining ?? false }
    const t = new Bindings(home, {
      mono: (
        (x) => () =>
          (x += 1000)
      )(0),
      now: () => 7,
      custody: (l) => identities.find((i) => i.label === l)?.custody ?? null,
      router: {
        bind: (label, c, restored) => calls.push(`bind ${label} ${c.handle} ${restored === true}`),
        unbind: () => {},
      },
      grant: async (c, label) => {
        calls.push(`grant ${label} ${c.handle}`)
        return { for: c.handle } as never
      },
      open: async (label) => {
        calls.push(`open ${label}`)
      },
    })
    return { t, calls, home }
  }

  it('binds on a connection that could have bound (a hook or a dialog), granted restored, and says so once', () => {
    const { t, calls } = restoring(ids(['omp', 'home-key'], ['work', 'home-key']))
    const hooked = conn({ hook: true, elicit: false })
    const dialog = conn({ elicit: true })
    expect(t.bindByRestore(hooked, 'omp', 'ed25519:omp').granted).toBe('restored')
    expect(t.bindByRestore(hooked, 'work', 'ed25519:work').granted).toBe('restored')
    expect(t.bindByRestore(dialog, 'omp', 'ed25519:omp').granted).toBe('restored')
    expect(hooked.notices.map(([m, p]) => `${m} ${String(p.as)} ${String(p.granted)}`)).toEqual([
      'service/bound omp restored',
      'service/bound work restored',
    ])
    // No speaking seat: the router is told it is a restore.
    expect(calls).toEqual([
      `bind omp ${hooked.handle} true`,
      `bind work ${hooked.handle} true`,
      `bind omp ${dialog.handle} true`,
    ])
    expect(t.notes(hooked.handle)).toEqual([
      'bag restarted; this window still acts as omp.',
      'bag restarted; this window still acts as work.',
    ])
    expect(t.notes(hooked.handle)).toEqual([])
    expect(t.require(hooked, 'send', 'work').label).toBe('work')
  })

  it('refuses a connection that can never bind, and one that already made a tool call: usage, nothing bound', async () => {
    const { t } = restoring(ids(['omp', 'home-key']))
    const neither = conn({ hook: false, elicit: false })
    expect(await code(() => t.bindByRestore(neither, 'omp', 'ed25519:omp'))).toBe('usage')
    const acted = conn({ hook: true })
    expect(await code(() => t.require(acted, 'status'))).toBe('not-bound')
    expect(await code(() => t.bindByRestore(acted, 'omp', 'ed25519:omp'))).toBe('usage')
    expect([t.state(neither), t.state(acted)]).toEqual(['unbound', 'unbound'])
  })

  it('the address must match: an identity removed and made again under the label does not come back', async () => {
    const { t } = restoring(ids(['omp', 'home-key']))
    const c = conn({ hook: true })
    expect(await code(() => t.bindByRestore(c, 'omp', 'ed25519:the-old-omp'))).toBe('unknown-identity')
    expect(await code(() => t.bindByRestore(c, 'gone', 'ed25519:gone'))).toBe('unknown-identity')
    expect(t.state(c)).toBe('unbound')
    // The window's next tool call says why, once, then how to bind.
    const e = (() => {
      try {
        t.require(c, 'send')
      } catch (x) {
        return (x as ToolError).message
      }
      return 'bound'
    })()
    expect(e).toBe(
      `not-bound: bag restarted and this window could not keep omp: it is no longer on this machine. bag restarted and this window could not keep gone: it is no longer on this machine. ${NOT_BOUND}`,
    )
    expect(() => t.require(c, 'send')).toThrow(`not-bound: ${NOT_BOUND}`)
  })

  it('lent: busy with the words; draining: draining, no words', async () => {
    const { t } = restoring(ids(['omp', 'home-key']))
    t.lend('omp', 'pair')
    const c = conn({ hook: true })
    expect(await code(() => t.bindByRestore(c, 'omp', 'ed25519:omp'))).toBe('busy')
    expect(t.notes(c.handle)).toEqual([
      'bag restarted and this window could not keep omp: a bag command is using it; your user types use omp when it is done.',
    ])
    const d = restoring(ids(['omp', 'home-key']), { draining: true })
    const e = conn({ hook: true })
    expect(await code(() => d.t.bindByRestore(e, 'omp', 'ed25519:omp'))).toBe('draining')
    expect(d.t.notes(e.handle)).toEqual([])
  })

  it('a restore on one connection binds that connection only: what the typed word gives a token holder, no more', () => {
    const { t } = restoring(ids(['omp', 'home-key'], ['work', 'home-key']))
    const window = conn({ hook: true })
    t.bindByWord(window, 'work')
    const other = conn({ hook: true })
    t.bindByRestore(other, 'omp', 'ed25519:omp')
    expect(t.as(window)).toBe('work')
    expect(t.as(other)).toBe('omp')
    expect(() => t.require(window, 'send', 'omp')).toThrow('this window is not bound to that identity')
    // The typed word on a third connection gives exactly the same.
    const typed = conn({ hook: true })
    t.bindByWord(typed, 'omp')
    expect(t.as(typed)).toBe('omp')
    expect(t.as(window)).toBe('work')
  })

  it('an agent-class restore asks no grant until the first act, and opens the identity at the first act only', async () => {
    // The identity was a key file before the restart and is agent custody now: the new class applies.
    const { t, calls } = restoring(ids(['ag', 'agent']))
    const c = conn({ hook: true })
    t.bindByRestore(c, 'ag', 'ed25519:ag')
    expect(calls).toEqual([`bind ag ${c.handle} true`])
    expect(t.require(c, 'send').custody).toBe('agent')
    await t.opened(c, 'ag')
    await t.opened(c, 'ag')
    expect(await t.grantOf(c, 'ag')).toEqual({ for: c.handle })
    expect(await t.grantOf(c, 'ag')).toEqual({ for: c.handle })
    expect(calls).toEqual([`bind ag ${c.handle} true`, 'open ag', `grant ag ${c.handle}`])
  })

  it('service/unbound only when a binding drops while the connection stays open: never at a close or a drain', () => {
    const identities = ids(['omp', 'home-key'], ['work', 'home-key'])
    const { t, home } = restoring(identities)
    const c = conn({ hook: true })
    t.bindByWord(c, 'omp')
    t.bindByWord(c, 'work')
    t.unbind(c, 'omp')
    expect(c.notices.filter(([m]) => m === 'service/unbound')).toEqual([['service/unbound', { as: 'omp' }]])
    c.close()
    expect(c.notices.filter(([m]) => m === 'service/unbound')).toHaveLength(1)
    const d = conn({ hook: true })
    t.bindByWord(d, 'omp')
    ;(home as { draining: boolean }).draining = true
    t.unbind(d)
    expect(d.notices.filter(([m]) => m === 'service/unbound')).toEqual([])
  })

  it('service/use takes via restored with its address; an unknown via or member is usage', async () => {
    const { t } = restoring(ids(['omp', 'home-key']))
    const use = serviceMethods(t)['service/use'] as NonNullable<ReturnType<typeof serviceMethods>[string]>
    const c = conn({ hook: true })
    expect(await use(c, { label: 'omp', via: 'restored', address: 'ed25519:omp', subagent: false })).toEqual({
      bound: true,
      as: 'omp',
      address: 'ed25519:omp',
      custody: 'home-key',
      granted: 'restored',
    })
    expect(await code(use(c, { label: 'omp', via: 'again' }))).toBe('usage')
    expect(await code(use(c, { label: 'omp', via: 'restored', when: 1 }))).toBe('usage')
  })
})

// The question card (design 2026-11-24, section 7): the bind dialog's card answer, read by pairing.ts cardSaid. The
// card's No is the person's No, remembered as for bind: false; no answer binds and remembers nothing.
describe('the bind dialog: a card answer (cardSaid)', () => {
  const card = (content: Record<string, unknown>): Answer =>
    ({ action: 'accept', content: { bag_open_ms: 4000, ...content } }) as ElicitResult
  const message = async (p: Promise<unknown>): Promise<string> =>
    p.then(
      () => 'ok',
      (e: unknown) => (e as Error).message,
    )
  const bindings = (step = 1000) => {
    let t = 0
    const home = {
      home: `/h${homes++}`,
      identities: () => ids(['omp', 'home-key'], ['id-c', 'home-key']),
      draining: false,
    }
    return new Bindings(home, { mono: () => (t += step), custody: () => 'home-key' })
  }

  for (const surface of ['claude-vscode', 'claude-desktop']) {
    it(`${surface}: a marked Yes binds, the pick by its exact label (under Other too); a marked Yes without bind: true binds nothing`, async () => {
      expect(
        (
          await bindings().bindByDialog(
            conn({ person: [card({ bind: true, bag_card: 'yes' })], surface }),
            'omp',
          )
        ).granted,
      ).toBe('dialog')
      const pick = (identity: string, mark: string) =>
        conn({ person: [card({ identity, bag_card: mark })], surface })
      expect((await bindings().bindByDialog(pick('omp', 'yes'))).label).toBe('omp')
      expect((await bindings().bindByDialog(pick('id-c', 'other'))).label).toBe('id-c')
      for (const [identity, mark] of [
        ['ID-C', 'other'],
        ['x'.repeat(600), 'other'],
        ['nope', 'yes'],
      ]) {
        const c = pick(identity as string, mark as string)
        const b = bindings()
        expect(await code(b.bindByDialog(c))).toBe('cancelled')
        expect(b.state(c)).toBe('unbound')
      }
      const b = bindings()
      const c = conn({ person: [card({ bind: false, bag_card: 'yes' }), yes], surface })
      expect(await code(b.bindByDialog(c, 'omp'))).toBe('cancelled')
      expect((await b.bindByDialog(c, 'omp')).granted).toBe('dialog')
    })

    it(`${surface}: the card's No is declined and remembered: the next bind of that label asks nothing`, async () => {
      for (const content of [{ bind: false, bag_card: 'no' }, { bag_card: 'no' }]) {
        const b = bindings()
        const c = conn({ person: [card(content), yes], surface })
        expect(await code(b.bindByDialog(c, 'omp'))).toBe('declined')
        expect(await code(b.bindByDialog(c, 'omp'))).toBe('declined')
        expect([c.dialogs.length, b.state(c)]).toEqual([1, 'unbound'])
      }
    })

    it(`${surface}: the card's No on a pick is declined, saying the window acts as no identity`, async () => {
      const c = conn({ person: [card({ identity: 'omp', bag_card: 'no' })], surface })
      const e = await bindings()
        .bindByDialog(c)
        .catch((x: unknown) => x)
      expect([(e as ToolError).code, (e as ToolError).message]).toEqual([
        'declined',
        'declined: your user said No: this window acts as no identity',
      ])
    })

    it(`${surface}: dismissed, idle, Other and an unknown marker are no answer: nothing bound or remembered, asked again`, async () => {
      for (const mark of ['dismissed', 'idle', 'other', 'maybe']) {
        const b = bindings()
        const c = conn({ person: [card({ bind: true, bag_card: mark }), yes], surface })
        expect([mark, await code(b.bindByDialog(c, 'omp'))]).toEqual([mark, 'cancelled'])
        expect(b.state(c)).toBe('unbound')
        expect((await b.bindByDialog(c, 'omp')).granted).toBe('dialog')
        expect(c.dialogs).toHaveLength(2)
      }
    })

    it(`${surface}: a seen card closed (dismissed) says the person closed it; idle, Other and an unknown marker did not reach them`, async () => {
      for (const label of ['omp', undefined]) {
        const field = label === undefined ? { identity: 'omp' } : { bind: true }
        const closed = conn({ person: [card({ ...field, bag_card: 'dismissed' })], surface })
        expect(await message(bindings().bindByDialog(closed, label))).toBe(`cancelled: ${BIND_CLOSED}`)
        // Other on a pick is the typed label (it binds 'omp'), so it is a no answer on the confirm alone.
        for (const mark of label === undefined ? ['idle', 'maybe'] : ['idle', 'other', 'maybe']) {
          const c = conn({ person: [card({ ...field, bag_card: mark })], surface })
          expect([mark, await message(bindings().bindByDialog(c, label))]).toEqual([
            mark,
            `cancelled: ${NOT_REACHED}`,
          ])
        }
      }
    })

    it(`${surface}: a dismissal open under 250 ms, and a marked Yes in 10 ms, are no-elicitation`, async () => {
      const b = bindings()
      const c = conn({ person: [card({ bag_card: 'dismissed', bag_open_ms: 40 }), yes], surface })
      expect(await code(b.bindByDialog(c, 'omp'))).toBe('no-elicitation')
      expect((await b.bindByDialog(c, 'omp')).granted).toBe('dialog')
      const fast = conn({ person: [card({ bind: true, bag_card: 'yes' })], surface })
      expect(await code(bindings(10).bindByDialog(fast, 'omp'))).toBe('no-elicitation')
    })
  }

  it('the terminal (cli) and no surface refuse a marker as no answer: a marked No remembers nothing, a marked Yes binds nothing', async () => {
    for (const surface of ['cli', undefined]) {
      for (const content of [
        { bind: false, bag_card: 'no' },
        { bind: true, bag_card: 'yes' },
      ]) {
        const b = bindings()
        const c = conn({ person: [card(content), yes], ...(surface ? { surface } : {}) })
        expect(await code(b.bindByDialog(c, 'omp'))).toBe('cancelled')
        expect((await b.bindByDialog(c, 'omp')).granted).toBe('dialog')
      }
      // No card is drawn here, so a dismissal mark says nothing about what the person saw.
      const forged = conn({
        person: [card({ bind: true, bag_card: 'dismissed' })],
        ...(surface ? { surface } : {}),
      })
      expect(await message(bindings().bindByDialog(forged, 'omp'))).toBe(`cancelled: ${NOT_REACHED}`)
      // Unmarked, a decline is the person's No, remembered (the decline rule below).
      const b = bindings()
      const c = conn({ person: [{ action: 'decline' }], ...(surface ? { surface } : {}) })
      expect(await code(b.bindByDialog(c, 'omp'))).toBe('declined')
      expect(await code(b.bindByDialog(c, 'omp'))).toBe('declined')
      expect(c.dialogs).toHaveLength(1)
    }
  })
})

// The decline rule (2026-11-24): a decline left after the timing (250 ms or more, on a surface that shows its dialogs) is
// the person's No, remembered for a named bind; an accept without bind: true (an untouched switch, opencode) is no
// answer, remembering nothing; a cancel stays cancelled.
describe('the bind dialog: only a decline is a No (2026-11-24)', () => {
  const at = (step: number) => {
    let t = 0
    const home = { home: `/h${homes++}`, identities: () => ids(['omp', 'home-key']), draining: false }
    return new Bindings(home, { mono: () => (t += step), custody: () => 'home-key' })
  }

  it('a decline at 900 ms on cli is declined and remembered; on claude-vscode it is unseen, remembering nothing', async () => {
    const b = at(900)
    const c = conn({ person: [{ action: 'decline' }, yes], surface: 'cli' })
    expect([await code(b.bindByDialog(c, 'omp')), await code(b.bindByDialog(c, 'omp'))]).toEqual([
      'declined',
      'declined',
    ])
    expect(c.dialogs).toHaveLength(1)
    const v = at(900)
    const d = conn({ person: [{ action: 'decline' }, yes], surface: 'claude-vscode' })
    expect(await code(v.bindByDialog(d, 'omp'))).toBe('no-elicitation')
    expect((await v.bindByDialog(d, 'omp')).granted).toBe('dialog')
  })

  it('an unmarked accept with bind: false, or with no bind, is cancelled on cli and with no surface, remembering nothing', async () => {
    for (const surface of ['cli', undefined])
      for (const content of [{ bind: false }, {}]) {
        const b = at(900)
        const c = conn({ person: [{ action: 'accept', content }, yes], ...(surface ? { surface } : {}) })
        expect(await code(b.bindByDialog(c, 'omp'))).toBe('cancelled')
        expect((await b.bindByDialog(c, 'omp')).granted).toBe('dialog')
      }
  })

  it('a cancel at 900 ms on cli is cancelled, remembering nothing', async () => {
    const b = at(900)
    const c = conn({ person: [{ action: 'cancel' }, yes], surface: 'cli' })
    expect(await code(b.bindByDialog(c, 'omp'))).toBe('cancelled')
    expect((await b.bindByDialog(c, 'omp')).granted).toBe('dialog')
  })

  it("a pick's decline at 900 ms on cli is declined with nothing to remember: the next pick binds", async () => {
    const b = at(900)
    const c = conn({
      person: [{ action: 'decline' }, { action: 'accept', content: { identity: 'omp' } }],
      surface: 'cli',
    })
    expect(await code(b.bindByDialog(c))).toBe('declined')
    expect((await b.bindByDialog(c)).label).toBe('omp')
  })
})

describe('the bind dialog: no answer spends the unanswered allowances of bind', () => {
  /** A home of its own whose clock the test moves; each mono read is `step` ms (a person's pace by default). */
  const world = () => {
    const home = { home: `/h${homes++}`, identities: () => ids(['omp', 'home-key']), draining: false }
    const w = { clock: 1_800_000_000, step: 1000, mono: 0 }
    const t = new Bindings(home, {
      mono: () => (w.mono += w.step),
      now: () => w.clock,
      custody: () => 'home-key',
    })
    return { w, t }
  }
  const timedOut = () => new ToolError('cancelled', TIMED_OUT)
  const dismissed = (): Answer => ({ action: 'cancel' })
  // These windows pass no typed word (no input hook): a new window has its own allowance.
  const left = (_label?: string) =>
    `rate-limited: bind was left unanswered ${UNANSWERED_PER_WINDOW} times lately here: ask again in ${ASK_EVERY_S} s, or in a new window`
  const message = async (p: Promise<unknown>): Promise<string> =>
    p.then(
      () => 'ok',
      (e: unknown) => (e as Error).message,
    )
  const allowance = Array.from({ length: UNANSWERED_PER_WINDOW })

  for (const [what, answer] of [
    ['dismissed', () => dismissed()],
    ["ended by bag's own bound", timedOut],
    ['dismissed and ended by the bound in turn', (i: number) => (i % 2 === 0 ? dismissed() : timedOut())],
  ] as const) {
    it(`${what}: the next bind past the allowance is rate-limited, left unanswered, and raises no dialog`, async () => {
      const { t } = world()
      const c = conn({ person: allowance.map((_, i) => answer(i)) })
      for (const [i] of allowance.entries()) {
        const label = i % 2 === 0 ? 'omp' : undefined
        expect(await message(t.bindByDialog(c, label))).toMatch(
          /^cancelled: (the bind dialog did not reach|no answer in time)/,
        )
      }
      expect(c.dialogs).toHaveLength(UNANSWERED_PER_WINDOW)
      expect(await message(t.bindByDialog(c, 'omp'))).toBe(left('omp'))
      expect(await message(t.bindByDialog(c))).toBe(left(undefined))
      expect(c.dialogs).toHaveLength(UNANSWERED_PER_WINDOW)
    })
  }

  it('the home counts every window together: past its cap a new window raises no dialog', async () => {
    const { t } = world()
    for (const _ of [1, 2]) {
      const c = conn()
      for (const _a of allowance) expect(await code(t.bindByDialog(c, 'omp'))).toBe('cancelled')
      expect(await code(t.bindByDialog(c, 'omp'))).toBe('rate-limited')
    }
    const fresh = conn()
    expect(await message(t.bindByDialog(fresh, 'omp'))).toMatch(
      /^rate-limited: bind was left unanswered 12 times lately by all windows of this bag home together/,
    )
    expect(fresh.dialogs).toEqual([])
  })

  it('a window that closes while its dialog stands spends nothing: the home count is unchanged', async () => {
    const { t } = world()
    for (const _ of allowance) {
      const c = conn()
      const elicit = c.elicit.bind(c)
      // The window goes while its card stands.
      Object.assign(c, {
        elicit: async (p: ElicitRequestFormParams) => {
          c.close()
          return elicit(p)
        },
      })
      expect(await message(t.bindByDialog(c, 'omp'))).toBe(`cancelled: ${NOT_REACHED}`)
      expect(c.dialogs).toHaveLength(1)
    }
    // Had the closes spent, these six would take the home to its cap of 12 and the next window would get no dialog.
    const other = conn()
    for (const _ of allowance) expect(await code(t.bindByDialog(other, 'omp'))).toBe('cancelled')
    const third = conn()
    expect(await code(t.bindByDialog(third, 'omp'))).toBe('cancelled')
    expect(third.dialogs).toHaveLength(1)
  })

  it('an answer faster than a person (no-elicitation) on claude-vscode spends nothing', async () => {
    const { w, t } = world()
    w.step = 10
    const c = conn({ surface: 'claude-vscode' })
    for (const _ of [...allowance, 0]) expect(await code(t.bindByDialog(c, 'omp'))).toBe('no-elicitation')
    expect(c.dialogs).toHaveLength(UNANSWERED_PER_WINDOW + 1)
  })

  it('a No spends nothing and is still remembered: the label is declined without a dialog', async () => {
    const { t } = world()
    const c = conn({ person: [{ action: 'decline' }], surface: 'cli' })
    expect(await code(t.bindByDialog(c, 'omp'))).toBe('declined')
    // The whole allowance is still there for the pick.
    for (const _ of allowance) expect(await code(t.bindByDialog(c))).toBe('cancelled')
    expect(await code(t.bindByDialog(c))).toBe('rate-limited')
    expect(await message(t.bindByDialog(c, 'omp'))).toMatch(/^declined: your user said No to omp/)
    expect(c.dialogs).toHaveLength(UNANSWERED_PER_WINDOW + 1)
  })

  it('the typed use is never paced: it binds while the dialog is rate-limited', async () => {
    const { t } = world()
    const c = conn({ hook: true })
    for (const _ of allowance) await t.bindByDialog(c, 'omp').catch(() => {})
    expect(await code(t.bindByDialog(c, 'omp'))).toBe('rate-limited')
    expect(t.bindByWord(c, 'omp').granted).toBe('typed')
  })

  it('after ASK_EVERY_S the dialog is asked again', async () => {
    const { w, t } = world()
    const c = conn()
    for (const _ of allowance) await t.bindByDialog(c, 'omp').catch(() => {})
    expect(await code(t.bindByDialog(c, 'omp'))).toBe('rate-limited')
    w.clock += ASK_EVERY_S
    c.person.push(yes)
    expect((await t.bindByDialog(c, 'omp')).granted).toBe('dialog')
    expect(c.dialogs).toHaveLength(UNANSWERED_PER_WINDOW + 1)
  })
})

describe("the bind's texts name the typed use only where the host passes it to bag", () => {
  const TYPED = ['type use', 'typing use', 'types use']
  const none = (text: string) => {
    for (const t of TYPED) expect(text).not.toContain(t)
  }
  const at = () => {
    const home = { home: `/h${homes++}`, identities: () => ids(['omp', 'home-key']), draining: false }
    let t = 0
    return new Bindings(home, {
      mono: () => (t += 1000),
      now: () => 1_800_000_000,
      custody: () => 'home-key',
    })
  }
  const head =
    'Act as omp in this window?\nIts tools then act as omp until it closes.\nNo: not asked again in this window for 5 minutes'
  const message = (p: Promise<unknown>): Promise<string> =>
    p.then(
      () => 'ok',
      (e: unknown) => (e as Error).message,
    )

  it("the named bind dialog's message: the typed use with an input hook, the five minutes alone without", async () => {
    const hooked = conn({ hook: true })
    await at()
      .bindByDialog(hooked, 'omp')
      .catch(() => {})
    expect(hooked.dialogs[0]?.message).toBe(`${head}; typing use omp binds it at any time.`)
    const plain = conn()
    await at()
      .bindByDialog(plain, 'omp')
      .catch(() => {})
    expect(plain.dialogs[0]?.message).toBe(`${head}.`)
    none(String(plain.dialogs[0]?.message))
  })

  it("the rate-limited refusal, this window's row and the home's: the typed use with a hook; a new window without, on the window's row only", async () => {
    const wait = `ask again in ${ASK_EVERY_S} s`
    const here = `rate-limited: bind was left unanswered ${UNANSWERED_PER_WINDOW} times lately here: ${wait}`
    const home = `rate-limited: bind was left unanswered ${2 * UNANSWERED_PER_WINDOW} times lately by all windows of this bag home together, past the cap for all of them: ${wait}`
    for (const hook of [true, false]) {
      const t = at()
      const [a, b] = [conn({ hook }), conn({ hook })]
      for (const c of [a, b])
        for (const _ of Array.from({ length: UNANSWERED_PER_WINDOW }))
          await t.bindByDialog(c, 'omp').catch(() => {})
      const [w, h] = [
        await message(t.bindByDialog(a, 'omp')),
        await message(t.bindByDialog(conn({ hook }), 'omp')),
      ]
      if (hook) {
        expect(w).toBe(`${here}; your user can type use omp at any time`)
        expect(h).toBe(`${home}; your user can type use omp at any time`)
      } else {
        expect(w).toBe(`${here}, or in a new window`)
        expect(h).toBe(home)
        none(w)
        none(h)
      }
    }
  })

  it('not-bound: the typed use and the dialog with a hook; the dialog alone without; neither way where neither works', () => {
    const t = at()
    expect(() => t.require(conn({ hook: true }), 'send')).toThrow(`not-bound: ${NOT_BOUND}`)
    expect(() => t.require(conn(), 'send')).toThrow(`not-bound: ${NOT_BOUND_DIALOG}`)
    expect(NOT_BOUND_DIALOG).toBe(
      'this window acts as no identity yet: your user asks you to use an identity and answers the bind dialog (the use tool opens it); only their Yes binds; you cannot choose for them',
    )
    none(NOT_BOUND_DIALOG)
    expect(() => t.require(conn({ elicit: false }), 'send')).toThrow(`not-bound: ${CANNOT_BIND}`)
    // With no connection at hand, both ways, each with where it works.
    const ctx = { config: { home: '/h', label: 'a' } } as unknown as ToolContext
    expect(() => servicePairings(ctx, null, () => ({}) as never)).toThrow(`not-bound: ${NOT_BOUND_ANY}`)
    expect(NOT_BOUND_ANY).toContain('where the host passes typed words to bag (Claude Code, omp)')
  })
})

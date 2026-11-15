import { generateEdgeKeys } from '@usebag/edge'
import type { AgentSession } from '@usebag/edge/agent'
import { describe, expect, it } from 'vitest'
import { Bindings, type HomeIdentity, type ServiceConnection } from '../src/binding.ts'
import { ConfigError } from '../src/config.ts'
import { GrantSlot, regrantLine } from '../src/regrant.ts'
import {
  type ConnectionGrant,
  regrantConnection,
  renewConnection,
  type WindowGrant,
  windowGrant,
} from '../src/session.ts'
import { seededRng } from './support/ports.ts'

// The regrant wiring below the service: the agent's renewal and new first grant for a window (session.ts), and the
// binding table's slots with the person-only reset (binding.ts). The service's own cases are in
// service-agent-regrant.test.ts.

const NOW = 1_800_000_000
const CAVEATS = ['type=chat.v1']
const clock = { now: () => NOW }
let seed = 0

function first(): ConnectionGrant {
  const keys = generateEdgeKeys(seededRng(`wiring-${seed++}`))
  return {
    keys,
    hop: { iss: 'ed25519:jane', sub: keys.signing.address, caveats: CAVEATS, exp: NOW + 3600, sig: 's' },
  }
}

describe('hook 1: the agent calls for a window', () => {
  it('renewConnection signs for the window own key, presenting its chain, and closes the client', async () => {
    const g = windowGrant(first())
    const seen: AgentSession[] = []
    let closed = 0
    const renewed = await renewConnection('/h', g, {
      clock,
      connect: (s) => {
        seen.push(s)
        return {
          sign: async (sub, caveats, exp) => ({ iss: g.iss, sub, caveats, exp, sig: 't' }),
          close: () => void closed++,
        }
      },
    })
    expect(seen[0]?.key).toBe(g.keys.signing)
    expect(seen[0]?.chain).toEqual([g.hop])
    expect(renewed.sub).toBe(g.sub)
    expect(renewed.keys).toBe(g.keys)
    expect(renewed.exp).toBeGreaterThan(NOW)
    expect(closed).toBe(1)
  })

  it("renewConnection throws the agent's code as a ConfigError", async () => {
    const g = windowGrant(first())
    const e = await renewConnection('/h', g, {
      clock,
      connect: () => ({
        sign: async () => {
          throw Object.assign(new Error('refused'), { code: 'not-in-grant' })
        },
        close: () => {},
      }),
    }).catch((x: unknown) => x)
    expect(e).toBeInstanceOf(ConfigError)
    expect((e as ConfigError).code).toBe('not-in-grant')
  })

  it('regrantConnection hands each agent client to onClient, so a drain can close it, and grants a fresh key', async () => {
    const clients: unknown[] = []
    const g = await regrantConnection('/h', {
      rng: seededRng('wiring-regrant'),
      clock,
      caveats: CAVEATS,
      connect: () => ({
        grant: async (session: string, caveats: readonly string[], exp: number) => ({
          ok: true as const,
          hop: { iss: 'ed25519:jane', sub: session, caveats: [...caveats], exp, sig: 's' },
        }),
        close: () => {},
      }),
      onClient: (c) => clients.push(c),
    })
    expect(clients.length).toBe(1)
    expect(g.sub).toBe(g.keys.signing.address)
  })
})

// The binding table with an agent identity: a fake hooked connection (the person's typed use).
let n = 0
function hooked(): ServiceConnection & { close(): void } {
  const closers = new Set<() => void>()
  const c = {
    handle: `w${(n++).toString(16).padStart(32, '0')}`,
    host: 'omp',
    cwd: '/work',
    capabilities: { elicitation: false, inputHook: true, raw: {} },
    closed: false,
    onClose: (fn: () => void) => {
      closers.add(fn)
      return () => closers.delete(fn)
    },
    elicit: async () => ({ action: 'cancel' }),
    notify: () => {},
    close() {
      c.closed = true
      for (const f of [...closers]) f()
    },
  }
  return c as unknown as ServiceConnection & { close(): void }
}

function rig(o: { grant?: () => Promise<ConnectionGrant>; slots?: boolean } = {}) {
  const ids: HomeIdentity[] = [{ label: 'jane', address: 'ed25519:jane', custody: 'agent' }]
  const r = { grants: 0, regrants: 0, aborts: 0, slots: [] as GrantSlot<WindowGrant>[] }
  const t = new Bindings(
    { home: '/h', identities: () => ids, draining: false },
    {
      mono: () => 0,
      now: () => NOW,
      custody: () => 'agent',
      grant: async () => {
        r.grants += 1
        return (o.grant ?? (async () => first()))()
      },
      ...(o.slots === false
        ? {}
        : {
            slot: (_c: ServiceConnection, _l: string, g: WindowGrant) => {
              const s = new GrantSlot<WindowGrant>(g, {
                now: () => NOW,
                renew: async (x) => x,
                regrant: async () => {
                  r.regrants += 1
                  return new Promise<WindowGrant>(() => {})
                },
                abort: () => void r.aborts++,
                words: (code) => regrantLine({ label: 'jane', host: 'omp', connection: 'w', code }),
              })
              r.slots.push(s)
              return s
            },
          }),
    },
  )
  return { t, r }
}

const settle = (): Promise<void> => new Promise((done) => setImmediate(done))

describe('hooks 2 and 3: the binding table slots and the person-only reset', () => {
  it('a window act signs under its slot (grantOf through forAct)', async () => {
    const { t, r } = rig()
    const c = hooked()
    t.bindByWord(c, 'jane')
    const g = (await t.grantOf(c, 'jane')) as WindowGrant
    expect(g.sub).toBe(g.keys.signing.address)
    expect(r.slots.length).toBe(1)
  })

  it('a second typed use on a live bound window asks the agent nothing', async () => {
    const { t, r } = rig()
    const c = hooked()
    t.bindByWord(c, 'jane')
    await t.grantOf(c, 'jane')
    t.bindByWord(c, 'jane')
    await settle()
    expect([r.grants, r.regrants]).toEqual([1, 0])
  })

  it('a first grant that failed is asked afresh by the next typed use', async () => {
    let calls = 0
    const { t, r } = rig({
      grant: async () => {
        calls += 1
        if (calls === 1) throw new ConfigError('declined', 'n')
        return first()
      },
    })
    const c = hooked()
    t.bindByWord(c, 'jane')
    await settle()
    t.bindByWord(c, 'jane')
    await settle()
    expect(r.grants).toBe(2)
    expect((await t.grantOf(c, 'jane')).hop.sub).toBeDefined()
  })

  it('an unbind cancels the slot and closes an ask in flight at the agent', async () => {
    const { t, r } = rig()
    const c = hooked()
    t.bindByWord(c, 'jane')
    const slot = await (async () => {
      await t.grantOf(c, 'jane')
      return r.slots[0] as GrantSlot<WindowGrant>
    })()
    slot.markLost('revoked')
    await t.grantOf(c, 'jane').catch(() => {})
    t.unbind(c, 'jane')
    await settle()
    expect([r.regrants, r.aborts]).toEqual([1, 1])
  })

  it('after a decline, a reconnected window asks nothing until the person binds it', async () => {
    const { t, r } = rig({
      grant: async () => {
        throw new ConfigError('declined', 'n')
      },
    })
    const before = hooked()
    t.bindByWord(before, 'jane')
    await settle()
    expect(r.grants).toBe(1)
    // The shim reconnects: the old connection closes and a new one from the same host and folder arrives.
    before.close()
    const after = hooked()
    await settle()
    // No automatic rebind: the new window is unbound, an act there is not-bound, and the agent was asked nothing.
    expect(t.state(after)).toBe('unbound')
    expect(await t.grantOf(after, 'jane').catch((e: { code?: string }) => e.code)).toBe('not-bound')
    expect([r.grants, r.regrants]).toEqual([1, 0])
    // Only the person's typed use asks again, once.
    t.bindByWord(after, 'jane')
    await settle()
    expect(r.grants).toBe(2)
  })

  it('with no slot maker the table keeps the first grant as before', async () => {
    const { t, r } = rig({ slots: false })
    const c = hooked()
    t.bindByWord(c, 'jane')
    const g = await t.grantOf(c, 'jane')
    expect(g.hop.sub).toBe(g.keys.signing.address)
    expect(r.slots.length).toBe(0)
  })
})

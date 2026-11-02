import {
  buildEnvelope,
  codingEvaluator,
  type Hop,
  type MembersRecord,
  newThread,
  type PolicyRecord,
  signHop,
  signPolicyRecord,
  type Thread,
  type UnsignedMembersRecord,
  type UnsignedPolicyRecord,
} from '@usebag/core'
import { expect } from 'vitest'
import { SqliteStore } from '../../src/adapters/sqlite-store.ts'
import { Edge, type EdgeOptions } from '../../src/edge.ts'
import type { Moderator } from '../../src/moderation/modules.ts'
import type { TrustedRoot } from '../../src/policy.ts'
import type { EdgeStore, InboundMessage, RelayClient, SessionHandler } from '../../src/ports.ts'
import { coreRng } from '../../src/sender.ts'
import {
  addressRecord,
  FakeClock,
  FakeRecords,
  MemoryAuditSink,
  P,
  type Party,
  seededRng,
  T0,
} from './fixtures.ts'
import { ScriptedRelay } from './relays.ts'

// The org policy's edge fixtures: the two policy records signed by the org root P.org (acme.test's key), the
// served one and the members one, bob's edge under them, and envelopes from the cast. Public test data from fixed seeds.

export const HOME = 'http://home.test'
export const ACME = 'acme.test'
const rng = coreRng(seededRng('org-policy'))

/** The served policy record signed by P.org: no scopes and no external rules unless given. */
export function orgPolicy(o: Partial<UnsignedPolicyRecord> = {}): PolicyRecord {
  return signPolicyRecord(P.org.signing, {
    kind: 'policy',
    key: P.org.address,
    scopes: [],
    external: null,
    inspection: null,
    iat: T0,
    ...o,
  })
}

/** The members record signed by P.org: every section null unless given. */
export function members(o: Partial<UnsignedMembersRecord> = {}): MembersRecord {
  return signPolicyRecord(P.org.signing, {
    kind: 'policy-members',
    key: P.org.address,
    roots: null,
    rates: null,
    outbound: null,
    moderation: null,
    iat: T0,
    ...o,
  })
}

/** acme.test's well-known record, carol's and mallory's address records at the home relay. */
export function records(): FakeRecords {
  const r = new FakeRecords()
  r.domain(ACME, addressRecord(P.org, { relays: [HOME], ttl: 86_400 }))
  r.put(HOME, addressRecord(P.carol))
  r.put(HOME, addressRecord(P.mallory))
  return r
}

export interface Bob {
  readonly edge: Edge
  readonly store: EdgeStore
  readonly audit: MemoryAuditSink
  readonly clock: FakeClock
  readonly got: InboundMessage[]
}

/** Bob's edge under an org policy: it trusts carol by key and acme.test by domain unless told otherwise. */
export function bob(
  o: {
    org?: PolicyRecord
    members?: MembersRecord
    maxQuarantined?: number
    roots?: TrustedRoot[]
    moderators?: Moderator[]
    timeoutMs?: number
    store?: EdgeStore
    relay?: RelayClient
    records?: FakeRecords
    clock?: FakeClock
    audit?: MemoryAuditSink
    gate?: EdgeOptions['gate']
  } = {},
): Bob {
  const audit = o.audit ?? new MemoryAuditSink()
  const clock = o.clock ?? new FakeClock()
  const store = o.store ?? new SqliteStore(':memory:')
  const edge = new Edge({
    keys: P.bob.keys,
    store,
    relays: { client: o.relay ?? new ScriptedRelay(), urls: [HOME] },
    records: o.records ?? records(),
    policy: {
      roots: o.roots ?? [{ address: P.carol.address }, { domain: ACME }],
      types: ['*'],
      evaluators: [codingEvaluator],
      ...(o.org === undefined ? {} : { org: o.org }),
      ...(o.members === undefined ? {} : { members: o.members }),
      ...(o.maxQuarantined === undefined ? {} : { maxQuarantined: o.maxQuarantined }),
      ...(o.moderators === undefined ? {} : { moderators: o.moderators }),
      ...(o.timeoutMs === undefined ? {} : { moderationTimeoutMs: o.timeoutMs }),
    },
    clock,
    rng: seededRng('bob'),
    audit,
    ...(o.gate === undefined ? {} : { gate: o.gate }),
  })
  const got: InboundMessage[] = []
  const handler: SessionHandler = { session: 'bob', deliver: (m) => void got.push(m) }
  edge.setDefault(handler)
  return { edge, store, audit, clock, got }
}

export interface Built {
  readonly id: string
  readonly bytes: Uint8Array
  readonly thread: Thread
}

/** An envelope to bob, from carol by default, self-rooted, chat.v1. */
export function envelope(
  o: {
    from?: Party
    to?: readonly Party[]
    auth?: readonly Hop[]
    type?: string
    body?: unknown
    ts?: number
    thread?: Thread
  } = {},
): Built {
  const thread = o.thread ?? newThread(rng)
  const built = buildEnvelope({
    from: (o.from ?? P.carol).signing,
    to: (o.to ?? [P.bob]).map((p) => ({ address: p.address, sealingKey: p.sealing.publicKey })),
    auth: o.auth ?? [],
    type: o.type ?? 'chat.v1',
    thread,
    body: o.body ?? { text: 'hello' },
    ts: o.ts ?? T0,
    rng,
  })
  return { id: built.envelope.id, bytes: built.bytes, thread }
}

/** The chain org -> jane -> session (acme's), with the caveats each hop adds and each hop's exp. */
export function acmeChain(
  caveats: readonly string[] = [],
  exps: readonly [number, number] = [T0 + 3600, T0 + 3600],
) {
  return [
    signHop(P.org.signing, P.jane.address, caveats, exps[0]),
    signHop(P.jane.signing, P.session.address, [], exps[1]),
  ]
}

/** The audit lines' "event decision reason rule" for compact assertions, without the resolver's resolve and pin lines. */
export function ruled(audit: MemoryAuditSink): string[] {
  const lines = audit.lines.filter((l) => !/^\{[^}]*"event":"(resolve|pin)"/.test(l))
  return lines.map((l) => {
    const v = JSON.parse(l) as { event: string; decision: string; reason: string; detail: string | null }
    const rule = v.detail === null ? undefined : (JSON.parse(v.detail) as { rule?: string }).rule
    return [v.event, v.decision, v.reason, rule].filter((x) => x !== undefined).join(' ')
  })
}

/** No quarantined row holds content, at any point a test reads the store. */
export function heldHaveNoContent(store: EdgeStore): number {
  const held = store.inboxList(['quarantined'])
  for (const r of held) expect(r.content, `row ${r.seq}`).toBeNull()
  return held.length
}

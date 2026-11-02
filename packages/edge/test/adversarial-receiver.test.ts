import {
  buildEnvelope,
  type Envelope,
  envelopeId,
  fromHex,
  type Hop,
  newThread,
  parseEnvelope,
  serializeEnvelope,
  signHop,
  toHex,
  verifyOuter,
} from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { verifyAuditLog } from '../src/audit.ts'
import { Edge } from '../src/edge.ts'
import type { TrustedRoot } from '../src/policy.ts'
import type { InboundMessage } from '../src/ports.ts'
import { coreRng } from '../src/sender.ts'
import {
  addressRecord,
  FakeClock,
  FakeRecords,
  MemoryAuditSink,
  P,
  type Party,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { ScriptedRelay } from './support/relays.ts'

// The edge halves of the duplicate check, F2 and F6(a), on the TypeScript edge in process (V3).
// Duplicate: the same bytes delivered twice are accepted once, the handler called once, the second audited `duplicate`.
// F2: the sealed part of a genuine envelope re-signed by another key (from replaced, id recomputed, sig by the
//     attacker, chain []): open-failed when the attacker's root is trusted, untrusted-root when it is not.
// F6(a): chain [] from an attacker key to a mailbox that trusts an org root: untrusted-root.

const HOME = 'http://127.0.0.1:9'
const OTHER = 'http://127.0.0.1:10'
const ACME = 'acme.test'
const rng = coreRng(seededRng('adversarial-receiver'))

function envelope(from: Party, o: { auth?: readonly Hop[]; ts?: number } = {}) {
  const built = buildEnvelope({
    from: from.signing,
    to: [{ address: P.bob.address, sealingKey: P.bob.sealing.publicKey }],
    auth: o.auth ?? [],
    type: 'chat.v1',
    thread: newThread(rng),
    body: { text: 'hello' },
    ts: o.ts ?? T0,
    rng,
  })
  return { id: built.envelope.id, bytes: built.bytes, envelope: built.envelope }
}

/** acme.test's well-known record (the org root), revoking no one, and the same record at the home relay. */
function acme(): FakeRecords {
  const records = new FakeRecords()
  records.domain(ACME, addressRecord(P.org, { relays: [HOME], ttl: 86_400 }))
  records.put(HOME, addressRecord(P.org, { relays: [HOME], ttl: 86_400 }))
  return records
}

/** Bob's edge with the given trusted roots, a default handler that counts what it is given, and its audit. */
function bob(roots: TrustedRoot[]) {
  const audit = new MemoryAuditSink()
  const delivered: InboundMessage[] = []
  const edge = new Edge({
    keys: P.bob.keys,
    store: new SqliteStore(':memory:'),
    relays: { client: new ScriptedRelay(), urls: [HOME] },
    records: acme(),
    policy: { roots, types: ['chat.*'] },
    clock: new FakeClock(),
    rng: seededRng('adversarial-bob'),
    audit,
  })
  edge.setDefault({ session: 'inbox', deliver: (m) => void delivered.push(m) })
  return { edge, audit, delivered }
}

/** F2's forgery: the genuine sealed part under `attacker`'s from, a recomputed id, the attacker's sig, chain []. */
function resign(genuine: Envelope, attacker: Party): Uint8Array {
  const unsigned = { ...genuine, from: attacker.address, auth: [] }
  const id = envelopeId(unsigned)
  const sig = toHex(attacker.signing.sign(fromHex(id, 32)))
  return serializeEnvelope({ ...unsigned, id, sig })
}

describe('duplicate (edge half): the same bytes delivered twice are accepted once', () => {
  it('a second delivery through another relay and cursor: rejected duplicate, the handler called once', async () => {
    const { edge, audit, delivered } = bob([{ address: P.carol.address }])
    const e = envelope(P.carol)
    // The positive control: the first delivery is accepted and handed to the handler.
    expect(await edge.receive(HOME, 1, e.bytes)).toMatchObject({
      state: 'routed',
      session: 'inbox',
      id: e.id,
    })
    expect(delivered.map((m) => m.id)).toEqual([e.id])
    expect(await edge.receive(OTHER, 7, e.bytes)).toMatchObject({
      state: 'rejected',
      reason: 'duplicate',
      id: e.id,
    })
    expect(await edge.receive(HOME, 2, e.bytes)).toMatchObject({
      state: 'rejected',
      reason: 'duplicate',
      id: e.id,
    })
    expect(delivered).toHaveLength(1)
    expect(audit.steps().filter((s) => s === 'dedup reject duplicate')).toHaveLength(2)
    expect(audit.steps().filter((s) => s.startsWith('route '))).toHaveLength(1)
    expect(verifyAuditLog(audit.lines)).toMatchObject({ ok: true })
  })

  it('the same frame (relay and cursor) delivered again: the stored row is returned, the handler not called again', async () => {
    const { edge, audit, delivered } = bob([{ address: P.carol.address }])
    const e = envelope(P.carol)
    const first = await edge.receive(HOME, 1, e.bytes)
    expect(first).toMatchObject({ state: 'routed', id: e.id })
    const lines = audit.lines.length
    expect(await edge.receive(HOME, 1, e.bytes)).toEqual(first)
    expect(delivered).toHaveLength(1)
    expect(audit.lines).toHaveLength(lines)
  })
})

describe('F2 (edge half): a re-signed sealed part never opens', () => {
  it('the forgery is well formed (id recomputes, sig verifies), and the genuine envelope is accepted', async () => {
    const e = envelope(P.carol)
    const forged = resign(e.envelope, P.mallory)
    const parsed = parseEnvelope(forged)
    verifyOuter(parsed, T0)
    expect(parsed.from).toBe(P.mallory.address)
    expect(parsed.sealed).toEqual(e.envelope.sealed)
    expect(parsed.id).not.toBe(e.id)
    const { edge } = bob([{ address: P.carol.address }, { address: P.mallory.address }])
    expect(await edge.receive(HOME, 1, e.bytes)).toMatchObject({ state: 'routed' })
  })

  it("the attacker's root trusted: open-failed at the unseal step, nothing delivered", async () => {
    const { edge, audit, delivered } = bob([{ address: P.carol.address }, { address: P.mallory.address }])
    const forged = resign(envelope(P.carol).envelope, P.mallory)
    expect(await edge.receive(HOME, 1, forged)).toMatchObject({ state: 'rejected', reason: 'open-failed' })
    expect(audit.steps()).toEqual([
      'verify accept ok',
      'policy accept ok',
      'dedup accept ok',
      'unseal reject open-failed',
    ])
    expect(delivered).toHaveLength(0)
  })

  it("the attacker's root not trusted: untrusted-root at the policy step, before any unseal", async () => {
    const { edge, audit, delivered } = bob([{ address: P.carol.address }])
    const forged = resign(envelope(P.carol).envelope, P.mallory)
    expect(await edge.receive(HOME, 1, forged)).toMatchObject({ state: 'rejected', reason: 'untrusted-root' })
    expect(audit.steps()).toEqual(['verify accept ok', 'policy reject untrusted-root'])
    expect(delivered).toHaveLength(0)
  })
})

describe('F6(a) (edge half): a self-rooted attacker posing to a mailbox that trusts an org root', () => {
  const chain = (): Hop[] => [
    signHop(P.org.signing, P.jane.address, [], T0 + 86_400),
    signHop(P.jane.signing, P.session.address, [], T0 + 3600),
  ]

  for (const [label, roots] of [
    ['by domain', [{ domain: ACME }]],
    ['by address', [{ address: P.org.address }]],
  ] as const) {
    it(`the org root trusted ${label}: the genuine chain is accepted, chain [] from the attacker is untrusted-root`, async () => {
      const { edge, audit, delivered } = bob([...roots])
      // The positive control: org -> jane -> session, under the trusted org root.
      expect(await edge.receive(HOME, 1, envelope(P.session, { auth: chain() }).bytes)).toMatchObject({
        state: 'routed',
      })
      expect(delivered).toHaveLength(1)
      const before = audit.lines.length
      expect(await edge.receive(HOME, 2, envelope(P.mallory).bytes)).toMatchObject({
        state: 'rejected',
        reason: 'untrusted-root',
      })
      expect(audit.steps().slice(before)).toEqual(['verify accept ok', 'policy reject untrusted-root'])
      expect(delivered).toHaveLength(1)
    })
  }
})

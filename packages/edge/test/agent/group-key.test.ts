import {
  buildEnvelope,
  codingEvaluator,
  GROUP_KEY_TYPE,
  type GroupKeyBody,
  groupEvaluator,
  newThread,
  SealingKey,
  sealGroupKey,
  signHop,
  signMembership,
  toHex,
} from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { Agent, AgentAudit, GROUPS_MAX } from '../../src/agent/index.ts'
import {
  DAY,
  FakeClock,
  MemoryAuditSink,
  P,
  type Party,
  party,
  seed,
  seededRng,
  T0,
} from '../support/fixtures.ts'
import {
  CAVEAT,
  coreRng,
  EXP,
  envelope,
  grant,
  JANE,
  JANE_KEYS,
  lines,
  refusal,
  Session,
  text,
} from './support.ts'

// Groups in the agent: the uid-only group-key op opens the group-key envelope in the agent and keeps
// generations in window memory only; `open` at a held group's mailbox under the chain [G -> P, P -> session]. jane
// is P, org the group. Unit tests of the core.

const J = P.jane.address
const G = P.org.address
const S = P.session.address
const MEMBER_EXP = T0 + DAY

/** The private key of generation `n`, from a fixture seed: public test data. */
const genKey = (n: number): SealingKey => new SealingKey(seed(0x40 + n))

let made = 0

/** A group-key.v1 body for jane: generation `n` of `group` (org), its key wrapped to jane, with her membership hop. */
function body(
  n: number,
  o: { key?: SealingKey; exp?: number; group?: Party; holder?: Party } = {},
): GroupKeyBody {
  const group = o.group ?? P.org
  const holder = o.holder ?? P.jane
  return sealGroupKey({
    group: group.signing,
    generation: n,
    key: o.key ?? genKey(n),
    holder: { address: holder.address, sealingKey: holder.sealing.publicKey },
    hop: signMembership(group.signing, holder.address, o.exp ?? MEMBER_EXP),
    iat: T0,
    rng: coreRng(`group key ${made++}`),
  })
}

/** The exact text of an envelope from org to jane carrying `value` as `type`. */
function carrying(type: string, value: unknown): string {
  const rng = coreRng(`carrying ${made++}`)
  const thread = newThread(rng)
  return text(buildEnvelope({ from: P.org.signing, to: [JANE], type, thread, body: value, ts: T0, rng }))
}

/** Mail from bob to the group's mailbox, sealed to generation `n`. */
const mail = (n: number) => envelope({ to: [{ address: G, sealingKey: genKey(n).publicKey }] })

function setup() {
  const clock = new FakeClock()
  const sink = new MemoryAuditSink()
  const audit = new AgentAudit(sink, clock)
  const evaluators = [codingEvaluator, groupEvaluator]
  const agent = new Agent({ principal: J, clock, rng: seededRng('groups'), audit, evaluators })
  agent.login(JANE_KEYS)
  return { agent, sink, clock }
}

/** A session at the group's mailbox: the membership hop of `b`, then a first grant from jane. */
const atGroup = (agent: Agent, b: GroupKeyBody) =>
  new Session(agent, P.session.signing, [b.hop as NonNullable<GroupKeyBody['hop']>, grant(agent)])

describe('group-key: the group-key envelope opened in the agent, the named exception', () => {
  it('takes a generation from a group-key.v1 envelope and releases only {group, generation, body}', () => {
    const { agent, sink } = setup()
    const b = body(1)
    const env = carrying(GROUP_KEY_TYPE, b)
    const reply = agent.takeGroupKey({ envelope: env })
    expect(reply).toEqual({ ok: true, group: G, generation: 1, body: b })
    expect(Object.keys(reply)).toEqual(['ok', 'group', 'generation', 'body'])
    expect(lines(sink).at(-1)).toMatchObject({
      event: 'rotate',
      decision: 'accept',
      reason: 'ok',
      id: JSON.parse(env).id,
      from: G,
      root: J,
      detail: JSON.stringify({
        group: G,
        generation: 1,
        sealing_key: b.sealing_key,
        hop_exp: MEMBER_EXP,
        kept: 'new',
      }),
    })
    const secrets = [toHex(genKey(1).exportSeed()), ...P.jane.secrets]
    for (const out of [JSON.stringify(reply), ...sink.lines])
      for (const k of secrets) expect(out).not.toContain(k)
  })

  it('refuses any other type type-not-accepted, keeps nothing, and writes a rotate reject line', () => {
    const { agent, sink } = setup()
    const b = body(1)
    expect(agent.takeGroupKey({ envelope: carrying('coding.task.v1', b) })).toEqual(
      refusal('type-not-accepted'),
    )
    expect(lines(sink).at(-1)).toMatchObject({
      event: 'rotate',
      decision: 'reject',
      reason: 'type-not-accepted',
    })
    expect(atGroup(agent, b).open(mail(1), G)).toEqual(refusal('not-authorized'))
  })

  it('refuses with the group-key codes: another holder, a bad envelope, a locked window', () => {
    const { agent } = setup()
    expect(agent.takeGroupKey({ body: body(1, { holder: P.bob }) })).toEqual(refusal('not-recipient'))
    expect(agent.takeGroupKey({ body: { ...body(1), sig: '00'.repeat(64) } })).toEqual(
      refusal('bad-record-sig'),
    )
    expect(agent.takeGroupKey({ envelope: '{}' })).toEqual(refusal('bad-shape'))
    agent.logout()
    expect(agent.takeGroupKey({ body: body(1) })).toEqual(refusal('agent-locked'))
  })
})

describe("open at a held group's mailbox", () => {
  it('opens mail sealed to a held generation under [G -> P, P -> S], the generation in the line', () => {
    const { agent, sink } = setup()
    const b = body(1)
    expect(agent.takeGroupKey({ body: b })).toMatchObject({ ok: true })
    const reply = atGroup(agent, b).open(mail(1), G)
    expect(reply).toMatchObject({ ok: true, op: 'open' })
    const line = lines(sink).at(-1) as Record<string, unknown>
    expect(line).toMatchObject({ event: 'open', decision: 'accept', root: J, from: S })
    expect(JSON.parse(line.detail as string)).toEqual({ mailbox: G, rule: 'root', generation: 1 })
  })

  it('keeps the newest two generations and the later hop exp, replying and logging what is held', () => {
    const { agent, sink } = setup()
    const detail = () => JSON.parse(lines(sink).at(-1)?.detail as string) as Record<string, unknown>
    for (const n of [1, 2, 3])
      expect(agent.takeGroupKey({ body: body(n) })).toMatchObject({ ok: true, generation: n })
    const s = atGroup(agent, body(3))
    expect(s.open(mail(1), G)).toEqual(refusal('open-failed'))
    expect(s.open(mail(2), G)).toMatchObject({ ok: true })
    expect(agent.takeGroupKey({ body: body(1) })).toMatchObject({ ok: true, generation: 1 })
    expect(detail()).toMatchObject({ generation: 1, kept: 'dropped' })
    expect(s.open(mail(1), G)).toEqual(refusal('open-failed'))
    expect(agent.takeGroupKey({ body: body(2, { key: genKey(9) }) })).toEqual(refusal('bad-key'))
    const later = body(2, { exp: MEMBER_EXP + 60 })
    expect(agent.takeGroupKey({ body: later })).toEqual({ ok: true, group: G, generation: 2, body: later })
    expect(detail()).toMatchObject({ hop_exp: MEMBER_EXP + 60, kept: 'renewed' })
    expect(agent.takeGroupKey({ body: body(2) })).toEqual({ ok: true, group: G, generation: 2, body: later })
    expect(detail()).toMatchObject({ hop_exp: MEMBER_EXP + 60, kept: 'held' })
    expect(s.open(mail(2), G)).toMatchObject({ ok: true })
  })

  it("refuses a sign under a group's chain, P's mailbox under it, and G under P's own chain", () => {
    const { agent } = setup()
    const b = body(1)
    agent.takeGroupKey({ body: b })
    const s = atGroup(agent, b)
    expect(s.sign(P.bob.address, [CAVEAT], EXP)).toEqual(refusal('not-authorized'))
    expect(s.open(envelope(), J)).toEqual(refusal('not-authorized'))
    expect(new Session(agent, P.session.signing, [grant(agent)]).open(mail(1), G)).toEqual(
      refusal('not-authorized'),
    )
    const noCaveat = signHop(P.org.signing, J, ['repo=r'], MEMBER_EXP)
    expect(new Session(agent, P.session.signing, [noCaveat, grant(agent)]).register('00'.repeat(32))).toEqual(
      refusal('not-authorized'),
    )
  })

  it(`holds at most ${GROUPS_MAX} groups: a new one past them is rate-limited, a held one still taken`, () => {
    const { agent } = setup()
    const groups = Array.from({ length: GROUPS_MAX + 1 }, (_, i) => party(`group ${i}`, 0x20 + i))
    for (const group of groups.slice(0, GROUPS_MAX)) {
      expect(agent.takeGroupKey({ body: body(1, { group }) })).toMatchObject({ ok: true })
    }
    expect(agent.takeGroupKey({ body: body(1, { group: groups[GROUPS_MAX] as Party }) })).toEqual(
      refusal('rate-limited'),
    )
    expect(agent.takeGroupKey({ body: body(2, { group: groups[0] as Party }) })).toMatchObject({ ok: true })
  })

  it('drops every generation at logout; the next login holds none until the bodies are replayed', () => {
    const { agent } = setup()
    const b = body(1)
    agent.takeGroupKey({ body: b })
    agent.logout()
    agent.login(JANE_KEYS)
    expect(atGroup(agent, b).open(mail(1), G)).toEqual(refusal('not-authorized'))
    expect(agent.takeGroupKey({ body: b })).toMatchObject({ ok: true })
    expect(atGroup(agent, b).open(mail(1), G)).toMatchObject({ ok: true })
  })
})

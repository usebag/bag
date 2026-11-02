import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  buildEnvelope,
  type GroupKeyBody,
  type Hop,
  newThread,
  SealingKey,
  SigningKey,
  sealGroupKey,
  signMembership,
} from '@usebag/core'
import { GroupKeyStore, generateEdgeKeys, HomeCustody, systemRng } from '@usebag/edge'
import { AgentClient, GROUPS_MAX } from '@usebag/edge/agent'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { type AgentHome, agentHome, CAVEAT, loggedIn, publishRecord } from './support/agent.ts'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'
import { FakeSecurity } from './support/security.ts'

// Groups in the agent: the `agent-groups` refusal is
// lifted. An agent identity whose name or principal holds a membership gets its pointer at keygen and its window at
// ac login, which replays the stored group-key bodies into the agent, so a session under [G -> P, P -> S] opens mail
// at the group's mailbox. These cases once asserted the refusal; each now asserts the admission.

const tmp = tempDir('agent-groups')
afterAll(() => tmp.cleanup())
// A test that fails with a window open leaves no agent behind: the signal ends it as a terminal's hangup would.
afterEach(() => {
  process.emit('SIGHUP')
})
let n = 0
// Short names: a Unix socket path holds about 100 bytes.
const home = (): string => {
  const dir = join(tmp.dir, `g${n++}`)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  return dir
}

/** A group's signing key and its generation 1 key, from fixed bytes: public test data. */
const groupKey = (ofs: number) => new SigningKey(new Uint8Array(32).fill(0x31 + ofs))
const generationKey = (ofs: number) => new SealingKey(new Uint8Array(32).fill(0x41 + ofs))
const fresh = (k: number) => new Uint8Array(randomBytes(k))

/** Gives the identity `name` a membership of a group, in its group store <home>/groups/<name>; returns the body. */
function hold(h: AgentHome, name: string, ofs: number, exp = T0 + 86_400): GroupKeyBody {
  const group = groupKey(ofs)
  const body: GroupKeyBody = sealGroupKey({
    group,
    generation: 1,
    key: generationKey(ofs),
    holder: { address: h.address, sealingKey: h.keys.sealing.publicKey },
    hop: signMembership(group, h.address, exp),
    iat: T0,
    rng: () => new Uint8Array(32).fill(0x51 + ofs),
  })
  new GroupKeyStore(join(h.dir, 'groups', name)).put(body)
  return body
}

/** `keygen <name> --custody agent --principal jane-keys` in the home of `h`. */
const keygen = (h: AgentHome, name: string) =>
  cli(
    testIo(new MemoryRelay()),
    'keygen',
    name,
    '--custody',
    'agent',
    '--principal',
    'jane-keys',
    '--dir',
    h.dir,
  )

/** The agent's rotate lines in the home of `h`, as `<decision> <reason>`: one per body the replay offered. */
const rotates = (h: AgentHome): string[] =>
  readFileSync(join(h.dir, 'agent-audit.jsonl'), 'utf8')
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => JSON.parse(l) as { event: string; decision: string; reason: string })
    .filter((l) => l.event === 'rotate')
    .map((l) => `${l.decision} ${l.reason}`)

/** No error line names agent-groups. */
const noRefusal = (err: readonly string[]): boolean => !err.some((l) => l.includes('agent-groups'))

describe('keygen --custody agent: the pointer is written when the principal or the new name holds a membership', () => {
  for (const [who, name] of [
    ['the principal', 'jane-keys'],
    ['the new name', 'again'],
    ['a third name of the principal address', 'jane-copy'],
  ] as const) {
    it(`writes it when ${who} holds one`, async () => {
      const h = agentHome(home())
      if (name === 'jane-copy') new HomeCustody(h.dir).create('jane-copy', h.keys, { custody: 'file' })
      hold(h, name, 0)
      const made = await keygen(h, 'again')
      expect([made.code, made.out, made.err]).toEqual([0, [h.address], []])
      expect(existsSync(join(h.dir, 'agent', 'again.json'))).toBe(true)
    })
  }

  it('writes it for a keychain principal that holds one', async () => {
    const fake = new FakeSecurity()
    const io = { ...testIo(new MemoryRelay()), security: fake.run }
    const h = agentHome(home())
    const kc = (await cli(io, 'keygen', 'kc', '--custody', 'keychain', '--dir', h.dir)).out[0] as string
    hold({ ...h, address: kc }, 'kc', 1)
    const args = ['again', '--custody', 'agent', '--principal', 'kc', '--dir', h.dir]
    const made = await cli(io, 'keygen', ...args)
    expect([made.code, made.out]).toEqual([0, [kc]])
    expect(noRefusal(made.err)).toBe(true)
  })
})

describe('ac login: the window opens with the memberships replayed into it', () => {
  /** Runs `ac login --as jane` on a terminal; resolves once it has opened a window or printed an error. */
  async function login(h: AgentHome) {
    const relay = new MemoryRelay()
    publishRecord(relay, h)
    const run = await loggedIn(relay, h)
    return { relay, ...run, opened: run.io.stdout.some((l) => l.startsWith('login ')) }
  }

  for (const [who, name] of [
    ['the agent identity', 'jane'],
    ['its principal', 'jane-keys'],
  ] as const) {
    it(`opens the window when ${who} holds one, the live body taken, an expired one not offered`, async () => {
      const h = agentHome(home())
      hold(h, name, 0)
      hold(h, name, 3, T0 - 1)
      const run = await login(h)
      expect(run.opened).toBe(true)
      expect(noRefusal(run.io.stderr)).toBe(true)
      expect(run.io.stderr.filter((l) => l.startsWith('login: group'))).toEqual([])
      expect((await cli(testIo(run.relay), 'logout', '--as', 'jane', '--dir', h.dir)).code).toBe(0)
      expect((await run.ran).code).toBe(0)
      expect(rotates(h)).toEqual(['accept ok'])
    })
  }

  it('replays the stores of the principal address only, not those of another identity', async () => {
    const h = agentHome(home())
    new HomeCustody(h.dir).create('other', generateEdgeKeys(systemRng), { custody: 'file' })
    hold(h, 'jane-keys', 0)
    hold(h, 'other', 1)
    const run = await login(h)
    expect(run.opened).toBe(true)
    expect((await cli(testIo(run.relay), 'logout', '--as', 'jane', '--dir', h.dir)).code).toBe(0)
    expect((await run.ran).code).toBe(0)
    expect(rotates(h)).toEqual(['accept ok'])
  })

  it(`names a body the window could not take and goes on: the ${GROUPS_MAX + 1}th group is rate-limited`, async () => {
    const h = agentHome(home())
    for (let i = 0; i <= GROUPS_MAX; i++) hold(h, 'jane-keys', i)
    const run = await login(h)
    expect(run.opened).toBe(true)
    expect(run.io.stderr.filter((l) => l.startsWith('login: group'))).toEqual([
      expect.stringMatching(/^login: group ed25519:\S+ generation 1 not held: rate-limited$/),
    ])
    expect((await cli(testIo(run.relay), 'logout', '--as', 'jane', '--dir', h.dir)).code).toBe(0)
    expect((await run.ran).code).toBe(0)
    expect(rotates(h).filter((r) => r === 'accept ok')).toHaveLength(GROUPS_MAX)
  })

  it('needs --relay unless the login is a device login', async () => {
    const h = agentHome(home())
    const r = await cli(testIo(new MemoryRelay()), 'login', '--as', 'jane', '--dir', h.dir)
    expect([r.out, r.err]).toEqual([
      [],
      ['bag: usage: --relay is required', expect.stringMatching(/ help" for the commands$/)],
    ])
    expect(r.code).not.toBe(0)
  })

  it("opens mail at the group's mailbox for a session under [G -> P, P -> S] after the replay", async () => {
    const h = agentHome(home())
    const body = hold(h, 'jane-keys', 2)
    const G = groupKey(2).address
    const run = await login(h)
    expect(run.opened).toBe(true)
    const key = new SigningKey(fresh(32))
    run.io.lines.push('y')
    const args = ['--session', key.address, '--caveat', CAVEAT, '--exp', '+600', '--dir', h.dir]
    const g = await cli(testIo(run.relay), 'grant', '--as', 'jane', ...args)
    expect(g.code).toBe(0)
    const hop = (JSON.parse(g.out[0] as string) as Hop[])[0] as Hop
    const built = buildEnvelope({
      from: new SigningKey(fresh(32)),
      to: [{ address: G, sealingKey: generationKey(2).publicKey }],
      auth: [],
      type: 'coding.task.v1',
      thread: newThread(fresh),
      body: { repo: 'r' },
      ts: T0,
      rng: fresh,
    })
    const text = new TextDecoder().decode(built.bytes)
    const sock = join(h.dir, 'agent.sock')
    const session = new AgentClient(sock, { key, chain: [body.hop as Hop, hop] })
    const own = new AgentClient(sock, { key, chain: [hop] })
    try {
      const content = await session.open(G, built.envelope.id, text)
      expect(content).toMatchObject({ type: 'coding.task.v1', body: { repo: 'r' } })
      // P's own chain is no group session: the group's mailbox is not-authorized under it.
      await expect(own.open(G, built.envelope.id, text)).rejects.toMatchObject({ code: 'not-authorized' })
    } finally {
      session.close()
      own.close()
    }
    expect((await cli(testIo(run.relay), 'logout', '--as', 'jane', '--dir', h.dir)).code).toBe(0)
    expect((await run.ran).code).toBe(0)
  })
})

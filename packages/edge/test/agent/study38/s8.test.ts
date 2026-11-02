import { randomBytes } from 'node:crypto'
import { chmodSync, copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { inspect } from 'node:util'
import {
  type BuiltEnvelope,
  fromHex,
  type Hop,
  openSealed,
  parseEnvelope,
  type Recipient,
  SealingKey,
  SigningKey,
  toHex,
} from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { buildRequest } from '../../../src/agent/index.ts'
import { P, tempDir } from '../../support/fixtures.ts'
import { forms, occurrences } from '../../support/security.ts'
import { CAVEAT, EXP, envelope, grant, text, threadId } from '../support.ts'
import {
  type Booted,
  boot,
  closeAll,
  codes,
  Driver,
  measure,
  notRun,
  type Outcome,
  outcome,
  SessionWire,
  Wire,
} from './support-a.ts'

// S8, a copied session key off the machine opens nothing. The session's key file and chain are
// copied to a client with (a) no socket to the agent, (b) a socket the agent does not trust by its file's owner and
// mode (`#trusted()` in server.ts; Node has no peer credentials to stub), (c) a forged `session`
// field; each tries to open every envelope of the mailbox. Then the principal's two seeds are searched for in every
// file of the session and the test's temp directory, in the environment, and in the session client's objects. Pass:
// 0 opened in (a) to (c), 0 seeds found. Control, stated not claimed: a same-uid process with the file and the socket
// opens what the grant opens.

const tmp = tempDir('s38-s8')
afterAll(() => tmp.cleanup())
afterEach(closeAll)
let homes = 0
const home = (): string => join(tmp.dir, `h${homes++}`)
const me = (process.getuid as () => number)()

// A principal of fresh random seeds, so a needle found anywhere is these keys and no fixture's.
const SEEDS = [Uint8Array.from(randomBytes(32)), Uint8Array.from(randomBytes(32))] as const
const PRINCIPAL = { signing: new SigningKey(SEEDS[0]), sealing: new SealingKey(SEEDS[1]) }
const PA = PRINCIPAL.signing.address
const NEEDLES = [...forms(SEEDS[0]), ...forms(SEEDS[1])]
const TO: Recipient = { address: PA, sealingKey: PRINCIPAL.sealing.publicKey }
const THREAD = threadId(0x5800)
const MAIL: BuiltEnvelope[] = [
  ...[0, 1, 2].map(() => envelope({ to: [TO], type: 'coding.task.v1' })),
  ...[0, 1, 2].map((i) =>
    envelope({ to: [TO], type: 'coding.result.v1', thread: { id: THREAD, prev: [threadId(0x5900 + i)] } }),
  ),
]

// The session: a key of its own (random) and the chain its first grant gives it, in its own files.
const SESSION_SEED = Uint8Array.from(randomBytes(32))
const SESSION = new SigningKey(SESSION_SEED)
const sessionDir = join(tmp.dir, 'session')
const thiefDir = join(tmp.dir, 'elsewhere')

/** Everything the session side holds in memory in this test: clients, replies, frames. */
const held: unknown[] = []

async function openAll(d: Driver): Promise<Outcome[]> {
  held.push(d)
  const out: Outcome[] = []
  for (const env of MAIL) out.push(await d.request('open', [PA, env.envelope.id], { envelope: text(env) }))
  return out
}

/** The copy: the session's key file and chain read back from the files a thief copied. */
function copied(): { readonly key: SigningKey; readonly chain: readonly Hop[] } {
  mkdirSync(thiefDir, { recursive: true, mode: 0o700 })
  for (const f of ['session-key.json', 'chain.json']) copyFileSync(join(sessionDir, f), join(thiefDir, f))
  const k = JSON.parse(readFileSync(join(thiefDir, 'session-key.json'), 'utf8')) as { sign_seed: string }
  const chain = JSON.parse(readFileSync(join(thiefDir, 'chain.json'), 'utf8')) as Hop[]
  return { key: new SigningKey(fromHex(k.sign_seed, 32)), chain }
}

async function live(o: { readonly uid?: number } = {}): Promise<{ m: Booted; first: Hop }> {
  const m = await boot({ home: home(), principal: PRINCIPAL, answers: ['y'], ...o })
  const first = grant(m.agent, SESSION.address, [CAVEAT], EXP)
  return { m, first }
}

function report(arm: string, out: readonly Outcome[], predicted: string): number {
  const opened = out.filter((o) => o.served).length
  measure('S8', arm, `${out.length} opens; opened ${opened}; codes ${codes(out)}; predicted ${predicted}`)
  return opened
}

function filesUnder(dir: string): string[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => join(e.parentPath, e.name))
}

describe('S8: a copied session key off the machine opens nothing', () => {
  it('opens 0 in (a) to (c), and no seed of the principal is in the session', async () => {
    // The session in the window: its grant from the agent, its key file and chain on disk, its thread registered.
    const { m, first } = await live()
    mkdirSync(sessionDir, { recursive: true, mode: 0o700 })
    writeFileSync(
      join(sessionDir, 'session-key.json'),
      JSON.stringify({ address: SESSION.address, sign_seed: toHex(SESSION_SEED) }),
      { mode: 0o600 },
    )
    writeFileSync(join(sessionDir, 'chain.json'), JSON.stringify([first]), { mode: 0o600 })
    const own = await SessionWire.open(m.path, SESSION, [first])
    held.push(own)
    expect((await own.request('register', [THREAD]))?.ok).toBe(true)
    const thief = copied()
    held.push(thief)
    let opened = 0

    // Control: the same uid, the copied file and the socket open what the grant opens (not claimed).
    const control = await openAll(new Driver(m.path, thief.key, thief.chain))
    measure(
      'S8',
      'control',
      `same uid, the copied key and the live socket: ${MAIL.length} opens; opened ` +
        `${control.filter((o) => o.served).length}; codes ${codes(control)} (stated, not claimed: no session isolation)`,
    )

    // (a) No socket to the agent: the client is off the machine, and the files are all it has.
    const away = await openAll(new Driver(join(thiefDir, 'agent.sock'), thief.key, thief.chain))
    opened += report('a', away, 'no connection')
    let direct = 0
    for (const env of MAIL) {
      for (const address of [PA, SESSION.address]) {
        try {
          openSealed(parseEnvelope(env.bytes), { address, key: new SealingKey(thief.key.exportSeed()) })
          direct++
        } catch {}
      }
    }
    measure(
      'S8',
      'a direct',
      `${MAIL.length * 2} attempts to open the mailbox with the only seed the files hold; opened ${direct}`,
    )
    opened += direct

    // (b) The uid floor by the socket file's owner and mode.
    const owner = await live({ uid: me + 1 })
    opened += report(
      'b owner',
      await openAll(new Driver(owner.m.path, thief.key, [owner.first])),
      "not-authorized (the socket is owned by a uid that is not the agent's)",
    )
    for (const [arm, mode, onDir] of [
      ['b group', 0o660, false],
      ['b other', 0o606, false],
      ['b dir', 0o750, true],
    ] as const) {
      const g = await live()
      chmodSync(onDir ? join(g.m.path, '..') : g.m.path, mode)
      opened += report(arm, await openAll(new Driver(g.m.path, thief.key, [g.first])), 'not-authorized')
    }
    notRun(
      'S8',
      'b another uid',
      'a client running as another uid needs a second account (root to set up); the 0700 directory refuses its ' +
        'connect before the agent sees it, and the owner-and-mode check above is what the agent itself enforces',
    )

    // (c) A forged `session` field, on the live trusted socket.
    const other = new SigningKey(Uint8Array.from(randomBytes(32)))
    const otherFirst = grant(m.agent, other.address, [CAVEAT], EXP)
    const claim: Outcome[] = []
    const onConn: Outcome[] = []
    const withChain: Outcome[] = []
    for (const env of MAIL) {
      const extras = { envelope: text(env) }
      const args = [PA, env.envelope.id]
      // c1: claims another granted session, signed with the copied key.
      const w1 = new Wire(m.path)
      held.push(w1)
      const n1 = (await w1.next())?.nonce as string
      const f1 = JSON.parse(buildRequest(thief.key, n1, 0, 'open', args, { chain: [otherFirst], ...extras }))
      claim.push(outcome(await w1.ask(JSON.stringify({ ...f1, session: other.address })), w1.error))
      // c2: the copied key's connection, then a request in another key's name on it.
      const w2 = await SessionWire.open(m.path, thief.key, thief.chain)
      held.push(w2)
      expect((await w2.request('register', [threadId(0x5a00)]))?.ok).toBe(true)
      onConn.push(
        outcome(
          await w2.wire.ask(buildRequest(P.mallory.signing, w2.nonce as string, 1, 'open', args, extras)),
          w2.wire.error,
        ),
      )
      // c3: another key presenting the copied chain.
      const w3 = new Wire(m.path)
      held.push(w3)
      const n3 = (await w3.next())?.nonce as string
      withChain.push(
        outcome(
          await w3.ask(
            buildRequest(P.mallory.signing, n3, 0, 'open', args, { chain: thief.chain, ...extras }),
          ),
          w3.error,
        ),
      )
    }
    opened += report('c claims another session', claim, 'not-authorized')
    opened += report('c another key on the connection', onConn, 'not-authorized')
    opened += report('c another key with the chain', withChain, 'not-authorized')
    measure('S8', 'a-c', `opened ${opened} in (a) to (c)`)

    // The seed search: the session's files and every file of the run, the environment, the client's objects.
    const received = held.flatMap((h) =>
      h instanceof Driver
        ? h.received()
        : h instanceof SessionWire
          ? h.wire.received
          : h instanceof Wire
            ? h.received
            : [],
    )
    writeFileSync(join(sessionDir, 'received.jsonl'), `${received.join('\n')}\n`, { mode: 0o600 })
    const files = filesUnder(tmp.dir)
    let inFiles = 0
    for (const f of files) {
      const bytes = readFileSync(f)
      inFiles += occurrences(bytes.toString('latin1'), NEEDLES)
      for (const s of SEEDS) for (let i = bytes.indexOf(s); i >= 0; i = bytes.indexOf(s, i + 1)) inFiles++
    }
    const inEnv = occurrences(JSON.stringify(process.env), NEEDLES)
    const dump = held
      .map((h) =>
        inspect(h, {
          depth: Number.POSITIVE_INFINITY,
          showHidden: true,
          maxArrayLength: null,
          maxStringLength: null,
        }),
      )
      .join('\n')
    const inMemory = occurrences(`${dump}\n${received.join('\n')}`, NEEDLES)
    measure(
      'S8',
      'seed search',
      `${NEEDLES.length / 2} text forms of each of the principal's 2 seeds, and the raw bytes in files: ` +
        `${files.length} files under the run's temp directory (the session's key file, chain and received lines, the ` +
        `copies, the agent homes; sockets skipped) ${inFiles}; the environment (${Object.keys(process.env).length} ` +
        `variables) ${inEnv}; the session side's objects (${held.length} clients and copies, inspected to full depth, ` +
        `${received.length} lines received from the agent, ${dump.length} characters) ${inMemory}`,
    )
    notRun(
      'S8',
      'memory dump',
      "a heap snapshot of the session's process: in this harness the agent runs in the test's own process, so its " +
        'heap holds the principal keys by design; the search above covers what the session side holds, not its heap',
    )
    expect(opened).toBe(0)
    expect(inFiles + inEnv + inMemory).toBe(0)
  })
})

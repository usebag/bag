import { lstatSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fromHex, type Hop, newThread, replyThread, type Thread } from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { FsAuditSink, readAuditLines } from '../../../src/adapters/fs-audit.ts'
import { AgentClient } from '../../../src/agent/index.ts'
import { verifyAuditLog } from '../../../src/audit.ts'
import { P, tempDir } from '../../support/fixtures.ts'
import { forms, occurrences } from '../../support/security.ts'
import { coreRng, envelope, grant } from '../support.ts'
import { bootServer, closeAll, HOME, measure, parsed, sentTask, sessionEdge, track } from './support-b.ts'

// S6, audit agreement. Two sessions of jane's, each an Edge whose sealing key is the
// agent's opener behind the Receiver, receive the same five messages (and one duplicate) over a real socket. Per session
// the envelope ids in the edge's `unseal accept` lines must equal those in the agent's `open accept` lines naming the
// session; the agent's log must verify as a hash chain; no seed, `private` or `secret` may be in the log or the temp
// directory; `detail` must name no type and no thread id; `sign` lines must carry counts only.

const tmp = tempDir('s38-s6')
afterAll(() => tmp.cleanup())
afterEach(closeAll)

const J = P.jane.address
const TASK = 'type=coding.task.v1'
const sorted = (xs: Array<string | undefined>): string[] => xs.map(String).sort()

/** Every regular file under `dir` (a socket is not one), by path. */
function filesUnder(dir: string): string[] {
  return readdirSync(dir, { recursive: true })
    .map((rel) => join(dir, String(rel)))
    .filter((p) => lstatSync(p).isFile())
}

describe('S6: the agent audit against the session edges, the chain, the search, the detail', () => {
  it('equal id sets per session, a verifying chain, 0 matches, detail without a type or a thread id, sign lines by counts', async () => {
    const logPath = join(tmp.dir, 'agent-audit.jsonl')
    const m = await bootServer(join(tmp.dir, 'home'), { sink: new FsAuditSink(logPath) })
    const cast = [
      { party: P.session, caveats: ['type=coding.*'] },
      { party: P.mallory, caveats: [TASK] },
    ]
    const sessions = cast.map(({ party, caveats }) => {
      const chain: Hop[] = [grant(m.agent, party.address, caveats)]
      const client = track(new AgentClient(m.path, { key: party.signing, chain }))
      return { party, chain, client, ...sessionEdge({ key: party, client, chain, clock: m.clock }) }
    })
    const [a, b] = sessions as [(typeof sessions)[number], (typeof sessions)[number]]

    // The messages: a task root, a result root, a chat root, a reply on a thread A registered, a reply on another.
    const threadIds: string[] = []
    const thread = (label: string): Thread => {
      const t = newThread(coreRng(label))
      threadIds.push(t.id)
      return t
    }
    const t1 = thread('s6 t1')
    await a.client.register(t1.id)
    const sent = sentTask(a.chain, t1, 's6 sent')
    const mail = [
      envelope({ type: 'coding.task.v1', thread: thread('s6 e1') }),
      envelope({ type: 'coding.result.v1', thread: thread('s6 e2') }),
      envelope({ type: 'chat.v1', thread: thread('s6 e3') }),
      envelope({ type: 'coding.result.v1', thread: replyThread(t1, [sent.envelope.id]) }),
      envelope({ type: 'coding.result.v1', thread: replyThread(thread('s6 t2'), [sent.envelope.id]) }),
    ]
    const states: string[] = []
    for (const [i, env] of mail.entries()) {
      for (const s of sessions) {
        const row = await s.edge.receive(HOME, i + 1, env.bytes)
        states.push(`${s.party.name}:${row.state}${row.reason === null ? '' : `/${row.reason}`}`)
      }
    }
    // A duplicate of the first message is dropped by the edge's dedup step before it asks the agent.
    const dup = await a.edge.receive(HOME, 99, (mail[0] as (typeof mail)[number]).bytes)
    states.push(`dup:${dup.state}/${dup.reason}`)

    // 1. The id sets, per session.
    const agentLines = readAuditLines(logPath).map((l) => JSON.parse(l) as Record<string, unknown>)
    const edgeIds = (s: (typeof sessions)[number]) =>
      sorted(
        parsed(s.audit)
          .filter((l) => l.event === 'unseal' && l.decision === 'accept')
          .map((l) => l.id as string),
      )
    const agentIds = (s: (typeof sessions)[number]) =>
      sorted(
        agentLines
          .filter((l) => l.event === 'open' && l.decision === 'accept' && l.from === s.party.address)
          .map((l) => l.id as string),
      )
    const equal = sessions.map((s) => JSON.stringify(edgeIds(s)) === JSON.stringify(agentIds(s)))
    const refusedByAgent = agentLines.filter((l) => l.event === 'open' && l.decision === 'reject').length
    measure(
      'S6',
      'sets',
      `session A edge unseal accept ${edgeIds(a).length}, agent open accept ${agentIds(a).length}, equal ${equal[0]}; session B edge ${edgeIds(b).length}, agent ${agentIds(b).length}, equal ${equal[1]}; agent open reject ${refusedByAgent}; rows ${states.join(' ')}`,
    )
    expect(equal).toEqual([true, true])
    expect(edgeIds(a)).toHaveLength(3)
    expect(edgeIds(b)).toHaveLength(1)

    // 2. The hash chain.
    const verdict = verifyAuditLog(readAuditLines(logPath))
    measure('S6', 'chain', `${agentLines.length} agent lines, verifyAuditLog ${JSON.stringify(verdict)}`)
    expect(verdict).toEqual({ ok: true, lines: agentLines.length })

    // 3. The search over the log and the temp directory: the log, and each edge's log beside it.
    for (const s of sessions)
      writeFileSync(join(tmp.dir, `edge-${s.party.name}-audit.jsonl`), `${s.audit.lines.join('\n')}\n`)
    const files = filesUnder(tmp.dir)
    const matched = files.filter((f) => /seed|private|secret/i.test(readFileSync(f, 'latin1')))
    const needles = [P.jane, P.session, P.mallory, P.bob].flatMap((p) =>
      p.secrets.flatMap((h) => forms(fromHex(h, 32))),
    )
    const found = files.reduce((sum, f) => sum + occurrences(readFileSync(f, 'latin1'), needles), 0)
    measure(
      'S6',
      'search',
      `${files.length} files (the agent log and ${sessions.length} edge logs among them), files matching seed|private|secret ${matched.length}, seed forms found ${found}`,
    )
    expect(matched).toEqual([])
    expect(found).toBe(0)

    // 4. The detail: no type and no thread id in the log; sign lines by counts only; open lines the mailbox and the limb.
    const logText = readFileSync(logPath, 'utf8')
    const types = ['coding.task.v1', 'coding.result.v1', 'chat.v1', 'type=']
    const typesNamed = types.filter((t) => logText.includes(t)).length
    const threadsNamed = threadIds.filter((id) => logText.includes(id)).length
    const detail = (l: Record<string, unknown>) => JSON.parse(String(l.detail)) as Record<string, unknown>
    const signs = agentLines.filter((l) => l.event === 'sign')
    const opens = agentLines.filter((l) => l.event === 'open')
    const signsByCounts = signs.every(
      (l) =>
        JSON.stringify(Object.keys(detail(l))) === JSON.stringify(['tag', 'sub', 'exp', 'caveats']) &&
        typeof detail(l).caveats === 'number',
    )
    const opensByLimb = opens.every((l) => {
      const keys = Object.keys(detail(l))
      return keys.every((k) => k === 'mailbox' || k === 'rule') && detail(l).mailbox === J
    })
    measure(
      'S6',
      'detail',
      `${agentLines.length} lines (${signs.length} sign, ${opens.length} open): types named ${typesNamed}, thread ids named ${threadsNamed} of ${threadIds.length}, sign lines counts only ${signsByCounts}, open lines mailbox and limb only ${opensByLimb}`,
    )
    expect(typesNamed).toBe(0)
    expect(threadsNamed).toBe(0)
    expect(signsByCounts).toBe(true)
    expect(opensByLimb).toBe(true)
    expect(signs).toHaveLength(2)
  })
})

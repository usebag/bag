import { join } from 'node:path'
import { type Hop, newThread, replyThread } from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { AgentClient } from '../../../src/agent/index.ts'
import { P, tempDir } from '../../support/fixtures.ts'
import {
  coreRng,
  envelope,
  grant,
  lines,
  refusal,
  Session,
  session,
  setup,
  text,
  threadId,
} from '../support.ts'
import { bootServer, closeAll, measure, sentTask, track } from './support-b.ts'

// S3, the read rule: a withheld read is `not-in-grant`
// on the socket whichever limb failed, and the precise reason (`caveat-failed`, `unknown-caveat`, an unregistered
// thread) is in the agent's audit alone. Arms (a) to (e) at the agent's entry; (f) counts `register` calls per thread
// and replies missed, in process and over the socket, across a forced reconnect. Each arm prints one MEASURE line.

const J = P.jane.address
const S = P.session.address
const TASK = 'type=coding.task.v1'
const tmp = tempDir('s38-s3')
afterAll(() => tmp.cleanup())
afterEach(closeAll)
let n = 0

const last = (sink: Parameters<typeof lines>[0]) => lines(sink).at(-1)
const detail = (rule: string) => JSON.stringify({ mailbox: J, rule })

describe('S3 (a) to (e): the read rule at the agent', () => {
  it('(a) a type=coding.task.v1 grant: send a root, register its thread, open the coding.result.v1 reply by rule (a)', () => {
    const { agent, sink } = setup()
    const chain = [grant(agent, S, [TASK])]
    const s = new Session(agent, P.session.signing, chain)
    const thread = newThread(coreRng('s3a'))
    const sent = sentTask(chain, thread, 's3a')
    expect(thread.prev).toEqual([])
    expect(s.register(thread.id)).toEqual({ ok: true, op: 'register' })
    const reply = envelope({ type: 'coding.result.v1', thread: replyThread(thread, [sent.envelope.id]) })
    const r = s.open(reply)
    expect(r).toMatchObject({ ok: true, op: 'open', content: { type: 'coding.result.v1' } })
    expect(last(sink)).toMatchObject({
      decision: 'accept',
      reason: 'ok',
      id: reply.envelope.id,
      detail: detail('thread'),
    })
    measure(
      'S3',
      'a',
      `reply opened ${r.ok ? 1 : 0} of 1, audit rule ${JSON.parse(String(last(sink)?.detail)).rule}`,
    )
  })

  it('(b) a root message of another type: not-in-grant, nothing released, caveat-failed in the audit alone', () => {
    const { agent, sink } = setup()
    const s = session(agent, P.session.signing, [grant(agent, S, [TASK])])
    const chat = envelope({ type: 'chat.v1' })
    const r = s.open(chat)
    expect(r).toEqual(refusal('not-in-grant'))
    expect(JSON.stringify(r)).not.toContain('chat.v1')
    expect(last(sink)).toMatchObject({ decision: 'reject', reason: 'caveat-failed', detail: detail('root') })
    expect(sink.lines.join('\n')).not.toContain('chat.v1')
    measure(
      'S3',
      'b',
      `released 0 of 1, socket code ${(r as { code: string }).code}, audit ${last(sink)?.reason}, type in reply or audit 0`,
    )
  })

  it('(c) a root message whose caveats hold opens by rule (b), rule root in the audit', () => {
    const { agent, sink } = setup()
    const s = session(agent, P.session.signing, [grant(agent, S, [TASK])])
    const root = envelope({ type: 'coding.task.v1' })
    const r = s.open(root)
    expect(r).toMatchObject({ ok: true, op: 'open', content: { type: 'coding.task.v1' } })
    expect(last(sink)).toMatchObject({ decision: 'accept', reason: 'ok', detail: detail('root') })
    measure(
      'S3',
      'c',
      `opened ${r.ok ? 1 : 0} of 1, audit rule ${JSON.parse(String(last(sink)?.detail)).rule}`,
    )
  })

  it('(d) a caveat no evaluator knows fails closed: not-in-grant on the socket, unknown-caveat in the audit', () => {
    const { agent, sink } = setup()
    const s = session(agent, P.session.signing, [grant(agent, S, ['zzz=1'])])
    const r = s.open(envelope())
    expect(r).toEqual(refusal('not-in-grant'))
    expect(last(sink)).toMatchObject({ decision: 'reject', reason: 'unknown-caveat', detail: detail('root') })
    measure(
      'S3',
      'd',
      `released 0 of 1, socket code ${(r as { code: string }).code}, audit ${last(sink)?.reason}`,
    )
  })

  it('(e) a reply in a thread the session did not register: not-in-grant, the thread limb in the audit', () => {
    const { agent, sink } = setup()
    const s = session(agent, P.session.signing, [grant(agent, S, [TASK])])
    const thread = newThread(coreRng('s3e'))
    const reply = envelope({ type: 'coding.result.v1', thread: replyThread(thread, [threadId(5)]) })
    const r = s.open(reply)
    expect(r).toEqual(refusal('not-in-grant'))
    expect(last(sink)).toMatchObject({ decision: 'reject', reason: 'not-in-grant', detail: detail('thread') })
    expect(sink.lines.join('\n')).not.toContain(thread.id)
    measure(
      'S3',
      'e',
      `released 0 of 1, socket code ${(r as { code: string }).code}, audit ${last(sink)?.reason} rule ${JSON.parse(String(last(sink)?.detail)).rule}, thread id in audit 0`,
    )
  })
})

describe('S3 (f): registration per thread and replies missed, across a forced reconnect', () => {
  const THREADS = 12

  it('in process: at most one register per thread, 0 replies missed, the old connection dead, the window kept', () => {
    const { agent } = setup()
    const chain = [grant(agent, S, [TASK])]
    let s = new Session(agent, P.session.signing, chain)
    const calls = new Map<string, number>()
    const register = (id: string) => {
      calls.set(id, (calls.get(id) ?? 0) + 1)
      return s.register(id)
    }
    const threads = Array.from({ length: THREADS }, (_, i) => newThread(coreRng(`s3f ${i}`)))
    const ids = threads.map((t, i) => sentTask(chain, t, `s3f sent ${i}`).envelope.id)
    // The first half registers on the first connection, the second half after a forced reconnect.
    for (const t of threads.slice(0, THREADS / 2)) expect(register(t.id).ok).toBe(true)
    const old = s.conn
    agent.disconnect(old)
    expect(agent.handle(old, '{}')).toEqual(refusal('bad-shape'))
    s = new Session(agent, P.session.signing, chain)
    for (const t of threads.slice(THREADS / 2)) expect(register(t.id).ok).toBe(true)
    // A second forced reconnect before the replies: the registrations and the grant outlive both.
    agent.disconnect(s.conn)
    s = new Session(agent, P.session.signing, chain)
    let missed = 0
    for (const [i, t] of threads.entries()) {
      const reply = envelope({ type: 'coding.result.v1', thread: replyThread(t, [ids[i] as string]) })
      if (!s.open(reply).ok) missed++
    }
    const perThread = [...calls.values()]
    const most = Math.max(...perThread)
    measure(
      'S3',
      'f (in process)',
      `${THREADS} threads, register calls per thread max ${most} (threads registered ${perThread.length}), replies missed ${missed} of ${THREADS}, 2 forced reconnects`,
    )
    expect(most).toBeLessThanOrEqual(1)
    expect(perThread).toHaveLength(THREADS)
    expect(missed).toBe(0)
  })

  it('over the socket: the client closes and reconnects, the registrations and the grant outlive it', async () => {
    const m = await bootServer(join(tmp.dir, `s${n++}`))
    const chain: Hop[] = [grant(m.agent, S, [TASK])]
    const connect = () => track(new AgentClient(m.path, { key: P.session.signing, chain }))
    const threads = Array.from({ length: THREADS }, (_, i) => newThread(coreRng(`s3f socket ${i}`)))
    const ids = threads.map((t, i) => sentTask(chain, t, `s3f socket sent ${i}`).envelope.id)
    const calls = new Map<string, number>()
    let client = connect()
    for (const t of threads.slice(0, THREADS / 2)) {
      calls.set(t.id, (calls.get(t.id) ?? 0) + 1)
      await client.register(t.id)
    }
    client.close()
    client = connect()
    for (const t of threads.slice(THREADS / 2)) {
      calls.set(t.id, (calls.get(t.id) ?? 0) + 1)
      await client.register(t.id)
    }
    client.close()
    client = connect()
    let missed = 0
    for (const [i, t] of threads.entries()) {
      const reply = envelope({ type: 'coding.result.v1', thread: replyThread(t, [ids[i] as string]) })
      try {
        await client.open(J, reply.envelope.id, text(reply))
      } catch {
        missed++
      }
    }
    const most = Math.max(...calls.values())
    measure(
      'S3',
      'f (socket)',
      `${THREADS} threads, register calls per thread max ${most}, replies missed ${missed} of ${THREADS}, 2 forced reconnects (client closed, a new connection and nonce each)`,
    )
    expect(most).toBeLessThanOrEqual(1)
    expect(missed).toBe(0)
  })
})

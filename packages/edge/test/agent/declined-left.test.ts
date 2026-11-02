import { createConnection } from 'node:net'
import { join } from 'node:path'
import type { AcRecord, RecordKind } from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { AgentServer, type Terminal } from '../../src/agent/index.ts'
import { verifyAuditLog } from '../../src/audit.ts'
import { P, tempDir } from '../support/fixtures.ts'
import { CAVEAT, EXP, JANE_KEYS, setup } from './support.ts'

// A grant prompt answered after its requester left (spec/SPEC.md §13.11):
// a refusal is still logged, one `declined` line and no signature; a `y` signs nothing and writes nothing.

const tmp = tempDir('dl')
afterAll(() => tmp.cleanup())
let n = 0
const servers: AgentServer[] = []
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()))
})
const sleep = (ms: number): Promise<unknown> => new Promise((resolve) => setTimeout(resolve, ms))

/** A requester that asks for a grant and leaves while the prompt waits; `answer` is then typed at the terminal. */
async function leftThenAnswered(answer: string) {
  let typed: (line: string) => void = () => {}
  let shown: () => void = () => {}
  const asked = new Promise<void>((resolve) => {
    shown = resolve
  })
  const terminal: Terminal = {
    print: () => {},
    ask: () =>
      new Promise((resolve) => {
        typed = resolve
        shown()
      }),
  }
  const { agent, clock, sink } = setup({ login: false })
  const records = new Map<RecordKind, AcRecord>()
  const quiet = { timers: { set: () => 1, clear: () => {} }, signals: { on: () => 0, off: () => 0 } }
  const home = join(tmp.dir, `d${n++}`)
  const server = new AgentServer({ agent, clock, home, terminal, records, ended: () => {}, ...quiet })
  servers.push(server)
  await server.listen()
  server.login(JANE_KEYS)
  const socket = createConnection(server.path).on('error', () => {})
  socket.write(`${JSON.stringify({ op: 'grant', args: [P.session.address, [CAVEAT], EXP] })}\n`)
  await asked
  socket.destroy()
  await sleep(50)
  typed(answer)
  await sleep(50)
  return { agent, sink }
}

describe('a grant prompt answered after its requester left (§13.11)', () => {
  it('logs a refusal: one declined line, nothing signed, and the chain verifies', async () => {
    const { agent, sink } = await leftThenAnswered('n')
    const events = sink.lines.map((l) => (JSON.parse(l) as { event: string }).event)
    expect(events).toEqual(['declined'])
    expect(agent.logout()).toEqual([])
    expect(verifyAuditLog(sink.lines).ok).toBe(true)
  })

  it('signs nothing and writes nothing for a y', async () => {
    const { agent, sink } = await leftThenAnswered('y')
    expect(sink.lines).toEqual([])
    expect(agent.logout()).toEqual([])
  })
})

import { join } from 'node:path'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { buildRequest } from '../../../src/agent/index.ts'
import { P, tempDir } from '../../support/fixtures.ts'
import { CAVEAT, EXP, threadId } from '../support.ts'
import {
  audited,
  boot,
  closeAll,
  codes,
  granted,
  measure,
  type Outcome,
  outcome,
  SessionWire,
  Wire,
} from './support-a.ts'

// S4, replay: a request captured off a live connection, (a) replayed on a new connection, (b) replayed
// on the same connection (its `seq` repeated), (c) a request whose `seq` skips one, (d) the capture sent after an
// agent restart, (e) a request signed for another `op` or with the `argsHash` of other arguments. Effects counted: a
// reply served, and any `accept` line the agent's audit gains. Pass: 5 of 5 refused, 0 effects.

const tmp = tempDir('s38-s4')
afterAll(() => tmp.cleanup())
afterEach(closeAll)
let homes = 0
const home = (): string => join(tmp.dir, `h${homes++}`)

const S = P.session.address
const B = P.bob.address
const T = threadId(0x5500)

interface Arm {
  readonly arm: string
  readonly predicted: string
  readonly out: Outcome[]
  readonly effects: number
}

describe('S4: replay', () => {
  it('refuses all five arms, with 0 effects', async () => {
    const dir = home()
    const m = await boot({ home: dir, answers: ['y'] })
    const first = await granted(m, S, [CAVEAT], EXP)
    const sw = await SessionWire.open(m.path, P.session.signing, [first])
    const captured = sw.frame('sign', [B, [CAVEAT], EXP])
    const live = await sw.wire.ask(captured)
    expect(live?.ok).toBe(true)
    expect((await sw.request('register', [T]))?.ok).toBe(true)
    const accepts = (): number => audited(m.sink, 'sign', 'accept') + audited(m.sink, 'open', 'accept')
    const arms: Arm[] = []
    const run = async (arm: string, predicted: string, f: () => Promise<Outcome[]>): Promise<void> => {
      const before = accepts()
      const out = await f()
      arms.push({ arm, predicted, out, effects: out.filter((o) => o.served).length + accepts() - before })
    }

    await run('a', 'refused (a new connection meets a new nonce)', async () => {
      const w = new Wire(m.path)
      await w.next()
      return [outcome(await w.ask(captured), w.error)]
    })
    await run('b', 'bad-shape', async () => [outcome(await sw.wire.ask(captured), sw.wire.error)])
    await run('c', 'bad-shape', async () => {
      const skip = buildRequest(P.session.signing, sw.nonce as string, sw.seq + 1, 'sign', [B, [CAVEAT], EXP])
      return [outcome(await sw.wire.ask(skip), sw.wire.error)]
    })
    await run('e', 'not-authorized (the signature fails under session)', async () => {
      // A request the session signed, its op or its arguments changed after: on the live connection at its next seq.
      const signed = JSON.parse(sw.frame('sign', [B, [CAVEAT], EXP])) as Record<string, unknown>
      const forged = [
        { ...signed, op: 'register', args: [T] },
        { ...signed, args: [P.mallory.address, [CAVEAT], EXP] },
        { ...signed, args: [B, [CAVEAT], EXP - 1] },
        { ...signed, op: 'open', args: [P.jane.address, T], envelope: '{}' },
      ]
      const out: Outcome[] = []
      for (const f of forged) out.push(outcome(await sw.wire.ask(JSON.stringify(f)), sw.wire.error))
      return out
    })

    // (d): the agent restarts on the same home and keys, a new window; the capture is sent to it.
    await m.server.close()
    const again = await boot({ home: dir, answers: [] })
    const restartAccepts = (): number => audited(again.sink, 'sign', 'accept')
    const before = restartAccepts()
    const w = new Wire(again.path)
    await w.next()
    const replayed = outcome(await w.ask(captured), w.error)
    const resigned = await SessionWire.open(again.path, P.session.signing, [first])
    const fresh = outcome(await resigned.request('sign', [B, [CAVEAT], EXP]), resigned.wire.error)
    arms.push({
      arm: 'd',
      predicted: 'refused',
      out: [replayed],
      effects: (replayed.served ? 1 : 0) + restartAccepts() - before,
    })
    measure(
      'S4',
      'd re-signed',
      `the same chain, a request re-signed with the restarted agent's nonce (not a replay; the grant-set guard): ` +
        `${fresh.code}`,
    )

    for (const a of arms.sort((x, y) => (x.arm < y.arm ? -1 : 1))) {
      const refused = a.out.every((o) => !o.served)
      measure(
        'S4',
        a.arm,
        `${a.out.length} request${a.out.length === 1 ? '' : 's'}; refused ${refused ? 'all' : 'NOT all'}; codes ` +
          `${codes(a.out)}; effects ${a.effects}; predicted ${a.predicted}`,
      )
    }
    measure(
      'S4',
      'all',
      `${arms.filter((a) => a.out.every((o) => !o.served)).length} of 5 arms refused; effects ` +
        `${arms.reduce((n, a) => n + a.effects, 0)}`,
    )
    expect(arms).toHaveLength(5)
    for (const a of arms) {
      expect(a.out.every((o) => !o.served)).toBe(true)
      expect(a.effects).toBe(0)
    }
  })
})

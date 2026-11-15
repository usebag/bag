import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { telemetryEraseId, telemetryEraseIds, telemetryId, telemetryState } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  NO_TELEMETRY_HOME,
  OFF_USE_FORGET,
  TELEMETRY_ON_QUESTION,
  telemetryLine,
  telemetrySwitch,
} from '../src/index.ts'
import { fakeIo, folder } from './support.ts'

// The machine's telemetry switch as packages/home runs it for the command line and the MCP server: on asks first and
// writes only after a yes; off and status ask nothing, and off never waits on an on's question. A fresh HOME per test.

/** A machine: a fresh HOME and its telemetry directory, HOME/.bag. */
function machine(): { env: Record<string, string>; dir: string } {
  const home = folder()
  return { env: { HOME: home }, dir: join(home, '.bag') }
}

describe('telemetrySwitch: on asks, off and status do not', () => {
  it('T15: on asks its one question and writes only after a yes; a no or a failed ask changes nothing', async () => {
    const m = machine()
    const no = fakeIo({ env: m.env, answer: false })
    await expect(telemetrySwitch(no, 'on')).rejects.toThrow(
      'declined: nothing was changed; telemetry stays as it was',
    )
    expect(no.asked).toEqual([TELEMETRY_ON_QUESTION])
    expect(no.said).toEqual([])
    expect(existsSync(join(m.dir, 'telemetry.json'))).toBe(false)
    const failed = fakeIo({ env: m.env, answer: 'throw' })
    await expect(telemetrySwitch(failed, 'on')).rejects.toThrow('the dialog failed')
    expect(existsSync(join(m.dir, 'telemetry.json'))).toBe(false)
    const yes = fakeIo({ env: m.env, answer: true })
    await telemetrySwitch(yes, 'on')
    const id = telemetryId(m.dir) as string
    expect(id).toMatch(/^[0-9a-f]{32}$/)
    expect(yes.said).toEqual([`telemetry on reason=file choice=on id=${id} spool=0 sent=none`])
    // The question names what is sent and where.
    for (const said of ['telemetry.bag.dev', 'random id', 'never an address', 'bag.dev/privacy'])
      expect(TELEMETRY_ON_QUESTION).toContain(said)
  })

  it('T16: off and status ask nothing; off prints its erasure line, and works while an on question is open', async () => {
    const m = machine()
    const status = fakeIo({ env: m.env, answer: 'throw' })
    await telemetrySwitch(status, 'status')
    expect(status.asked).toEqual([])
    expect(status.said).toEqual(['telemetry off reason=no-file choice=none id=none spool=0 sent=none'])
    await telemetrySwitch(fakeIo({ env: m.env }), 'on')
    const id = telemetryId(m.dir) as string
    // An on question left open: off runs to its end meanwhile, and the open question's later no changes nothing.
    let answer: (yes: boolean) => void = () => {}
    const open = fakeIo({ env: m.env, answer: () => new Promise<boolean>((r) => (answer = r)) })
    const pending = telemetrySwitch(open, 'on')
    const off = fakeIo({ env: m.env, answer: 'throw' })
    await telemetrySwitch(off, 'off')
    expect(off.asked).toEqual([])
    expect(off.said).toEqual([
      'telemetry off reason=file choice=off id=none spool=0 sent=none',
      `telemetry off: reports already sent stay up to 90 days; to erase them, send ${id} to privacy@bag.dev`,
    ])
    expect(telemetryId(m.dir)).toBeNull()
    answer(false)
    await expect(pending).rejects.toThrow('declined')
    expect(telemetryLine(m.env, m.dir)).toBe('telemetry off reason=file choice=off id=none spool=0 sent=none')
    // A refused on question never blocks a later off either.
    await expect(telemetrySwitch(fakeIo({ env: m.env, answer: false }), 'on')).rejects.toThrow('declined')
    const again = fakeIo({ env: m.env })
    await telemetrySwitch(again, 'off')
    expect(again.said).toEqual(['telemetry off reason=file choice=off id=none spool=0 sent=none'])
  })

  it('with showId false (a tool answer) no line carries the install id: id=set, and off names forget', async () => {
    const m = machine()
    const hide = { showId: false }
    const on = fakeIo({ env: m.env })
    await telemetrySwitch(on, 'on', hide)
    const id = telemetryId(m.dir) as string
    expect(on.said).toEqual(['telemetry on reason=file choice=on id=set spool=0 sent=none'])
    const status = fakeIo({ env: m.env })
    await telemetrySwitch(status, 'status', hide)
    expect(status.said).toEqual(['telemetry on reason=file choice=on id=set spool=0 sent=none'])
    expect(telemetryLine(m.env, m.dir)).toBe(`telemetry on reason=file choice=on id=${id} spool=0 sent=none`)
    const off = fakeIo({ env: m.env })
    await telemetrySwitch(off, 'off', hide)
    expect(off.said).toEqual([
      'telemetry off reason=file choice=off id=none spool=0 sent=none',
      OFF_USE_FORGET,
    ])
    for (const io of [on, status, off]) expect(io.said.join('\n')).not.toContain(id)
    expect(OFF_USE_FORGET).toBe(
      'to also erase the reports already sent, use forget instead of off (here, or `bag telemetry forget` in a terminal); off keeps them up to 90 days',
    )
  })

  it('forget asks nothing, turns off, then erases every report under the id at the endpoint; a failure keeps the id', async () => {
    const m = machine()
    await expect(telemetrySwitch(fakeIo({ env: m.env }), 'forget')).rejects.toThrow(
      'not-found: no install id: telemetry is not on, so nothing is erased from here',
    )
    await telemetrySwitch(fakeIo({ env: m.env }), 'on')
    const id = telemetryId(m.dir) as string
    const calls: string[] = []
    const answering = (status: number): typeof fetch =>
      (async (_url: string | URL | Request, init?: RequestInit) => {
        calls.push(String(init?.body))
        return new Response(null, { status })
      }) as typeof fetch
    // A failure: sending is off, the id is kept for a retry, and with showId false the refusal names no id.
    const failed = fakeIo({ env: m.env, answer: 'throw' })
    await expect(telemetrySwitch(failed, 'forget', { showId: false, fetch: answering(503) })).rejects.toThrow(
      "http-503: sending is off; the erasure of this machine's id failed, so the id is kept: run forget again to retry",
    )
    await expect(telemetrySwitch(fakeIo({ env: m.env }), 'forget')).rejects.toThrow(
      `unreachable: sending is off; the erasure of ${id} failed, so the id is kept: run forget again to retry, or send the id to privacy@bag.dev`,
    )
    expect([telemetryId(m.dir), telemetryEraseId(m.dir)]).toEqual([null, id])
    const done = fakeIo({ env: m.env, answer: 'throw' })
    await telemetrySwitch(done, 'forget', { showId: false, fetch: answering(204) })
    expect(done.asked).toEqual([])
    expect(done.said).toEqual([
      'telemetry off reason=file choice=off id=none spool=0 sent=none',
      "telemetry forget: the erasure of this machine's id was accepted; telemetry off",
    ])
    expect(done.said.join('\n')).not.toContain(id)
    expect(calls).toEqual([JSON.stringify({ id }), JSON.stringify({ id })])
    expect(telemetryId(m.dir)).toBeNull()
    expect(telemetryEraseId(m.dir)).toBeNull()
  })

  it('forget writes off to disk before the endpoint is called; success drops the id, a failure keeps off and the id', async () => {
    const m = machine()
    await telemetrySwitch(fakeIo({ env: m.env }), 'on')
    const id = telemetryId(m.dir) as string
    const file = join(m.dir, 'telemetry.json')
    // The fake endpoint reads the consent file as it stands when the erasure is asked for.
    const seen: unknown[] = []
    const answering = (status: number): typeof fetch =>
      (async () => {
        seen.push(JSON.parse(readFileSync(file, 'utf8')))
        return new Response(null, { status })
      }) as typeof fetch
    const failed = fakeIo({ env: m.env })
    await expect(telemetrySwitch(failed, 'forget', { fetch: answering(500) })).rejects.toThrow(
      `http-500: sending is off; the erasure of ${id} failed, so the id is kept: run forget again to retry, or send the id to privacy@bag.dev`,
    )
    expect(failed.said).toEqual([])
    expect(seen).toEqual([{ version: 2, telemetry: 'off', erase: id }])
    expect(telemetryState(m.env, m.dir)).toEqual({ on: false, reason: 'file', choice: 'off' })
    expect([telemetryId(m.dir), telemetryEraseId(m.dir)]).toEqual([null, id])
    // Through a tool (showId false) the refusal says the same without the id.
    const tool = fakeIo({ env: m.env })
    const refused = await telemetrySwitch(tool, 'forget', { showId: false, fetch: answering(503) }).then(
      () => '',
      (e: unknown) => String((e as Error).message),
    )
    expect(refused).toContain(
      "sending is off; the erasure of this machine's id failed, so the id is kept: run forget again to retry",
    )
    expect(refused).not.toContain(id)
    expect(telemetryEraseId(m.dir)).toBe(id)
    // The retry: off is still on disk when the endpoint is called, and its 204 drops the id.
    const done = fakeIo({ env: m.env })
    await telemetrySwitch(done, 'forget', { fetch: answering(204) })
    expect(seen.at(-1)).toEqual({ version: 2, telemetry: 'off', erase: id })
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ version: 2, telemetry: 'off' })
    expect([telemetryId(m.dir), telemetryEraseId(m.dir)]).toEqual([null, null])
    expect(done.said).toEqual([
      'telemetry off reason=file choice=off id=none spool=0 sent=none',
      `telemetry forget: the erasure of ${id} was accepted; telemetry off`,
    ])
    await expect(
      telemetrySwitch(fakeIo({ env: m.env }), 'forget', { fetch: answering(204) }),
    ).rejects.toThrow('not-found: no install id')
  })

  it('an on after a failed forget draws a new id; the next forget erases the old one first, then the new, and drops each confirmed', async () => {
    const m = machine()
    await telemetrySwitch(fakeIo({ env: m.env }), 'on')
    const old = telemetryId(m.dir) as string
    const bodies: string[] = []
    const answering = (...statuses: number[]): typeof fetch =>
      (async (_url: string | URL | Request, init?: RequestInit) => {
        bodies.push(String(init?.body))
        return new Response(null, { status: statuses.shift() ?? 204 })
      }) as typeof fetch
    await expect(
      telemetrySwitch(fakeIo({ env: m.env }), 'forget', { fetch: answering(503) }),
    ).rejects.toThrow(`http-503: sending is off; the erasure of ${old} failed, so the id is kept`)
    // on draws its own id, not the one still to be erased, which stays pending beside it.
    await telemetrySwitch(fakeIo({ env: m.env, answer: true }), 'on')
    const next = telemetryId(m.dir) as string
    expect(next).not.toBe(old)
    expect(telemetryEraseIds(m.dir)).toEqual([old])
    // A failure on the second: the first, confirmed, is dropped; the second is kept and named.
    bodies.length = 0
    await expect(
      telemetrySwitch(fakeIo({ env: m.env }), 'forget', { fetch: answering(204, 500) }),
    ).rejects.toThrow(
      `http-500: sending is off; the erasure of ${next} failed, so the id is kept: run forget again to retry, or send the id to privacy@bag.dev`,
    )
    expect(bodies).toEqual([JSON.stringify({ id: old }), JSON.stringify({ id: next })])
    expect([telemetryState(m.env, m.dir).on, telemetryId(m.dir), telemetryEraseIds(m.dir)]).toEqual([
      false,
      null,
      [next],
    ])
    // Both failing keep both; through a tool the line names neither.
    await telemetrySwitch(fakeIo({ env: m.env, answer: true }), 'on')
    const third = telemetryId(m.dir) as string
    const refused = await telemetrySwitch(fakeIo({ env: m.env }), 'forget', {
      showId: false,
      fetch: answering(503, 503),
    }).then(
      () => '',
      (e: unknown) => String((e as Error).message),
    )
    expect(refused).toBe(
      "http-503: sending is off; the erasure of this machine's ids failed, so the ids are kept: run forget again to retry",
    )
    expect(telemetryEraseIds(m.dir)).toEqual([next, third])
    // Two confirmed: two fetches, the pending one first, and both dropped.
    bodies.length = 0
    const done = fakeIo({ env: m.env })
    await telemetrySwitch(done, 'forget', { fetch: answering(204, 204) })
    expect(bodies).toEqual([JSON.stringify({ id: next }), JSON.stringify({ id: third })])
    expect(done.said).toEqual([
      'telemetry off reason=file choice=off id=none spool=0 sent=none',
      `telemetry forget: the erasure of ${next} and ${third} was accepted; telemetry off`,
    ])
    expect([telemetryId(m.dir), telemetryEraseIds(m.dir)]).toEqual([null, []])
  })

  it('off keeps an id still to be erased: only a confirmed forget drops it', async () => {
    const m = machine()
    await telemetrySwitch(fakeIo({ env: m.env }), 'on')
    const old = telemetryId(m.dir) as string
    await expect(telemetrySwitch(fakeIo({ env: m.env }), 'forget')).rejects.toThrow(
      'unreachable: sending is off',
    )
    await telemetrySwitch(fakeIo({ env: m.env, answer: true }), 'on')
    await telemetrySwitch(fakeIo({ env: m.env }), 'off')
    expect([telemetryId(m.dir), telemetryEraseIds(m.dir)]).toEqual([null, [old]])
  })

  it('refuses usage with no HOME, asking nothing', async () => {
    const io = fakeIo({ env: {} })
    await expect(telemetrySwitch(io, 'on')).rejects.toThrow(`usage: ${NO_TELEMETRY_HOME}`)
    expect(io.asked).toEqual([])
  })
})

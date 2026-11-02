import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  AcError,
  buildEnvelope,
  DEFAULT_WINDOW,
  newThread,
  parseEnvelope,
  type SealedContent,
  type Thread,
} from '@usebag/core'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { nodeLockFs, processStart } from '../../src/adapters/fs-lock.ts'
import {
  appendDurable,
  DESK_RETRY_MS,
  type EnvelopeOpener,
  FrontDesk,
  type FrontDeskOptions,
  HELD_MAX,
} from '../../src/agent/index.ts'
import { P, T0, tempDir } from '../support/fixtures.ts'

// The front desk: one session of a principal, the holder of desk.lock, takes root messages; another
// holds a root back as a retryable wait (not seen, not final) and takes it once it is the desk; desk-handled refuses a
// root the desk took already, so no root is answered twice across a handover. Replies pass as the agent released them.

const rng = (length: number): Uint8Array => new Uint8Array(randomBytes(length))

/** Timers fired by hand. */
class Timers {
  pending: { ms: number; fn: () => void; cancelled: boolean }[] = []

  after(ms: number, fn: () => void): () => void {
    const t = { ms, fn, cancelled: false }
    this.pending.push(t)
    return () => {
      t.cancelled = true
    }
  }

  live(): number[] {
    return this.pending.filter((t) => !t.cancelled).map((t) => t.ms)
  }

  fire(): void {
    const due = this.pending.filter((t) => !t.cancelled)
    this.pending = []
    for (const t of due) t.fn()
  }
}

/** A message from bob to jane on `thread`, its bytes and the content the agent would release. */
function message(thread: Thread): { bytes: Uint8Array; id: string; content: SealedContent } {
  const content = { type: 'chat.v1', thread, body: 'hi' }
  const { bytes } = buildEnvelope({
    from: P.bob.signing,
    to: [{ address: P.jane.address, sealingKey: P.jane.sealing.publicKey }],
    ...content,
    ts: T0,
    rng,
  })
  return { bytes, id: parseEnvelope(bytes).id, content }
}

describe('FrontDesk on one principal directory', () => {
  let tmp: ReturnType<typeof tempDir>
  let timers: Timers
  const live = new Set<number>()
  const desk = (pid: number, more: Omit<FrontDeskOptions, 'lock'> = {}): FrontDesk => {
    live.add(pid)
    return new FrontDesk(tmp.dir, timers, {
      lock: { pid, start: 1, alive: (p) => live.has(p), startOf: () => 1 },
      now: () => T0,
      ...more,
    })
  }
  /** An agent opener that releases what `contents` holds, counting its opens. */
  const agentOpener = (contents: Map<string, SealedContent>): EnvelopeOpener & { opens: number } => {
    const o = {
      opens: 0,
      publicKey: P.jane.sealing.publicKey,
      open: (): never => {
        throw new Error('the agent opens whole envelopes')
      },
      openEnvelope: async (bytes: Uint8Array): Promise<SealedContent> => {
        o.opens++
        return contents.get(parseEnvelope(bytes).id) as SealedContent
      },
    }
    return o
  }

  beforeEach(() => {
    tmp = tempDir('front-desk')
    timers = new Timers()
    live.clear()
  })

  afterEach(() => tmp.cleanup())

  it('gives the desk to one session; when it closes, the other takes it at its next try', () => {
    const [a, b] = [desk(1), desk(2)]
    a.start()
    b.start()
    expect([a.desk, b.desk]).toEqual([true, false])
    expect(timers.live()).toEqual([DESK_RETRY_MS])
    timers.fire()
    expect(b.desk).toBe(false)
    a.close()
    timers.fire()
    expect(b.desk).toBe(true)
    b.close()
    expect(existsSync(join(tmp.dir, 'desk.lock'))).toBe(false)
  })

  it('takes over a desk whose holder is gone', () => {
    const [a, b] = [desk(1), desk(2)]
    a.start()
    live.delete(1)
    b.start()
    expect(b.desk).toBe(true)
  })

  it('holds a root back on a session that is not the desk, retryably, and opens it once it is the desk', async () => {
    const [a, b] = [desk(1), desk(2)]
    a.start()
    b.start()
    const root = message(newThread(rng))
    const inner = agentOpener(new Map([[root.id, root.content]]))
    const opener = b.wrap(inner, () => false)
    for (let i = 0; i < 2; i++) {
      const e = await opener.openEnvelope(root.bytes).catch((x: unknown) => x)
      expect(e).toBeInstanceOf(Error)
      expect(e).not.toBeInstanceOf(AcError) // a plain error: the receiver retries it, never final
      expect((e as Error).message).toMatch(/^desk-held:/)
    }
    expect(inner.opens).toBe(1) // the retry is answered from memory
    a.close()
    timers.fire()
    expect(await opener.openEnvelope(root.bytes)).toEqual(root.content)
    expect(inner.opens).toBe(1)
    expect(readFileSync(join(tmp.dir, 'desk-handled'), 'utf8')).toBe(`${root.id} ${T0}\n`)
  })

  it('passes a reply and a root on a registered thread on a session that is not the desk', async () => {
    const [a, b] = [desk(1), desk(2)]
    a.start()
    b.start()
    const mine = newThread(rng)
    const reply = message({ id: newThread(rng).id, prev: ['ab'.repeat(32)] })
    const root = message(mine)
    const opener = b.wrap(
      agentOpener(
        new Map([
          [reply.id, reply.content],
          [root.id, root.content],
        ]),
      ),
      (t) => t === mine.id,
    )
    expect(await opener.openEnvelope(reply.bytes)).toEqual(reply.content)
    expect(await opener.openEnvelope(root.bytes)).toEqual(root.content)
    expect(existsSync(join(tmp.dir, 'desk-handled'))).toBe(false)
  })

  it('refuses, final, a root the desk took before a handover, and takes one it did not', async () => {
    const [a, b] = [desk(1), desk(2)]
    a.start()
    b.start()
    const [taken, waiting] = [message(newThread(rng)), message(newThread(rng))]
    const contents = new Map([
      [taken.id, taken.content],
      [waiting.id, waiting.content],
    ])
    const [atA, atB] = [
      a.wrap(agentOpener(contents), () => false),
      b.wrap(agentOpener(contents), () => false),
    ]
    // Both rows reach both sessions: b holds both back; the desk takes `taken` only.
    for (const m of [taken, waiting]) await expect(atB.openEnvelope(m.bytes)).rejects.toThrow('front desk')
    expect(await atA.openEnvelope(taken.bytes)).toEqual(taken.content)
    a.close()
    timers.fire()
    const refused = await atB.openEnvelope(taken.bytes).catch((x: unknown) => x)
    // Not the agent's code: only the agent raises not-in-grant. A closed-set code the receiver treats as final.
    expect(refused).toBeInstanceOf(AcError)
    expect(refused).toMatchObject({ code: 'not-recipient' })
    expect((refused as Error).message).toMatch(/desk-answered/)
    expect(await atB.openEnvelope(waiting.bytes)).toEqual(waiting.content)
    const handled = readFileSync(join(tmp.dir, 'desk-handled'), 'utf8')
      .split('\n')
      .filter((l) => l !== '')
      .map((l) => l.split(' ')[0])
    expect(handled).toEqual([taken.id, waiting.id])
  })

  it('re-checks its lock token before each root: a desk whose lock another holder took is not the desk', async () => {
    const [a, b] = [desk(1), desk(2)]
    a.start()
    b.start()
    const first = message(newThread(rng))
    const second = message(newThread(rng))
    const opener = a.wrap(
      agentOpener(
        new Map([
          [first.id, first.content],
          [second.id, second.content],
        ]),
      ),
      () => false,
    )
    expect(await opener.openEnvelope(first.bytes)).toEqual(first.content)
    // Another process took the lock (as after a drifted start judged stale): the old desk must not take a root.
    writeFileSync(join(tmp.dir, 'desk.lock'), `${JSON.stringify({ pid: 2, start: 1, token: 'other' })}\n`)
    await expect(opener.openEnvelope(second.bytes)).rejects.toThrow(/^desk-held/)
    expect(a.desk).toBe(false)
    expect(timers.live()).toContain(DESK_RETRY_MS)
    const ledger = readFileSync(join(tmp.dir, 'desk-handled'), 'utf8')
    expect(ledger).not.toContain(second.id)
  })

  it('takes the desk lock with the real start of the process, not now less an uptime that drifted', () => {
    // After a sleep node's uptime runs short of the clock: the lock must not record a start derived from it.
    const uptime = vi.spyOn(process, 'uptime').mockReturnValue(100_000)
    try {
      const real = new FrontDesk(tmp.dir, timers)
      real.start()
      const held = JSON.parse(readFileSync(join(tmp.dir, 'desk.lock'), 'utf8')) as {
        pid: number
        start: number
      }
      expect(held.pid).toBe(process.pid)
      expect(held.start).toBe(processStart(process.pid))
      expect(Math.abs(held.start - (Date.now() / 1000 - 100_000))).toBeGreaterThan(1000)
      real.close()
    } finally {
      uptime.mockRestore()
    }
  })

  it('fsyncs the ledger line before the root is released to the edge', async () => {
    const seen: string[] = []
    const a = desk(1, {
      sync: () => seen.push(readFileSync(join(tmp.dir, 'desk-handled'), 'utf8')),
    })
    a.start()
    const root = message(newThread(rng))
    const opener = a.wrap(agentOpener(new Map([[root.id, root.content]])), () => false)
    expect(await opener.openEnvelope(root.bytes)).toEqual(root.content)
    expect(seen).toEqual([`${root.id} ${T0}\n`]) // written, then synced, before the open returned
  })

  it('appendDurable writes, syncs the same descriptor and closes', () => {
    const calls: number[] = []
    appendDurable(join(tmp.dir, 'x'), 'a\n', (fd) => calls.push(fd))
    appendDurable(join(tmp.dir, 'x'), 'b\n', (fd) => calls.push(fd))
    expect(readFileSync(join(tmp.dir, 'x'), 'utf8')).toBe('a\nb\n')
    expect(calls).toHaveLength(2)
  })

  it('tells the server when it becomes the desk, at the start and at a handover', () => {
    const became: number[] = []
    const [a, b] = [desk(1, { onDesk: () => became.push(1) }), desk(2, { onDesk: () => became.push(2) })]
    a.start()
    b.start()
    expect(became).toEqual([1])
    a.close()
    timers.fire()
    expect(became).toEqual([1, 2])
  })

  it('drops ledger entries past ts + ttl + skew when it becomes the desk, and keeps the rest', () => {
    const old = T0 - DEFAULT_WINDOW.ttl - DEFAULT_WINDOW.skew - 1
    const fresh = T0 - 10
    writeFileSync(join(tmp.dir, 'desk-handled'), `${'aa'.repeat(32)} ${old}\n${'bb'.repeat(32)} ${fresh}\n`)
    desk(1).start()
    expect(readFileSync(join(tmp.dir, 'desk-handled'), 'utf8')).toBe(`${'bb'.repeat(32)} ${fresh}\n`)
  })

  it("keeps what the edge's own wider window still accepts: a ledger entry and a held root past the default window", async () => {
    const window = { ttl: DEFAULT_WINDOW.ttl * 2, skew: DEFAULT_WINDOW.skew }
    const past = T0 - DEFAULT_WINDOW.ttl - DEFAULT_WINDOW.skew - 1 // stale under the default, live under `window`
    writeFileSync(join(tmp.dir, 'desk-handled'), `${'aa'.repeat(32)} ${past}\n`)
    desk(1, { window }).start()
    expect(readFileSync(join(tmp.dir, 'desk-handled'), 'utf8')).toBe(`${'aa'.repeat(32)} ${past}\n`)
    let now = T0
    const b = desk(2, { now: () => now, window })
    b.start()
    const [first, second] = [message(newThread(rng)), message(newThread(rng))]
    const inner = agentOpener(
      new Map([
        [first.id, first.content],
        [second.id, second.content],
      ]),
    )
    const opener = b.wrap(inner, () => false)
    await opener.openEnvelope(first.bytes).catch(() => {})
    now = T0 + DEFAULT_WINDOW.ttl + DEFAULT_WINDOW.skew + 1 // past the default, inside `window`
    await opener.openEnvelope(second.bytes).catch(() => {})
    await opener.openEnvelope(first.bytes).catch(() => {})
    expect(inner.opens).toBe(2) // first is still held: not evicted under the wider window
  })

  it('pauses without closing: the lock goes, another session takes it, and the paused one may start again', () => {
    const [a, b] = [desk(1), desk(2)]
    a.start()
    a.pause()
    expect(a.desk).toBe(false)
    expect(existsSync(join(tmp.dir, 'desk.lock'))).toBe(false)
    b.start()
    expect(b.desk).toBe(true)
    a.start() // after its new grant: not the desk while b holds it, but trying again
    expect(a.desk).toBe(false)
    expect(timers.live()).toEqual([DESK_RETRY_MS])
    b.close()
    timers.fire()
    expect(a.desk).toBe(true)
    a.close()
    a.start() // a closed desk never starts again
    expect(a.desk).toBe(false)
  })

  it('keeps one pending retry however often start() is called', () => {
    const [a, b] = [desk(1), desk(2)]
    a.start()
    b.start()
    b.start()
    b.start()
    expect(timers.live()).toEqual([DESK_RETRY_MS])
  })

  it('reports a fault of the timer start and keeps retrying', () => {
    let broken = false
    const faults: unknown[] = []
    live.add(1)
    live.add(2)
    const a = desk(1)
    const b = new FrontDesk(tmp.dir, timers, {
      lock: {
        pid: 2,
        start: 1,
        alive: (p) => live.has(p),
        startOf: () => 1,
        fs: {
          ...nodeLockFs,
          write: (path, text) => {
            if (broken) throw new Error('EIO')
            nodeLockFs.write(path, text)
          },
        },
      },
      onError: (e) => faults.push(e),
    })
    a.start()
    b.start()
    broken = true
    timers.fire()
    expect(faults).toHaveLength(1)
    expect(timers.live()).toEqual([DESK_RETRY_MS]) // still trying
    broken = false
    a.close()
    timers.fire()
    expect(b.desk).toBe(true)
  })

  it('gives up the desk when its lock file no longer parses, holding the root back', async () => {
    const a = desk(1)
    a.start()
    expect(a.desk).toBe(true)
    writeFileSync(join(tmp.dir, 'desk.lock'), '{')
    const root = message(newThread(rng))
    const opener = a.wrap(agentOpener(new Map([[root.id, root.content]])), () => false)
    expect(((await opener.openEnvelope(root.bytes).catch((e: unknown) => e)) as Error).message).toMatch(
      /^desk-held:/,
    )
    expect(a.desk).toBe(false)
  })

  it('passes a ledger it cannot read on, and the agent opener open as it is', async () => {
    const a = desk(1)
    a.start()
    mkdirSync(join(tmp.dir, 'desk-handled'))
    const root = message(newThread(rng))
    const inner = agentOpener(new Map([[root.id, root.content]]))
    const opener = a.wrap(
      { ...inner, open: ((...x: unknown[]) => ['opened', x.length]) as unknown as EnvelopeOpener['open'] },
      () => false,
    )
    await expect(opener.openEnvelope(root.bytes)).rejects.toMatchObject({ code: 'EISDIR' })
    expect((opener.open as unknown as (...x: unknown[]) => unknown)(1, 2)).toEqual(['opened', 2])
  })

  it(`keeps at most HELD_MAX roots in memory; one more is opened again at its retry`, async () => {
    const [a, b] = [desk(1), desk(2)]
    a.start()
    b.start()
    const roots = Array.from({ length: HELD_MAX + 1 }, () => message(newThread(rng)))
    const inner = agentOpener(new Map(roots.map((r) => [r.id, r.content])))
    const opener = b.wrap(inner, () => false)
    for (const r of roots) await opener.openEnvelope(r.bytes).catch(() => {})
    expect(inner.opens).toBe(HELD_MAX + 1)
    const last = roots.at(-1) as (typeof roots)[number]
    await opener.openEnvelope(last.bytes).catch(() => {})
    expect(inner.opens).toBe(HELD_MAX + 2) // not held: asked of the agent again
    await opener.openEnvelope((roots[0] as (typeof roots)[number]).bytes).catch(() => {})
    expect(inner.opens).toBe(HELD_MAX + 2) // held: answered from memory
  }, 60_000)

  it('gives up a lock it cannot read back, and tries again', () => {
    const b = new FrontDesk(tmp.dir, timers, {
      lock: {
        pid: 2,
        start: 1,
        alive: () => true,
        startOf: () => 1,
        fs: { ...nodeLockFs, write: (p, t) => nodeLockFs.write(p, t.replace('token', 'nope')) },
      },
    })
    b.start()
    expect(b.desk).toBe(false)
    expect(timers.live()).toEqual([DESK_RETRY_MS])
  })

  it('prunes the ledger again every pruneEvery appends, not only when it becomes the desk', async () => {
    const a = desk(1, { pruneEvery: 2 })
    a.start()
    const old = T0 - DEFAULT_WINDOW.ttl - DEFAULT_WINDOW.skew - 1
    writeFileSync(join(tmp.dir, 'desk-handled'), `${'aa'.repeat(32)} ${old}\n`) // an old entry after the desk began
    const roots = [message(newThread(rng)), message(newThread(rng))]
    const opener = a.wrap(agentOpener(new Map(roots.map((r) => [r.id, r.content]))), () => false)
    await opener.openEnvelope((roots[0] as (typeof roots)[number]).bytes)
    expect(readFileSync(join(tmp.dir, 'desk-handled'), 'utf8')).toContain('aa'.repeat(32))
    await opener.openEnvelope((roots[1] as (typeof roots)[number]).bytes)
    expect(readFileSync(join(tmp.dir, 'desk-handled'), 'utf8')).not.toContain('aa'.repeat(32))
  })

  it('evicts a held root once its ts + ttl + skew is past', async () => {
    let now = T0
    const [a, b] = [desk(1), desk(2, { now: () => now })]
    a.start()
    b.start()
    const [first, second] = [message(newThread(rng)), message(newThread(rng))]
    const inner = agentOpener(
      new Map([
        [first.id, first.content],
        [second.id, second.content],
      ]),
    )
    const opener = b.wrap(inner, () => false)
    await opener.openEnvelope(first.bytes).catch(() => {})
    await opener.openEnvelope(first.bytes).catch(() => {})
    expect(inner.opens).toBe(1) // held in memory
    now = T0 + DEFAULT_WINDOW.ttl + DEFAULT_WINDOW.skew + 1
    await opener.openEnvelope(second.bytes).catch(() => {}) // holding another drops the expired one
    await opener.openEnvelope(first.bytes).catch(() => {})
    expect(inner.opens).toBe(3) // first was opened again: it was evicted
  })
})

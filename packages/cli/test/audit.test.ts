import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { auditHash } from '@usebag/core'
import { Audit, FsAuditSink, SqliteStore, withConnection } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

const tmp = tempDir('audit')
afterAll(() => tmp.cleanup())

describe('audit verify: the edge chain verifier over an audit log file', () => {
  it('prints ok with the line count for an intact log, and the first bad line, with exit 1, for an edited one', async () => {
    const file = join(tmp.dir, 'audit.jsonl')
    const audit = new Audit(new FsAuditSink(file), { now: () => 1_800_000_000 })
    for (const event of ['verify', 'policy', 'route'] as const) audit.record({ event, decision: 'accept' })
    const io = testIo(new MemoryRelay())
    expect(await cli(io, 'audit', 'verify', file)).toEqual({ code: 0, out: ['ok 3 lines'], err: [] })
    const lines = readFileSync(file, 'utf8').split('\n')
    lines[1] = (lines[1] as string).replace('"policy"', '"verify"')
    const edited = join(tmp.dir, 'edited.jsonl')
    writeFileSync(edited, lines.join('\n'))
    expect(await cli(io, 'audit', 'verify', edited)).toEqual({
      code: 1,
      out: ['bad line 2: the hash does not recompute'],
      err: [],
    })
  })

  it('counts the connection member on a log the bag service continued, and prints nothing more for an older log', async () => {
    const file = join(tmp.dir, 'served.jsonl')
    new Audit(new FsAuditSink(file), { now: () => 1_800_000_000 }).record({
      event: 'verify',
      decision: 'accept',
    })
    const io = testIo(new MemoryRelay())
    expect((await cli(io, 'audit', 'verify', file)).out).toEqual(['ok 1 lines'])
    const service = new Audit(new FsAuditSink(file), { now: () => 1_800_000_001 })
    service.attribute(() => null)
    withConnection('c-1f3a', () => service.record({ event: 'publish', decision: 'accept' }))
    service.record({ event: 'subscribe', decision: 'retry' })
    expect(await cli(io, 'audit', 'verify', file)).toEqual({
      code: 0,
      out: ['ok 3 lines', 'connections: 1 name one, 1 name none, 1 before the service'],
      err: [],
    })
  })

  it('refuses a missing file and any verb but verify', async () => {
    const io = testIo(new MemoryRelay())
    const missing = join(tmp.dir, 'missing.jsonl')
    expect((await cli(io, 'audit', 'verify', missing)).err).toEqual([
      `bag: ENOENT: ${missing} does not exist`,
    ])
    expect((await cli(io, 'audit', 'show', missing)).err[0]).toBe('bag: usage: audit verify <file>')
    expect((await cli(io, 'audit', 'verify')).err[0]).toBe('bag: usage: expected <file>')
  })
})

describe('audit verify against the anchor in the edge store beside the log (L4)', () => {
  /** A state directory as an identity's: edge.sqlite and a 20-line audit.jsonl the store anchors at line 20. */
  function state(name: string): { dir: string; log: string; store: string; lines: string[] } {
    const dir = join(tmp.dir, name)
    mkdirSync(dir)
    const log = join(dir, 'audit.jsonl')
    const store = join(dir, 'edge.sqlite')
    const db = new SqliteStore(store)
    let t = 1_800_000_000
    const audit = new Audit(
      new FsAuditSink(log),
      { now: () => t++ },
      {
        get: () => db.auditAnchorGet('audit.jsonl'),
        put: (a) => db.auditAnchorPut('audit.jsonl', a, t),
      },
    )
    for (let i = 1; i <= 20; i++)
      audit.record({ event: 'verify', decision: 'accept', id: `${i}`.padStart(64, '0') })
    db.close()
    return { dir, log, store, lines: readFileSync(log, 'utf8').trim().split('\n') }
  }

  /** Line k edited and every later line re-hashed: a rewrite whose chain verifies. */
  function rewrite(lines: readonly string[], k: number): string {
    let prev = (JSON.parse(lines[k - 2] as string) as { hash: string }).hash
    const out = lines.slice(0, k - 1)
    for (const text of lines.slice(k - 1)) {
      const l = JSON.parse(text)
      if (l.seq === k) l.decision = 'reject'
      l.prev = prev
      l.hash = auditHash(l)
      prev = l.hash
      out.push(JSON.stringify(l))
    }
    return `${out.join('\n')}\n`
  }

  it('prints ok as before for an intact log, and truncated or diverged, with exit 1, for one cut or rewritten', async () => {
    const io = testIo(new MemoryRelay())
    const s = state('anchored')
    expect(await cli(io, 'audit', 'verify', s.log)).toEqual({ code: 0, out: ['ok 20 lines'], err: [] })
    writeFileSync(s.log, `${s.lines.slice(0, 17).join('\n')}\n`)
    expect(await cli(io, 'audit', 'verify', s.log)).toEqual({
      code: 1,
      out: [`truncated: the log has 17 lines; its anchor in ${s.store} is at line 20`],
      err: [],
    })
    writeFileSync(s.log, rewrite(s.lines, 10))
    expect(await cli(io, 'audit', 'verify', s.log)).toEqual({
      code: 1,
      out: [`diverged: line 20 of the log does not have the hash of its anchor in ${s.store}`],
      err: [],
    })
    // The last line edited, its hash left: the chain sees it, and the anchor still matches the stored hash.
    const last = [...s.lines]
    last[19] = (last[19] as string).replace('"accept"', '"reject"')
    writeFileSync(s.log, `${last.join('\n')}\n`)
    expect(await cli(io, 'audit', 'verify', s.log)).toEqual({
      code: 1,
      out: ['bad line 20: the hash does not recompute'],
      err: [],
    })
    // A rewrite that leaves a bad line as well: both are printed.
    const both = rewrite(s.lines, 10).trim().split('\n')
    both[4] = (both[4] as string).replace('"accept"', '"reject"')
    writeFileSync(s.log, `${both.join('\n')}\n`)
    expect((await cli(io, 'audit', 'verify', s.log)).out).toEqual([
      'bad line 5: the hash does not recompute',
      `diverged: line 20 of the log does not have the hash of its anchor in ${s.store}`,
    ])
  })

  it('reads lines past the anchor as ahead, and a log with no anchor in its store, or no store, as before', async () => {
    const io = testIo(new MemoryRelay())
    const s = state('ahead')
    new Audit(new FsAuditSink(s.log), { now: () => 1_900_000_000 }).record({
      event: 'route',
      decision: 'queue',
    })
    expect(await cli(io, 'audit', 'verify', s.log)).toEqual({
      code: 0,
      out: ['ok 21 lines', `ahead: its anchor in ${s.store} is at line 20 of 21`],
      err: [],
    })
    const other = join(s.dir, 'other.jsonl')
    writeFileSync(other, readFileSync(s.log))
    // No anchor of its own; the anchored log beside it is checked with it, the anchor rows being the set.
    expect((await cli(io, 'audit', 'verify', other)).out).toEqual(['ok 21 lines', 'audit.jsonl: ok 21 lines'])
  })
})

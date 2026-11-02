import { mkdirSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterAll, describe, expect, it } from 'vitest'
import { FsAuditSink, readAuditLines } from '../src/adapters/fs-audit.ts'
import { readAuditAnchors, SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Audit } from '../src/audit.ts'
import { FakeClock, MemoryAuditSink, tempDir } from './support/fixtures.ts'

// The set of audit files of a state directory: the anchor rows
// say which files must exist, so a log opening refuses a file of the set that is gone, cut short or rewritten.

const tmp = tempDir('audit-set')
afterAll(() => tmp.cleanup())
let n = 0
const clock = new FakeClock()
const entry = { event: 'rotate', decision: 'accept' } as const

function state() {
  const dir = join(tmp.dir, `s${n++}`)
  mkdirSync(dir, { recursive: true })
  const store = new SqliteStore(join(dir, 'edge.sqlite'))
  const anchors = (name: string) => ({
    get: () => store.auditAnchorGet(name),
    put: (a: { seq: number; hash: string }) => store.auditAnchorPut(name, a, clock.now()),
    others: () => store.auditAnchors().filter((a) => a.name !== name),
  })
  const write = (name: string, lines: number): void => {
    const audit = new Audit(new FsAuditSink(join(dir, name)), clock, anchors(name))
    for (let i = 0; i < lines; i++) audit.record(entry)
  }
  const open = () => new Audit(new FsAuditSink(join(dir, 'audit.jsonl')), clock, anchors('audit.jsonl'))
  return { dir, store, anchors, write, open, side: join(dir, 'side.jsonl') }
}

describe('a log opening checks every anchored file of its set', () => {
  it('opens beside a whole file, and lists the set', () => {
    const s = state()
    s.write('side.jsonl', 2)
    s.write('audit.jsonl', 1)
    expect(() => s.open()).not.toThrow()
    expect(s.store.auditAnchors().map((a) => [a.name, a.seq])).toEqual([
      ['audit.jsonl', 1],
      ['side.jsonl', 2],
    ])
    s.store.close()
    expect(readAuditAnchors(join(s.dir, 'edge.sqlite')).map((a) => a.name)).toEqual([
      'audit.jsonl',
      'side.jsonl',
    ])
  })

  it('refuses a file that is gone, truncated', () => {
    const s = state()
    s.write('side.jsonl', 2)
    renameSync(s.side, `${s.side}.gone`)
    expect(() => s.open()).toThrow(
      'truncated: the audit log side.jsonl is anchored at line 2 and is not there',
    )
    s.store.close()
  })

  it('refuses a file cut short, or with a line rewritten', () => {
    const s = state()
    s.write('side.jsonl', 3)
    const lines = readAuditLines(s.side)
    writeFileSync(s.side, `${lines.slice(0, 2).join('\n')}\n`)
    expect(() => s.open()).toThrow('truncated: the audit log side.jsonl has 2 lines; its anchor is at line 3')
    writeFileSync(
      s.side,
      `${lines.map((l, i) => (i === 0 ? l.replace('"accept"', '"reject"') : l)).join('\n')}\n`,
    )
    expect(() => s.open()).toThrow(/^diverged: line 1 of the audit log side\.jsonl breaks its hash chain/)
    s.store.close()
  })

  it('checks none from a sink that cannot read its neighbours', () => {
    const s = state()
    s.write('side.jsonl', 1)
    renameSync(s.side, `${s.side}.gone`)
    expect(() => new Audit(new MemoryAuditSink(), clock, s.anchors('audit.jsonl'))).not.toThrow()
    s.store.close()
  })

  it('reads no anchors from a store that has no table for them', () => {
    const path = join(tmp.dir, `plain-${n++}.sqlite`)
    new DatabaseSync(path).close()
    expect(readAuditAnchors(path)).toEqual([])
  })
})

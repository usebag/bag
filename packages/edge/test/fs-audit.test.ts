import { readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { FsAuditSink, readAuditLines } from '../src/adapters/fs-audit.ts'
import { Audit, verifyAuditLog } from '../src/audit.ts'
import { FakeClock, tempDir } from './support/fixtures.ts'

const tmp = tempDir('audit')
afterAll(() => tmp.cleanup())

describe('FsAuditSink: an append-only JSONL file', () => {
  it('appends lines to a 0600 file, and a new instance continues the chain', () => {
    const path = join(tmp.dir, 'audit.jsonl')
    expect(readAuditLines(path)).toEqual([])
    const sink = new FsAuditSink(path)
    expect(sink.last()).toBeNull()
    const clock = new FakeClock()
    new Audit(sink, clock).record({ event: 'verify', decision: 'accept' })
    new Audit(sink, clock).record({ event: 'route', decision: 'queue' })
    new Audit(new FsAuditSink(path), clock).record({
      event: 'publish',
      decision: 'retry',
      reason: 'publish-failed',
    })
    expect(statSync(path).mode & 0o777).toBe(0o600)
    const lines = readAuditLines(path)
    expect(lines.map((l) => JSON.parse(l).seq)).toEqual([1, 2, 3])
    expect(readFileSync(path, 'utf8').endsWith('\n')).toBe(true)
    expect(verifyAuditLog(lines)).toEqual({ ok: true, lines: 3 })
    expect(sink.last()).toBe(lines[2])
    expect([sink.name, sink.read()]).toEqual(['audit.jsonl', lines])
    expect(new FsAuditSink(join(tmp.dir, 'none.jsonl')).read()).toEqual([])
  })

  it('refuses a line with a newline in it, and reads a file without a final newline whole', () => {
    const path = join(tmp.dir, 'raw.jsonl')
    expect(() => new FsAuditSink(path).append('a\nb')).toThrow('fs-audit: an audit line holds no newline')
    writeFileSync(path, 'one\ntwo')
    expect(readAuditLines(path)).toEqual(['one', 'two'])
  })
})

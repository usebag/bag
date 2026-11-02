import { type AuditFields, auditHash } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { Audit, type AuditEntry, verifyAuditLog } from '../src/audit.ts'
import { FakeClock, MemoryAuditSink } from './support/fixtures.ts'

// Audit-log tampering on a 20-line log. (a) one byte of a middle line's reason changed, (b) a middle
// line removed, (c) two lines swapped, (e) a line appended with a recomputed hash but the wrong prev: each refused by
// verifyAuditLog, naming the first bad line. (d) the last three lines removed: measured, and printed as MEASURE.
// The CLI's `audit verify` on (a) and (d) runs in packages/cli/test/adversarial-secrets.test.ts, since the edge
// may not use the CLI (CONTRIBUTING.md, "Dependency direction").

const ID = (i: number): string => i.toString(16).padStart(64, '0')

/** Twenty lines of the shapes an edge writes: verify and policy accepts, rejects with codes, a publish, a route. */
function twentyLines(): string[] {
  const sink = new MemoryAuditSink()
  const clock = new FakeClock()
  const audit = new Audit(sink, clock)
  for (let i = 1; i <= 20; i++) {
    const entry: AuditEntry =
      i === 10
        ? { event: 'verify', decision: 'reject', reason: 'bad-sig', id: ID(i), detail: { cursor: i } }
        : i % 5 === 0
          ? { event: 'dedup', decision: 'reject', reason: 'duplicate', id: ID(i), detail: { cursor: i } }
          : i % 3 === 0
            ? {
                event: 'publish',
                decision: 'accept',
                id: ID(i),
                detail: { relay: 'http://127.0.0.1:9', tries: 1 },
              }
            : { event: 'verify', decision: 'accept', id: ID(i), detail: { cursor: i } }
    audit.record(entry)
    clock.advance(1)
  }
  return [...sink.lines]
}

/** The untampered log verifies (V1's positive control), and the tampered one differs from it. */
function controls(original: readonly string[], tampered: readonly string[]): void {
  expect(verifyAuditLog(original)).toEqual({ ok: true, lines: 20 })
  expect(tampered).not.toEqual(original)
}

describe('audit-log tampering is refused at the first bad line (spec/SPEC.md §9.8)', () => {
  it('(a) one byte of the middle line 10 reason changed: refused at line 10', () => {
    const log = twentyLines()
    const line = log[9] as string
    expect(line).toContain('"reason":"bad-sig"')
    const tampered = [...log]
    tampered[9] = line.replace('"reason":"bad-sig"', '"reason":"bad-sih"')
    expect(Buffer.from(tampered[9] as string).length).toBe(Buffer.from(line).length)
    controls(log, tampered)
    expect(verifyAuditLog(tampered)).toEqual({ ok: false, line: 10, problem: 'not an audit line' })
  })

  it('(a, variant) line 10 reason replaced by another valid code: refused at line 10, the hash does not recompute', () => {
    const log = twentyLines()
    const tampered = [...log]
    tampered[9] = (log[9] as string).replace('"reason":"bad-sig"', '"reason":"bad-id"')
    controls(log, tampered)
    expect(verifyAuditLog(tampered)).toEqual({ ok: false, line: 10, problem: 'the hash does not recompute' })
  })

  it('(b) the middle line 10 removed: refused at line 10', () => {
    const log = twentyLines()
    const tampered = log.filter((_, i) => i !== 9)
    controls(log, tampered)
    expect(tampered).toHaveLength(19)
    expect(verifyAuditLog(tampered)).toEqual({ ok: false, line: 10, problem: 'seq is 11, not 10' })
  })

  it('(c) lines 9 and 10 swapped: refused at line 9', () => {
    const log = twentyLines()
    const tampered = [...log]
    tampered[8] = log[9] as string
    tampered[9] = log[8] as string
    controls(log, tampered)
    expect(verifyAuditLog(tampered)).toEqual({ ok: false, line: 9, problem: 'seq is 10, not 9' })
  })

  it('(e) a line 21 appended with a recomputed hash but the wrong prev: refused at line 21', () => {
    const log = twentyLines()
    const last = JSON.parse(log[19] as string) as AuditFields & { hash: string }
    const before = JSON.parse(log[18] as string) as { hash: string }
    const fields: AuditFields = {
      seq: 21,
      prev: before.hash,
      ts: last.ts + 1,
      event: 'verify',
      decision: 'accept',
      reason: 'ok',
      id: ID(21),
      from: null,
      root: null,
      detail: null,
    }
    const appended = JSON.stringify({ ...fields, hash: auditHash(fields) })
    const tampered = [...log, appended]
    controls(log, tampered)
    // The appended line's own hash recomputes: only its prev is wrong.
    expect(auditHash(JSON.parse(appended) as AuditFields)).toBe(
      (JSON.parse(appended) as { hash: string }).hash,
    )
    expect(verifyAuditLog(tampered)).toEqual({
      ok: false,
      line: 21,
      problem: "prev is not the previous line's hash",
    })
  })

  it('(d) the last three lines removed: measured (the expectation: ok with 17 lines)', () => {
    const log = twentyLines()
    const tampered = log.slice(0, 17)
    controls(log, tampered)
    const verdict = verifyAuditLog(tampered)
    console.log(
      `MEASURE L1(d): verifyAuditLog on the 20-line log less its last 3 lines -> ${JSON.stringify(verdict)}`,
    )
    // What is observed: nothing outside the file anchors its length, so a truncated tail verifies.
    expect(verdict).toEqual({ ok: true, lines: 17 })
  })
})

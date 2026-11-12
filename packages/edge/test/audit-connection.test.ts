import { auditHash } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import {
  Audit,
  type AuditLine,
  checkAuditAnchor,
  connectionOf,
  parseAuditLine,
  verifyAuditLog,
  withConnection,
} from '../src/audit.ts'
import type { AuditAnchor } from '../src/ports.ts'
import { FakeClock, MemoryAuditSink } from './support/fixtures.ts'

// The bag service's connection member (bag 0.4.0): a line names the connection whose call wrote it, the member is
// hashed, an older log is continued (never rewritten), and the verifier reads both forms.

const parsed = (sink: MemoryAuditSink): AuditLine[] => sink.lines.map(parseAuditLine)

/** An anchor store in memory, as the edge store keeps one per file. */
function anchors(): { get(): AuditAnchor | null; put(a: AuditAnchor): void; kept: AuditAnchor | null } {
  return {
    kept: null,
    get() {
      return this.kept
    },
    put(a) {
      this.kept = a
    },
  }
}

describe('the audit connection member', () => {
  it('names the connection of the call that wrote each line, across awaits, and never conflates two calls', async () => {
    const sink = new MemoryAuditSink()
    const audit = new Audit(sink, new FakeClock())
    audit.attribute(() => null)
    const act = async (id: string): Promise<void> => {
      await Promise.resolve()
      audit.record({ event: 'publish', decision: 'accept', id })
      await new Promise((r) => setTimeout(r, 1))
      audit.record({ event: 'resolve', decision: 'accept', id })
    }
    await Promise.all([
      withConnection('c-one', () => act('a'.repeat(64))),
      withConnection('c-two', () => act('b'.repeat(64))),
    ])
    const byId = parsed(sink).map((l) => `${l.id?.slice(0, 1)} ${connectionOf(l)}`)
    expect(byId.sort()).toEqual(['a c-one', 'a c-one', 'b c-two', 'b c-two'])
    expect(verifyAuditLog(sink.lines)).toEqual({ ok: true, lines: 4 })
  })

  it('gives work a call only started the fallback: a timer and a promise chain that outlive the call', async () => {
    const sink = new MemoryAuditSink()
    const audit = new Audit(sink, new FakeClock())
    audit.attribute(() => 'c-fallback')
    let later: Promise<void> = Promise.resolve()
    const fired = new Promise<void>((resolve) => {
      withConnection('c-call', () => {
        audit.record({ event: 'publish', decision: 'accept' })
        setTimeout(() => {
          audit.record({ event: 'subscribe', decision: 'retry' })
          resolve()
        }, 5)
        later = new Promise<void>((r) => setTimeout(r, 1)).then(() => {
          audit.record({ event: 'resolve', decision: 'accept' })
        })
      })
    })
    await fired
    await later
    expect(parsed(sink).map((l) => [l.event, connectionOf(l)])).toEqual([
      ['publish', 'c-call'],
      ['resolve', 'c-fallback'],
      ['subscribe', 'c-fallback'],
    ])
  })

  it('takes the fallback outside any call (an unseal to the speaking connection), and an explicit entry over both', () => {
    const sink = new MemoryAuditSink()
    const audit = new Audit(sink, new FakeClock())
    audit.attribute((event) => (event === 'unseal' ? 'c-speaking' : null))
    audit.record({ event: 'unseal', decision: 'accept' })
    audit.record({ event: 'subscribe', decision: 'retry' })
    withConnection('c-call', () => audit.record({ event: 'pair', decision: 'accept', connection: 'c-named' }))
    expect(parsed(sink).map(connectionOf)).toEqual(['c-speaking', null, 'c-named'])
  })

  it('writes the eleven members exactly as before on a log whose attribution is off, even inside a call', () => {
    const sink = new MemoryAuditSink()
    withConnection('c-one', () =>
      new Audit(sink, new FakeClock()).record({ event: 'verify', decision: 'accept' }),
    )
    const line = parsed(sink)[0] as AuditLine
    expect(Object.keys(JSON.parse(sink.lines[0] as string))).not.toContain('connection')
    expect([connectionOf(line), line.hash]).toEqual([undefined, auditHash(line)])
  })

  it('hashes the member: an edited connection breaks the chain, and a stripped one too', () => {
    const sink = new MemoryAuditSink()
    const audit = new Audit(sink, new FakeClock())
    audit.attribute(() => null)
    withConnection('c-one', () => {
      audit.record({ event: 'publish', decision: 'accept' })
      audit.record({ event: 'publish', decision: 'accept' })
    })
    const line = JSON.parse(sink.lines[0] as string) as Record<string, unknown>
    expect(line.hash).not.toBe(auditHash(line as unknown as AuditLine))
    const edited = [sink.lines[0]?.replace('"c-one"', '"c-two"') as string, sink.lines[1] as string]
    expect(verifyAuditLog(edited)).toEqual({ ok: false, line: 1, problem: 'the hash does not recompute' })
    const { connection: _, ...stripped } = line
    expect(verifyAuditLog([JSON.stringify(stripped), sink.lines[1] as string])).toEqual({
      ok: false,
      line: 1,
      problem: 'the hash does not recompute',
    })
  })

  it('refuses a malformed connection: a capability-length secret, a space, a number; and a bad id to withConnection', () => {
    const sink = new MemoryAuditSink()
    const audit = new Audit(sink, new FakeClock())
    audit.attribute(() => null)
    audit.record({ event: 'publish', decision: 'accept', connection: 'c-ok' })
    const base = JSON.parse(sink.lines[0] as string) as Record<string, unknown>
    for (const bad of ['x'.repeat(65), 'c one', 7]) {
      expect(() => parseAuditLine(JSON.stringify({ ...base, connection: bad }))).toThrow(
        'an audit line has exactly',
      )
    }
    expect(() => withConnection('c one', () => 1)).toThrow('a connection id')
    expect(() => audit.record({ event: 'publish', decision: 'accept', connection: 'c one' })).toThrow(
      'not a connection id',
    )
  })

  it('migrates an existing log by continuing it: old lines kept byte for byte, the anchor holds, the whole verifies', () => {
    const sink = new MemoryAuditSink()
    const store = anchors()
    const old = new Audit(sink, new FakeClock(), store)
    for (let i = 0; i < 3; i++) old.record({ event: 'verify', decision: 'accept' })
    const before = [...sink.lines]
    const service = new Audit(sink, new FakeClock(), store)
    service.attribute(() => null)
    withConnection('c-one', () => service.record({ event: 'publish', decision: 'accept' }))
    expect(sink.lines.slice(0, 3)).toEqual(before)
    expect(parsed(sink).map(connectionOf)).toEqual([undefined, undefined, undefined, 'c-one'])
    expect(verifyAuditLog(sink.lines, store.kept)).toEqual({
      ok: true,
      lines: 4,
      anchor: { state: 'ok', seq: 4, lines: 4 },
    })
    // A per-folder server (the rollback) continues the service's log in the old form, and it still verifies.
    new Audit(sink, new FakeClock(), store).record({ event: 'verify', decision: 'accept' })
    expect(checkAuditAnchor(sink.lines, store.kept as AuditAnchor).state).toBe('ok')
    expect(verifyAuditLog(sink.lines)).toEqual({ ok: true, lines: 5 })
  })
})

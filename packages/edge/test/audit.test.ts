import { AcError, AUDIT_GENESIS, auditHash } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { Audit, checkAuditAnchor, parseAuditLine, reasonOf, verifyAuditLog } from '../src/audit.ts'
import { FakeClock, MemoryAuditSink } from './support/fixtures.ts'

function log(n: number): MemoryAuditSink {
  const sink = new MemoryAuditSink()
  const audit = new Audit(sink, new FakeClock())
  for (let i = 0; i < n; i++) {
    audit.record({ event: 'verify', decision: 'accept', id: `${i}`.padStart(64, '0'), detail: { i } })
  }
  return sink
}

describe('the audit log (spec/SPEC.md §9.8)', () => {
  it('chains each line to the one before it, from 64 zeros, over the canonical audit preimage', () => {
    const sink = new MemoryAuditSink()
    const clock = new FakeClock()
    const audit = new Audit(sink, clock)
    const first = audit.record({
      event: 'publish',
      decision: 'accept',
      detail: { relay: 'http://r', tries: 1 },
    })
    clock.advance(5)
    const second = audit.record({
      event: 'verify',
      decision: 'reject',
      reason: 'bad-sig',
      id: 'a'.repeat(64),
      from: 'f',
      root: 'r',
    })
    expect(first).toMatchObject({
      seq: 1,
      prev: AUDIT_GENESIS,
      ts: 1_800_000_000,
      reason: 'ok',
      id: null,
      from: null,
      root: null,
    })
    expect(first.detail).toBe('{"relay":"http://r","tries":1}')
    expect(first.hash).toBe(auditHash(first))
    expect(second).toMatchObject({
      seq: 2,
      prev: first.hash,
      ts: 1_800_000_005,
      reason: 'bad-sig',
      detail: null,
    })
    expect(sink.lines.map((l) => Object.keys(JSON.parse(l)))).toEqual([
      ['seq', 'prev', 'ts', 'event', 'decision', 'reason', 'id', 'from', 'root', 'detail', 'hash'],
      ['seq', 'prev', 'ts', 'event', 'decision', 'reason', 'id', 'from', 'root', 'detail', 'hash'],
    ])
    expect(verifyAuditLog(sink.lines)).toEqual({ ok: true, lines: 2 })
  })

  it('continues the chain a sink already holds', () => {
    const sink = log(3)
    const line = new Audit(sink, new FakeClock()).record({ event: 'route', decision: 'queue' })
    expect(line.seq).toBe(4)
    expect(line.prev).toBe(parseAuditLine(sink.lines[2] as string).hash)
    expect(verifyAuditLog(sink.lines)).toEqual({ ok: true, lines: 4 })
  })

  it('refuses to continue a log whose last line is not an audit line', () => {
    const sink = log(1)
    sink.lines.push('{"seq":2}')
    expect(() => new Audit(sink, new FakeClock())).toThrow('an audit line has exactly')
  })

  it('finds an edited line: the first line whose hash does not recompute', () => {
    const lines = log(4).lines
    const edited = JSON.parse(lines[2] as string)
    edited.decision = 'reject'
    lines[2] = JSON.stringify(edited)
    expect(verifyAuditLog(lines)).toEqual({ ok: false, line: 3, problem: 'the hash does not recompute' })
  })

  it('finds an edited line whose hash was recomputed: the next line no longer chains to it', () => {
    const lines = log(4).lines
    const edited = JSON.parse(lines[1] as string)
    edited.detail = '{"i":99}'
    edited.hash = auditHash(edited)
    lines[1] = JSON.stringify(edited)
    expect(verifyAuditLog(lines)).toEqual({
      ok: false,
      line: 3,
      problem: "prev is not the previous line's hash",
    })
  })

  it('finds a removed line', () => {
    const lines = log(4).lines
    lines.splice(1, 1)
    expect(verifyAuditLog(lines)).toEqual({ ok: false, line: 2, problem: 'seq is 3, not 2' })
    expect(verifyAuditLog(log(3).lines.slice(1))).toEqual({ ok: false, line: 1, problem: 'seq is 2, not 1' })
  })

  it('finds reordered lines', () => {
    const lines = log(4).lines
    ;[lines[1], lines[2]] = [lines[2] as string, lines[1] as string]
    expect(verifyAuditLog(lines)).toEqual({ ok: false, line: 2, problem: 'seq is 3, not 2' })
  })

  it('finds a line that renumbers to hide a removal: prev breaks', () => {
    const lines = log(3).lines
    const third = JSON.parse(lines[2] as string)
    third.seq = 2
    third.hash = auditHash(third)
    expect(verifyAuditLog([lines[0] as string, JSON.stringify(third)])).toEqual({
      ok: false,
      line: 2,
      problem: "prev is not the previous line's hash",
    })
  })

  it('reports a line that is not an audit line, and accepts an empty log', () => {
    expect(verifyAuditLog(['not json'])).toEqual({ ok: false, line: 1, problem: 'not an audit line' })
    expect(verifyAuditLog([])).toEqual({ ok: true, lines: 0 })
  })

  it('parses only lines with exactly the eleven members, each of its type', () => {
    const good = JSON.parse(log(1).lines[0] as string)
    expect(parseAuditLine(JSON.stringify(good))).toEqual(good)
    const bad = [
      '[]',
      'null',
      '"line"',
      JSON.stringify({ ...good, extra: 1 }),
      JSON.stringify({ ...good, seq: -1 }),
      JSON.stringify({ ...good, prev: 'zz' }),
      JSON.stringify({ ...good, ts: 1.5 }),
      JSON.stringify({ ...good, event: 'spawn' }),
      JSON.stringify({ ...good, event: 7 }),
      JSON.stringify({ ...good, decision: 'maybe' }),
      JSON.stringify({ ...good, decision: 1 }),
      JSON.stringify({ ...good, reason: 'made-up' }),
      JSON.stringify({ ...good, id: 1 }),
      JSON.stringify({ ...good, from: 1 }),
      JSON.stringify({ ...good, root: 1 }),
      JSON.stringify({ ...good, detail: {} }),
      JSON.stringify({ ...good, hash: 'x' }),
    ]
    for (const text of bad) expect(() => parseAuditLine(text), text).toThrow()
    const { hash: _, ...missing } = good
    expect(() => parseAuditLine(JSON.stringify({ ...missing, other: 1 }))).toThrow('exactly seq')
  })

  it("takes an AcError's code as a reason, and the fallback for anything else", () => {
    expect(reasonOf(new AcError('bad-sig'), 'bad-shape')).toBe('bad-sig')
    expect(reasonOf(new Error('x'), 'bad-shape')).toBe('bad-shape')
    expect(reasonOf('x', 'open-failed')).toBe('open-failed')
  })
})

/** An anchor store in memory, as the edge's SQLite row would be. */
function anchorStore(initial: { seq: number; hash: string } | null = null) {
  const s = {
    kept: initial,
    puts: 0,
    get: () => s.kept,
    put: (a: { seq: number; hash: string }) => {
      s.kept = a
      s.puts++
    },
  }
  return s
}

const anchorOf = (line: string): { seq: number; hash: string } => {
  const l = JSON.parse(line) as { seq: number; hash: string }
  return { seq: l.seq, hash: l.hash }
}

/** A log of n lines whose line k is edited and every later line re-hashed: a consistent rewrite of the chain. */
function rewritten(lines: readonly string[], k: number): string[] {
  const out = lines.slice(0, k - 1)
  let prev = k === 1 ? AUDIT_GENESIS : (JSON.parse(lines[k - 2] as string) as { hash: string }).hash
  for (const text of lines.slice(k - 1)) {
    const l = JSON.parse(text)
    if (l.seq === k) l.decision = 'reject'
    l.prev = prev
    l.hash = auditHash(l)
    prev = l.hash
    out.push(JSON.stringify(l))
  }
  return out
}

describe('the audit anchor', () => {
  it('accepts the subscribe event, for a subscription made again or ended', () => {
    const sink = new MemoryAuditSink()
    new Audit(sink, new FakeClock()).record({ event: 'subscribe', decision: 'reject', reason: 'bad-auth' })
    expect(parseAuditLine(sink.lines[0] as string).event).toBe('subscribe')
  })

  it('adopts the last line as the anchor when there is none, and puts the anchor after every line', () => {
    const sink = log(3)
    const anchor = anchorStore()
    const audit = new Audit(sink, new FakeClock(), anchor)
    expect(anchor.kept).toEqual(anchorOf(sink.lines[2] as string))
    const line = audit.record({ event: 'route', decision: 'queue' })
    expect(anchor.kept).toEqual({ seq: 4, hash: line.hash })
    expect(anchor.puts).toBe(2)
    const empty = anchorStore()
    new Audit(new MemoryAuditSink(), new FakeClock(), empty)
    expect(empty.kept).toBeNull()
  })

  it('refuses to continue a log cut short of its anchor (truncated) or rewritten (diverged)', () => {
    const full = log(20).lines
    const anchor = anchorOf(full[19] as string)
    const cut = new MemoryAuditSink()
    cut.lines.push(...full.slice(0, 17))
    expect(() => new Audit(cut, new FakeClock(), anchorStore(anchor))).toThrow(
      'truncated: the audit log audit has 17 lines; its anchor is at line 20',
    )
    const gone = new MemoryAuditSink()
    expect(() => new Audit(gone, new FakeClock(), anchorStore(anchor))).toThrow(
      expect.objectContaining({ code: 'truncated', name: 'EdgeError' }),
    )
    const forged = new MemoryAuditSink()
    forged.lines.push(...rewritten(full, 10))
    expect(verifyAuditLog(forged.lines)).toEqual({ ok: true, lines: 20 })
    expect(() => new Audit(forged, new FakeClock(), anchorStore(anchor))).toThrow(
      "diverged: line 20 of the audit log audit does not have its anchor's hash",
    )
  })

  it('accepts a log one line past its anchor (a crash between the append and the anchor) and moves the anchor', () => {
    const sink = log(5)
    const anchor = anchorStore(anchorOf(sink.lines[3] as string))
    new Audit(sink, new FakeClock(), anchor)
    expect(anchor.kept).toEqual(anchorOf(sink.lines[4] as string))
  })

  it('recomputes the whole chain on join, so lines rewritten under a verbatim anchored line are diverged', () => {
    const full = log(20).lines
    const anchor = anchorOf(full[19] as string)
    const sinkOf = (lines: readonly string[]): MemoryAuditSink => {
      const s = new MemoryAuditSink()
      s.lines.push(...lines)
      return s
    }
    // Lines 10 to 19 rewritten with recomputed hashes, line 20 kept verbatim: the anchored line alone reads ok.
    const forged = [...rewritten(full, 10).slice(0, 19), full[19] as string]
    expect(forged[19]).toBe(full[19])
    expect(checkAuditAnchor(forged, anchor)).toEqual({ state: 'ok', seq: 20, lines: 20 })
    const store = anchorStore(anchor)
    const sink = sinkOf(forged)
    expect(() => new Audit(sink, new FakeClock(), store)).toThrow(
      expect.objectContaining({
        name: 'EdgeError',
        code: 'diverged',
        message:
          "diverged: line 20 of the audit log audit breaks its hash chain (prev is not the previous line's hash); its anchor is at line 20",
      }),
    )
    expect([sink.lines, store.kept, store.puts]).toEqual([forged, anchor, 0])
    // A line before the anchor edited without its hash, and a line after it (ahead) that breaks the chain: diverged.
    const edited = [...full]
    edited[4] = (edited[4] as string).replace('"accept"', '"reject"')
    expect(() => new Audit(sinkOf(edited), new FakeClock(), anchorStore(anchor))).toThrow(
      'diverged: line 5 of the audit log audit breaks its hash chain (the hash does not recompute)',
    )
    const past = log(21).lines
    const broken = [...past]
    broken[20] = (broken[20] as string).replace('"accept"', '"reject"')
    expect(
      () => new Audit(sinkOf(broken), new FakeClock(), anchorStore(anchorOf(past[19] as string))),
    ).toThrow('diverged: line 21 of the audit log audit breaks its hash chain')
    // As before: a clean log opens (ok), a clean log with a line after its anchor opens and moves it (ahead), a cut one
    // is truncated, and an empty log is adopted with no anchor or truncated against one.
    const clean = anchorStore(anchor)
    new Audit(sinkOf(full), new FakeClock(), clean)
    expect([clean.kept, clean.puts]).toEqual([anchor, 0])
    const ahead = anchorStore(anchor)
    new Audit(sinkOf(past), new FakeClock(), ahead)
    expect(ahead.kept).toEqual(anchorOf(past[20] as string))
    expect(() => new Audit(sinkOf(full.slice(0, 17)), new FakeClock(), anchorStore(anchor))).toThrow(
      'truncated: the audit log audit has 17 lines; its anchor is at line 20',
    )
    const none = anchorStore()
    new Audit(new MemoryAuditSink(), new FakeClock(), none)
    expect(none.kept).toBeNull()
    expect(() => new Audit(new MemoryAuditSink(), new FakeClock(), anchorStore(anchor))).toThrow(
      expect.objectContaining({ code: 'truncated' }),
    )
  })

  it('checks a sink that cannot read its lines by its last line alone', () => {
    const full = log(4)
    const lastOnly = { append: (l: string) => full.append(l), last: () => full.last(), name: 'x.jsonl' }
    const at = (n: number) => anchorOf(full.lines[n - 1] as string)
    new Audit(lastOnly, new FakeClock(), anchorStore(at(4)))
    const ahead = anchorStore(at(2))
    new Audit(lastOnly, new FakeClock(), ahead)
    expect(ahead.kept).toEqual(at(4))
    expect(() => new Audit(lastOnly, new FakeClock(), anchorStore({ seq: 9, hash: at(4).hash }))).toThrow(
      'truncated: the audit log x.jsonl has 4 lines; its anchor is at line 9',
    )
    expect(() => new Audit(lastOnly, new FakeClock(), anchorStore({ seq: 4, hash: 'f'.repeat(64) }))).toThrow(
      'diverged: line 4 of the audit log x.jsonl',
    )
    const none = { append: () => {}, last: () => null }
    expect(() => new Audit(none, new FakeClock(), anchorStore(at(1)))).toThrow('has 0 lines')
  })

  it('verifies a log against its anchor: ok, ahead, truncated and diverged, beside the chain result', () => {
    const full = log(20).lines
    const anchor = anchorOf(full[19] as string)
    expect(verifyAuditLog(full, anchor)).toEqual({
      ok: true,
      lines: 20,
      anchor: { state: 'ok', seq: 20, lines: 20 },
    })
    expect(verifyAuditLog(full, null)).toEqual({ ok: true, lines: 20 })
    expect(verifyAuditLog(full, anchorOf(full[17] as string))).toMatchObject({
      ok: true,
      anchor: { state: 'ahead' },
    })
    expect(verifyAuditLog(full.slice(0, 17), anchor)).toEqual({
      ok: false,
      line: 18,
      problem: 'truncated: the log has 17 lines; its anchor is at line 20',
      anchor: { state: 'truncated', seq: 20, lines: 17 },
    })
    expect(verifyAuditLog(rewritten(full, 10), anchor)).toEqual({
      ok: false,
      line: 20,
      problem: "diverged: line 20 does not have its anchor's hash",
      anchor: { state: 'diverged', seq: 20, lines: 20 },
    })
    const edited = [...full]
    edited[4] = (edited[4] as string).replace('"accept"', '"reject"')
    expect(verifyAuditLog(edited, anchor)).toEqual({
      ok: false,
      line: 5,
      problem: 'the hash does not recompute',
      anchor: { state: 'ok', seq: 20, lines: 20 },
    })
    expect(checkAuditAnchor([...full.slice(0, 19), 'not a line'], anchor)).toEqual({
      state: 'diverged',
      seq: 20,
      lines: 20,
    })
    expect(checkAuditAnchor(full, { seq: 20, hash: anchorOf(full[18] as string).hash }).state).toBe(
      'diverged',
    )
    expect(checkAuditAnchor(full, { seq: 19, hash: anchor.hash }).state).toBe('diverged')
  })
})

import {
  type AcErrorCode,
  AUDIT_GENESIS,
  type AuditFields,
  auditHash,
  isAcError,
  isCanonicalInteger,
  isHex,
  isPolicyCode,
  type PolicyCode,
  parseJson,
} from '@usebag/core'
import { type AuditAnchor, type AuditSink, type Clock, EdgeError, type NamedAnchor } from './ports.ts'
import { countTelemetry } from './telemetry.ts'

// The hash-chained audit log (spec/SPEC.md §9.8): one JSON line per step, each line's hash over the canonical audit
// preimage, each line's prev the hash of the line before it, 64 zeros for the first. Its anchor, the seq and hash of
// the last line written, lives in the edge store, updated after every append, so that a log cut short or rewritten
// is seen: verifyAuditLog reports it, and a new edge refuses to continue such a log.

/** The steps the edge audits. */
export const AUDIT_EVENTS = [
  'verify',
  'policy',
  'dedup',
  'unseal',
  'route',
  'publish',
  'resolve',
  'pin',
  'rotate',
  'rate-limit',
  // A subscription the relay ended, made again (`retry`) or ended for good (`reject`).
  'subscribe',
  // The org policy: a moderation module's verdict on a message, and an explicit release (`accept`) or drop (`reject`) of a
  // quarantined message or a held send.
  'moderate',
  'release',
  // A person's ac init (`onboard`, its copy in the detail) and ac restore (`restore`), in the identity's own log
  // (personal recovery).
  'onboard',
  'restore',
  // Each step of a pairing the MCP server's pair tools drive.
  'pair',
] as const
export type AuditEvent = (typeof AUDIT_EVENTS)[number]

/** What a step decided (implementation default: the spec names the field, not its values). */
export const AUDIT_DECISIONS = ['accept', 'reject', 'retry', 'route', 'queue'] as const
export type AuditDecision = (typeof AUDIT_DECISIONS)[number]

/** A detail value: plain data only, so no key object can reach a line. */
export type AuditValue = string | number | boolean | null | readonly string[]

/**
 * What a service records; the audit adds seq, prev, ts and hash. `reason` is a code, policy-refused among them
 * (until its registration in the closed set), or "ok" by default.
 */
export interface AuditEntry {
  readonly event: AuditEvent
  readonly decision: AuditDecision
  readonly reason?: PolicyCode | 'ok'
  readonly id?: string | null
  readonly from?: string | null
  readonly root?: string | null
  readonly detail?: Readonly<Record<string, AuditValue>>
}

/** One audit line as written: the hashed fields, with `detail` as JSON text, and the line's hash. */
export interface AuditLine extends AuditFields {
  readonly hash: string
}

/** How a log stands against its anchor: as anchored, with lines past it, cut short, or rewritten. */
export type AnchorState = 'ok' | 'ahead' | 'truncated' | 'diverged'

/** A log checked against its anchor: the state, the anchor's seq and the number of lines the log has. */
export interface AnchorCheck {
  readonly state: AnchorState
  readonly seq: number
  readonly lines: number
}

/**
 * The result of checking a log: ok with its line count, or the first bad line (1-based) and what is wrong; given an
 * anchor, also how the log stands against it, and a log cut short (`truncated`) or rewritten (`diverged`) is not ok.
 */
export type AuditVerdict =
  | { readonly ok: true; readonly lines: number; readonly anchor?: AnchorCheck }
  | { readonly ok: false; readonly line: number; readonly problem: string; readonly anchor?: AnchorCheck }

/** Where a log's anchor is kept (the edge store's audit_anchor row of the log): read once, written after each line. */
export interface AnchorStore {
  get(): AuditAnchor | null
  put(anchor: AuditAnchor): void
  /** The other files of the set this log belongs to, each with its anchor; checked when the log opens. */
  others?(): readonly NamedAnchor[]
}

/**
 * Compares a log's lines with its anchor: `truncated` when the log has fewer lines than the anchor's seq, `diverged`
 * when the line at that seq does not parse or has another seq or hash, `ahead` when lines follow it (a crash between an
 * append and its anchor, or a writer without the store), else `ok`. It reads the anchored line alone, so lines before it
 * rewritten with recomputed hashes still read `ok`: its callers recompute the chain as well (verifyAuditLog, and Audit,
 * which refuses such a log as `diverged`).
 */
export function checkAuditAnchor(lines: readonly string[], anchor: AuditAnchor): AnchorCheck {
  const at = (state: AnchorState): AnchorCheck => ({ state, seq: anchor.seq, lines: lines.length })
  if (lines.length < anchor.seq) return at('truncated')
  let line: AuditLine
  try {
    line = parseAuditLine(lines[anchor.seq - 1] as string)
  } catch {
    return at('diverged')
  }
  if (line.seq !== anchor.seq || line.hash !== anchor.hash) return at('diverged')
  return at(lines.length > anchor.seq ? 'ahead' : 'ok')
}

/** The same check from the last line alone, for a sink that cannot read its lines: a log ahead is not checked. */
function checkHead(head: AuditLine | null, anchor: AuditAnchor): AnchorCheck {
  const lines = head?.seq ?? 0
  const at = (state: AnchorState): AnchorCheck => ({ state, seq: anchor.seq, lines })
  if (head === null || head.seq < anchor.seq) return at('truncated')
  if (head.seq > anchor.seq) return at('ahead')
  return at(head.hash === anchor.hash ? 'ok' : 'diverged')
}

/** The code an error carries into an audit line: its own when it is an AcError, else `fallback`. */
export function reasonOf(error: unknown, fallback: AcErrorCode): AcErrorCode {
  return isAcError(error) ? error.code : fallback
}

const LINE_KEYS = ['seq', 'prev', 'ts', 'event', 'decision', 'reason', 'id', 'from', 'root', 'detail', 'hash']
// The agent's lines parse (its events `sign`, `open`, `declined`, `device`; `rotate` is the edge's too),
// and each of its codes on the events that write it only, so no edge line takes one.
const EVENTS: ReadonlySet<string> = new Set([...AUDIT_EVENTS, 'sign', 'open', 'declined', 'device'])
const DECISIONS: ReadonlySet<string> = new Set(AUDIT_DECISIONS)
const AGENT = new Map<unknown, readonly unknown[]>([
  ['not-in-grant', ['sign', 'open']],
  ['agent-locked', ['sign', 'open', 'device', 'rotate']],
  ['declined', ['declined', 'device']],
])

const isNullableString = (v: unknown): v is string | null => v === null || typeof v === 'string'

/**
 * Parses one line of the log; throws unless it has exactly the eleven members, each of its type. A number is read
 * only when written as a plain decimal integer (spec/SPEC.md §2.5): `1.0` or `1e0` for `seq` or `ts` is not one.
 */
export function parseAuditLine(text: string): AuditLine {
  let v: unknown
  try {
    v = parseJson(text)
  } catch {
    // A plain Error, as for every other bad line: the audit log is the edge's own file, not a protocol object.
    throw new Error('an audit line is JSON text')
  }
  if (typeof v !== 'object' || v === null || Array.isArray(v))
    throw new Error('an audit line is a JSON object')
  const o = v as Record<string, unknown>
  const keys = Object.keys(o)
  const ok =
    keys.length === LINE_KEYS.length &&
    LINE_KEYS.every((k) => Object.hasOwn(o, k)) &&
    isCanonicalInteger(o.seq) &&
    isHex(o.prev, 32) &&
    isCanonicalInteger(o.ts) &&
    typeof o.event === 'string' &&
    EVENTS.has(o.event) &&
    typeof o.decision === 'string' &&
    DECISIONS.has(o.decision) &&
    (o.event !== 'declined' || o.reason === 'declined') &&
    (o.reason === 'ok' || isPolicyCode(o.reason) || AGENT.get(o.reason)?.includes(o.event) === true) &&
    isNullableString(o.id) &&
    isNullableString(o.from) &&
    isNullableString(o.root) &&
    isNullableString(o.detail) &&
    isHex(o.hash, 32)
  if (!ok)
    throw new Error(
      'an audit line has exactly seq, prev, ts, event, decision, reason, id, from, root, detail and hash',
    )
  return o as unknown as AuditLine
}

/**
 * Appends hash-chained lines to a sink, continuing the chain the sink already holds. With an anchor store, it first
 * checks the log against its anchor and refuses (EdgeError) a log that is `truncated` or `diverged`; it adopts the
 * last line as the anchor when there is none, moves the anchor past lines a crash left after it, and puts the anchor
 * after every append. When the sink can read its lines, the check reads the whole file and recomputes the whole chain
 * once, O(n) in lines: a break anywhere, such as interior lines rewritten with recomputed hashes under a last line
 * kept verbatim, is `diverged` too; a sink that cannot read its lines is checked from its last line alone.
 */
export class Audit {
  readonly #sink: AuditSink
  readonly #clock: Clock
  readonly #anchor: AnchorStore | null
  #seq: number
  #prev: string

  constructor(sink: AuditSink, clock: Clock, anchor?: AnchorStore) {
    this.#sink = sink
    this.#clock = clock
    this.#anchor = anchor ?? null
    const lines = anchor === undefined ? undefined : sink.read?.()
    const last = lines === undefined ? sink.last() : (lines.at(-1) ?? null)
    const line = last === null ? null : parseAuditLine(last)
    this.#seq = line?.seq ?? 0
    this.#prev = line?.hash ?? AUDIT_GENESIS
    if (anchor !== undefined) this.#join(anchor, line, lines)
  }

  #join(anchor: AnchorStore, last: AuditLine | null, lines: readonly string[] | undefined): void {
    this.#peers(anchor)
    const kept = anchor.get()
    const head = last === null ? null : { seq: last.seq, hash: last.hash }
    if (kept === null) {
      if (head !== null) anchor.put(head)
      return
    }
    const check = lines === undefined ? checkHead(last, kept) : checkAuditAnchor(lines, kept)
    Audit.#refuse(this.#sink.name ?? 'audit', check, lines)
    if (check.state === 'ahead' && head !== null) anchor.put(head)
  }

  /**
   * Checks every other anchored file of the set as this one: the anchor rows say
   * which files must exist, so one that is gone is `truncated`. A sink that cannot read its neighbours checks none.
   */
  #peers(anchor: AnchorStore): void {
    if (this.#sink.peer === undefined) return
    for (const a of anchor.others?.() ?? []) {
      const lines = this.#sink.peer(a.name)
      if (lines === null) {
        throw new EdgeError(
          'truncated',
          `the audit log ${a.name} is anchored at line ${a.seq} and is not there`,
        )
      }
      Audit.#refuse(a.name, checkAuditAnchor(lines, a), lines)
    }
  }

  /** Refuses a log cut short of its anchor, or that does not hold it, or whose chain does not recompute. */
  static #refuse(name: string, check: AnchorCheck, lines: readonly string[] | undefined): void {
    if (check.state === 'truncated') {
      throw new EdgeError(
        'truncated',
        `the audit log ${name} has ${check.lines} lines; its anchor is at line ${check.seq}`,
      )
    }
    if (check.state === 'diverged') {
      throw new EdgeError(
        'diverged',
        `line ${check.seq} of the audit log ${name} does not have its anchor's hash`,
      )
    }
    // The anchor binds its line's hash, and that hash binds the line before it only through each prev: the whole chain
    // is recomputed, or lines before the anchor could be rewritten under it.
    const chain = lines === undefined ? null : verifyLines(lines)
    if (chain !== null && !chain.ok) {
      throw new EdgeError(
        'diverged',
        `line ${chain.line} of the audit log ${name} breaks its hash chain (${chain.problem}); its anchor is at line ${check.seq}`,
      )
    }
  }

  /** Writes one line and returns it. */
  record(entry: AuditEntry): AuditLine {
    const fields: AuditFields = {
      seq: this.#seq + 1,
      prev: this.#prev,
      ts: this.#clock.now(),
      event: entry.event,
      decision: entry.decision,
      reason: entry.reason ?? 'ok',
      id: entry.id ?? null,
      from: entry.from ?? null,
      root: entry.root ?? null,
      detail: entry.detail === undefined ? null : JSON.stringify(entry.detail),
    }
    const line: AuditLine = { ...fields, hash: auditHash(fields) }
    this.#sink.append(JSON.stringify(line))
    this.#seq = line.seq
    this.#prev = line.hash
    // After the append: a crash between the two leaves the log one line ahead of its anchor, which a new edge accepts.
    this.#anchor?.put({ seq: line.seq, hash: line.hash })
    // The machine's telemetry, while it is on, counts the line's event, decision and reason, nothing else of it.
    countTelemetry('audit', [line.event, line.decision, line.reason])
    return line
  }
}

/**
 * Recomputes the chain of a log's lines (spec/SPEC.md §9.8) and reports the first bad line: one that does not parse,
 * a seq out of order (a removed or reordered line), a prev that is not the previous hash, or a hash that does not
 * recompute (an edited line). Given the log's anchor, it also reports a log cut short of it (`truncated`) or whose
 * line at the anchor has another hash (`diverged`), which the chain alone cannot see.
 */
export function verifyAuditLog(lines: readonly string[], anchor?: AuditAnchor | null): AuditVerdict {
  const chain = verifyLines(lines)
  if (anchor === undefined || anchor === null) return chain
  const check = checkAuditAnchor(lines, anchor)
  if (!chain.ok) return { ...chain, anchor: check }
  if (check.state === 'truncated') {
    const problem = `truncated: the log has ${check.lines} lines; its anchor is at line ${check.seq}`
    return { ok: false, line: check.lines + 1, problem, anchor: check }
  }
  if (check.state === 'diverged') {
    const problem = `diverged: line ${check.seq} does not have its anchor's hash`
    return { ok: false, line: check.seq, problem, anchor: check }
  }
  return { ...chain, anchor: check }
}

function verifyLines(lines: readonly string[]): AuditVerdict {
  let prev = AUDIT_GENESIS
  for (const [i, text] of lines.entries()) {
    const n = i + 1
    let line: AuditLine
    try {
      line = parseAuditLine(text)
    } catch {
      return { ok: false, line: n, problem: 'not an audit line' }
    }
    if (line.seq !== n) return { ok: false, line: n, problem: `seq is ${line.seq}, not ${n}` }
    if (line.prev !== prev) return { ok: false, line: n, problem: "prev is not the previous line's hash" }
    if (auditHash(line) !== line.hash) return { ok: false, line: n, problem: 'the hash does not recompute' }
    prev = line.hash
  }
  return { ok: true, lines: lines.length }
}

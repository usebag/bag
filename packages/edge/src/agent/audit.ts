import { AUDIT_GENESIS, type AuditFields, auditHash, HOP_TAG, isCanonicalInteger, isHex } from '@usebag/core'
import type { AuditSink, Clock } from '../ports.ts'
import type { AgentCode, OpenRequest } from './model.ts'
import { hopDigest, type ReadRule, type UnsignedHop } from './rules.ts'

// The agent's own hash-chained audit log, in the line format of spec/SPEC.md §9 item 8,
// written through the edge's AuditSink port with the core's auditHash. It is a log of its own: the edge's Audit and
// its line parser know the agent's events as its own: `sign`, `open`, `declined`, `device` and `rotate`.

/**
 * What the agent audits: a signature under the held key, an opening for a session, a refused grant prompt, a device
 * grant and a group's generation taken.
 */
export type AgentAuditEvent = 'sign' | 'open' | 'declined' | 'device' | 'rotate'
export type AgentAuditReason = AgentCode | 'ok' | 'declined'

/** One step; the log adds seq, prev, ts and hash. `reason` is a code, or "ok" on an accept. */
export interface AgentAuditEntry {
  readonly event: AgentAuditEvent
  readonly decision: 'accept' | 'reject'
  readonly reason: AgentAuditReason
  readonly id: string | null
  readonly from: string | null
  readonly root: string | null
  readonly detail: Readonly<Record<string, string | number>>
}

/**
 * The `sign` line: the hop's digest, the requester (null for `ac grant`, a non-session client), the principal,
 * and the hop's shape by counts. Never a key, and never a caveat's text.
 */
export function signEntry(reason: AgentAuditReason, hop: UnsignedHop, from: string | null): AgentAuditEntry {
  const detail = { tag: HOP_TAG, sub: hop.sub, exp: hop.exp, caveats: hop.caveats.length }
  const decision = reason === 'ok' ? 'accept' : 'reject'
  return { event: 'sign', decision, reason, id: hopDigest(hop), from, root: hop.iss, detail }
}

/**
 * The `open` line: the envelope id, the session, the principal, the mailbox and, once the read rule ran, the
 * limb that decided. Never the sealed `type` and never a thread id.
 */
export function openEntry(
  reason: AgentCode | 'ok',
  req: Pick<OpenRequest, 'id' | 'session' | 'mailbox'>,
  root: string,
  rule: ReadRule | null,
): AgentAuditEntry {
  const decision = reason === 'ok' ? 'accept' : 'reject'
  const detail = rule === null ? { mailbox: req.mailbox } : { mailbox: req.mailbox, rule }
  return { event: 'open', decision, reason, id: req.id, from: req.session, root, detail }
}

/** Appends hash-chained lines to a sink, continuing the chain its last line ends. */
export class AgentAudit {
  readonly #sink: AuditSink
  readonly #clock: Clock
  #seq: number
  #prev: string

  /** Throws when the sink's last line is not an audit line: a log the agent cannot continue. */
  constructor(sink: AuditSink, clock: Clock) {
    this.#sink = sink
    this.#clock = clock
    const last = sink.last()
    const head: unknown = last === null ? { seq: 0, hash: AUDIT_GENESIS } : JSON.parse(last)
    const { seq, hash } = (head ?? {}) as { seq?: unknown; hash?: unknown }
    if (!isCanonicalInteger(seq) || !isHex(hash, 32)) throw new Error('a bad last line')
    this.#seq = seq
    this.#prev = hash
  }

  /** Writes one line and returns its text. */
  record(e: AgentAuditEntry): string {
    const fields: AuditFields = {
      seq: this.#seq + 1,
      prev: this.#prev,
      ts: this.#clock.now(),
      event: e.event,
      decision: e.decision,
      reason: e.reason,
      id: e.id,
      from: e.from,
      root: e.root,
      detail: JSON.stringify(e.detail),
    }
    const hash = auditHash(fields)
    const line = JSON.stringify({ ...fields, hash })
    this.#sink.append(line)
    this.#seq = fields.seq
    this.#prev = hash
    return line
  }
}

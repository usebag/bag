import type { OutboxReason, OutboxTarget } from './ports.ts'

// One send's delivery, counted the same way for the CLI's send (and resend, held release, group send) and the MCP
// server's send tool (W9, 2026-11-11). Before, a partial delivery read as a success in the MCP send, with no count,
// and as an error in the CLI. Now both say: delivered via at least one relay is a success, with a warning naming each
// relay that refused and its reason; no relay delivered is an error, as before.

/** A relay that refused the envelope for good (its target failed), with the relay's code or publish-failed. */
export interface RelayRefusal {
  readonly relay: string
  readonly reason: OutboxReason | null
}

/** How many of a send's relays took it, which refused it and why, and how many the outbox still tries. */
export interface Delivery {
  readonly delivered: number
  readonly relays: number
  readonly refused: readonly RelayRefusal[]
  readonly retrying: number
  /** One line: "delivered via n of m relays", then "; refused k: <relay> <reason>, ..." and "; retrying j". */
  readonly line: string
}

/** The delivery of `targets` (a retired target, replaced by a spare, is left out by the caller). */
export function deliveryOf(targets: readonly OutboxTarget[]): Delivery {
  const delivered = targets.filter((t) => t.state === 'published').length
  const refused = targets
    .filter((t) => t.state === 'failed')
    .map((t) => ({ relay: t.relay, reason: t.reason }))
  const retrying = targets.filter((t) => t.state === 'retry').length
  const parts = [`delivered via ${delivered} of ${targets.length} relay${targets.length === 1 ? '' : 's'}`]
  if (refused.length > 0)
    parts.push(
      `refused ${refused.length}: ${refused.map((r) => `${r.relay} ${r.reason ?? 'publish-failed'}`).join(', ')}`,
    )
  if (retrying > 0) parts.push(`retrying ${retrying}`)
  return { delivered, relays: targets.length, refused, retrying, line: parts.join('; ') }
}

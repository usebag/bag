import type { AuditEntry } from '../audit.ts'

// Regrant's lines in the identity's own log: the existing `policy` event, never a word of its own, since the audit
// event words are a closed set the telemetry schema mirrors (a new word is a new schema and a Worker deploy). The
// shape is the consent ask's (`step`, then `act`), so the grants are counted under policy with the other acts.

/** The four steps of a grant renewed in place, as the bag service's regrant names them. */
export const GRANT_ACTS = ['grant-renewed', 'regrant-asked', 'regrant-granted', 'regrant-refused'] as const
export type GrantAct = (typeof GRANT_ACTS)[number]

/** What a grant line may name: the label, the old and new subjects, the new `exp` and a refusal's code. */
export interface GrantDetail {
  readonly label?: string
  readonly from?: string
  readonly to?: string
  readonly exp?: number
  readonly code?: string
}

const DECISION = {
  'grant-renewed': 'accept',
  'regrant-asked': 'queue',
  'regrant-granted': 'accept',
  'regrant-refused': 'reject',
} as const

/**
 * One regrant line: `policy`, its decision by the act, `ok`, and a detail built from GrantDetail's members only, so
 * nothing else a caller holds (a key, a caveat's text) can reach the line.
 */
export function grantAuditEntry(act: GrantAct, f: GrantDetail = {}): AuditEntry {
  const detail: Record<string, string | number> = { step: 'grant', act }
  for (const k of ['label', 'from', 'to', 'code'] as const) {
    const v = f[k]
    if (typeof v === 'string') detail[k] = v
  }
  if (typeof f.exp === 'number') detail.exp = f.exp
  return { event: 'policy', decision: DECISION[act], reason: 'ok', from: null, detail }
}

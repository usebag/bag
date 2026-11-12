import { MAX_ENVELOPE_BYTES } from '@usebag/core'

// The accept-from max_bytes lift (W9, Dilip's decision of 2026-11-11). Every accept-from record signed before the
// envelope cap rose carries max_bytes 65,536, the old cap and the old default, and every re-sign path kept it: the
// peer's admit (pairing.ts), onboard, the MCP server's keepalive, record keep and unpair. Each now passes the held
// value through liftMaxBytes, so an identity takes the new default on its next re-sign (record keep re-signs at least
// every 11 hours), unattended. Any other value, chosen on purpose, is kept as it was. The cost: a max_bytes of 65,536
// chosen on purpose cannot be told from the old default, and is lifted too.

/** The old envelope cap, which every accept-from record carried as its max_bytes by default before the raise. */
export const OLD_DEFAULT_MAX_BYTES = 65_536

/** The max_bytes a re-sign writes for a held one: core's MAX_ENVELOPE_BYTES in place of exactly 65,536, else `held`. */
export function liftMaxBytes(held: number): number {
  return held === OLD_DEFAULT_MAX_BYTES ? MAX_ENVELOPE_BYTES : held
}

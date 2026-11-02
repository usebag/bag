import {
  AcError,
  type CaveatContext,
  type CaveatEvaluator,
  canonical,
  checkChainShape,
  evaluateCaveats,
  groupCaveat,
  type Hop,
  hopPreimage,
  isAddress,
  type SealedContent,
  sha256hex,
} from '@usebag/core'
import { AgentError, DEVICE_MAX, MIN_CAVEATS, WINDOW_MAX } from './model.ts'

// The agent's rules as pure functions: what it may sign and what it may release,
// from facts the caller supplies. No key, no clock and no state: the Agent holds those.

/** A hop before its signature: the form the agent checks before it signs. */
export type UnsignedHop = Omit<Hop, 'sig'>

/** What `ac grant` asks for. */
export interface GrantRequest {
  readonly session: string
  readonly caveats: readonly string[]
  readonly exp: number
}

/** What `ac device grant` asks for: D's key, the caveats (none allowed) and `exp`. */
export type DeviceGrantRequest = Omit<GrantRequest, 'session'> & { readonly device: string }
/** The index of a chain's held-key hop, which the grant-set tests, and the held group it is rooted at. */
export type ChainRoot = { readonly at: number; readonly group: string | null }

const NO_SIG = '0'.repeat(128)

/** sha256hex of a hop's preimage: the key of the grant-set and the `sign` audit id. */
export function hopDigest(h: UnsignedHop): string {
  return sha256hex(canonical(hopPreimage(h)))
}

/**
 * True when `caveats` is not empty and begins with `prefix` string for string: a byte-level test, never a
 * semantic one, so `type=coding.task.v1` is not taken as narrower than `type=coding.*`.
 */
export function hasCaveatPrefix(caveats: readonly string[], prefix: readonly string[]): boolean {
  return caveats.length >= MIN_CAVEATS && prefix.every((c, i) => caveats[i] === c)
}

/**
 * The derived hop, in its fixed order: §6.2 rules 2 to 4 (`bad-hop`, `too-many-caveats`, `caveat-too-long`);
 * the exact prefix of the effective caveats (`not-in-grant`, an empty list included); `exp` at most `limit`
 * (`exp-not-monotone`). `limit` is the chain's earliest `exp`, or the window's end for a renewal, and never past
 * `now` + 8 hours.
 */
export function deriveHop(
  principal: string,
  effective: readonly string[],
  req: Pick<Hop, 'sub' | 'caveats' | 'exp'>,
  limit: number,
): UnsignedHop {
  const hop = { iss: principal, sub: req.sub, caveats: [...req.caveats], exp: req.exp }
  checkChainShape([{ ...hop, sig: NO_SIG }])
  if (!hasCaveatPrefix(hop.caveats, effective)) {
    throw new AgentError('not-in-grant', "the caveats do not begin with the session's caveats")
  }
  if (hop.exp > limit) throw new AcError('exp-not-monotone', `exp is past ${limit}`)
  return hop
}

/**
 * The first grant before the terminal's `y`: `bad-shape` with no caveat, §6.2 rules 2 to 4, then
 * `exp-not-monotone` past `limit`, the window's end and `now` + 8 hours.
 */
export function checkGrant(principal: string, req: GrantRequest, limit: number): UnsignedHop {
  if (req.caveats.length < MIN_CAVEATS) throw new AcError('bad-shape', 'a grant carries at least one caveat')
  const hop = { iss: principal, sub: req.session, caveats: [...req.caveats], exp: req.exp }
  checkChainShape([{ ...hop, sig: NO_SIG }])
  if (hop.exp > limit) throw new AcError('exp-not-monotone', `exp is past ${limit}`)
  return hop
}

/** The device hop before the `y`: `bad-address`, `bad-shape`, then `exp-not-monotone`. */
export function checkDeviceGrant(principal: string, req: DeviceGrantRequest, now: number): UnsignedHop {
  if (!isAddress(req.device) || req.device === principal) throw new AcError('bad-address', 'not a device')
  const hop = { iss: principal, sub: req.device, caveats: [...req.caveats], exp: req.exp }
  try {
    checkChainShape([{ ...hop, sig: NO_SIG }])
  } catch {
    throw new AcError('bad-shape', "the caveats or exp break section 6.1's bounds")
  }
  if (hop.exp > now + DEVICE_MAX) throw new AcError('exp-not-monotone', `exp is past ${now + DEVICE_MAX}`)
  return hop
}

/**
 * The root rule of a verified chain: (a) root P, chain[0] P's hop, or on a
 * device the held device hop by digest; (b) never on a device, root a held group G, chain[0] its membership of P
 * carrying `group=<G>`. Anything else is `not-authorized`.
 */
export function rootRule(
  chain: readonly Hop[],
  principal: string,
  device: Hop | null,
  held: (group: string) => boolean,
): ChainRoot {
  const first = chain[0]
  if (first?.iss === principal) {
    if (device === null) return { at: 0, group: null }
    if (hopDigest(first) === hopDigest(device)) return { at: 1, group: null }
  } else if (first !== undefined && device === null && held(first.iss) && first.sub === principal) {
    if (first.caveats.includes(groupCaveat(first.iss))) return { at: 1, group: first.iss }
  }
  throw new AcError(
    'not-authorized',
    "the chain's root is not the principal, nor a held group's membership of it",
  )
}

/** The latest `exp` a hop signed at `now` may carry in a window ending at `end`. */
export function grantLimit(now: number, end: number): number {
  return Math.min(end, now + WINDOW_MAX)
}

/** The read rule's limb: (a) a registered thread, (b) a root message the caveats admit. */
export type ReadRule = 'thread' | 'root'

/** The read rule's verdict. A withheld read leaves as `not-in-grant`; `reason` is for the agent's audit alone. */
export type ReadDecision =
  | { readonly release: true; readonly rule: ReadRule }
  | {
      readonly release: false
      readonly rule: ReadRule
      readonly reason: 'not-in-grant' | 'caveat-failed' | 'unknown-caveat'
    }

/**
 * The read rule: release when (a) the thread id is one the session registered, or (b) the content is a root
 * message (`thread.prev` empty) and every effective caveat holds for it, a caveat no evaluator knows failing closed.
 */
export function decideRead(
  content: SealedContent,
  threads: ReadonlySet<string>,
  caveats: readonly string[],
  evaluators: readonly CaveatEvaluator[],
  ctx: Omit<CaveatContext, 'sealed'>,
): ReadDecision {
  if (threads.has(content.thread.id)) return { release: true, rule: 'thread' }
  if (content.thread.prev.length > 0) return { release: false, rule: 'thread', reason: 'not-in-grant' }
  if (caveats.length < MIN_CAVEATS) return { release: false, rule: 'root', reason: 'not-in-grant' }
  const verdict = evaluateCaveats(caveats, evaluators, { ...ctx, sealed: content })
  return verdict.ok ? { release: true, rule: 'root' } : { release: false, rule: 'root', reason: verdict.code }
}

// Caveats are printed on the agent's own terminal before the `y` as JSON text, with every control and format
// character (the bidirectional and the invisible ones), every unassigned code point (the tags' gaps) and the line and
// paragraph separators escaped, one \u per UTF-16 unit, so no caveat can redraw, hide or pass for another.
const UNPRINTABLE = /[\p{Cc}\p{Cf}\p{Cn}\p{Zl}\p{Zp}]/gu
const escapeChar = (ch: string): string =>
  ch
    .split('')
    .map((u) => `\\u${u.charCodeAt(0).toString(16).padStart(4, '0')}`)
    .join('')

/** The lines printed before the `y`: the subject, its caveats (or `unrestricted`) and its `exp`. */
export function grantLines(hop: UnsignedHop, kind: 'grant' | 'device grant' = 'grant'): readonly string[] {
  const shown = hop.caveats.map((c) => JSON.stringify(c).replace(UNPRINTABLE, escapeChar))
  return [
    `${kind} to ${kind === 'grant' ? 'session ' : ''}${hop.sub}`,
    `caveats ${shown.length > 0 ? shown.join(' ') : 'unrestricted'}`,
    `until ${hop.exp} (${new Date(hop.exp * 1000).toISOString()})`,
    `sign this ${kind}? type y to sign`,
  ]
}

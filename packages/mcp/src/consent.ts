import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

// The pairing consent bridge for a host that cannot show a dialog (omp's no-elicitation): the server asks the person
// through a file the host's extension answers, in place of today's no-elicitation refusal (consent-bridge.md, decision
// 83h). The extension writes <home>/state/<name>/consent/.bridge at session start and refreshes it; the server treats
// the bridge as present when that file is younger than 600 s and its pid is alive. For a pairing the server writes a
// request file, 0600, atomic, and polls the answer the extension writes beside it every 250 ms until its expires_at,
// 120 s on; the person pressing Yes is the human act. The seam (the file shapes) is W1's and does not change here.
//
// The code never reaches the model (decision 83i, 15:50 UTC), so "the code is never a tool argument" stays true. The
// three kinds:
// - pair-accept-code: the acceptor's first dialog, peer null. The person pastes the invite or code they got out of
//   band; the extension returns it in answer.code (a string, up to 256 characters, trimmed, no six-digit rule), and the
//   server resolves the inviter from it as the paste dialog does today.
// - pair-accept: the confirm. For the acceptor the request carries the six check digits the server computed, and the
//   person reads them out and presses Yes (answer.code null). For the inviter's one request the server sends code null,
//   and the person types the six digits the peer reads out, returned in answer.code, which the server verifies against
//   its own computation.
// - pair-invite-show: a pure "shown to the peer" confirm, code the invite code to show, a boolean answer.
// A local pair's dialog (spec/SPEC.md 9.2) never uses these files: on omp the bag service asks over the extension's own
// registered link (service.ts, service/consent-ask), never through a file a command could write.
// The server completes the pairing only with the peer and root from ITS request, never from the answer, which may carry
// only v, id, accepted, code and answered_at.

/** How young the .bridge presence file must be for the bridge to count as present, in milliseconds. */
export const BRIDGE_FRESH_MS = 600_000
/** A consent request's life, in seconds: asked_at + this is its expires_at. */
export const CONSENT_TTL_S = 120
/** How often the answer file is polled, in milliseconds. */
export const CONSENT_POLL_MS = 250

/** The peer a consent request names: its petname (or null before one is known), address and root. */
export interface ConsentPeer {
  readonly name: string | null
  readonly address: string
  readonly root: string
}

/** The request kinds: paste the peer's code, accept/confirm a peer (digits), or confirm an invite code was shown. */
export type ConsentKind = 'pair-accept-code' | 'pair-accept' | 'pair-invite-show'

/** A local act's dialog words (a local pair, a hide or a show): its title and message, built by the service. */
export interface ConsentWords {
  readonly title: string
  readonly message: string
}

/**
 * The longest pasted invite or code a pair-accept-code answer may carry, in characters (after trimming). An invite
 * string (ac-peer1:..., two ed25519 addresses base64url) runs ~310, so the cap leaves room for a long relay URL. The
 * seam with W1's ctx.ui.input length check (1 to 512), pinned at 512 by decision 83i (a real invite measured 309).
 */
export const MAX_PASTE = 512

/** What a settled consent is: the person's yes with any typed code, or a refusal with its reason. */
export type ConsentOutcome =
  | { readonly accepted: true; readonly code: string | null }
  | { readonly accepted: false; readonly reason: string }

const bad = (reason: string): ConsentOutcome => ({ accepted: false, reason })

/**
 * The directory an identity's consent files live in: <home>/state/<name>/consent; with name null, `home` is the
 * directory itself (the bag service's bridge per connection, which the shim of an omp session owns).
 */
function consentDir(home: string, name: string | null): string {
  return name === null ? home : join(home, 'state', name, 'consent')
}

/** Whether the process `pid` is alive, as the lock's holder check is: a signal of 0 reaches it, EPERM means it lives. */
export function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return (e as { code?: string }).code === 'EPERM'
  }
}

const iso = (seconds: number): string => new Date(seconds * 1000).toISOString()

/**
 * True when the host's extension has a live bridge: <home>/state/<name>/consent/.bridge parses as {v:1, pid, at, ...},
 * was written less than 600 s ago, and its pid is alive. Any read, parse or shape error is "no bridge" (the fallback).
 */
export function bridgePresent(
  home: string,
  name: string | null,
  now: number,
  alive: (pid: number) => boolean,
): boolean {
  try {
    const b = JSON.parse(readFileSync(join(consentDir(home, name), '.bridge'), 'utf8')) as {
      v?: unknown
      pid?: unknown
      at?: unknown
    }
    if (b.v !== 1 || typeof b.pid !== 'number') return false
    const at = Date.parse(String(b.at))
    return Number.isFinite(at) && now * 1000 - at < BRIDGE_FRESH_MS && alive(b.pid)
  } catch {
    return false
  }
}

/**
 * One consent request: on construction it writes <dir>/<id>.json (0600, atomic temp-and-rename); poll reads the answer
 * the extension writes to <dir>/<id>.answer.json and settles, or times out at expires_at, removing both files. One runs
 * at a time per identity, enforced by the one-pairing-per-server rule that holds it. wait polls every 250 ms until it
 * settles or the call's signal aborts, when it leaves the request in place for a resume to go on polling.
 */
export class Consent {
  readonly #req: string
  readonly #answer: string
  readonly #id: string
  readonly #kind: ConsentKind
  readonly #expiresAt: number

  constructor(
    home: string,
    name: string | null,
    id: string,
    kind: ConsentKind,
    peer: ConsentPeer | null,
    code: string | null,
    relay: string,
    now: number,
  ) {
    const dir = consentDir(home, name)
    this.#id = id
    this.#kind = kind
    this.#req = join(dir, `${id}.json`)
    this.#answer = join(dir, `${id}.answer.json`)
    this.#expiresAt = now + CONSENT_TTL_S
    const body = {
      v: 1,
      id,
      kind,
      peer,
      code,
      relay,
      asked_at: iso(now),
      expires_at: iso(this.#expiresAt),
    }
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const tmp = `${this.#req}.${process.pid}.tmp`
    writeFileSync(tmp, JSON.stringify(body), { mode: 0o600 })
    renameSync(tmp, this.#req)
  }

  /** The answer once it is there, a timeout at expires_at (both remove the files), or 'pending' while neither holds. */
  poll(now: number): ConsentOutcome | 'pending' {
    let text: string
    try {
      text = readFileSync(this.#answer, 'utf8')
    } catch {
      if (now >= this.#expiresAt) return this.#settle(bad('timeout'))
      return 'pending'
    }
    return this.#settle(this.#read(text))
  }

  /**
   * The answer, validated: it parses, carries only v, id, accepted, code and answered_at, v is 1, id matches the
   * request, accepted is a boolean, and code is null or six digits (spaces and hyphens ignored). Any miss is a refusal
   * with its reason; the server still verifies a non-null code against its own digits, so a well-formed wrong code is
   * caught there.
   */
  #read(text: string): ConsentOutcome {
    let a: Record<string, unknown>
    try {
      a = JSON.parse(text) as Record<string, unknown>
    } catch {
      return bad('answer-unparsable')
    }
    if (Object.keys(a).sort().join(',') !== 'accepted,answered_at,code,id,v') return bad('answer-shape')
    if (a.v !== 1) return bad('answer-version')
    if (a.id !== this.#id) return bad('answer-id-mismatch')
    // A late answer is never read: the extension defaults a timed-out confirm to No and aborts at expires_at, so an
    // answer stamped at or after expires_at (or with no parsable stamp) is a timeout, not the person's word (83i omp).
    const answeredAt = Date.parse(String(a.answered_at))
    if (!Number.isFinite(answeredAt)) return bad('answer-time')
    if (answeredAt >= this.#expiresAt * 1000) return bad('timeout')
    if (typeof a.accepted !== 'boolean') return bad('answer-accepted')
    if (!a.accepted) return bad('declined')
    // pair-accept-code carries the pasted invite or code, a string the server resolves as the paste dialog does; the
    // digit kinds carry six digits or null. A bad code of either shape is a refusal.
    if (this.#kind === 'pair-accept-code') {
      const pasted = typeof a.code === 'string' ? a.code.trim() : ''
      return pasted !== '' && pasted.length <= MAX_PASTE
        ? { accepted: true, code: pasted }
        : bad('answer-code')
    }
    const code = a.code === null ? null : String(a.code).replace(/[\s-]/g, '')
    if (code !== null && !/^\d{6}$/.test(code)) return bad('answer-code')
    return { accepted: true, code }
  }

  /** Polls until the request settles, or the call's signal aborts (then 'pending': the request file stays for a resume). */
  async wait(
    signal: AbortSignal,
    sleep: (ms: number) => Promise<void>,
    now: () => number,
  ): Promise<ConsentOutcome | 'pending'> {
    for (;;) {
      const o = this.poll(now())
      if (o !== 'pending') return o
      if (signal.aborted) return 'pending'
      await sleep(CONSENT_POLL_MS)
    }
  }

  /** Removes the request and answer files; a settled consent leaves nothing behind. */
  #settle(o: ConsentOutcome): ConsentOutcome {
    rmSync(this.#req, { force: true })
    rmSync(this.#answer, { force: true })
    return o
  }

  /** Drops the request without an answer: the pairing ended under it (an abort that will not resume, a refusal). */
  cancel(): void {
    this.#settle(bad('cancelled'))
  }
}

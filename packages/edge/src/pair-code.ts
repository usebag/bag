import { hkdfSync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { guardCheck, type RelayGuard } from './net.ts'
import type { PairOpen, PairReach, RelayClient, Rng } from './ports.ts'

// The short word code: `<nameplate>-<word>-<word>-<word>`, and
// `...@<host>` to name a private rendezvous relay. The rendezvous relay, which both sides configure, allocates the
// nameplate, a public locator for the invitation (§3); the three words are the secret, drawn here from the wordlist, and
// never reach a relay. They seed S, the invitation's mac key, bound to the nameplate and the invitation identity I (§2;
// spec/vectors/pair-code.json). The six digits still carry integrity: S's secrecy only keeps strangers' requests out.

/** The words a code carries (§4: 31 bits against the relay's 60 requests per invitation). */
export const CODE_WORDS = 3

/** A wordlist as the codec needs it (§4's arithmetic): exactly 1296 distinct words of a to z; throws for anything else. */
export function wordlist(v: unknown): readonly string[] {
  const words = Array.isArray(v) && v.every((w) => typeof w === 'string' && /^[a-z]+$/.test(w)) ? v : []
  if (words.length !== 1296 || new Set(words).size !== 1296)
    throw new Error('not 1296 distinct words of a to z')
  return Object.freeze([...words])
}

/** The wordlist.json: the EFF short wordlist 1, with yarn for yo-yo (CC BY 3.0 US; THIRD-PARTY.md). */
export const WORDS = wordlist(JSON.parse(readFileSync(new URL('./wordlist.json', import.meta.url), 'utf8')))

/** A code's parts: the nameplate (decimal digits, no leading zero), its words (a to z), and its rendezvous host if any. */
export interface Code {
  readonly nameplate: string
  readonly words: readonly string[]
  readonly at?: string
}

/** The code as a person reads it: `472-tulip-orbit-cedar`. */
export function formatCode(c: Code): string {
  return [c.nameplate, ...c.words].join('-')
}

/**
 * A code typed back in any case, with spaces or hyphens between and around its parts, and `@<host>[:<port>]` after it
 * for a private rendezvous (claimed at https://<host>); null for anything else.
 */
export function parseCode(text: string): Code | null {
  const [code, at, ...more] = text.normalize('NFKC').toLowerCase().trim().split('@') as [string, ...string[]]
  const [nameplate, ...words] = code.replace(/^[\s-]+|[\s-]+$/g, '').split(/[\s-]+/) as [string, ...string[]]
  const host = at === undefined || /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$/.test(at.trim())
  const ok = /^[1-9][0-9]{0,8}$/.test(nameplate) && words.length === CODE_WORDS && host && more.length === 0
  if (!ok || !words.every((w) => /^[a-z]+$/.test(w))) return null
  return at === undefined ? { nameplate, words } : { nameplate, words, at: `https://${at.trim()}` }
}

/** Three words drawn uniformly (two random bytes each, those past the last whole multiple of the list drawn again). */
export function newWords(rng: Rng): string[] {
  const words: string[] = []
  const top = WORDS.length * Math.floor(65_536 / WORDS.length)
  while (words.length < CODE_WORDS) {
    const two = rng.bytes(2)
    const n = (two[0] as number) * 256 + (two[1] as number)
    if (n < top) words.push(WORDS[n % WORDS.length] as string)
  }
  return words
}

/** S in hex (§2): HKDF-SHA256 of NFKC(lower(the words joined by a space)), salt `<nameplate>|<I>`, 16 bytes. */
export function codeSecret(c: Code, invitation: string): string {
  const ikm = Buffer.from(c.words.join(' ').toLowerCase().normalize('NFKC'))
  const salt = Buffer.from(`${c.nameplate}|${invitation}`)
  return Buffer.from(hkdfSync('sha256', ikm, salt, 'ac/peer-code/1', 16)).toString('hex')
}

/**
 * Opens a rendezvous at `url`: its nameplate, or null when the client or the relay offers no pair call. A `guard`
 * refuses a private or loopback `url` that is not one of the edge's relays (resolve-failed, before any request).
 */
export async function openRendezvous(
  client: RelayClient,
  url: string,
  open: PairOpen,
  guard?: RelayGuard,
): Promise<string | null> {
  await guardCheck(guard, url)
  return client.pairOpen === undefined ? null : client.pairOpen(url, open)
}

/** The reach open under `nameplate` at `url`, or null when none is (or the client offers no pair call); guarded so. */
export async function claimRendezvous(
  client: RelayClient,
  url: string,
  nameplate: string,
  guard?: RelayGuard,
): Promise<PairReach | null> {
  await guardCheck(guard, url)
  return client.pairClaim === undefined ? null : client.pairClaim(url, nameplate)
}

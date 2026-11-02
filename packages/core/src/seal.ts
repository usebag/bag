import { isAddress } from './address.ts'
import { type CanonicalValue, canonical } from './canonical.ts'
import { AcError } from './errors.ts'
import { sha256hex } from './hash.ts'
import { fromHex, isHex, toHex, utf8 } from './hex.ts'
import { aeadOpen, aeadSeal, hpkeSeal } from './hpke.ts'
import { hasExactKeys, hexField, isPlainObject, parseJson } from './json.ts'
import type { OpenerLike, Rng } from './keys.ts'
import { checkThread, type Thread } from './thread.ts'

/** The envelope format version, `v`. The content AAD binds it. */
export const ENVELOPE_VERSION = 1
/** The HPKE `info` of every wrap (spec/SPEC.md §4). */
export const SEAL_INFO = 'ac/seal/1'
/** The most recipients an envelope has. */
export const MAX_RECIPIENTS = 16

/**
 * A `type` holds no Unicode control character (General_Category `Cc`: U+0000 to U+001F, U+007F, U+0080 to U+009F) and
 * no line or paragraph separator (U+2028, U+2029). A raw C0 is already rejected at JSON parse; this also refuses an
 * escaped C0, and DEL, C1 and the separators, which are legal JSON but break a line at a display sink (spec/SPEC.md
 * §5.2, added 2026-10-27; the same class the relay-URL rule bans, records.ts). Used by both encode and decode.
 */
const TYPE_FORBIDDEN = /[\p{Cc}\u2028\u2029]/u

/** One recipient's wrap: the content key, HPKE-sealed to that recipient's sealing key. */
export interface Wrap {
  readonly to: string
  readonly enc: string
  readonly ct: string
}

/** The sealed part on the wire: one wrap per recipient, the content nonce and ciphertext. */
export interface Sealed {
  readonly wraps: readonly Wrap[]
  readonly nonce: string
  readonly ct: string
}

/** What the seal hides from relays: the type, the thread and the body. */
export interface SealedContent {
  readonly type: string
  readonly thread: Thread
  readonly body: unknown
}

/** A recipient to seal to: its address and its 32-byte X25519 sealing key. */
export interface Recipient {
  readonly address: string
  readonly sealingKey: Uint8Array
}

/** The recipient that opens: its address and its sealing key. */
export interface RecipientKey {
  readonly address: string
  readonly key: OpenerLike
}

/** The fields of an envelope that opening reads. */
export interface SealedEnvelope {
  readonly to: readonly string[]
  readonly from: string
  readonly sealed: Sealed
}

const SEALED_KEYS = ['wraps', 'nonce', 'ct'] as const
const WRAP_KEYS = ['to', 'enc', 'ct'] as const
const CONTENT_KEYS = ['type', 'thread', 'body'] as const

/**
 * Checks a recipient list: 1 to 16 unique addresses (bad-shape when empty, not strings or repeated;
 * too-many-recipients over 16; bad-address for a string that is not an address). Returns a copy.
 */
export function checkRecipients(to: unknown): readonly string[] {
  if (!Array.isArray(to) || to.length === 0)
    throw new AcError('bad-shape', 'to is a list of 1 to 16 addresses')
  if (to.length > MAX_RECIPIENTS) {
    throw new AcError('too-many-recipients', `${to.length} recipients; the cap is ${MAX_RECIPIENTS}`)
  }
  for (const a of to) {
    if (typeof a !== 'string') throw new AcError('bad-shape', 'each recipient is an address string')
    if (!isAddress(a)) throw new AcError('bad-address', 'a recipient is not an address')
  }
  if (new Set(to).size !== to.length) throw new AcError('bad-shape', 'a recipient is listed twice')
  return [...to]
}

/** The AAD of the content ciphertext: utf8(canonical([v, to, from])). */
export function contentAad(to: readonly string[], from: string): Uint8Array {
  return utf8(canonical([ENVELOPE_VERSION, to, from]))
}

/** The plaintext of the content: utf8(JSON.stringify({type, thread, body})). */
export function encodeContent(content: SealedContent): Uint8Array {
  if (typeof content.type !== 'string' || content.type.length === 0 || TYPE_FORBIDDEN.test(content.type)) {
    throw new AcError('bad-content', 'type is a non-empty string with no control or line-separator character')
  }
  const thread = checkThread(content.thread)
  const body: unknown = content.body
  if (body === undefined || typeof body === 'function' || typeof body === 'symbol') {
    throw new AcError('bad-content', 'body is a JSON value')
  }
  try {
    return utf8(JSON.stringify({ type: content.type, thread: { id: thread.id, prev: thread.prev }, body }))
  } catch {
    throw new AcError('bad-content', 'body is not JSON-serializable')
  }
}

/**
 * The content of a plaintext: bad-content, bad-thread or too-many-prev unless it is {type, thread, body}. Numbers are
 * read as JSON.parse reads them, because `body` may hold any JSON value, fractions included (spec/SPEC.md §4.2); the
 * integer rule of §2.5 holds for `thread` all the same, since a thread holds strings only and any number in it is
 * bad-thread.
 */
export function decodeContent(plaintext: Uint8Array): SealedContent {
  const value = parseJson(plaintext, 'bad-content', { strictIntegers: false })
  if (!isPlainObject(value) || !hasExactKeys(value, CONTENT_KEYS)) {
    throw new AcError('bad-content', 'the sealed content is an object with exactly type, thread and body')
  }
  if (typeof value.type !== 'string' || value.type.length === 0 || TYPE_FORBIDDEN.test(value.type)) {
    throw new AcError('bad-content', 'type is a non-empty string with no control or line-separator character')
  }
  return { type: value.type, thread: checkThread(value.thread), body: value.body }
}

function draw(rng: Rng, length: number): Uint8Array {
  const bytes = rng(length)
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
    throw new AcError('bad-key', `the rng returned other than ${length} bytes`)
  }
  return bytes
}

/**
 * Seals the content to every recipient (spec/SPEC.md §4). The rng supplies, in this order, the 32-byte content key,
 * the 12-byte nonce and one 32-byte ephemeral X25519 key per recipient.
 */
export function sealTo(
  recipients: readonly Recipient[],
  from: string,
  content: SealedContent,
  rng: Rng,
): Sealed {
  const to = checkRecipients(recipients.map((r) => r.address))
  if (!isAddress(from)) throw new AcError('bad-address', 'from is not an address')
  for (const r of recipients) {
    if (!(r.sealingKey instanceof Uint8Array) || r.sealingKey.length !== 32) {
      throw new AcError('bad-key', 'a sealing key is 32 bytes')
    }
  }
  const plaintext = encodeContent(content)
  const contentKey = draw(rng, 32)
  const nonce = draw(rng, 12)
  const info = utf8(SEAL_INFO)
  const wraps = recipients.map((r) => {
    const { enc, ct } = hpkeSeal(r.sealingKey, info, utf8(r.address), contentKey, draw(rng, 32))
    return { to: r.address, enc: toHex(enc), ct: toHex(ct) }
  })
  return {
    wraps,
    nonce: toHex(nonce),
    ct: toHex(aeadSeal(contentKey, nonce, contentAad(to, from), plaintext)),
  }
}

/**
 * Opens the sealed part as one recipient: not-recipient when no wrap names the address, open-failed when the wrap or
 * the content does not open, and bad-content, bad-thread or too-many-prev when the plaintext is malformed.
 */
export function openSealed(e: SealedEnvelope, me: RecipientKey): SealedContent {
  const wrap = e.sealed.wraps.find((w) => w.to === me.address)
  if (wrap === undefined) throw new AcError('not-recipient', 'no wrap names this address')
  if (!isHex(wrap.enc, 32) || !isHex(wrap.ct) || !isHex(e.sealed.nonce, 12) || !isHex(e.sealed.ct)) {
    throw new AcError('open-failed', 'the sealed part is not well-formed hex')
  }
  const contentKey = me.key.open(fromHex(wrap.enc), utf8(SEAL_INFO), utf8(me.address), fromHex(wrap.ct))
  if (contentKey.length !== 32) throw new AcError('open-failed', 'the wrapped content key is not 32 bytes')
  return decodeContent(
    aeadOpen(contentKey, fromHex(e.sealed.nonce), contentAad(e.to, e.from), fromHex(e.sealed.ct)),
  )
}

/** The sealed-hash preimage (spec/SPEC.md §2): [wraps as [[to, enc, ct]...], nonce, ct]. */
export function sealedHashPreimage(s: Sealed): CanonicalValue {
  return [s.wraps.map((w) => [w.to, w.enc, w.ct]), s.nonce, s.ct]
}

/** sha256hex of the sealed part's canonical form: position 6 of the envelope id preimage. */
export function sealedHash(s: Sealed): string {
  return sha256hex(canonical(sealedHashPreimage(s)))
}

/**
 * Checks the sealed part of a parsed envelope against its `to` (spec/SPEC.md §5): exactly wraps, nonce and ct; one
 * wrap per recipient, in the order of `to`; enc 32 bytes, each wrap's ct 48 bytes, nonce 12 bytes, ct at least 16
 * bytes (bad-shape, bad-hex). Returns a copy.
 */
export function checkSealed(value: unknown, to: readonly string[]): Sealed {
  if (!isPlainObject(value) || !hasExactKeys(value, SEALED_KEYS)) {
    throw new AcError('bad-shape', 'sealed is an object with exactly wraps, nonce and ct')
  }
  if (!Array.isArray(value.wraps) || value.wraps.length !== to.length) {
    throw new AcError('bad-shape', 'sealed.wraps holds one wrap per recipient')
  }
  const wraps = value.wraps.map((w: unknown, i) => {
    if (!isPlainObject(w) || !hasExactKeys(w, WRAP_KEYS)) {
      throw new AcError('bad-shape', 'a wrap is an object with exactly to, enc and ct')
    }
    if (w.to !== to[i]) throw new AcError('bad-shape', 'the wraps follow the order of to')
    return {
      to: to[i] as string,
      enc: hexField(w.enc, 32, 'a wrap enc'),
      ct: hexField(w.ct, 48, 'a wrap ct'),
    }
  })
  const nonce = hexField(value.nonce, 12, 'sealed.nonce')
  const ct = hexField(value.ct, undefined, 'sealed.ct')
  if (ct.length < 32) throw new AcError('bad-hex', 'sealed.ct holds at least the 16-byte tag')
  return { wraps, nonce, ct }
}

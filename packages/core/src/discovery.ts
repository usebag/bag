import { isAddress } from './address.ts'
import { AcError } from './errors.ts'
import { isSpecialUseDomain } from './handles.ts'
import { type AddressRecord, isDomainHost, MAX_DOMAIN_LENGTH, verifyRotationClaim } from './records.ts'

// Discovery by DNS (spec/SPEC.md §12.1 and §12.2, L2; 2026-10-26):
// an org's TXT record at `_bag.<domain>` names the key that signs its address record and, at most, that the
// org's one origin is `https://bag.<domain>` rather than `https://<domain>`; it names no URL. DNS is a
// hint and the signature is the authority: the record at the origin must still verify and agree with the TXT's key, by
// that key or by one rotation it countersigned, so a forged TXT can fail a resolution but never choose the key a
// reader pins, and never moves a pin. Pure: a reader looks the records up itself and hands them here.

/** The name under which an org publishes its TXT record, before its domain. */
export const DISCOVERY_PREFIX = '_bag.'
/** The path of an org's address record at its origin (§12.1). */
export const WELL_KNOWN_RECORD_PATH = '/.well-known/bag/address.json'
/** The one value of a TXT's `host` field: the org's origin is then `https://bag.<domain>` (§12.1). */
export const BAG_HOST = 'bag'
/** The first field of a bag TXT record. */
export const TXT_VERSION_FIELD = 'v=ac1'
/** The longest bag TXT record, in bytes once its strings are joined (implementation default). */
export const MAX_TXT_BYTES = 1024
/** The longest character-string of a TXT record, in bytes (RFC 1035 §3.3). */
export const MAX_TXT_STRING = 255

/** A bag TXT record: the key that signs the org's record, and its `host`, `bag` or null. */
export interface DiscoveryTxt {
  readonly key: string
  readonly host: string | null
}

/** Where a domain's address record is, and the key it must agree with (null when the domain has no TXT record). */
export interface Discovery {
  readonly key: string | null
  /** The org's address record: `<origin>/.well-known/bag/address.json`. */
  readonly url: string
  /** The org's one origin (§12.1), `https://bag.<domain>` or `https://<domain>`: its records are all there. */
  readonly origin: string
}

const NAME = /^[A-Za-z][A-Za-z0-9_-]{0,31}$/
// One or more of ! to ~ but ;, so no space or tab inside.
const VALUE = /^[!-:<-~]+$/
// Tab, and space to ~: the only characters a bag record and a TXT record's text form may hold.
const PRINTABLE = /^[\t -~]*$/
const SPACE = /^[ \t]+|[ \t]+$/g

function refused(detail: string): AcError {
  return new AcError('resolve-failed', detail)
}

function trim(text: string): string {
  return text.replace(SPACE, '')
}

/** The host of a domain, or resolve-failed. */
function domainOf(domain: string): string {
  if (!isDomainHost(domain)) throw refused(`${JSON.stringify(domain)} is not a domain`)
  return domain
}

/**
 * The name to look the TXT records of a domain up at, or null when none is asked (§12.2 item 4): a name over 253
 * characters (none exists), or a domain under a special-use name, which RFC 6761, 6762, 7686 and 9476 keep off DNS.
 */
export function txtName(domain: string): string | null {
  const name = DISCOVERY_PREFIX + domainOf(domain)
  return name.length > MAX_DOMAIN_LENGTH || isSpecialUseDomain(domain) ? null : name
}

/**
 * Reads the text form of one TXT record (RFC 1035 §5.1; spec/SPEC.md §12.2 item 7): character-strings separated by
 * spaces or tabs, each quoted or bare, with `\DDD` and `\X` escapes, at most 255 bytes each, the text tab and space to
 * ~ only. Each string comes back as a binary string, one character per byte. resolve-failed for anything else.
 */
export function parseTxtPresentation(text: string): string[] {
  if (!PRINTABLE.test(text)) throw refused('a TXT text holds a character other than tab and space to ~')
  const out: string[] = []
  let i = 0
  const white = (c: string | undefined): boolean => c === ' ' || c === '\t'
  // The byte an escape at text[i] (just after its backslash) stands for, and the index after it.
  const escaped = (at: number): [string, number] => {
    const c = text[at]
    if (c === undefined) throw refused('a TXT text ends in a backslash')
    if (c < '0' || c > '9') return [c, at + 1]
    const digits = text.slice(at, at + 3)
    if (!/^[0-9]{3}$/.test(digits) || Number(digits) > 255)
      throw refused('\\DDD needs three digits up to 255')
    return [String.fromCharCode(Number(digits)), at + 3]
  }
  for (;;) {
    while (white(text[i])) i++
    if (i >= text.length) break
    let s = ''
    const quoted = text[i] === '"'
    if (quoted) i++
    for (;;) {
      const c = text[i]
      if (c === undefined) {
        if (quoted) throw refused('a quoted TXT string is not closed')
        break
      }
      if (quoted && c === '"') {
        i++
        if (i < text.length && !white(text[i])) throw refused('a quoted TXT string is followed by more text')
        break
      }
      if (!quoted && white(c)) break
      if (!quoted && c === '"') throw refused('a quote inside a bare TXT string')
      if (!quoted && (c === '(' || c === ')')) throw refused('a parenthesis inside a bare TXT string')
      if (c === '\\') {
        const [byte, next] = escaped(i + 1)
        s += byte
        i = next
      } else {
        s += c
        i++
      }
    }
    if (s.length > MAX_TXT_STRING)
      throw refused(`a TXT string of ${s.length} bytes; the cap is ${MAX_TXT_STRING}`)
    out.push(s)
  }
  if (out.length === 0) throw refused('a TXT text with no string')
  return out
}

/** A field `name=value` with spaces and tabs around, or null when it breaks the grammar of §12.2 item 1. */
function field(part: string): readonly [string, string] | null {
  const at = part.indexOf('=')
  if (at === -1) return null
  const name = trim(part.slice(0, at))
  const value = trim(part.slice(at + 1))
  return NAME.test(name) && VALUE.test(value) ? [name, value] : null
}

/**
 * Reads one TXT record's joined text for the domain (spec/SPEC.md §12.2 items 1 to 3): null when it is not an
 * bag record (its first field is not `v=ac1`); resolve-failed when it is one but malformed: a field given twice,
 * no `key`, a `rec` (no URL is read from DNS), a field that breaks the grammar, a `key` that is not an address,
 * a `host` other than `bag`, a character other than tab and space to ~, or over 1,024 bytes. A field of another
 * name is ignored.
 */
export function parseDiscoveryTxt(text: string, domain: string): DiscoveryTxt | null {
  domainOf(domain)
  const parts = text
    .split(';')
    .map(trim)
    .filter((p) => p !== '')
  const first = parts[0] === undefined ? null : field(parts[0])
  if (first === null || `${first[0]}=${first[1]}` !== TXT_VERSION_FIELD) return null
  if (!PRINTABLE.test(text)) throw refused('a bag TXT record holds a character other than tab and space to ~')
  if (text.length > MAX_TXT_BYTES)
    throw refused(`a bag TXT record of ${text.length} bytes; the cap is ${MAX_TXT_BYTES}`)
  const fields = new Map<string, string>()
  for (const part of parts) {
    const f = field(part)
    if (f === null) throw refused(`a TXT field that is not name=value: ${JSON.stringify(part)}`)
    if (fields.has(f[0])) throw refused(`the TXT field ${f[0]} is given twice`)
    fields.set(f[0], f[1])
  }
  if (fields.has('rec')) throw refused('the TXT names a rec: no URL is read from DNS')
  const key = fields.get('key')
  if (key === undefined) throw refused('a bag TXT record names no key')
  if (!isAddress(key)) throw refused('the TXT key is not an address')
  const host = fields.get('host') ?? null
  if (host !== null && host !== BAG_HOST) throw refused(`the TXT host is ${BAG_HOST} or absent`)
  return { key, host }
}

/**
 * Where a domain's address record is, from the TXT records its lookup of `_bag.<domain>` gave, each a list of
 * character-strings (spec/SPEC.md §12.2 item 4): with no bag record, the origin `https://<domain>` and no key;
 * with one, its key and the origin its `host` names; with two or more, or a malformed one, resolve-failed. A domain
 * that txtName does not ask has no bag record, whatever records are handed in.
 */
export function discover(records: readonly (readonly string[])[], domain: string): Discovery {
  const asked = txtName(domain) === null ? [] : records
  const ours = asked.map((r) => parseDiscoveryTxt(r.join(''), domain)).filter((t) => t !== null)
  if (ours.length > 1) throw refused(`${ours.length} bag TXT records; a domain has one at most`)
  const txt = ours[0] ?? null
  const origin = `https://${txt?.host ? `${txt.host}.${domain}` : domain}`
  return { key: txt?.key ?? null, url: `${origin}${WELL_KNOWN_RECORD_PATH}`, origin }
}

/**
 * Checks the org record a discovery led to (spec/SPEC.md §12.2 item 5): when the TXT named a key,
 * the record agrees with it when its key is that key, or when it names that key in rotated_from and its rotation_sig
 * verifies under it (verifyRotationClaim: one countersigned step); anything else is resolve-failed, before any pin is
 * read. Verify the record (verifyRecord) first; this checks the agreement only, and never moves a pin.
 */
export function checkDiscovered(record: AddressRecord, d: Discovery): void {
  if (d.key === null || record.key === d.key || countersignedBy(record, d.key)) return
  throw refused(
    `the record's key ${record.key} is neither the TXT's key ${d.key} nor one rotation countersigned by it`,
  )
}

/** True when the record names `key` in rotated_from and its rotation_sig verifies under it (§7.3's claim, one step). */
function countersignedBy(record: AddressRecord, key: string): boolean {
  if (record.rotated_from !== key) return false
  try {
    verifyRotationClaim(record)
    return true
  } catch {
    return false
  }
}

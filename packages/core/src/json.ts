import { MAX_CANONICAL_INTEGER } from './canonical.ts'
import { AcError, type AcErrorCode } from './errors.ts'
import { isHex } from './hex.ts'

/** A parsed JSON object. */
export type JsonObject = Record<string, unknown>

const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

/** How parseJson reads numbers. */
export interface ParseJsonOptions {
  /**
   * True (the default): a number is kept only when its source text is a plain decimal integer, `0` or
   * `[1-9][0-9]*`, of at most 2^53 - 1 (spec/SPEC.md §2.5). Any other number (`1.0`, `1e0`, `-0`, `-1`, `0.5`,
   * `1e-400`, `9007199254740990.9`, `9007199254740992`) is read as NaN, a number that is no canonical integer and
   * equals nothing, so the reader that expects an integer there refuses it with its own code; a number past the
   * range of a double (`1e400`) is `code`. False: JSON.parse's reading, for the sealed `body` (§4.2), except that a
   * number past the range of a double is still `code` (§2.5; changed 2026-10-25).
   */
  readonly strictIntegers?: boolean
}

const PLAIN_INTEGER = /^(?:0|[1-9][0-9]*)$/

// JSON.parse passes a reviver the source text of each primitive value as a third argument (the JSON.parse source
// text access proposal, in V8 since Node 21). Without it the test below fails, so every number is refused.
function strictNumber(_key: string, value: unknown, context?: { readonly source: string }): unknown {
  if (typeof value !== 'number') return value
  if (!Number.isFinite(value)) throw new RangeError('a number past the range of a double')
  return PLAIN_INTEGER.test(String(context?.source)) && value <= MAX_CANONICAL_INTEGER ? value : Number.NaN
}

// The non-strict reviver: the body is exempt from the integer rule only (§4.2), so a number past the range
// of a double, which JSON.parse reads as Infinity or -Infinity, is refused there too; every finite number is kept.
function finiteNumber(_key: string, value: unknown): unknown {
  if (typeof value === 'number' && !Number.isFinite(value))
    throw new RangeError('a number past the range of a double')
  return value
}

/**
 * Parses UTF-8 JSON text (spec/SPEC.md §2): `code` (bad-json by default) when the bytes are not UTF-8, the text is not
 * JSON, a byte-order mark precedes it, an object names a member twice (changed 2026-10-25: §2.5's MUST,
 * the sealed content included), a string or member name escapes a lone surrogate, or a number is past the range of a
 * double (with strict integers off too, since 2026-10-25). See ParseJsonOptions for how other numbers are read.
 */
export function parseJson(
  input: Uint8Array | string,
  code: AcErrorCode = 'bad-json',
  options: ParseJsonOptions = {},
): unknown {
  let text: string
  let value: unknown
  let scan: Scan
  try {
    text = typeof input === 'string' ? input : decoder.decode(input)
    value = JSON.parse(text)
    scan = scanJson(text)
    // The strict reviver gives back every plain integer of at most 2^53 - 1 as JSON.parse read it, so it is run
    // only when some number is written otherwise; it then reads that number as NaN, or throws past a double's range.
    // A plain safe integer is finite, so the non-strict reviver is needed only then too.
    if (scan.otherNumber)
      value = JSON.parse(text, options.strictIntegers === false ? finiteNumber : strictNumber)
  } catch {
    throw new AcError(code, 'not UTF-8 JSON text')
  }
  if (scan.duplicate) throw new AcError(code, 'an object names a member twice')
  if (!wellFormedText(text, value)) throw new AcError(code, 'a string escapes a lone surrogate')
  return value
}

/** What one pass over JSON text that JSON.parse accepted finds. */
interface Scan {
  /** An object names a member twice (§2.5). */
  readonly duplicate: boolean
  /** A number is not written as a plain decimal integer of at most 2^53 - 1, so the strict reading must revive it. */
  readonly otherNumber: boolean
}

const QUOTE = 0x22
const BACKSLASH = 0x5c
const COMMA = 0x2c
const MINUS = 0x2d
const ZERO = 0x30
const NINE = 0x39
const OPEN_OBJECT = 0x7b
const CLOSE_OBJECT = 0x7d
const OPEN_LIST = 0x5b
const CLOSE_LIST = 0x5d
/** 2^53 - 1 in decimal: a plain integer of 16 digits is canonical when it is at most this. */
const MAX_DIGITS = String(MAX_CANONICAL_INTEGER)

/** Whether a character continues a JSON number token: a digit, `.`, `e`, `E`, `+` or `-`. */
function inNumber(c: number): boolean {
  return (c >= ZERO && c <= NINE) || c === 0x2e || c === 0x65 || c === 0x45 || c === 0x2b || c === MINUS
}

/**
 * Whether the number token text[start, end) is `0` or `[1-9][0-9]*` and at most 2^53 - 1: digits only, since JSON
 * itself has no leading zero, and no more than 2^53 - 1's sixteen.
 */
function plainSafeInteger(text: string, start: number, end: number): boolean {
  const length = end - start
  if (length > MAX_DIGITS.length) return false
  for (let k = start; k < end; k++) {
    const d = text.charCodeAt(k)
    if (d < ZERO || d > NINE) return false
  }
  return length < MAX_DIGITS.length || text.slice(start, end) <= MAX_DIGITS
}

/**
 * One pass over JSON text that JSON.parse has accepted, so it needs only strings, brackets and number tokens:
 * JSON.parse keeps the last of two members and its reviver runs once for them, so neither can see a duplicate.
 * Two names are one when their decoded strings are equal (`"a"` and `"\u0061"`). A list of the open
 * containers holds the names of each open object, and null for each open list.
 */
function scanJson(text: string): Scan {
  const open: (Set<string> | null)[] = []
  let name = false // the next string is a member name
  let otherNumber = false
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (c === QUOTE) {
      let end = i + 1
      let escaped = false
      for (let d = text.charCodeAt(end); d !== QUOTE; d = text.charCodeAt(++end)) {
        if (d === BACKSLASH) {
          escaped = true
          end++
        }
      }
      if (name) {
        const names = open[open.length - 1] as Set<string>
        const member = escaped ? (JSON.parse(text.slice(i, end + 1)) as string) : text.slice(i + 1, end)
        if (names.has(member)) return { duplicate: true, otherNumber }
        names.add(member)
        name = false
      }
      i = end
    } else if (c === MINUS || (c >= ZERO && c <= NINE)) {
      let end = i + 1
      while (end < text.length && inNumber(text.charCodeAt(end))) end++
      otherNumber ||= !plainSafeInteger(text, i, end)
      i = end - 1
    } else if (c === OPEN_OBJECT) {
      open.push(new Set())
      name = true
    } else if (c === OPEN_LIST) {
      open.push(null)
    } else if (c === CLOSE_OBJECT || c === CLOSE_LIST) {
      open.pop()
      name = false
    } else if (c === COMMA) {
      name = open[open.length - 1] !== null
    }
  }
  return { duplicate: false, otherNumber }
}

/**
 * True when an object of the JSON text names a member twice (spec/SPEC.md §2.5): two names are one when their decoded
 * strings are equal, so `"a"` and `"\u0061"` are the same name. The text must be one JSON value that JSON.parse has
 * accepted.
 */
export function hasDuplicateMember(text: string): boolean {
  return scanJson(text).duplicate
}

// A lone surrogate reaches a parsed string only raw, which leaves the text not well formed, or through a \u escape of
// D800 to DFFF; with neither in the text, the walk over the parsed value can be skipped.
const SURROGATE_ESCAPE = /\\u[dD][89a-fA-F]/

function wellFormedText(text: string, value: unknown): boolean {
  return text.isWellFormed() && (!SURROGATE_ESCAPE.test(text) || wellFormed(value))
}

function wellFormed(value: unknown): boolean {
  if (typeof value === 'string') return value.isWellFormed()
  if (Array.isArray(value)) return value.every(wellFormed)
  if (isPlainObject(value)) return Object.entries(value).every(([k, v]) => k.isWellFormed() && wellFormed(v))
  return true
}

/** True for a JSON object: not null, not a list. */
export function isPlainObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** True when the object's own member names are exactly `keys`, in any order. */
export function hasExactKeys(value: JsonObject, keys: readonly string[]): boolean {
  const own = Object.keys(value)
  return own.length === keys.length && keys.every((k) => Object.hasOwn(value, k))
}

/** The number of UTF-8 bytes of a string. */
export function utf8Length(text: string): number {
  return Buffer.byteLength(text, 'utf8')
}

/** A byte field of a parsed object: bad-shape when it is not a string, bad-hex when it is not hex of that length. */
export function hexField(value: unknown, bytes: number | undefined, name: string): string {
  if (typeof value !== 'string') throw new AcError('bad-shape', `${name} is a string of lowercase hex`)
  if (!isHex(value, bytes)) {
    throw new AcError('bad-hex', `${name} is ${bytes === undefined ? '' : `${bytes} bytes of `}lowercase hex`)
  }
  return value
}

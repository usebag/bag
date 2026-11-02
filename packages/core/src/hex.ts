import { AcError } from './errors.ts'

const HEX = /^(?:[0-9a-f]{2})*$/
const encoder = new TextEncoder()

/** The bytes as lowercase hex. */
export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('hex')
}

/** True when the value is lowercase hex with an even length, of exactly `bytes` bytes when that is given. */
export function isHex(value: unknown, bytes?: number): value is string {
  return typeof value === 'string' && HEX.test(value) && (bytes === undefined || value.length === bytes * 2)
}

/** The bytes of lowercase hex; bad-hex unless it is lowercase hex, of exactly `bytes` bytes when that is given. */
export function fromHex(value: string, bytes?: number): Uint8Array {
  if (!isHex(value, bytes)) {
    throw new AcError(
      'bad-hex',
      bytes === undefined ? 'not lowercase hex' : `not ${bytes} bytes of lowercase hex`,
    )
  }
  return new Uint8Array(Buffer.from(value, 'hex'))
}

/** The UTF-8 bytes of a string. Callers pass well-formed strings: an encoder replaces a lone surrogate. */
export function utf8(text: string): Uint8Array {
  return encoder.encode(text)
}

/** The bytes of the parts, one after another. */
export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

/** True when the two byte strings are equal. Not constant-time: for public values only. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i])
}

import { createHash } from 'node:crypto'
import { type CanonicalValue, canonical } from './canonical.ts'
import { toHex, utf8 } from './hex.ts'

/** SHA-256 of the bytes, or of a string's UTF-8 bytes. */
export function sha256(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(
    createHash('sha256')
      .update(typeof data === 'string' ? utf8(data) : data)
      .digest(),
  )
}

/** SHA-256 as lowercase hex. */
export function sha256hex(data: Uint8Array | string): string {
  return toHex(sha256(data))
}

/** The 32 bytes every signature covers (spec/SPEC.md §2): sha256(utf8(canonical(preimage))). */
export function preimageDigest(preimage: CanonicalValue): Uint8Array {
  return sha256(canonical(preimage))
}

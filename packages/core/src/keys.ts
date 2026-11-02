import { createPrivateKey, createPublicKey, type KeyObject, sign, verify } from 'node:crypto'
import { decodeAddress, encodeAddress, isAddress } from './address.ts'
import type { CanonicalValue } from './canonical.ts'
import { AcError } from './errors.ts'
import { preimageDigest } from './hash.ts'
import { concatBytes, fromHex, isHex, toHex } from './hex.ts'
import { hpkeOpen, x25519PublicKey } from './hpke.ts'

/**
 * A source of random bytes: `rng(n)` returns n bytes. The core reads no randomness of its own (apart from hpkeSeal's
 * default ephemeral key): callers pass the edge's CSPRNG, and test vectors pass a seeded generator.
 */
export type Rng = (length: number) => Uint8Array

/**
 * What the core's signing functions ask of a signer: its address and a signature over a message. The message is only
 * ever a 32-byte digest of a preimage that the core built (spec/SPEC.md §2), so a signer sees the digest and never the
 * content or a raw key. The class SigningKey is one, and so is any holder of a key that never enters this process,
 * since TypeScript treats a class with ES private fields nominally. A type only: the
 * wire and the vectors do not change.
 */
export interface SignerLike {
  readonly address: string
  sign(message: Uint8Array): Uint8Array
}

/**
 * What opening a wrap asks of an opener: HPKE's single-shot open (see hpkeOpen) over the wrap's own bytes. The core
 * never asks an opener for its private key, only for the opened content key. The class SealingKey is one.
 */
export interface OpenerLike {
  open(enc: Uint8Array, info: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array
}

const ED25519_PKCS8 = fromHex('302e020100300506032b657004220420')
const ED25519_SPKI = fromHex('302a300506032b6570032100')
const INSPECT = Symbol.for('nodejs.util.inspect.custom')

function seedOf(seed: Uint8Array, what: string): Uint8Array {
  if (!(seed instanceof Uint8Array) || seed.length !== 32)
    throw new AcError('bad-key', `${what} seed is 32 bytes`)
  return Uint8Array.from(seed)
}

/**
 * An Ed25519 signing key (spec/SPEC.md §3). It never prints its seed: console.log and JSON.stringify show the
 * address only. `exportSeed` is for a key store, which writes it to a 0600 file.
 */
export class SigningKey {
  /** The 32-byte Ed25519 public key. */
  readonly publicKey: Uint8Array
  /** `ed25519:` and the public key in hex: public by design. */
  readonly address: string
  readonly #seed: Uint8Array
  readonly #key: KeyObject

  constructor(seed: Uint8Array) {
    this.#seed = seedOf(seed, 'an Ed25519')
    this.#key = createPrivateKey({
      key: Buffer.from(concatBytes(ED25519_PKCS8, this.#seed)),
      format: 'der',
      type: 'pkcs8',
    })
    const spki = createPublicKey(this.#key).export({ type: 'spki', format: 'der' })
    this.publicKey = new Uint8Array(spki.subarray(spki.length - 32))
    this.address = encodeAddress(this.publicKey)
  }

  /** The 64-byte Ed25519 signature of the message. */
  sign(message: Uint8Array): Uint8Array {
    return new Uint8Array(sign(null, message, this.#key))
  }

  /** A copy of the 32-byte seed, for a key store. Never print it. */
  exportSeed(): Uint8Array {
    return Uint8Array.from(this.#seed)
  }

  toJSON(): { readonly address: string } {
    return { address: this.address }
  }

  [INSPECT](): string {
    return `SigningKey { address: '${this.address}' }`
  }
}

/**
 * An X25519 sealing key (spec/SPEC.md §4), separate from the signing key. It opens the HPKE
 * wraps addressed to it and never prints its private key.
 */
export class SealingKey {
  /** The 32-byte X25519 public key, published as `sealing_key` in hex. */
  readonly publicKey: Uint8Array
  readonly #seed: Uint8Array

  constructor(seed: Uint8Array) {
    this.#seed = seedOf(seed, 'an X25519')
    this.publicKey = x25519PublicKey(this.#seed)
  }

  /** Single-shot HPKE open with this key (see hpkeOpen). */
  open(enc: Uint8Array, info: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array {
    return hpkeOpen(this.#seed, enc, info, aad, ct)
  }

  /** A copy of the 32-byte private key, for a key store. Never print it. */
  exportSeed(): Uint8Array {
    return Uint8Array.from(this.#seed)
  }

  toJSON(): { readonly sealing_key: string } {
    return { sealing_key: toHex(this.publicKey) }
  }

  [INSPECT](): string {
    return `SealingKey { sealing_key: '${toHex(this.publicKey)}' }`
  }
}

/** The signing key of a 32-byte seed (the Ed25519 private key of RFC 8032). */
export function signingKeyFromSeed(seed: Uint8Array): SigningKey {
  return new SigningKey(seed)
}

/** A new signing key from 32 bytes of the rng. */
export function generateSigningKey(rng: Rng): SigningKey {
  return new SigningKey(rng(32))
}

/** The sealing key of a 32-byte X25519 private key. */
export function sealingKeyFromSeed(seed: Uint8Array): SealingKey {
  return new SealingKey(seed)
}

/** A new sealing key from 32 bytes of the rng. */
export function generateSealingKey(rng: Rng): SealingKey {
  return new SealingKey(rng(32))
}

/**
 * The eight points of small order on edwards25519 (the torsion subgroup: [8]P is the identity), canonically encoded
 * as RFC 8032 §5.1.2 writes a point: y in 255 bits, little-endian, with the sign of x in the top bit. In order: the
 * identity (order 1), the point of order 2, the two of order 4 and the four of order 8. They are public constants, not
 * keys; test/keys-strict.test.ts derives each from the curve arithmetic of RFC 8032 §6. A signature under one of them,
 * or with one of them as R, proves nothing: R = identity and S = 0 pass the cofactorless check under the identity for
 * any message (spec/SPEC.md §10, "Malleability").
 */
export const SMALL_ORDER_POINTS: readonly Uint8Array[] = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
].map((h) => fromHex(h, 32))

/** L, the order of the prime subgroup (RFC 8032 §5.1), little-endian: 2^252 + 27742317777372353535851937790883648493. */
const L_BYTES = fromHex('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010', 32)

/**
 * True when the 32 bytes at `at` write y >= p = 2^255 - 19 once the sign bit is cleared: a non-canonical encoding
 * (y + p for y < 19). Such a y is 0x7fff...ff with a first byte of 0xed or more.
 */
function isNonCanonicalPoint(b: Uint8Array, at: number): boolean {
  if (((b[at + 31] as number) & 0x7f) !== 0x7f) return false
  for (let i = 30; i >= 1; i--) if (b[at + i] !== 0xff) return false
  return (b[at] as number) >= 0xed
}

/**
 * True when the 32 bytes at `at` are one of SMALL_ORDER_POINTS, the sign bit aside: x = 0 with the sign bit set
 * (`01...80`, `ec...ff`) is not a valid encoding (RFC 8032 §5.1.3), yet OpenSSL decodes it as the identity or the
 * point of order 2.
 */
function isSmallOrderPoint(b: Uint8Array, at: number): boolean {
  return SMALL_ORDER_POINTS.some((e) => {
    for (let i = 0; i < 31; i++) if (b[at + i] !== e[i]) return false
    return (((b[at + 31] as number) ^ (e[31] as number)) & 0x7f) === 0
  })
}

/** True when the 32 bytes at `at`, little-endian, are below L: a canonical S. */
function isCanonicalScalar(b: Uint8Array, at: number): boolean {
  for (let i = 31; i >= 0; i--) {
    const x = b[at + i] as number
    const l = L_BYTES[i] as number
    if (x !== l) return x < l
  }
  return false
}

/**
 * True when `signature` is a valid Ed25519 signature of `message` by `publicKey`; false for any malformed input.
 * Strict (spec/SPEC.md §10): before OpenSSL sees anything, it refuses a public key or R (the first 32 bytes of the
 * signature) that is non-canonical or of small order, and an S (the last 32) at or above L, so it agrees with the Rust
 * core's verify_strict and refuses what OpenSSL alone would accept.
 */
export function verifySig(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false
  if (isNonCanonicalPoint(publicKey, 0) || isSmallOrderPoint(publicKey, 0)) return false
  if (isNonCanonicalPoint(signature, 0) || isSmallOrderPoint(signature, 0)) return false
  if (!isCanonicalScalar(signature, 32)) return false
  const key = createPublicKey({
    key: Buffer.from(concatBytes(ED25519_SPKI, publicKey)),
    format: 'der',
    type: 'spki',
  })
  return verify(null, message, key, signature)
}

/** The signature, in hex, over a preimage's digest (spec/SPEC.md §2). */
export function signPreimage(key: SignerLike, preimage: CanonicalValue): string {
  return toHex(key.sign(preimageDigest(preimage)))
}

/** True when `sig` (128 hex characters) is the signature by `address` over the preimage's digest; else false. */
export function verifyPreimage(address: string, preimage: CanonicalValue, sig: string): boolean {
  if (!isAddress(address) || !isHex(sig, 64)) return false
  let digest: Uint8Array
  try {
    digest = preimageDigest(preimage)
  } catch {
    return false
  }
  return verifySig(decodeAddress(address), digest, fromHex(sig, 64))
}

import { createHash } from 'node:crypto'

// RFC 8032 §5.1 and §6: edwards25519 point arithmetic over bigint, for the tests and the vector generator. It derives
// the constants rather than trusting them (test/keys-strict.test.ts), and it builds the signatures no honest signer
// makes, a small-order R, a mixed-order key, an R written y + p, that pin the strict rule of spec/SPEC.md §2.3 in
// spec/vectors (packages/core/scripts/gen-vectors.ts). Test code: it is never a signer of anything real.

/** p, the field prime. */
export const FIELD_P = (1n << 255n) - 19n
/** L, the order of the prime subgroup. */
export const ORDER_L = (1n << 252n) + 27742317777372353535851937790883648493n

export const mod = (a: bigint): bigint => ((a % FIELD_P) + FIELD_P) % FIELD_P

export function pow(b: bigint, e: bigint): bigint {
  let r = 1n
  for (let x = mod(b), k = e; k > 0n; k >>= 1n, x = (x * x) % FIELD_P) if (k & 1n) r = (r * x) % FIELD_P
  return r
}

const inv = (a: bigint): bigint => pow(a, FIELD_P - 2n)
const D = mod(-121665n * inv(121666n))
const SQRT_M1 = pow(2n, (FIELD_P - 1n) / 4n)

/** A point in extended coordinates X, Y, Z, T. */
export type Point = readonly [bigint, bigint, bigint, bigint]
export const IDENTITY: Point = [0n, 1n, 1n, 0n]

export function add(a: Point, b: Point): Point {
  const A = mod((a[1] - a[0]) * (b[1] - b[0]))
  const B = mod((a[1] + a[0]) * (b[1] + b[0]))
  const C = mod(2n * a[3] * b[3] * D)
  const E2 = mod(2n * a[2] * b[2])
  const [E, F, G, H] = [B - A, E2 - C, E2 + C, B + A]
  return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)]
}

export function mul(s: bigint, a: Point): Point {
  let r = IDENTITY
  for (let k = s, x = a; k > 0n; k >>= 1n, x = add(x, x)) if (k & 1n) r = add(r, x)
  return r
}

export const same = (a: Point, b: Point): boolean =>
  mod(a[0] * b[2] - b[0] * a[2]) === 0n && mod(a[1] * b[2] - b[1] * a[2]) === 0n

/** Bytes, little-endian, as an integer. */
export const le = (b: Uint8Array): bigint => b.reduceRight((n, x) => (n << 8n) | BigInt(x), 0n)

/** An integer as 32 bytes, little-endian. */
export const bytesOf = (n: bigint): Uint8Array =>
  Uint8Array.from({ length: 32 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn))

/** RFC 8032 §5.1.3, except that y is reduced mod p first (as OpenSSL and dalek do): null when no point has this y. */
export function decodeLoose(b: Uint8Array): Point | null {
  const n = le(b)
  const sign = n >> 255n
  const y = mod(n & ((1n << 255n) - 1n))
  const x2 = mod((y * y - 1n) * inv(D * y * y + 1n))
  let x = pow(x2, (FIELD_P + 3n) / 8n)
  if (mod(x * x - x2) !== 0n) x = mod(x * SQRT_M1)
  if (mod(x * x - x2) !== 0n) return null
  if ((x & 1n) !== sign) x = mod(-x)
  return [x, y, 1n, mod(x * y)]
}

/** RFC 8032 §5.1.2: y in 255 bits, little-endian, with the sign of x in the top bit. */
export function encode(a: Point): Uint8Array {
  const zi = inv(a[2])
  return bytesOf(mod(a[1] * zi) | ((mod(a[0] * zi) & 1n) << 255n))
}

/** 1, 2, 4 or 8 for a point of small order, 0 for any other. */
export const orderOf = (a: Point): number => [1, 2, 4, 8].find((n) => same(mul(BigInt(n), a), IDENTITY)) ?? 0

/** B, the base point: y = 4/5, x even. */
export const BASE = decodeLoose(Uint8Array.from([0x58, ...Array.from({ length: 31 }, () => 0x66)])) as Point

const sha512 = (...parts: readonly Uint8Array[]): Uint8Array => {
  const h = createHash('sha512')
  for (const p of parts) h.update(p)
  return new Uint8Array(h.digest())
}

/** The secret scalar a and the nonce prefix of an RFC 8032 seed (§5.1.5). */
export function secretOf(seed: Uint8Array): { readonly a: bigint; readonly prefix: Uint8Array } {
  const h = sha512(seed)
  const s = h.slice(0, 32)
  s[0] = (s[0] as number) & 248
  s[31] = ((s[31] as number) & 127) | 64
  return { a: le(s), prefix: h.slice(32) }
}

/** k = SHA-512(R || A || M) mod L, the challenge of RFC 8032 §5.1.6 and §5.1.7, from the encodings as given. */
export function challenge(r: Uint8Array, a: Uint8Array, message: Uint8Array): bigint {
  return le(sha512(r, a, message)) % ORDER_L
}

/**
 * RFC 8032 §5.1.6 with the seed's scalar, and the given encoding of the public key in the challenge: for an honest
 * key, `publicKey` is its own encoding and the signature is Node's; for a mixed-order key (the honest key plus a point
 * of small order), the cofactorless equation holds exactly when [k] takes the small-order part to the identity.
 * `nonce` adds a point to R: a mixed-order R when it is of small order.
 */
export function signAs(
  seed: Uint8Array,
  publicKey: Uint8Array,
  message: Uint8Array,
  nonce: Point = IDENTITY,
): Uint8Array {
  const { a, prefix } = secretOf(seed)
  const r = le(sha512(prefix, message)) % ORDER_L
  const R = encode(add(mul(r, BASE), nonce))
  const s = (r + challenge(R, publicKey, message) * a) % ORDER_L
  return Uint8Array.from([...R, ...bytesOf(s)])
}

/**
 * A signature with the given R and S = k·a: the cofactorless equation [S]B = R + [k]A holds for an R that decodes to
 * the identity, whatever its encoding, so a verifier that compares points instead of R's 32 bytes, or that lets a
 * small-order or non-canonical R through, accepts it.
 */
export function signWithR(
  seed: Uint8Array,
  publicKey: Uint8Array,
  message: Uint8Array,
  r: Uint8Array,
): Uint8Array {
  const { a } = secretOf(seed)
  const s = (challenge(r, publicKey, message) * a) % ORDER_L
  return Uint8Array.from([...r, ...bytesOf(s)])
}

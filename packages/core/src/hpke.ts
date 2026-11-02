import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  type KeyObject,
  randomBytes,
} from 'node:crypto'
import { AcError } from './errors.ts'
import { concatBytes, fromHex, utf8 } from './hex.ts'

// RFC 9180 (HPKE), base mode, for suite 1's parameters: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM
// (spec/SPEC.md §4). Every function is pure apart from hpkeSeal's default ephemeral key.

export const HPKE_MODE_BASE = 0x00
export const HPKE_KEM_ID = 0x0020
export const HPKE_KDF_ID = 0x0001
export const HPKE_AEAD_ID = 0x0002

const N_SECRET = 32
const N_ENC = 32
const N_SK = 32
const N_K = 32
const N_N = 12
const N_T = 16
const N_H = 32
const EMPTY = new Uint8Array(0)

const X25519_PKCS8 = fromHex('302e020100300506032b656e04220420')
const X25519_SPKI = fromHex('302a300506032b656e032100')

/** I2OSP: a non-negative integer as `length` big-endian bytes. */
export function i2osp(value: number, length: number): Uint8Array {
  const out = new Uint8Array(length)
  let v = value
  for (let i = length - 1; i >= 0 && v > 0; i--) {
    out[i] = v % 256
    v = Math.floor(v / 256)
  }
  return out
}

const KEM_SUITE_ID = concatBytes(utf8('KEM'), i2osp(HPKE_KEM_ID, 2))
const HPKE_SUITE_ID = concatBytes(
  utf8('HPKE'),
  i2osp(HPKE_KEM_ID, 2),
  i2osp(HPKE_KDF_ID, 2),
  i2osp(HPKE_AEAD_ID, 2),
)
const HPKE_V1 = utf8('HPKE-v1')

function hmac(key: Uint8Array, data: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac('sha256', key).update(data).digest())
}

/** HKDF-Extract with SHA-256 (RFC 5869). */
export function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmac(salt, ikm)
}

/** HKDF-Expand with SHA-256 (RFC 5869); at most 255 * 32 bytes. */
export function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0 || length > 255 * N_H) {
    throw new AcError('bad-key', 'HKDF-Expand gives at most 8,160 bytes')
  }
  const out = new Uint8Array(length)
  let block: Uint8Array = EMPTY
  for (let i = 1, offset = 0; offset < length; i++) {
    block = hmac(prk, concatBytes(block, info, Uint8Array.of(i)))
    out.set(block.subarray(0, length - offset), offset)
    offset += block.length
  }
  return out
}

function labeledExtract(suiteId: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {
  return hkdfExtract(salt, concatBytes(HPKE_V1, suiteId, utf8(label), ikm))
}

function labeledExpand(
  suiteId: Uint8Array,
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
) {
  return hkdfExpand(prk, concatBytes(i2osp(length, 2), HPKE_V1, suiteId, utf8(label), info), length)
}

function privateKeyObject(sk: Uint8Array): KeyObject {
  if (sk.length !== N_SK) throw new AcError('bad-key', 'an X25519 private key is 32 bytes')
  return createPrivateKey({ key: Buffer.from(concatBytes(X25519_PKCS8, sk)), format: 'der', type: 'pkcs8' })
}

function publicKeyObject(pk: Uint8Array): KeyObject {
  if (pk.length !== N_ENC) throw new AcError('bad-key', 'an X25519 public key is 32 bytes')
  return createPublicKey({ key: Buffer.from(concatBytes(X25519_SPKI, pk)), format: 'der', type: 'spki' })
}

/** The X25519 public key of a 32-byte private key. */
export function x25519PublicKey(sk: Uint8Array): Uint8Array {
  const spki = createPublicKey(privateKeyObject(sk)).export({ type: 'spki', format: 'der' })
  return new Uint8Array(spki.subarray(spki.length - N_ENC))
}

/** X25519(sk, pk); bad-key when it fails, as it does for a small-order public key (an all-zero result). */
export function x25519(sk: Uint8Array, pk: Uint8Array): Uint8Array {
  const privateKey = privateKeyObject(sk)
  const publicKey = publicKeyObject(pk)
  try {
    return new Uint8Array(diffieHellman({ privateKey, publicKey }))
  } catch {
    throw new AcError('bad-key', 'X25519 failed: a small-order public key')
  }
}

/** DeriveKeyPair (RFC 9180 §7.1.3) for X25519: the key pair of input keying material. */
export function deriveKeyPair(ikm: Uint8Array): { readonly sk: Uint8Array; readonly pk: Uint8Array } {
  const dkpPrk = labeledExtract(KEM_SUITE_ID, EMPTY, 'dkp_prk', ikm)
  const sk = labeledExpand(KEM_SUITE_ID, dkpPrk, 'sk', EMPTY, N_SK)
  return { sk, pk: x25519PublicKey(sk) }
}

function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Uint8Array {
  const eaePrk = labeledExtract(KEM_SUITE_ID, EMPTY, 'eae_prk', dh)
  return labeledExpand(KEM_SUITE_ID, eaePrk, 'shared_secret', kemContext, N_SECRET)
}

/** Encap (RFC 9180 §4.1) with the ephemeral private key given. */
export function encap(
  pkR: Uint8Array,
  skE: Uint8Array,
): { readonly sharedSecret: Uint8Array; readonly enc: Uint8Array } {
  const enc = x25519PublicKey(skE)
  const dh = x25519(skE, pkR)
  return { sharedSecret: extractAndExpand(dh, concatBytes(enc, pkR)), enc }
}

/** Decap (RFC 9180 §4.1). */
export function decap(enc: Uint8Array, skR: Uint8Array): Uint8Array {
  const dh = x25519(skR, enc)
  return extractAndExpand(dh, concatBytes(enc, x25519PublicKey(skR)))
}

/** The key schedule's outputs (RFC 9180 §5.1), base mode, no PSK. */
export interface KeySchedule {
  readonly keyScheduleContext: Uint8Array
  readonly secret: Uint8Array
  readonly key: Uint8Array
  readonly baseNonce: Uint8Array
  readonly exporterSecret: Uint8Array
}

/** KeyScheduleS / KeyScheduleR (RFC 9180 §5.1) in base mode. */
export function keySchedule(sharedSecret: Uint8Array, info: Uint8Array): KeySchedule {
  const pskIdHash = labeledExtract(HPKE_SUITE_ID, EMPTY, 'psk_id_hash', EMPTY)
  const infoHash = labeledExtract(HPKE_SUITE_ID, EMPTY, 'info_hash', info)
  const keyScheduleContext = concatBytes(Uint8Array.of(HPKE_MODE_BASE), pskIdHash, infoHash)
  const secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, 'secret', EMPTY)
  return {
    keyScheduleContext,
    secret,
    key: labeledExpand(HPKE_SUITE_ID, secret, 'key', keyScheduleContext, N_K),
    baseNonce: labeledExpand(HPKE_SUITE_ID, secret, 'base_nonce', keyScheduleContext, N_N),
    exporterSecret: labeledExpand(HPKE_SUITE_ID, secret, 'exp', keyScheduleContext, N_H),
  }
}

/** ComputeNonce (RFC 9180 §5.2): the base nonce XOR the sequence number. */
export function computeNonce(baseNonce: Uint8Array, seq: number): Uint8Array {
  const s = i2osp(seq, N_N)
  const out = new Uint8Array(N_N)
  for (let i = 0; i < N_N; i++) out[i] = (baseNonce[i] as number) ^ (s[i] as number)
  return out
}

/** Context.Export (RFC 9180 §5.3). */
export function exportSecret(
  exporterSecret: Uint8Array,
  exporterContext: Uint8Array,
  length: number,
): Uint8Array {
  return labeledExpand(HPKE_SUITE_ID, exporterSecret, 'sec', exporterContext, length)
}

/** AES-256-GCM: the ciphertext with its 16-byte tag appended. */
export function aeadSeal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array): Uint8Array {
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: N_T })
  cipher.setAAD(aad)
  return concatBytes(cipher.update(pt), cipher.final(), cipher.getAuthTag())
}

/** AES-256-GCM open; open-failed when the key, nonce or tag is wrong or the ciphertext was changed. */
export function aeadOpen(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array {
  if (key.length !== N_K || nonce.length !== N_N || ct.length < N_T) {
    throw new AcError('open-failed', 'AES-256-GCM takes a 32-byte key, a 12-byte nonce and a 16-byte tag')
  }
  const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: N_T })
  decipher.setAAD(aad)
  decipher.setAuthTag(ct.subarray(ct.length - N_T))
  try {
    return concatBytes(decipher.update(ct.subarray(0, ct.length - N_T)), decipher.final())
  } catch {
    throw new AcError('open-failed', 'the AES-256-GCM tag does not verify')
  }
}

/** The result of a single-shot HPKE seal: the encapsulated key and the ciphertext. */
export interface HpkeSealed {
  readonly enc: Uint8Array
  readonly ct: Uint8Array
}

/**
 * Single-shot HPKE seal in base mode (RFC 9180 §6.1). `skE` injects the ephemeral private key, for test vectors; when
 * it is absent the key is 32 bytes from node:crypto's CSPRNG. bad-key for a malformed or small-order `pkR`.
 */
export function hpkeSeal(
  pkR: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  pt: Uint8Array,
  skE?: Uint8Array,
): HpkeSealed {
  const ephemeral = skE ?? new Uint8Array(randomBytes(N_SK))
  const { sharedSecret, enc } = encap(pkR, ephemeral)
  const ks = keySchedule(sharedSecret, info)
  return { enc, ct: aeadSeal(ks.key, computeNonce(ks.baseNonce, 0), aad, pt) }
}

/** Single-shot HPKE open in base mode (RFC 9180 §6.1); open-failed for any `enc` or `ct` that does not open. */
export function hpkeOpen(
  skR: Uint8Array,
  enc: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
) {
  if (skR.length !== N_SK) throw new AcError('bad-key', 'an X25519 private key is 32 bytes')
  let sharedSecret: Uint8Array
  try {
    sharedSecret = decap(enc, skR)
  } catch {
    throw new AcError('open-failed', 'the encapsulated key does not decapsulate')
  }
  const ks = keySchedule(sharedSecret, info)
  return aeadOpen(ks.key, computeNonce(ks.baseNonce, 0), aad, ct)
}

import { AcError } from './errors.ts'
import { fromHex, toHex } from './hex.ts'

/** The prefix of an address under identity suite 1. */
export const ADDRESS_PREFIX = 'ed25519:'

/**
 * The suite registry (spec/SPEC.md §3). Suite 1 is the only suite of v0: Ed25519 signatures, and sealing with RFC 9180
 * base mode over DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM. Its addresses carry the `ed25519:` prefix.
 */
export const SUITE_1 = {
  id: 1,
  addressPrefix: ADDRESS_PREFIX,
  signature: 'Ed25519',
  kem: 0x0020,
  kdf: 0x0001,
  aead: 0x0002,
} as const

const ADDRESS = /^ed25519:[0-9a-f]{64}$/

/** True when the value is an address: `ed25519:` and 64 lowercase hex characters. */
export function isAddress(value: unknown): value is string {
  return typeof value === 'string' && ADDRESS.test(value)
}

/** The address of a 32-byte Ed25519 public key. */
export function encodeAddress(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new AcError('bad-key', 'an Ed25519 public key is 32 bytes')
  return ADDRESS_PREFIX + toHex(publicKey)
}

/** The 32-byte public key of an address; bad-address unless it is `ed25519:` and 64 lowercase hex characters. */
export function decodeAddress(address: string): Uint8Array {
  if (!isAddress(address))
    throw new AcError('bad-address', 'an address is "ed25519:" and 64 lowercase hex characters')
  return fromHex(address.slice(ADDRESS_PREFIX.length), 32)
}

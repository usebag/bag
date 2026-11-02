import { SealingKey, SigningKey } from '../../src/keys.ts'
import type { Recipient, RecipientKey } from '../../src/seal.ts'

// Fixed test identities and times. Every seed below is test data by construction (a byte repeated 32 times): these keys
// are public knowledge and must never hold anything real.

/** A fixed "now": 2027-01-15 08:00:00 UTC. */
export const T0 = 1_800_000_000
export const HOUR = 3_600
export const DAY = 86_400

/** A 32-byte seed of one repeated byte. */
export function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte)
}

/** A party with a signing key and, for those that receive, a sealing key. */
export interface Party {
  readonly name: string
  readonly signingSeed: Uint8Array
  readonly key: SigningKey
  readonly address: string
  readonly sealingSeed?: Uint8Array
  readonly sealing?: SealingKey
}

function party(name: string, signing: number, sealing?: number): Party {
  const key = new SigningKey(seed(signing))
  if (sealing === undefined) return { name, signingSeed: seed(signing), key, address: key.address }
  return {
    name,
    signingSeed: seed(signing),
    key,
    address: key.address,
    sealingSeed: seed(sealing),
    sealing: new SealingKey(seed(sealing)),
  }
}

/**
 * The cast: an org root, its principal jane and jane's session; bob, carol and dave at other orgs; mallory, who holds
 * no authority; the org's rotation key and its next key; a sub-agent of the session. Seeds 0x01 to 0x0a sign, 0x12 to
 * 0x16 seal.
 */
export const P = {
  org: party('org', 0x01),
  jane: party('jane', 0x02, 0x12),
  session: party('session', 0x03),
  bob: party('bob', 0x04, 0x14),
  carol: party('carol', 0x05, 0x15),
  dave: party('dave', 0x06, 0x16),
  mallory: party('mallory', 0x07, 0x17),
  rotation: party('rotation', 0x08),
  orgNext: party('orgNext', 0x09),
  worker: party('worker', 0x0a),
} as const

/** Sixteen recipients for the cap: signing seeds 0x40 to 0x4f, sealing seeds 0x60 to 0x6f. */
export const SIXTEEN: readonly Party[] = Array.from({ length: 16 }, (_, i) =>
  party(`r${i}`, 0x40 + i, 0x60 + i),
)

/** The party as a recipient to seal to. */
export function recipient(p: Party): Recipient {
  if (p.sealing === undefined) throw new Error(`${p.name} has no sealing key`)
  return { address: p.address, sealingKey: p.sealing.publicKey }
}

/** The party as the recipient that opens. */
export function opener(p: Party): RecipientKey {
  if (p.sealing === undefined) throw new Error(`${p.name} has no sealing key`)
  return { address: p.address, key: p.sealing }
}

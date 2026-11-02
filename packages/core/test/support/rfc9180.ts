import { fromHex, toHex } from '../../src/hex.ts'
import {
  aeadSeal,
  computeNonce,
  deriveKeyPair,
  encap,
  exportSecret,
  HPKE_AEAD_ID,
  HPKE_KDF_ID,
  HPKE_KEM_ID,
  HPKE_MODE_BASE,
  keySchedule,
} from '../../src/hpke.ts'

/** One encryption of an RFC 9180 test vector: the sequence number is its index. */
export interface RfcEncryption {
  readonly aad: string
  readonly ct: string
  readonly nonce: string
  readonly pt: string
}

/** One secret export of an RFC 9180 test vector. */
export interface RfcExport {
  readonly exporter_context: string
  readonly L: number
  readonly exported_value: string
}

/** A base-mode RFC 9180 test vector, with the members in the upstream file's order. */
export interface RfcCase {
  readonly mode: number
  readonly kem_id: number
  readonly kdf_id: number
  readonly aead_id: number
  readonly info: string
  readonly ikmR: string
  readonly ikmE: string
  readonly skRm: string
  readonly skEm: string
  readonly pkRm: string
  readonly pkEm: string
  readonly enc: string
  readonly shared_secret: string
  readonly key_schedule_context: string
  readonly secret: string
  readonly key: string
  readonly base_nonce: string
  readonly exporter_secret: string
  readonly encryptions: readonly RfcEncryption[]
  readonly exports: readonly RfcExport[]
}

/**
 * Rebuilds a base-mode case from its inputs alone (info, both ikm, each pt and aad, each exporter context and length)
 * with this package's HPKE: every other field is recomputed. The result equals the case exactly when the implementation
 * reproduces the RFC's key derivation, shared secret, key schedule, every encryption and every export.
 */
export function rebuildRfcCase(c: RfcCase): RfcCase {
  const r = deriveKeyPair(fromHex(c.ikmR))
  const e = deriveKeyPair(fromHex(c.ikmE))
  const { sharedSecret, enc } = encap(r.pk, e.sk)
  const ks = keySchedule(sharedSecret, fromHex(c.info))
  return {
    mode: HPKE_MODE_BASE,
    kem_id: HPKE_KEM_ID,
    kdf_id: HPKE_KDF_ID,
    aead_id: HPKE_AEAD_ID,
    info: c.info,
    ikmR: c.ikmR,
    ikmE: c.ikmE,
    skRm: toHex(r.sk),
    skEm: toHex(e.sk),
    pkRm: toHex(r.pk),
    pkEm: toHex(e.pk),
    enc: toHex(enc),
    shared_secret: toHex(sharedSecret),
    key_schedule_context: toHex(ks.keyScheduleContext),
    secret: toHex(ks.secret),
    key: toHex(ks.key),
    base_nonce: toHex(ks.baseNonce),
    exporter_secret: toHex(ks.exporterSecret),
    encryptions: c.encryptions.map((x, seq) => {
      const nonce = computeNonce(ks.baseNonce, seq)
      return {
        aad: x.aad,
        ct: toHex(aeadSeal(ks.key, nonce, fromHex(x.aad), fromHex(x.pt))),
        nonce: toHex(nonce),
        pt: x.pt,
      }
    }),
    exports: c.exports.map((x) => ({
      exporter_context: x.exporter_context,
      L: x.L,
      exported_value: toHex(exportSecret(ks.exporterSecret, fromHex(x.exporter_context), x.L)),
    })),
  }
}

import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  type AcceptFromRecord,
  type AcRecord,
  type AddressRecord,
  type KeyRecord,
  recordSigner,
  SealingKey,
  SigningKey,
  serializeRecord,
  signRecord,
  toHex,
  type UnsignedAddressRecord,
} from '@usebag/core'
import type { Lookup } from '../../src/net.ts'
import type { AuditSink, Clock, EdgeKeys, RecordSource, Rng } from '../../src/ports.ts'

// Fixed test identities, a fake clock, a seeded rng, an in-memory audit sink and record source. Every seed is one
// byte repeated 32 times: public test data, never a real key.

/** A fixed "now": 2027-01-15 08:00:00 UTC, as in spec/vectors. */
export const T0 = 1_800_000_000
export const DAY = 86_400

export function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte)
}

export interface Party {
  readonly name: string
  readonly signing: SigningKey
  readonly sealing: SealingKey
  readonly address: string
  readonly keys: EdgeKeys
  /** The hex of both seeds, so a test can prove they never reach a log. */
  readonly secrets: readonly string[]
}

export function party(name: string, n: number): Party {
  const signing = new SigningKey(seed(n))
  const sealing = new SealingKey(seed(n + 0x80))
  return {
    name,
    signing,
    sealing,
    address: signing.address,
    keys: { signing, sealing },
    secrets: [toHex(seed(n)), toHex(seed(n + 0x80))],
  }
}

/** The cast: an org root with its principal jane and jane's session; bob and carol elsewhere; mallory; keys to rotate. */
export const P = {
  org: party('org', 0x01),
  jane: party('jane', 0x02),
  session: party('session', 0x03),
  bob: party('bob', 0x04),
  carol: party('carol', 0x05),
  mallory: party('mallory', 0x06),
  orgNext: party('orgNext', 0x07),
  rotation: party('rotation', 0x08),
  other: party('other', 0x09),
} as const

export class FakeClock implements Clock {
  t: number

  constructor(t: number = T0) {
    this.t = t
  }

  now(): number {
    return this.t
  }

  advance(seconds: number): void {
    this.t += seconds
  }
}

/** A deterministic rng: sha256 of the label and a counter, block after block. */
export function seededRng(label: string): Rng {
  let counter = 0
  return {
    bytes(length: number): Uint8Array {
      const out = new Uint8Array(length)
      for (let off = 0; off < length; off += 32) {
        const block = createHash('sha256').update(`${label}:${counter++}`).digest()
        out.set(block.subarray(0, Math.min(32, length - off)), off)
      }
      return out
    },
  }
}

export class MemoryAuditSink implements AuditSink {
  readonly lines: string[] = []

  append(line: string): void {
    this.lines.push(line)
  }

  last(): string | null {
    return this.lines.at(-1) ?? null
  }

  read(): string[] {
    return [...this.lines]
  }

  /** The parsed lines' events, decisions and reasons, for compact assertions. */
  steps(): string[] {
    return this.lines.map((l) => {
      const v = JSON.parse(l) as { event: string; decision: string; reason: string }
      return `${v.event} ${v.decision} ${v.reason}`
    })
  }
}

/** A signed address record of a party: its sealing key, no relays, a ttl of an hour from T0. */
export function addressRecord(p: Party, o: Partial<UnsignedAddressRecord> = {}): AddressRecord {
  return signRecord(p.signing, {
    kind: 'address',
    key: p.address,
    sealing_key: toHex(p.sealing.publicKey),
    relays: [],
    rotation_key: null,
    revoked: [],
    ttl: 3600,
    iat: T0,
    rotated_from: null,
    ...o,
  })
}

export function keyRecord(p: Party, exp: number = T0 + DAY): KeyRecord {
  return signRecord(p.signing, {
    kind: 'key',
    key: p.address,
    sealing_key: toHex(p.sealing.publicKey),
    iat: T0,
    exp,
  })
}

export function acceptFrom(p: Party, roots: readonly string[] = ['*']): AcceptFromRecord {
  return signRecord(p.signing, {
    kind: 'accept-from',
    owner: p.address,
    roots,
    max_bytes: 65_536,
    ttl: DAY,
    iat: T0,
  })
}

/** Records by domain and by relay; a missing domain throws, a missing relay record is null. */
export class FakeRecords implements RecordSource {
  readonly domains = new Map<string, Uint8Array | Error>()
  readonly relays = new Map<string, Uint8Array | Error>()
  calls = 0

  domain(domain: string, record: AcRecord | Error | Uint8Array): void {
    this.domains.set(
      domain,
      record instanceof Error || record instanceof Uint8Array ? record : serializeRecord(record),
    )
  }

  put(url: string, record: AcRecord, address: string = recordSigner(record)): void {
    this.relays.set(`${url} ${address} ${record.kind}`, serializeRecord(record))
  }

  async wellKnown(domain: string): Promise<Uint8Array> {
    this.calls++
    const v = this.domains.get(domain)
    if (v === undefined) throw new Error(`no well-known record for ${domain}`)
    if (v instanceof Error) throw v
    return v
  }

  async relayRecord(url: string, address: string, kind: string): Promise<Uint8Array | null> {
    this.calls++
    const v = this.relays.get(`${url} ${address} ${kind}`)
    if (v instanceof Error) throw v
    return v ?? null
  }
}

/**
 * A DNS stand-in for the private-address guard: every name resolves to one public address (Cloudflare's 1.1.1.1), so
 * no test asks a real resolver about a `.test` name.
 */
export const PUBLIC_LOOKUP: Lookup = async () => ['1.1.1.1']

/** A temporary directory under AC_TEST_TMP (else the system's), removed by `cleanup` unless AC_KEEP_TMP=1. */
export function tempDir(prefix: string): { readonly dir: string; cleanup(): void } {
  const dir = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), `bag-edge-${prefix}-`))
  return {
    dir,
    cleanup(): void {
      if (process.env.AC_KEEP_TMP === '1') return
      rmSync(dir, { recursive: true, force: true })
    },
  }
}

/** The text of a byte string. */
export const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes)

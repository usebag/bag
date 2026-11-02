import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  type AcceptFromRecord,
  type AddressRecord,
  type Hop,
  SealingKey,
  SigningKey,
  serializeRecord,
  signHop,
  signRecord,
  toHex,
} from '@usebag/core'
import {
  type Clock,
  type EdgeKeys,
  FsKeyStore,
  type RecordSource,
  type RelayClient,
  type Rng,
} from '@usebag/edge'
import type { Timers } from '../../src/desk.ts'
import type { Logger, LogLevel, LogValue } from '../../src/log.ts'
import type { MemoryRelay } from './relay.ts'

// The MCP tests' ports and parties, with no test framework and no MCP client, so that the loaded-set driver
// (loaded-session.ts) can use them in a child process: fixed identities (each seed one byte repeated 32 times: public
// test data, never a real key), a fake clock, timers the test fires, a seeded rng, homes on temporary files, records
// on the memory relay, a log that keeps its lines, and a record source.

/** A fixed "now": 2027-01-15 08:00:00 UTC, as in spec/vectors. */
export const T0 = 1_800_000_000
export const RELAY = 'http://relay.test'

export const seed = (byte: number): Uint8Array => new Uint8Array(32).fill(byte)

export interface Party {
  readonly name: string
  readonly address: string
  readonly keys: EdgeKeys
  /** The hex of both seeds, so a test can prove they never reach a log or a result. */
  readonly secrets: readonly string[]
}

export function party(name: string, n: number): Party {
  const keys = { signing: new SigningKey(seed(n)), sealing: new SealingKey(seed(n + 0x80)) }
  return { name, address: keys.signing.address, keys, secrets: [toHex(seed(n)), toHex(seed(n + 0x80))] }
}

export const P = {
  alice: party('alice', 0x11),
  bob: party('bob', 0x12),
  carol: party('carol', 0x13),
  org: party('org', 0x14),
  jane: party('jane', 0x15),
  session: party('session', 0x16),
} as const

export class FakeClock implements Clock {
  t = T0

  now(): number {
    return this.t
  }
}

/** Timers the test fires by hand: `fire()` runs every pending callback that was not cancelled. */
export class ManualTimers implements Timers {
  pending: { readonly ms: number; readonly fn: () => void; cancelled: boolean }[] = []

  after(ms: number, fn: () => void): () => void {
    const t = { ms, fn, cancelled: false }
    this.pending.push(t)
    return () => {
      t.cancelled = true
    }
  }

  /** The delays of the timers still pending, in ms. */
  live(): number[] {
    return this.pending.filter((t) => !t.cancelled).map((t) => t.ms)
  }

  /** Runs every pending callback that was not cancelled, or only those whose delay `which` picks. */
  fire(which: (ms: number) => boolean = () => true): void {
    const due = this.pending.filter((t) => !t.cancelled && which(t.ms))
    this.pending = this.pending.filter((t) => !t.cancelled && !which(t.ms))
    for (const t of due) t.fn()
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

/** A temporary directory under AC_TEST_TMP (else the system's), removed by `cleanup` unless AC_KEEP_TMP=1. */
export function tempDir(prefix: string): { readonly dir: string; cleanup(): void } {
  const dir = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), `bag-mcp-${prefix}-`))
  return {
    dir,
    cleanup(): void {
      if (process.env.AC_KEEP_TMP === '1') return
      rmSync(dir, { recursive: true, force: true })
    },
  }
}

/** Writes a party's key file into a home, as keygen does: <home>/keys/<name>.json, 0600 in 0700. */
export function saveKeys(home: string, p: Party, keys: EdgeKeys = p.keys, name: string = p.name): void {
  new FsKeyStore(join(home, 'keys')).save(name, keys)
}

export function addressRecord(p: Party, relays: readonly string[] = [RELAY]): AddressRecord {
  return signRecord(p.keys.signing, {
    kind: 'address',
    key: p.address,
    sealing_key: toHex(p.keys.sealing.publicKey),
    relays,
    rotation_key: null,
    revoked: [],
    ttl: 86_400,
    iat: T0,
    rotated_from: null,
  })
}

export function acceptFrom(p: Party, roots: readonly string[] = ['*']): AcceptFromRecord {
  return signRecord(p.keys.signing, {
    kind: 'accept-from',
    owner: p.address,
    roots,
    max_bytes: 65_536,
    ttl: 86_400,
    iat: T0,
  })
}

/** Publishes a party's address record (with its sealing key) to the memory relay. */
export async function publishAddress(relay: MemoryRelay, p: Party): Promise<void> {
  await relay.publish(RELAY, serializeRecord(addressRecord(p)))
}

/** A chain org -> jane (type=chat.*) -> session (no caveat), valid for a day from T0. */
export function sessionChain(): Hop[] {
  return [
    signHop(P.org.keys.signing, P.jane.address, ['type=chat.*'], T0 + 86_400),
    signHop(P.jane.keys.signing, P.session.address, [], T0 + 3600),
  ]
}

/** A logger that keeps its lines, to assert on them and to prove no key reaches them. */
export class MemoryLog implements Logger {
  readonly lines: { level: LogLevel; event: string; fields: Readonly<Record<string, LogValue>> }[] = []

  log(level: LogLevel, event: string, fields: Readonly<Record<string, LogValue>> = {}): void {
    this.lines.push({ level, event, fields })
  }

  text(): string {
    return this.lines.map((l) => JSON.stringify(l)).join('\n')
  }
}

/** An org's DNS and origin for handle tests: TXT records by name, handle records by `<host> <handle>`. */
export interface FakeNaming {
  readonly txt: Map<string, string[][]>
  readonly handles: Map<string, Uint8Array>
}

/**
 * Records: a well-known map for domains, and the relay through the client; with `naming`, TXT records and handle
 * records from its maps (no DNS, no fetch); without it, the source asks no DNS, as before discovery.
 */
export function fakeRecords(
  domains: Map<string, Uint8Array>,
  naming?: FakeNaming,
): (client: RelayClient) => RecordSource {
  return (client) => ({
    wellKnown: async (domain) => {
      const bytes = domains.get(domain)
      if (bytes === undefined) throw new Error(`no well-known record for ${domain}`)
      return bytes
    },
    relayRecord: (url, address, kind) => client.fetchRecord(url, address, kind),
    ...(naming === undefined
      ? {}
      : {
          txt: async (name: string) => naming.txt.get(name) ?? [],
          handleRecord: async (host: string, handle: string) =>
            naming.handles.get(`${host} ${handle}`) ?? null,
        }),
  })
}

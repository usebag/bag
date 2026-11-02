import { mkdirSync } from 'node:fs'
import {
  type AddressRecord,
  countersignRotation,
  type SignerLike,
  serializeRecord,
  signRecord,
  toHex,
} from '@usebag/core'
import { type EdgeKeys, generateEdgeKeys, HomeCustody, systemRng } from '@usebag/edge'
import { T0, type TestIo, testIo } from './io.ts'
import type { MemoryRelay } from './relay.ts'
import { cli, type Ran } from './run.ts'

// The agent commands' homes (ac login, grant, logout): `jane` is an agent pointer whose seeds are the key file
// `jane-keys`, and her address record is at the memory relay. Every key is made fresh here and never printed.

export const RELAY = 'http://127.0.0.1:9'
export const CAVEAT = 'type=coding.*'

export interface AgentHome {
  readonly dir: string
  readonly keys: EdgeKeys
  readonly address: string
}

/** A home (0700, as the agent's socket needs) with the agent identity `name` over the key file `<name>-keys`. */
export function agentHome(dir: string, name = 'jane', seeds = true): AgentHome {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const keys = generateEdgeKeys(systemRng)
  const custody = new HomeCustody(dir)
  if (seeds) custody.create(`${name}-keys`, keys, { custody: 'file' })
  custody.agent.create(name, keys)
  return { dir, keys, address: keys.signing.address }
}

type Members = Partial<Pick<AddressRecord, 'relays' | 'revoked' | 'rotated_from' | 'iat'>>

/** Signs the address record of `h` (members from `o`, countersigned by `by`) and puts it at the relay. */
export function publishRecord(
  relay: MemoryRelay,
  h: AgentHome,
  o: Members = {},
  by?: SignerLike,
): AddressRecord {
  const signed = signRecord(h.keys.signing, {
    kind: 'address',
    key: h.address,
    sealing_key: toHex(h.keys.sealing.publicKey),
    relays: [RELAY],
    rotation_key: null,
    revoked: [],
    ttl: 3600,
    iat: T0,
    rotated_from: null,
    ...o,
  })
  const record = by === undefined ? signed : countersignRotation(by, signed)
  relay.records.set(`${h.address} address`, serializeRecord(record))
  return record
}

/** The address record of `address` the relay holds now. */
export function heldAddress(relay: MemoryRelay, address: string): AddressRecord {
  return JSON.parse(new TextDecoder().decode(relay.records.get(`${address} address`))) as AddressRecord
}

type LoggedIn = { io: TestIo; ran: Promise<Ran> }

/** Runs `ac login` on a terminal io of its own; resolves once the window is open, with the run's outcome to await. */
export function loggedIn(relay: MemoryRelay, h: AgentHome, ...more: string[]): Promise<LoggedIn> {
  return loggedInAt(relay, h, T0, ...more)
}

/** `ac login` as loggedIn, its clock at `at`. */
export async function loggedInAt(
  relay: MemoryRelay,
  h: AgentHome,
  at: number,
  ...more: string[]
): Promise<LoggedIn> {
  const io = testIo(relay)
  io.tty = true
  io.time.now = at
  const ran = cli(io, 'login', '--as', 'jane', '--relay', RELAY, '--dir', h.dir, ...more)
  const open = (): boolean => io.stdout.some((l) => l.startsWith('login '))
  while (!open() && !io.stderr.some((l) => l.startsWith('bag:'))) {
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
  return { io, ran }
}

/** A session address, made fresh. */
export function sessionAddress(): string {
  return generateEdgeKeys(systemRng).signing.address
}

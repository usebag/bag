import { randomUUID } from 'node:crypto'
import { existsSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  canonical,
  fromHex,
  isAddress,
  isHex,
  type SigningKey,
  sealingKeyFromSeed,
  sha256hex,
  signingKeyFromSeed,
  toHex,
} from '@usebag/core'
import type { EdgeKeys, Rng } from '../ports.ts'

// Personal recovery: the three seeds of a self-rooted identity, the
// sheet `ac init` prints once and `ac restore` reads back (two seeds under forward secrecy), its 8-hex checksum, and the recovery state. The state lives
// in a sibling file, <home>/recovery-state.<address>.json, beside the write-once key file or pointer;
// the rotation seed is a key file of its own, the identity the record's `rotation_key` names.

/**
 * The two seeds a restore recovers under forward secrecy (2026-10-28): the signing seed (the
 * identity, its address) and the rotation key's. No sealing seed: mail is sealed to short-lived epoch keys that never
 * leave the device and are deleted past their horizon, so a restore recovers the identity, not past mail, and starts
 * a fresh epoch. The identity's key file still holds a sealing key, fresh and random, which no record names.
 */
export interface Seeds {
  readonly sign: Uint8Array
  readonly rotation: Uint8Array
}

/** Two fresh seeds. */
export const newSeeds = (rng: Rng): Seeds => ({ sign: rng.bytes(32), rotation: rng.bytes(32) })

/** Zeroes the seeds in memory, once they are in custody. */
export function zeroSeeds(seeds: Seeds): void {
  for (const s of [seeds.sign, seeds.rotation]) s.fill(0)
}

/**
 * The identity's keys and the rotation key the seeds stand for, with `sealing` the key file's sealing
 * seed, fresh at each init or restore: under forward secrecy no record names it.
 */
export function seedKeys(
  seeds: Seeds,
  sealing: Uint8Array,
): { readonly keys: EdgeKeys; readonly rotation: SigningKey } {
  return {
    keys: { signing: signingKeyFromSeed(seeds.sign), sealing: sealingKeyFromSeed(sealing) },
    rotation: signingKeyFromSeed(seeds.rotation),
  }
}

/**
 * The sheet checksum: the last 8 hex characters of sha256 over the canonical tag, the two seeds in hex and the relay line (the relay is
 * inside the check). `ac/sheet/2`: the sheet of forward secrecy, with no sealing
 * seed, so a sheet of the earlier form never checks. Not a MAC.
 */
export function sheetChecksum(seeds: Seeds, relay: string): string {
  return sha256hex(canonical(['ac/sheet/2', toHex(seeds.sign), toHex(seeds.rotation), relay])).slice(-8)
}

const LABELS = ['signing', 'rotation'] as const

/** The sheet's lines: the two seeds labelled, the primary relay, and the checksum alone last. */
export function sheetLines(seeds: Seeds, relay: string): string[] {
  const hex = [seeds.sign, seeds.rotation].map(toHex)
  return [...LABELS.map((l, i) => `${l} ${hex[i]}`), `relay ${relay}`, sheetChecksum(seeds, relay)]
}

/** How many lines a sheet has: the seeds, the relay and the checksum. */
export const SHEET_LINES = LABELS.length + 2

/**
 * The seeds and relay of a sheet's lines as typed back: `bad-sheet` when a line is missing or not its label and value
 * (spaces around a line and the case of the hex are forgiven), `checksum-mismatch` when the checksum line is not the
 * seeds' (a mistyped seed: checked before any network call).
 */
export function readSheet(
  lines: readonly string[],
): { seeds: Seeds; relay: string } | 'bad-sheet' | 'checksum-mismatch' {
  const typed = lines.map((l) => l.trim()).filter((l) => l !== '')
  if (typed.length !== SHEET_LINES) return 'bad-sheet'
  const hex: string[] = []
  for (const [i, label] of LABELS.entries()) {
    const [l, v, ...rest] = (typed[i] as string).split(/\s+/)
    const h = v?.toLowerCase()
    if (l !== label || rest.length > 0 || !isHex(h, 32)) return 'bad-sheet'
    hex.push(h)
  }
  const [r, relay, ...more] = (typed[LABELS.length] as string).split(/\s+/)
  if (r !== 'relay' || relay === undefined || more.length > 0) return 'bad-sheet'
  const seeds = { sign: fromHex(hex[0] as string), rotation: fromHex(hex[1] as string) }
  return (typed[SHEET_LINES - 1] as string).toLowerCase() === sheetChecksum(seeds, relay)
    ? { seeds, relay }
    : 'checksum-mismatch'
}

/**
 * The recovery state: `copy` is how the second copy stands (`sheet` confirmed; `wrap`, a holder's answered
 * challenge, kept for the wrap, not built yet; `none` by --accept-loss; or `single-copy`), `confirmed_at` when a sheet was confirmed, `stale_since` when a rotation made the copy stale (cleared
 * by a confirmed reprint).
 */
export interface RecoveryState {
  readonly v: 1
  readonly copy: 'sheet' | 'wrap' | 'single-copy' | 'none'
  readonly confirmed_at: number | null
  readonly stale_since: number | null
}

const statePath = (home: string, address: string): string => join(home, `recovery-state.${address}.json`)
const second = (v: unknown): v is number | null => v === null || Number.isSafeInteger(v)

/** The state of `address`, or null without a file; `bad-state` (thrown) for a file that is not one. */
export function readRecoveryState(home: string, address: string): RecoveryState | null {
  let v: Partial<Record<keyof RecoveryState, unknown>>
  try {
    v = Object(JSON.parse(readFileSync(statePath(home, address), 'utf8')))
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw new Error(`bad-state: ${statePath(home, address)} cannot be read: ${(e as Error).message}`)
  }
  const ok = v.v === 1 && ['sheet', 'wrap', 'single-copy', 'none'].includes(v.copy as string)
  if (!ok || !second(v.confirmed_at) || !second(v.stale_since)) {
    throw new Error(`bad-state: ${statePath(home, address)} is not a recovery state of version 1`)
  }
  return v as RecoveryState
}

/** Writes the state of `address` whole: a temporary file of mode 0600, then a rename over the old one. */
export function writeRecoveryState(home: string, address: string, state: RecoveryState): void {
  if (!isAddress(address)) throw new Error(`bad-state: ${JSON.stringify(address)} is not an address`)
  const tmp = join(home, `.recovery-state.${randomUUID()}.tmp`)
  try {
    writeFileSync(tmp, `${JSON.stringify(state)}\n`, { mode: 0o600, flag: 'wx' })
    renameSync(tmp, statePath(home, address))
  } finally {
    if (existsSync(tmp)) unlinkSync(tmp) // a failed write or rename leaves no temporary file
  }
}

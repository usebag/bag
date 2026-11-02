import { readFileSync } from 'node:fs'
import type { Hop } from '../../src/chain.ts'
import { signHop } from '../../src/chain.ts'
import { type BuiltEnvelope, buildEnvelope } from '../../src/envelope.ts'
import {
  generateSealingKey,
  generateSigningKey,
  type Rng,
  type SealingKey,
  type SigningKey,
} from '../../src/keys.ts'
import type { Recipient, RecipientKey } from '../../src/seal.ts'
import { newThread } from '../../src/thread.ts'
import { xorshiftRng } from '../support/rng.ts'

// Shared by the adversarial tests: seeded keys and envelopes (every key from xorshiftRng with the seed the
// test names: test data, never real), and the committed differential cases of spec/adversarial.

export const T0 = 1_800_000_000
export const NOW = T0 + 60
export const DAY = 86_400
export const MAX = Number.MAX_SAFE_INTEGER

export interface Party {
  readonly key: SigningKey
  readonly address: string
  readonly seal: SealingKey
}

export interface World {
  readonly rng: Rng
  readonly signers: readonly SigningKey[]
  readonly parties: readonly Party[]
  readonly attacker: SigningKey
}

export function world(seed: number): World {
  const rng = xorshiftRng(seed)
  const signers = Array.from({ length: 12 }, () => generateSigningKey(rng))
  const parties = Array.from({ length: 20 }, () => {
    const key = generateSigningKey(rng)
    return { key, address: key.address, seal: generateSealingKey(rng) }
  })
  return { rng, signers, parties, attacker: generateSigningKey(rng) }
}

export function item<T>(items: readonly T[], i: number): T {
  const v = items[i]
  if (v === undefined) throw new Error(`no item ${i} of ${items.length}`)
  return v
}

export const recipient = (p: Party): Recipient => ({ address: p.address, sealingKey: p.seal.publicKey })
export const opener = (p: Party): RecipientKey => ({ address: p.address, key: p.seal })

/** A chain of n hops from signers[0..n-1] to `from`, exp T0 + (20 - i) days, one caveat per hop. */
export function chain(w: World, from: SigningKey, n: number): Hop[] {
  return Array.from({ length: n }, (_, i) =>
    signHop(
      item(w.signers, i),
      i + 1 < n ? item(w.signers, i + 1).address : from.address,
      [`type=coding.t${i}.*`],
      T0 + DAY * (20 - i),
    ),
  )
}

export interface Sent extends BuiltEnvelope {
  readonly from: SigningKey
  readonly to: readonly Party[]
}

/** An envelope from signers[11] to the first nTo parties, with an n-hop chain, at ts. */
export function send(w: World, nTo: number, nHops: number, ts = T0): Sent {
  const from = item(w.signers, 11)
  const to = w.parties.slice(0, nTo)
  const built = buildEnvelope({
    from,
    to: to.map(recipient),
    auth: chain(w, from, nHops),
    type: 'coding.t0.task',
    thread: newThread(w.rng),
    body: { repo: 'acme/api' },
    ts,
    rng: w.rng,
  })
  return { ...built, from, to }
}

export interface AdvCase {
  readonly name: string
  readonly line: string
  readonly kind: string
  readonly input: Record<string, unknown>
  readonly expected: string
  readonly allowed?: Record<string, { readonly verdict: string; readonly reason: string }>
}

const ADVERSARIAL = new URL('../../../../spec/adversarial/', import.meta.url)

/** The cases of one committed file of spec/adversarial. */
export function cases(file: string): readonly AdvCase[] {
  return (JSON.parse(readFileSync(new URL(file, ADVERSARIAL), 'utf8')) as { cases: AdvCase[] }).cases
}

export function readAdversarial(file: string): unknown {
  return JSON.parse(readFileSync(new URL(file, ADVERSARIAL), 'utf8'))
}

/** The cases of one line in a file, at least one (a line with no case would pass vacuously). */
export function lineCases(file: string, line: string, prefix = ''): readonly AdvCase[] {
  const found = cases(file).filter((c) => c.line === line && c.name.split('/')[2]?.startsWith(prefix))
  if (found.length === 0) throw new Error(`${file} has no ${line} case starting ${prefix}`)
  return found
}

export const bytesOf = (c: AdvCase, key = 'bytes_hex'): Uint8Array =>
  Uint8Array.from(Buffer.from(c.input[key] as string, 'hex'))
export const label = (c: AdvCase): string => c.name.split('/')[2] ?? c.name

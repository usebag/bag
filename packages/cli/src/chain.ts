import { readFileSync, writeFileSync } from 'node:fs'
import { AcError, checkChainShape, type Hop } from '@usebag/core'

// Chain files: an envelope's `auth` as a JSON array of hops, root first (spec/SPEC.md §6.1), written by delegate and
// read by delegate --chain and send --auth. Hops are public, as records are, so the file has the default mode.

/** The hops of a chain file, checked by chain rules 1 to 4: bad-json, bad-shape, bad-hop and the caps' codes. */
export function readChain(file: string): readonly Hop[] {
  const text = readFileSync(file, 'utf8')
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    throw new AcError('bad-json', `${file} is not JSON`)
  }
  return checkChainShape(value)
}

/** Writes a chain file: one line of JSON, each hop's members in the spec's order. */
export function writeChain(file: string, hops: readonly Hop[]): void {
  writeFileSync(file, `${JSON.stringify(hops)}\n`)
}

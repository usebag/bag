import { readFileSync } from 'node:fs'

/** The repository root's spec/ directory, read by the tests that check the committed vectors and the spec's tables. */
export const SPEC_DIR = new URL('../../../../spec/', import.meta.url)

/** A committed vector file, parsed. */
export function readVectors(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(new URL(`vectors/${name}`, SPEC_DIR), 'utf8')) as Record<string, unknown>
}

/** The cases of one list in a vector file. */
export function casesOf<T>(file: Record<string, unknown>, key = 'cases'): readonly T[] {
  return file[key] as T[]
}

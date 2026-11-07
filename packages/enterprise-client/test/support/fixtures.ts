import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Rng } from '@usebag/edge'

// The tests' fixed values: a "now" of 2027-01-15 08:00:00 UTC (as the vectors), a seeded rng, and a temp directory
// under AC_TEST_TMP (else the system's), removed by its cleanup unless AC_KEEP_TMP=1.

export const T0 = 1_800_000_000
export const DAY = 86_400

/** A deterministic rng: sha256 blocks of `label:counter`. Test data only. */
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
  const dir = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), `bag-ent-${prefix}-`))
  return {
    dir,
    cleanup(): void {
      if (process.env.AC_KEEP_TMP === '1') return
      rmSync(dir, { recursive: true, force: true })
    },
  }
}

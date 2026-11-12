import { MAX_ENVELOPE_BYTES } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import * as edge from '../src/index.ts'
import { liftMaxBytes, OLD_DEFAULT_MAX_BYTES } from '../src/max-bytes.ts'

// The accept-from max_bytes lift (W9): a re-sign writes the envelope cap in place of exactly the old default.
describe('liftMaxBytes', () => {
  it('lifts exactly 65,536 to the envelope cap and keeps every other value', () => {
    expect(OLD_DEFAULT_MAX_BYTES).toBe(65_536)
    expect(liftMaxBytes(65_536)).toBe(MAX_ENVELOPE_BYTES)
    for (const kept of [
      1,
      4096,
      32_768,
      65_535,
      65_537,
      100_000,
      MAX_ENVELOPE_BYTES,
      Number.MAX_SAFE_INTEGER,
    ])
      expect(liftMaxBytes(kept), `${kept}`).toBe(kept)
  })

  it('is exported by the package', () => {
    expect([edge.liftMaxBytes, edge.OLD_DEFAULT_MAX_BYTES]).toEqual([liftMaxBytes, 65_536])
  })
})

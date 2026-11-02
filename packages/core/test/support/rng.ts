import type { Rng } from '../../src/keys.ts'

// Deterministic randomness for tests and test vectors only. Nothing here may produce a key that is used for real.

const MASK = (1n << 64n) - 1n

/** splitmix64 (Steele, Lea and Flood): expands a seed into xorshift128+'s two words of state. */
function splitmix64(state: bigint): { readonly next: bigint; readonly value: bigint } {
  const next = (state + 0x9e3779b97f4a7c15n) & MASK
  let z = next
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK
  return { next, value: z ^ (z >> 31n) }
}

/**
 * A seeded xorshift128+ generator (Vigna, shifts 23, 18 and 5) of bytes. Each call takes ceil(n / 8) 64-bit outputs
 * and writes each little-endian, dropping the bytes past n, so a vector's bytes depend only on the seed and the
 * sequence of lengths asked for.
 */
export function xorshiftRng(seed: number | bigint): Rng {
  const a = splitmix64(BigInt(seed) & MASK)
  const b = splitmix64(a.next)
  let s0 = a.value
  let s1 = b.value
  const next = (): bigint => {
    let x = s0
    const y = s1
    s0 = y
    x = (x ^ (x << 23n)) & MASK
    s1 = x ^ y ^ (x >> 18n) ^ (y >> 5n)
    return (s1 + y) & MASK
  }
  return (length: number): Uint8Array => {
    const out = new Uint8Array(length)
    for (let i = 0; i < length; i += 8) {
      let word = next()
      for (let j = 0; j < 8 && i + j < length; j++) {
        out[i + j] = Number(word & 0xffn)
        word >>= 8n
      }
    }
    return out
  }
}

/** An rng that records what it hands out, so a vector can list every injected value. */
export function recordingRng(inner: Rng): { readonly rng: Rng; readonly drawn: Uint8Array[] } {
  const drawn: Uint8Array[] = []
  return {
    drawn,
    rng: (length: number) => {
      const bytes = inner(length)
      drawn.push(bytes)
      return bytes
    },
  }
}

/** An rng that replays recorded byte strings in order, for rebuilding a vector from its listed inputs. */
export function replayRng(chunks: readonly Uint8Array[]): Rng {
  let i = 0
  return (length: number) => {
    const chunk = chunks[i++]
    if (chunk === undefined || chunk.length !== length) {
      throw new Error(
        `replayRng: draw ${i} asked for ${length} bytes; the recording holds ${chunk?.length ?? 'none'}`,
      )
    }
    return chunk
  }
}

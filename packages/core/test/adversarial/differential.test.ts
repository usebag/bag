import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  chainVerdict,
  FILES,
  jsonVerdict,
  type OpenInput,
  openVerdict,
  outcome,
  outerVerdict,
  parseVerdict,
  recordVerdict,
  rotationClaimVerdict,
  rotationVerdict,
} from '../../scripts/gen-adversarial.ts'
import { canonical } from '../../src/canonical.ts'
import { sha256hex } from '../../src/hash.ts'
import { toHex } from '../../src/hex.ts'
import { xorshiftRng } from '../support/rng.ts'
import { type AdvCase, bytesOf, cases, readAdversarial } from './support.ts'

// S-DIFF, the TypeScript reader: G2 (the generator regenerates every file byte for byte, and the seeded rng
// reproduces its committed draws), every committed case's verdict recomputed through the core, and G3 (a planted
// one-byte change to an expected verdict is caught). The files also include round2-*.json, whose expected
// verdicts are the pre-registered ones: a TypeScript verdict that differs fails here, as in the other readers.

const PACKAGE = fileURLToPath(new URL('../../', import.meta.url))

function utf16(hex: string): string {
  let s = ''
  for (let i = 0; i < hex.length; i += 4) s += String.fromCharCode(Number.parseInt(hex.slice(i, i + 4), 16))
  return s
}

/** The TypeScript verdict of a case, by its kind (spec/adversarial/README.md). */
function verdict(c: AdvCase): string {
  const i = c.input
  switch (c.kind) {
    case 'json':
      return jsonVerdict(bytesOf(c))
    case 'parse':
      return parseVerdict(bytesOf(c))
    case 'outer':
      return outerVerdict(bytesOf(c), i.now as number, i.ttl as number, i.skew as number)
    case 'chain':
      return chainVerdict(i.auth, i.from as string, i.ts as number)
    case 'record':
      return recordVerdict(bytesOf(c), i.now as number, i.skew as number)
    case 'rotation':
      return rotationVerdict(bytesOf(c, 'prev_bytes_hex'), bytesOf(c, 'next_bytes_hex'))
    case 'rotation-claim':
      return rotationClaimVerdict(bytesOf(c), i.now as number, i.skew as number)
    case 'open':
      return openVerdict(i as unknown as OpenInput)
    case 'canonical': {
      if ('sparse_list' in i) {
        const s = i.sparse_list as { length: number; items: [number, string][] }
        const holey: string[] = []
        holey.length = s.length
        for (const [k, v] of s.items) holey[k] = v
        return outcome(() => canonical(holey))
      }
      const value = 'utf16_hex' in i ? utf16(i.utf16_hex as string) : i.value
      return outcome(() => {
        const text = canonical(value as never)
        if (text !== i.canonical || sha256hex(text) !== i.sha256) throw new Error(`${c.name}: other bytes`)
      })
    }
    default:
      throw new Error(`${c.name}: unknown kind ${c.kind}`)
  }
}

describe('G2: determinism', () => {
  it('regenerates every spec/adversarial file byte for byte (adversarial:check)', () => {
    // spawnSync blocks the event loop, so the it() timeout cannot fire while the child runs: bound the child itself.
    const r = spawnSync(process.execPath, ['scripts/gen-adversarial.ts', '--check'], {
      cwd: PACKAGE,
      encoding: 'utf8',
      env: { ...process.env },
      timeout: 900_000,
      killSignal: 'SIGKILL',
    })
    if (r.error !== undefined || r.signal !== null) {
      const why =
        (r.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT'
          ? 'timed out after 900000 ms'
          : `did not finish (${r.error?.message ?? `signal ${r.signal}`})`
      expect.fail(`adversarial:check ${why}; stderr: ${r.stderr?.slice(0, 400) ?? ''}`)
    }
    expect(r.stderr).toBe('')
    expect(r.stdout).toContain(
      `adversarial:check: OK, ${FILES.length} of ${FILES.length} files byte-identical`,
    )
    expect(r.status).toBe(0)
  }, 960_000)

  it('xorshiftRng reproduces the committed first three 32-byte draws for seeds 1, 2 and 20261025', () => {
    const want = readAdversarial('rng-expected.json') as { seeds: Record<string, string[]> }
    expect(Object.keys(want.seeds)).toEqual(['1', '2', '20261025'])
    for (const [seed, draws] of Object.entries(want.seeds)) {
      const rng = xorshiftRng(Number(seed))
      expect([0, 1, 2].map(() => toHex(rng(32)))).toEqual(draws)
    }
  })
})

describe('S-DIFF: the TypeScript verdict of every committed case is its expected verdict', () => {
  for (const file of FILES) {
    it(file, () => {
      const all = cases(file)
      expect(all.length).toBeGreaterThan(0)
      const wrong = all.filter((c) => verdict(c) !== c.expected).map((c) => `${c.name}: ${verdict(c)}`)
      expect(wrong).toEqual([])
    })
  }
})

describe('G3: a planted one-byte change to an expected verdict is caught', () => {
  for (const file of FILES) {
    it(file, () => {
      const all = cases(file)
      const picks = [all[0], all[Math.floor(all.length / 2)], all.at(-1)] as AdvCase[]
      for (const c of picks) {
        const planted = {
          ...c,
          expected: `${c.expected.slice(0, -1)}${c.expected.endsWith('x') ? 'y' : 'x'}`,
        }
        expect(verdict(planted)).not.toBe(planted.expected)
      }
    })
  }
})

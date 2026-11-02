import { createHash } from 'node:crypto'
import { mkdirSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { signingKeyFromSeed, toHex } from '@usebag/core'
import { afterEach, describe, expect, it } from 'vitest'
import {
  newSeeds,
  type RecoveryState,
  readRecoveryState,
  readSheet,
  SHEET_LINES,
  seedKeys,
  sheetChecksum,
  sheetLines,
  writeRecoveryState,
  zeroSeeds,
} from '../src/index.ts'
import { seed, T0, tempDir } from './support/fixtures.ts'

// Personal recovery's edge half: the seeds, the sheet and its checksum, the
// sheet typed back, and the recovery state beside the pointer.

const SEEDS = { sign: seed(1), rotation: seed(3) }
const RELAY = 'https://relay.example'
let tmp: ReturnType<typeof tempDir> | null = null
afterEach(() => {
  tmp?.cleanup()
  tmp = null
})

describe('the seeds and the sheet', () => {
  it('makes two fresh 32-byte seeds, no sealing seed, and zeroes them', () => {
    let n = 0
    const s = newSeeds({ bytes: (l) => new Uint8Array(l).fill(++n) })
    expect(Object.keys(s)).toEqual(['sign', 'rotation'])
    expect([s.sign, s.rotation].map((x) => [x.length, x[0]])).toEqual([
      [32, 1],
      [32, 2],
    ])
    zeroSeeds(s)
    expect([...s.sign, ...s.rotation].every((b) => b === 0)).toBe(true)
  })

  it('derives the identity and the rotation key from the seeds, the sealing key from the fresh seed given', () => {
    const { keys, rotation } = seedKeys(SEEDS, seed(2))
    expect(keys.signing.address).toBe(signingKeyFromSeed(seed(1)).address)
    expect(rotation.address).toBe(signingKeyFromSeed(seed(3)).address)
    expect(toHex(keys.sealing.exportSeed())).toBe(toHex(seed(2)))
  })

  it('takes the checksum as the sheet says: the last 8 hex of sha256 over the canonical tag and seeds', () => {
    const text = JSON.stringify(['ac/sheet/2', toHex(seed(1)), toHex(seed(3)), RELAY])
    const want = createHash('sha256').update(text).digest('hex').slice(-8)
    expect(sheetChecksum(SEEDS, RELAY)).toBe(want)
    expect(sheetChecksum(SEEDS, 'https://other.example')).not.toBe(want) // the relay line is inside the check
    expect(sheetLines(SEEDS, RELAY)).toEqual([
      `signing ${toHex(seed(1))}`,
      `rotation ${toHex(seed(3))}`,
      `relay ${RELAY}`,
      want,
    ])
    expect(SHEET_LINES).toBe(4)
  })

  it('reads a sheet typed back, forgiving spaces and the case of the hex, and refuses one that is not', () => {
    const lines = sheetLines(SEEDS, RELAY)
    const read = readSheet(lines)
    expect(read).toEqual({ seeds: SEEDS, relay: RELAY })
    const upper = (l: string): string => l.replace(/ ([0-9a-f]+)$/, (h) => h.toUpperCase())
    const loose = [
      '',
      ...lines.slice(0, 2).map((l) => `  ${upper(l)}  `),
      `relay   ${RELAY} `,
      (lines[3] as string).toUpperCase(),
      '',
    ]
    expect(readSheet(loose)).toEqual({ seeds: SEEDS, relay: RELAY })
    const wrong = [...lines]
    wrong[0] = `signing ${toHex(seed(9))}`
    expect(readSheet(wrong)).toBe('checksum-mismatch')
    expect(readSheet([...lines.slice(0, 2), 'relay https://other.example', lines[3] as string])).toBe(
      'checksum-mismatch',
    )
    // A sheet of the earlier form (ac/sheet/1: signing, sealing, rotation, relay, checksum) is refused.
    const old = createHash('sha256')
      .update(JSON.stringify(['ac/sheet/1', toHex(seed(1)), toHex(seed(2)), toHex(seed(3)), RELAY]))
      .digest('hex')
      .slice(-8)
    for (const bad of [
      lines.slice(0, 3),
      [lines[0] as string, `sealing ${toHex(seed(2))}`, ...lines.slice(1)],
      [lines[0] as string, `sealing ${toHex(seed(2))}`, ...lines.slice(1, 3), old],
      [`sealing ${toHex(seed(2))}`, ...lines.slice(1)],
      [`signing ${toHex(seed(1)).slice(2)}`, ...lines.slice(1)],
      [`signing ${toHex(seed(1))} extra`, ...lines.slice(1)],
      [...lines.slice(0, 2), 'relay', lines[3] as string],
      [...lines.slice(0, 2), `relay ${RELAY} extra`, lines[3] as string],
      [...lines.slice(0, 2), `relays ${RELAY}`, lines[3] as string],
    ]) {
      expect(readSheet(bad)).toBe('bad-sheet')
    }
  })
})

describe('the recovery state beside the pointer', () => {
  const address = signingKeyFromSeed(seed(1)).address
  const state: RecoveryState = { v: 1, copy: 'sheet', confirmed_at: T0, stale_since: null }

  it('is null without a file, and reads back what was written, 0600, with no temporary file left', () => {
    tmp = tempDir('recovery')
    expect(readRecoveryState(tmp.dir, address)).toBeNull()
    writeRecoveryState(tmp.dir, address, state)
    writeRecoveryState(tmp.dir, address, { ...state, copy: 'wrap', stale_since: T0 + 5 })
    expect(readRecoveryState(tmp.dir, address)).toEqual({ ...state, copy: 'wrap', stale_since: T0 + 5 })
    const file = join(tmp.dir, `recovery-state.${address}.json`)
    expect(statSync(file).mode & 0o777).toBe(0o600)
    expect(readdirSync(tmp.dir)).toEqual([`recovery-state.${address}.json`])
  })

  it('refuses a file that is not a state of version 1, an unreadable one, and a name that is not an address', () => {
    const t = tempDir('recovery')
    tmp = t
    const file = join(t.dir, `recovery-state.${address}.json`)
    for (const text of [
      '{',
      'null',
      '{"v":2,"copy":"sheet","confirmed_at":null,"stale_since":null}',
      '{"v":1,"copy":"two","confirmed_at":null,"stale_since":null}',
      '{"v":1,"copy":"none","confirmed_at":1.5,"stale_since":null}',
      '{"v":1,"copy":"none","confirmed_at":null,"stale_since":"x"}',
    ]) {
      writeFileSync(file, text)
      expect(() => readRecoveryState(t.dir, address)).toThrow(/^bad-state: /)
    }
    expect(() => writeRecoveryState(t.dir, '../x', state)).toThrow(/^bad-state: "..\/x" is not an address$/)
    // A rename that fails (the state's path is a directory) leaves no temporary file behind.
    const blocked = join(t.dir, 'b')
    mkdirSync(join(blocked, `recovery-state.${address}.json`), { recursive: true })
    expect(() => writeRecoveryState(blocked, address, state)).toThrow()
    expect(readdirSync(blocked)).toEqual([`recovery-state.${address}.json`])
    const dir = join(t.dir, 'd')
    mkdirSync(join(dir, `recovery-state.${address}.json`), { recursive: true })
    expect(() => readRecoveryState(dir, address)).toThrow(/^bad-state: .* cannot be read: EISDIR/)
  })
})

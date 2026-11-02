import { mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { tempDir, testIo } from '../support/io.ts'
import { MemoryRelay } from '../support/relay.ts'
import { cli } from '../support/run.ts'

// S7 (a2), the corrected line of S7 (a). Two agent identities whose names hold neither value (`rec-1`, `rec-2`). Pass when `keygen --custody agent --recovery <v>` exits
// 0, the pointer's field EQUALS the setting (not a substring), and the `keys list` line names the setting as a whole
// word while the line of an identity made without `--recovery` names neither value; and three refusals: an unknown
// value exits 1 and makes no pointer, `--recovery` without `--custody agent` exits 1, and a pointer without the field
// still lists. Prediction 2 of 2 and 3 of 3; the line is red on anything less. S7 (a), as measured at c3778a6, is not
// edited by this file.
//
// This file is the registered one, committed on main before any run of it and before any build (14:25 UTC (15:25 Madrid),
// 225ce2b), where the two positive arms were `it.fails`, red 0 of 2, with a plain sibling asserting the recorded red
// reason ("Unknown option '--recovery'"). At the build head the two arms are plain and the
// sibling is gone: it said only what main did. The three refusals are plain tests, on main and after the build.

const tmp = tempDir('study38-s7a2')
afterAll(() => tmp.cleanup())
let n = 0
const home = (): string => {
  const dir = join(tmp.dir, `h${n++}`)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  return dir
}

type Io = ReturnType<typeof testIo>
const AGENT = ['--custody', 'agent', '--principal', 'jane-keys']

/** The `keys list` line of the identity `name`, or null when it has none. */
async function line(io: Io, dir: string, name: string): Promise<string | null> {
  return (await cli(io, 'keys', 'list', '--dir', dir)).out.find((l) => l.startsWith(`${name} `)) ?? null
}

/** The fields of that line. */
async function fields(io: Io, dir: string, name: string): Promise<string[] | null> {
  return (await line(io, dir, name))?.split(' ') ?? null
}

/** A home with the key file `jane-keys` and `rec-3`, an agent identity made without `--recovery`. */
async function fresh(): Promise<{ io: Io; dir: string }> {
  const dir = home()
  const io = testIo(new MemoryRelay())
  expect((await cli(io, 'keygen', 'jane-keys', '--dir', dir)).code).toBe(0)
  expect((await cli(io, 'keygen', 'rec-3', ...AGENT, '--dir', dir)).code).toBe(0)
  return { io, dir }
}

/** One positive arm: `name` made with `--recovery <setting>`; true when all of S7 (a2)'s three conditions hold. */
async function arm(name: string, setting: string): Promise<boolean> {
  const { io, dir } = await fresh()
  const made = await cli(io, 'keygen', name, ...AGENT, '--recovery', setting, '--dir', dir)
  const file = join(dir, 'agent', `${name}.json`)
  const field =
    made.code === 0 ? (JSON.parse(readFileSync(file, 'utf8')) as { recovery?: unknown }).recovery : undefined
  const named = (await line(io, dir, name)) ?? ''
  const plain = (await line(io, dir, 'rec-3')) ?? ''
  const exact = field === setting
  const word = new RegExp(`\\b${setting}\\b`).test(named)
  const neither = !/\b(personal|none)\b/.test(plain)
  console.log(
    `MEASURE S7(a2): ${name} ${setting}: keygen exit ${made.code}, pointer field ${JSON.stringify(field)} equals ${exact}, listed as a whole word ${word}, rec-3 names neither value ${neither}`,
  )
  expect(made.code, `keygen exit ${made.err[0] ?? ''}`).toBe(0)
  expect(field, 'the pointer field equals the setting').toBe(setting)
  expect(word, 'the keys list line names the setting as a whole word').toBe(true)
  expect(neither, 'the line of an identity made without --recovery names neither value').toBe(true)
  return true
}

describe('S7 (a2): the recovery setting round-trips, by equality and as a whole word', () => {
  it('rec-1 made with --recovery personal: exit 0, the pointer field equals it, the line names it', async () => {
    expect(await arm('rec-1', 'personal')).toBe(true)
  })

  it('rec-2 made with --recovery none: exit 0, the pointer field equals it, the line names it', async () => {
    expect(await arm('rec-2', 'none')).toBe(true)
  })
})

describe('S7 (a2): the three refusals hold, on main and after the build (3 of 3)', () => {
  it('an unknown value exits 1 and makes no pointer; --recovery without --custody agent exits 1; a pointer without the field lists', async () => {
    const { io, dir } = await fresh()
    const unknown = await cli(io, 'keygen', 'rec-4', ...AGENT, '--recovery', 'bogus', '--dir', dir)
    const noPointer = (await fields(io, dir, 'rec-4')) === null
    const outside = await cli(io, 'keygen', 'rec-5', '--recovery', 'personal', '--dir', dir)
    const noKey = (await fields(io, dir, 'rec-5')) === null
    const plain = await fields(io, dir, 'rec-3')
    const held = [
      [unknown.code === 1 && noPointer, 'an unknown value exits 1 and makes no pointer'],
      [outside.code === 1 && noKey, '--recovery without --custody agent exits 1 and makes nothing'],
      [plain?.length === 4 && plain[2] === 'agent', 'a pointer without the field still lists, four fields'],
    ] as const
    const ok = held.filter(([yes]) => yes).length
    console.log(
      `MEASURE S7(a2): refusals ${ok} of 3. ${held.map(([yes, what]) => `${what}: ${yes}`).join('; ')}`,
    )
    expect(held.filter(([yes]) => !yes).map(([, what]) => what)).toEqual([])
    expect(ok).toBe(3)
  })
})

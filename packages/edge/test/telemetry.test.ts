import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { systemRng } from '../src/adapters/system-clock.ts'
import * as edge from '../src/index.ts'
import {
  machineTelemetryNotice,
  noticeText,
  setTelemetry,
  TELEMETRY_COUNTS_FILE,
  TELEMETRY_FILE,
  TELEMETRY_NOTICE,
  telemetryDir,
  telemetryId,
  telemetryNotice,
  telemetryOn,
  telemetrySince,
  telemetryState,
} from '../src/telemetry.ts'
import { tempDir } from './support/fixtures.ts'

// The telemetry switch: opt-in, the state matrix of the environment and <dir>/telemetry.json, the file's mode and
// atomic write, the install id, and the notice once per directory; then the machine's directory, HOME/.bag, one
// consent, one id and one notice per machine. Temp directories only; nothing is sent.

const tmp = tempDir('telemetry')
afterAll(() => tmp.cleanup())
let n = 0
const fresh = (): string => {
  const home = join(tmp.dir, `home-${n++}`)
  mkdirSync(home)
  return home
}
const file = (home: string): string => join(home, TELEMETRY_FILE)
const mode = (path: string): number => statSync(path).mode & 0o777
const chosen = (choice: 'on' | 'off'): string => {
  const home = fresh()
  setTelemetry(home, choice, systemRng)
  return home
}

describe('telemetryState: off until a person turns it on, and an environment variable can only turn it off', () => {
  it('is off with no file, and on only by the file', () => {
    expect(telemetryState({}, fresh())).toEqual({ on: false, reason: 'no-file', choice: null })
    expect(telemetryState({}, join(tmp.dir, 'no-such-home'))).toEqual({
      on: false,
      reason: 'no-file',
      choice: null,
    })
    expect(telemetryState({}, chosen('on'))).toEqual({ on: true, reason: 'file', choice: 'on' })
    expect(telemetryState({}, chosen('off'))).toEqual({ on: false, reason: 'file', choice: 'off' })
  })

  it('turns off by AC_TELEMETRY, DO_NOT_TRACK or CI, in that order, and keeps the choice beside the reason', () => {
    const on = chosen('on')
    for (const [env, reason] of [
      [{ AC_TELEMETRY: 'off' }, 'AC_TELEMETRY'],
      [{ AC_TELEMETRY: ' OFF ' }, 'AC_TELEMETRY'],
      [{ AC_TELEMETRY: '0' }, 'AC_TELEMETRY'],
      [{ AC_TELEMETRY: 'false' }, 'AC_TELEMETRY'],
      [{ AC_TELEMETRY: 'no' }, 'AC_TELEMETRY'],
      [{ AC_TELEMETRY: 'off', DO_NOT_TRACK: '1', CI: 'true' }, 'AC_TELEMETRY'],
      [{ DO_NOT_TRACK: '1' }, 'DO_NOT_TRACK'],
      [{ DO_NOT_TRACK: 'true' }, 'DO_NOT_TRACK'],
      [{ DO_NOT_TRACK: 'yes', CI: 'true' }, 'DO_NOT_TRACK'],
      [{ CI: 'true' }, 'CI'],
      [{ CI: '1' }, 'CI'],
    ] as const) {
      expect(telemetryState(env, on), JSON.stringify(env)).toEqual({ on: false, reason, choice: 'on' })
    }
    expect(telemetryState({ DO_NOT_TRACK: '1' }, fresh())).toEqual({
      on: false,
      reason: 'DO_NOT_TRACK',
      choice: null,
    })
  })

  it('never turns on by the environment, and reads an unset, empty, 0, false, no or off variable as not set', () => {
    for (const env of [
      { AC_TELEMETRY: 'on' },
      { AC_TELEMETRY: 'yes' },
      { AC_TELEMETRY: '' },
      { DO_NOT_TRACK: '' },
      { DO_NOT_TRACK: '0' },
      { DO_NOT_TRACK: 'false' },
      { CI: 'false' },
      { CI: 'off' },
      { CI: undefined },
    ]) {
      expect(telemetryState(env, chosen('on')).on, JSON.stringify(env)).toBe(true)
      expect(telemetryState(env, chosen('off')).on, JSON.stringify(env)).toBe(false)
      expect(telemetryState(env, fresh()), JSON.stringify(env)).toEqual({
        on: false,
        reason: 'no-file',
        choice: null,
      })
    }
  })

  it('reads a file it cannot read as off, bad-file, with no choice and no id, and never throws', () => {
    const id = '0'.repeat(32)
    for (const text of [
      'not json',
      'null',
      '5',
      `{"version":2,"telemetry":"on","id":"${id}"}`,
      '{"version":2,"telemetry":"on","since":"2027-01-15"}',
      `{"version":2,"telemetry":"on","id":"ABCDEF00000000000000000000000000","since":"2027-01-15"}`,
      `{"version":2,"telemetry":"on","id":"${id}","since":"2027-02-30"}`,
      '{"version":2,"telemetry":"yes"}',
      '{"version":3,"telemetry":"off"}',
    ]) {
      const home = fresh()
      writeFileSync(file(home), text)
      expect(telemetryState({}, home), text).toEqual({ on: false, reason: 'bad-file', choice: null })
      expect(telemetryId(home), text).toBeNull()
    }
    const dir = fresh()
    mkdirSync(file(dir))
    expect(telemetryState({}, dir)).toEqual({ on: false, reason: 'bad-file', choice: null })
    const notDir = join(tmp.dir, `plain-${n++}`)
    writeFileSync(notDir, '')
    expect(telemetryState({}, notDir)).toEqual({ on: false, reason: 'bad-file', choice: null })
  })

  it('reads a version-1 choice, made before pairs, as off, old-file, with no id, and asks again (Q2)', () => {
    for (const text of [
      `{"version":1,"telemetry":"on","id":"${'ab'.repeat(16)}"}`,
      '{"version":1,"telemetry":"off"}',
      '{"version":1}',
    ]) {
      const home = fresh()
      writeFileSync(file(home), text)
      writeFileSync(join(home, 'telemetry-noticed'), '')
      expect(telemetryState({}, home), text).toEqual({ on: false, reason: 'old-file', choice: null })
      expect([telemetryId(home), telemetryNotice({}, home)], text).toEqual([null, TELEMETRY_NOTICE])
      setTelemetry(home, 'on', systemRng)
      expect(telemetryId(home), text).not.toBe('ab'.repeat(16))
    }
  })

  it('reads the file afresh on every call', () => {
    const home = fresh()
    expect(telemetryState({}, home).on).toBe(false)
    setTelemetry(home, 'on', systemRng)
    expect(telemetryState({}, home).on).toBe(true)
    setTelemetry(home, 'off', systemRng)
    expect(telemetryState({}, home).on).toBe(false)
  })
})

describe('setTelemetry and telemetryId: the choice in a 0600 file, an install id made at on and removed at off', () => {
  it('writes version 2 with a 32-hex id and its date at on, keeps both at a second on, drops them at off, and draws anew after', () => {
    const home = fresh()
    const T = 1_800_000_000 // 2027-01-15 08:00 UTC
    setTelemetry(home, 'on', systemRng, T)
    const id = telemetryId(home) as string
    expect(id).toMatch(/^[0-9a-f]{32}$/)
    const doc = { version: 2, telemetry: 'on', id, since: '2027-01-15' }
    expect(JSON.parse(readFileSync(file(home), 'utf8'))).toEqual(doc)
    expect(telemetrySince(home)).toBe('2027-01-15')
    expect(mode(file(home))).toBe(0o600)
    setTelemetry(home, 'on', systemRng, T + 86_400)
    expect(JSON.parse(readFileSync(file(home), 'utf8'))).toEqual(doc)
    setTelemetry(home, 'off', systemRng)
    expect(readFileSync(file(home), 'utf8')).toBe('{"version":2,"telemetry":"off"}\n')
    expect([telemetryId(home), telemetrySince(home)]).toEqual([null, null])
    setTelemetry(home, 'on', systemRng)
    expect(telemetryId(home)).toMatch(/^[0-9a-f]{32}$/)
    expect(telemetryId(home)).not.toBe(id)
    expect(readdirSync(home)).toEqual([TELEMETRY_FILE])
  })

  it('draws an id from the rng it is given, never from the home, and replaces a bad file', () => {
    const home = fresh()
    writeFileSync(file(home), '{"version":1,"telemetry":"on"}')
    const rng = { bytes: (k: number) => new Uint8Array(k).fill(k === 16 ? 0xab : 1) }
    setTelemetry(home, 'on', rng)
    expect(telemetryId(home)).toBe('ab'.repeat(16))
    expect(telemetryState({}, home)).toEqual({ on: true, reason: 'file', choice: 'on' })
  })

  it('makes a missing home 0700, and leaves no temporary file when the rename fails', () => {
    const home = join(tmp.dir, `new-${n++}`, 'home')
    setTelemetry(home, 'off', systemRng)
    expect(mode(home)).toBe(0o700)
    expect(telemetryState({}, home).choice).toBe('off')
    const blocked = fresh()
    mkdirSync(join(file(blocked), 'inside'), { recursive: true })
    expect(() => setTelemetry(blocked, 'on', systemRng)).toThrow()
    expect(readdirSync(blocked)).toEqual([TELEMETRY_FILE])
  })
})

describe('telemetryNotice: the notice, once per home, while no choice is made', () => {
  it('is the fixed notice text, word for word, naming the preview and never ac telemetry on (ruling 13)', () => {
    const words =
      'bag: telemetry is off. It is used to find failures, see which versions, commands and tools are used, and decide what to build. If you turn it on, bag sends one report a day to telemetry.bag.dev: the version, OS, and counts of commands, messages, peers and error codes, under a random id. Never addresses, keys, messages, file paths or your IP address. See the exact report: PREVIEW. Details: bag.dev/privacy'
    const cmd = 'node /x/main.ts telemetry preview'
    expect(TELEMETRY_NOTICE).toBe(words.replace('PREVIEW', 'telemetry preview, in the bag command line'))
    expect(noticeText(cmd)).toBe(words.replace('PREVIEW', cmd))
    expect(TELEMETRY_NOTICE).not.toContain('telemetry on')
  })

  it('names the preview command it is given', () => {
    const home = fresh()
    expect(telemetryNotice({}, home, 'node /x/main.ts telemetry preview')).toBe(
      noticeText('node /x/main.ts telemetry preview'),
    )
  })

  it('gives the notice to the first caller for a home, by a 0600 mark, and null after', () => {
    const home = fresh()
    expect(telemetryNotice({}, home)).toBe(TELEMETRY_NOTICE)
    expect(mode(join(home, 'telemetry-noticed-2'))).toBe(0o600)
    expect(telemetryNotice({}, home)).toBeNull()
    expect(telemetryNotice({}, fresh())).toBe(TELEMETRY_NOTICE)
  })

  it('gives none once a choice is made, while the environment turns it off, to a bad file or to a missing home', () => {
    expect(telemetryNotice({}, chosen('on'))).toBeNull()
    expect(telemetryNotice({}, chosen('off'))).toBeNull()
    for (const env of [{ AC_TELEMETRY: 'off' }, { DO_NOT_TRACK: '1' }, { CI: 'true' }]) {
      const home = fresh()
      expect(telemetryNotice(env, home)).toBeNull()
      expect(existsSync(join(home, 'telemetry-noticed-2'))).toBe(false)
    }
    const bad = fresh()
    writeFileSync(file(bad), '{}')
    expect(telemetryNotice({}, bad)).toBeNull()
    const missing = join(tmp.dir, `missing-${n++}`)
    expect(telemetryNotice({}, missing)).toBeNull()
    expect(existsSync(missing)).toBe(false)
  })

  it('is exported by @usebag/edge with the state, the id, the writer and the machine API', () => {
    for (const name of [
      'telemetryState',
      'telemetryId',
      'telemetryNotice',
      'setTelemetry',
      'TELEMETRY_FILE',
      'TELEMETRY_NOTICE',
      'telemetryDir',
      'telemetryOn',
      'machineTelemetryNotice',
      'addTelemetryCounts',
      'readTelemetrySpool',
      'telemetryReport',
      'startTelemetry',
      'stopTelemetry',
      'countTelemetry',
      'countDuration',
    ]) {
      expect(edge, name).toHaveProperty(name)
    }
  })
})

describe('the machine: one directory, one consent, one install id and one notice per machine', () => {
  const machine = (): { env: Record<string, string>; dir: string } => {
    const home = fresh()
    return { env: { HOME: home }, dir: join(home, '.bag') }
  }

  it('is HOME/.bag whatever the identity home, from env only, and none without HOME', () => {
    expect(telemetryDir({ HOME: '/u/x', AC_HOME: '/elsewhere' })).toBe(join('/u/x', '.bag'))
    expect(telemetryDir({})).toBeNull()
    expect(telemetryDir({ HOME: '' })).toBeNull()
  })

  it('is on only by the machine file, and off by any variable, without HOME, or with a bad file', () => {
    const m = machine()
    expect(telemetryOn(m.env)).toBe(false)
    setTelemetry(m.dir, 'on', systemRng)
    expect(telemetryOn(m.env)).toBe(true)
    for (const env of [{ AC_TELEMETRY: 'off' }, { DO_NOT_TRACK: '1' }, { CI: 'true' }]) {
      expect(telemetryOn({ ...m.env, ...env }), JSON.stringify(env)).toBe(false)
    }
    expect(telemetryOn({})).toBe(false)
    setTelemetry(m.dir, 'off', systemRng)
    expect(telemetryOn(m.env)).toBe(false)
    writeFileSync(file(m.dir), '{}')
    expect(telemetryOn(m.env)).toBe(false)
  })

  it('makes one random 32-hex id at on, keeps it, drops it and the spool at off, and draws a new one after', () => {
    const m = machine()
    setTelemetry(m.dir, 'on', systemRng)
    const id = telemetryId(m.dir) as string
    expect(id).toMatch(/^[0-9a-f]{32}$/)
    setTelemetry(m.dir, 'on', systemRng)
    expect(telemetryId(m.dir)).toBe(id)
    writeFileSync(join(m.dir, TELEMETRY_COUNTS_FILE), '{"v":1}\n')
    writeFileSync(join(m.dir, `${TELEMETRY_COUNTS_FILE}.0a1b.taken`), '')
    writeFileSync(join(m.dir, 'names.json'), '{}')
    setTelemetry(m.dir, 'off', systemRng)
    expect(telemetryId(m.dir)).toBeNull()
    expect(readdirSync(m.dir).sort()).toEqual(['names.json', TELEMETRY_FILE])
    setTelemetry(m.dir, 'on', systemRng)
    expect(telemetryId(m.dir)).not.toBe(id)
    const ids = new Set<string | null>()
    for (let i = 0; i < 64; i++) {
      const other = machine()
      setTelemetry(other.dir, 'on', systemRng)
      ids.add(telemetryId(other.dir))
    }
    expect(ids.size).toBe(64)
  })

  it('derives the id from the random source alone, never from HOME, the user or a path', () => {
    const rng = { bytes: (k: number) => new Uint8Array(k).fill(k === 16 ? 0x5c : 7) }
    const [a, b] = [machine(), machine()]
    setTelemetry(a.dir, 'on', rng)
    setTelemetry(b.dir, 'on', rng)
    expect(telemetryId(a.dir)).toBe('5c'.repeat(16))
    expect(telemetryId(b.dir)).toBe(telemetryId(a.dir))
  })

  it('shows the notice once per machine, making HOME/.bag 0700, naming the preview; none when chosen or off', () => {
    const m = machine()
    const preview = 'node /x/main.ts telemetry preview'
    expect(machineTelemetryNotice(m.env, preview)).toBe(noticeText(preview))
    expect(mode(m.dir)).toBe(0o700)
    expect(machineTelemetryNotice(m.env, preview)).toBeNull()
    expect(machineTelemetryNotice({ HOME: m.env.HOME as string, AC_HOME: fresh() })).toBeNull()
    const quiet = machine()
    expect(machineTelemetryNotice({ ...quiet.env, DO_NOT_TRACK: '1' })).toBeNull()
    expect(existsSync(quiet.dir)).toBe(false)
    expect(machineTelemetryNotice({})).toBeNull()
    const chosen = machine()
    setTelemetry(chosen.dir, 'off', systemRng)
    expect(machineTelemetryNotice(chosen.env)).toBeNull()
    const blocked = machine()
    writeFileSync(blocked.dir, '')
    expect(machineTelemetryNotice(blocked.env)).toBeNull()
  })
})

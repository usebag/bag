import { chmodSync, mkdirSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  ANCESTOR_LEVELS,
  ancestors,
  HOST_FACTS_FILE,
  HOST_FACTS_MAX,
  readHostFacts,
  STALE_SECONDS,
} from '../src/facts.ts'
import { T0, tempDir } from './support/ports.ts'

let tmp: ReturnType<typeof tempDir>
let dir: string
const at = (s: number): string => new Date(s * 1000).toISOString()
const put = (value: unknown, mode = 0o600): void => {
  const path = join(dir, HOST_FACTS_FILE)
  writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value), { mode })
  chmodSync(path, mode)
}
const omp = {
  v: 1,
  host: 'omp',
  updated_at: at(T0 - 30),
  host_version: '18.17.0',
  host_pid: 4242,
  session_id: 's-1',
  main_session: true,
  model: 'deepinfra/deepseek-ai/DeepSeek-V4.1-Flash-1017',
  cost_usd: 0.42,
  context_percent: 37.5,
  context_tokens: 61_000,
}

beforeEach(() => {
  tmp = tempDir('facts')
  dir = join(tmp.dir, 'state', 'alice')
  mkdirSync(dir, { recursive: true, mode: 0o700 })
})
afterEach(() => tmp.cleanup())

describe('readHostFacts', () => {
  it('reads every field of a fresh file with its time and age, and checks host_pid against the ancestors', () => {
    put({ ...omp, extra: 'ignored', fields_at: { model: at(T0 - 3600), cost_usd: 'not a time' } })
    const v = readHostFacts(dir, T0, [100, 4242])
    expect(v).toMatchObject({
      state: 'fresh',
      host: 'omp',
      age_s: 30,
      own_host: true,
      detail: 'written by omp 30 s ago',
      not_provided: [],
      invalid: [],
      values: { main_session: true, session_id: 's-1', host_version: '18.17.0' },
      figures: {
        model: { value: omp.model, updated_at: at(T0 - 3600), age_s: 3600 },
        cost_usd: { value: 0.42, updated_at: at(T0 - 30), age_s: 30 },
        context_percent: { value: 37.5, age_s: 30 },
        context_tokens: { value: 61_000, age_s: 30 },
      },
    })
    expect(v).not.toHaveProperty('values.extra')
  })

  it('names what the host did not provide (absent or null) and what it gave wrongly, and keeps the rest', () => {
    put({
      v: 1,
      host: 'claude-code',
      updated_at: at(T0),
      model: 'claude-opus-5-5',
      cost_usd: null,
      context_percent: 140,
    })
    const v = readHostFacts(dir, T0, [])
    expect(v).toMatchObject({
      state: 'fresh',
      own_host: null,
      not_provided: ['host_version', 'host_pid', 'session_id', 'main_session', 'cost_usd', 'context_tokens'],
      invalid: ['context_percent'],
      figures: {
        model: { value: 'claude-opus-5-5' },
        cost_usd: { value: null, note: 'not provided by claude-code' },
        context_percent: { value: null, note: `invalid in ${HOST_FACTS_FILE}, so not used` },
        context_tokens: { value: null, note: 'not provided by claude-code' },
      },
    })
  })

  it(`marks facts older than ${STALE_SECONDS} s stale, still with their values, and notes a host_pid not among the ancestors`, () => {
    put({ ...omp, updated_at: at(T0 - STALE_SECONDS - 1) })
    const v = readHostFacts(dir, T0, [7, 8])
    expect(v.state).toBe('stale')
    expect(v).toMatchObject({ own_host: false, figures: { cost_usd: { value: 0.42 } } })
    expect(v.detail).toContain(`last wrote these ${STALE_SECONDS + 1} s ago`)
    expect(v.detail).toContain('host_pid 4242 is not this server')
    put({ ...omp, updated_at: at(T0 - STALE_SECONDS) })
    expect(readHostFacts(dir, T0, []).state).toBe('fresh')
  })

  it('answers a missing file as missing, never an exception', () => {
    const v = readHostFacts(dir, T0, [])
    expect(v).toMatchObject({ state: 'missing', path: join(dir, HOST_FACTS_FILE) })
    expect(v.detail).toContain('the host provides none')
  })

  it.each([
    ['not JSON', '{nope', 'is not a JSON object'],
    ['an array', '[1]', 'not a JSON object'],
    ['null', 'null', 'not a JSON object'],
    ['a wrong version', JSON.stringify({ ...omp, v: 2 }), 'v is not 1'],
    ['no host', JSON.stringify({ ...omp, host: '' }), 'host is not a host name'],
    ['a local time', JSON.stringify({ ...omp, updated_at: '2026-11-11 12:00' }), 'updated_at is not'],
    [
      'an impossible time',
      JSON.stringify({ ...omp, updated_at: '2026-13-45T99:99:99Z' }),
      'updated_at is not',
    ],
  ])('answers %s as malformed with the reason', (_, text, why) => {
    put(text)
    const v = readHostFacts(dir, T0, [])
    expect(v.state).toBe('malformed')
    expect(v.detail).toContain(why)
  })

  it('refuses a group- or other-readable file, a symbolic link, a directory and an oversized file', () => {
    put(omp, 0o644)
    expect(readHostFacts(dir, T0, []).detail).toContain('its mode is 644, not 600')
    put('x'.repeat(HOST_FACTS_MAX + 1))
    expect(readHostFacts(dir, T0, []).detail).toContain(`over ${HOST_FACTS_MAX}`)
    const other = join(tmp.dir, 'elsewhere.json')
    writeFileSync(other, JSON.stringify(omp), { mode: 0o600 })
    const link = join(tmp.dir, 'state', 'linked')
    mkdirSync(link)
    symlinkSync(other, join(link, HOST_FACTS_FILE))
    expect(readHostFacts(link, T0, [])).toMatchObject({
      state: 'malformed',
      detail: expect.stringContaining('symbolic link'),
    })
    const odd = join(tmp.dir, 'state', 'odd')
    mkdirSync(join(odd, HOST_FACTS_FILE), { recursive: true, mode: 0o700 })
    expect(readHostFacts(odd, T0, [])).toMatchObject({
      state: 'malformed',
      detail: expect.stringContaining('not a regular file'),
    })
  })
})

describe('ancestors', () => {
  it(`walks parent pids up to ${ANCESTOR_LEVELS} levels, stopping at pid 1, a non-pid or a failure`, () => {
    const tree: Record<number, string> = { 50: ' 40\n', 40: '30', 30: '20', 20: '10', 10: '1' }
    expect(ancestors(50, (p) => tree[p] as string)).toEqual([50, 40, 30, 20])
    expect(ancestors(30, (p) => tree[p] as string)).toEqual([30, 20, 10].slice(0, ANCESTOR_LEVELS))
    expect(ancestors(10, (p) => tree[p] as string)).toEqual([10])
    expect(ancestors(9, () => '')).toEqual([9])
    expect(
      ancestors(9, () => {
        throw new Error('no ps')
      }),
    ).toEqual([9])
    expect(ancestors(1)).toEqual([])
  })

  it("reads this process's real parent with ps", () => {
    expect(ancestors()[0]).toBe(process.ppid)
  })
})

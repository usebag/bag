import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import {
  cachedHealth,
  HEALTH_CACHE_MS,
  HomeError,
  homeIdentities,
  homeRelays,
  relaysHealth,
} from '../src/index.ts'

// packages/home's reads: the identities a home lists, their relays, and those relays' health through a probe.

const root = mkdtempSync(join(tmpdir(), 'home-'))
afterAll(() => rmSync(root, { recursive: true, force: true }))
let n = 0
function home(identities?: unknown, raw?: string): string {
  const dir = join(root, `h${n++}`)
  mkdirSync(dir)
  if (raw !== undefined) writeFileSync(join(dir, 'identities.json'), raw)
  else if (identities !== undefined) writeFileSync(join(dir, 'identities.json'), JSON.stringify(identities))
  return dir
}

describe('homeIdentities', () => {
  it('no identities file is an empty home', () => {
    expect(homeIdentities(home())).toEqual([])
  })

  it('lists each label in order with its string relays', () => {
    const h = home({
      version: 1,
      identities: [
        { label: 'omp', key: 'omp', relays: ['https://relay1.bag.dev', 'https://relay2.bag.dev'] },
        { label: 'qrfolk', key: 'qrfolk', relays: ['https://relay1.bag.dev', 7] },
        { label: 'bare', key: 'bare' },
      ],
    })
    expect(homeIdentities(h)).toEqual([
      { label: 'omp', relays: ['https://relay1.bag.dev', 'https://relay2.bag.dev'] },
      { label: 'qrfolk', relays: ['https://relay1.bag.dev'] },
      { label: 'bare', relays: [] },
    ])
  })

  it("leaves out a label that does not pass, and the service's own key names", () => {
    const h = home({
      identities: [{ label: 'Bad Name' }, { label: 'jane.service' }, { label: 7 }, null, { label: 'ok-1' }],
    })
    expect(homeIdentities(h).map((i) => i.label)).toEqual(['ok-1'])
  })

  it('refuses a file that is not JSON, or has no identities list', () => {
    expect(() => homeIdentities(home(undefined, '{not json'))).toThrow(HomeError)
    expect(() => homeIdentities(home({ version: 1 }))).toThrow(
      'identities-invalid: identities.json has no identities list',
    )
    expect(() => homeIdentities(home(undefined, 'null'))).toThrow('no identities list')
  })

  it('passes on an error other than a missing file', () => {
    const dir = join(root, `h${n++}`)
    mkdirSync(join(dir, 'identities.json'), { recursive: true })
    expect(() => homeIdentities(dir)).toThrow(/EISDIR/)
  })
})

describe('homeRelays and relaysHealth', () => {
  it('names each relay once, in the order first named', () => {
    expect(
      homeRelays([
        { label: 'a', relays: ['https://r1', 'https://r2'] },
        { label: 'b', relays: ['https://r2', 'https://r3'] },
      ]),
    ).toEqual(['https://r1', 'https://r2', 'https://r3'])
  })

  it('a relay is ok only when its probe answers true in time', async () => {
    const probe = async (relay: string): Promise<boolean> => {
      if (relay === 'https://throws') throw new Error('refused')
      if (relay === 'https://slow') return new Promise((done) => setTimeout(() => done(true), 200))
      return relay === 'https://up'
    }
    const got = await relaysHealth(
      ['https://up', 'https://down', 'https://throws', 'https://slow'],
      probe,
      50,
    )
    expect(got).toEqual([
      { relay: 'https://up', ok: true },
      { relay: 'https://down', ok: false },
      { relay: 'https://throws', ok: false },
      { relay: 'https://slow', ok: false },
    ])
  })

  it('no relays, no probe', async () => {
    let calls = 0
    const probe = async (): Promise<boolean> => {
      calls++
      return true
    }
    expect(await relaysHealth([], probe)).toEqual([])
    expect(calls).toBe(0)
  })
})

describe('cachedHealth', () => {
  it('reuses an answer for the same relays within the window, and probes again after it or for another list', async () => {
    let t = 1_000
    let calls = 0
    const probe = async (): Promise<boolean> => {
      calls++
      return true
    }
    const health = cachedHealth(probe, HEALTH_CACHE_MS, () => t)
    expect(HEALTH_CACHE_MS).toBe(60_000)
    const want = [{ relay: 'https://r1', ok: true }]
    expect(await health(['https://r1'])).toEqual(want)
    t += HEALTH_CACHE_MS - 1
    expect(await health(['https://r1'])).toEqual(want)
    expect(calls).toBe(1)
    t += 1
    await health(['https://r1'])
    expect(calls).toBe(2)
    await health(['https://r1', 'https://r2'])
    expect(calls).toBe(4)
  })
})

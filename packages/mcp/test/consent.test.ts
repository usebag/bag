import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import {
  BRIDGE_FRESH_MS,
  bridgePresent,
  CONSENT_TTL_S,
  Consent,
  type ConsentKind,
  type ConsentPeer,
} from '../src/consent.ts'
import { tempDir } from './support/ports.ts'

// The consent bridge: presence from the extension's .bridge, a request file the server writes, and the answer the
// extension writes beside it. The fake answerer here is the test writing <id>.answer.json. consent-bridge.md 83h.

const tmp = tempDir('consent')
afterAll(() => tmp.cleanup())
let n = 0
const home = (): string => join(tmp.dir, `home-${n++}`)
const NAME = 'alice'
const PEER: ConsentPeer = {
  name: 'bob',
  address: 'ed25519:bc822c87c4b32634a01db889d291810aa2f4ba2c9a2353bab81b3c0c10dae106',
  root: 'ed25519:bc822c87c4b32634a01db889d291810aa2f4ba2c9a2353bab81b3c0c10dae106',
}
const T0 = 1_800_000_000
const alwaysAlive = (): boolean => true
const neverAlive = (): boolean => false
const dir = (h: string): string => join(h, 'state', NAME, 'consent')

function writeBridge(h: string, body: unknown): void {
  const d = dir(h)
  mkdirSync(d, { recursive: true })
  writeFileSync(join(d, '.bridge'), JSON.stringify(body))
}

/** The one request file the server wrote, parsed (there is exactly one per pairing). */
function request(h: string): Record<string, unknown> {
  const d = dir(h)
  const f = readdirSync(d).find((x) => /^[0-9a-f]{16}\.json$/.test(x)) as string
  return JSON.parse(readFileSync(join(d, f), 'utf8')) as Record<string, unknown>
}

/** The fake answerer: writes <id>.answer.json for the request `id`. */
function answer(h: string, id: string, body: Record<string, unknown>): void {
  writeFileSync(join(dir(h), `${id}.answer.json`), JSON.stringify(body))
}

const start = (h: string, kind: ConsentKind, code: string | null, now = T0): Consent =>
  new Consent(h, NAME, '0123456789abcdef', kind, PEER, code, 'https://relay.test', now)

describe('bridgePresent', () => {
  it('is true for a fresh .bridge with a live pid, false for stale, dead, malformed or absent', () => {
    const h = home()
    expect(bridgePresent(h, NAME, T0, alwaysAlive)).toBe(false) // absent
    const at = (ms: number): string => new Date(T0 * 1000 - ms).toISOString()
    writeBridge(h, { v: 1, pid: 4242, host: 'omp', mode: 'tui', at: at(1000) })
    expect(bridgePresent(h, NAME, T0, alwaysAlive)).toBe(true)
    expect(bridgePresent(h, NAME, T0, neverAlive)).toBe(false) // pid not alive
    writeBridge(h, { v: 1, pid: 4242, host: 'omp', mode: 'tui', at: at(BRIDGE_FRESH_MS + 1) })
    expect(bridgePresent(h, NAME, T0, alwaysAlive)).toBe(false) // stale
    for (const junk of ['not json', JSON.stringify({ v: 2, pid: 1, at: at(0) }), JSON.stringify({ v: 1 })]) {
      writeFileSync(join(dir(h), '.bridge'), junk)
      expect(bridgePresent(h, NAME, T0, alwaysAlive)).toBe(false)
    }
  })
})

describe('a consent request and its answer', () => {
  it('writes the request file 0600 with the seam shape, and polls pending until an answer', () => {
    const h = home()
    start(h, 'pair-accept', '123 456')
    const r = request(h)
    expect(r).toMatchObject({
      v: 1,
      id: '0123456789abcdef',
      kind: 'pair-accept',
      peer: PEER,
      code: '123 456',
      relay: 'https://relay.test',
    })
    expect(Date.parse(r.expires_at as string) - Date.parse(r.asked_at as string)).toBe(CONSENT_TTL_S * 1000)
    const f = join(dir(h), '0123456789abcdef.json')
    expect(statSync(f).mode & 0o777).toBe(0o600)
  })

  it('accepts (acceptor: code null in the answer), and removes both files', () => {
    const h = home()
    const c = start(h, 'pair-accept', '123456')
    expect(c.poll(T0)).toBe('pending')
    answer(h, '0123456789abcdef', {
      v: 1,
      id: '0123456789abcdef',
      accepted: true,
      code: null,
      answered_at: new Date(T0 * 1000).toISOString(),
    })
    expect(c.poll(T0 + 1)).toEqual({ accepted: true, code: null })
    expect(existsSync(join(dir(h), '0123456789abcdef.json'))).toBe(false)
    expect(existsSync(join(dir(h), '0123456789abcdef.answer.json'))).toBe(false)
  })

  it('pair-accept-code: peer null, and the answer carries the pasted code (trimmed, capped at 256)', () => {
    const h = home()
    const c = new Consent(
      h,
      NAME,
      '0123456789abcdef',
      'pair-accept-code',
      null,
      null,
      'https://relay.test',
      T0,
    )
    expect(request(h)).toMatchObject({ kind: 'pair-accept-code', peer: null, code: null })
    answer(h, '0123456789abcdef', {
      v: 1,
      id: '0123456789abcdef',
      accepted: true,
      code: '  ac-peer1:abcDEF  ',
      answered_at: new Date(T0 * 1000).toISOString(),
    })
    expect(c.poll(T0)).toEqual({ accepted: true, code: 'ac-peer1:abcDEF' })
    for (const paste of ['', '   ', 'x'.repeat(513)]) {
      const h2 = home()
      const c2 = new Consent(h2, NAME, '0123456789abcdef', 'pair-accept-code', null, null, 'r', T0)
      answer(h2, '0123456789abcdef', {
        v: 1,
        id: '0123456789abcdef',
        accepted: true,
        code: paste,
        answered_at: new Date(T0 * 1000).toISOString(),
      })
      expect(c2.poll(T0)).toEqual({ accepted: false, reason: 'answer-code' })
    }
  })

  it("carries the inviter's typed digits in answer.code (pair-accept, code null request)", () => {
    const h = home()
    const c = start(h, 'pair-accept', null)
    answer(h, '0123456789abcdef', {
      v: 1,
      id: '0123456789abcdef',
      accepted: true,
      code: '456 123',
      answered_at: new Date(T0 * 1000).toISOString(),
    })
    expect(c.poll(T0)).toEqual({ accepted: true, code: '456123' })
  })

  it('refuses when accepted is false, times out at expires_at, and both leave nothing behind', () => {
    const h1 = home()
    const c1 = start(h1, 'pair-invite-show', null)
    answer(h1, '0123456789abcdef', {
      v: 1,
      id: '0123456789abcdef',
      accepted: false,
      code: null,
      answered_at: new Date(T0 * 1000).toISOString(),
    })
    expect(c1.poll(T0)).toEqual({ accepted: false, reason: 'declined' })
    const h2 = home()
    const c2 = start(h2, 'pair-accept', '123456')
    expect(c2.poll(T0 + CONSENT_TTL_S - 1)).toBe('pending')
    expect(c2.poll(T0 + CONSENT_TTL_S)).toEqual({ accepted: false, reason: 'timeout' })
    expect(existsSync(join(dir(h2), '0123456789abcdef.json'))).toBe(false)
  })

  it('refuses a mismatched id, extra or missing fields, a bad version, and a malformed code', () => {
    const base = {
      v: 1,
      id: '0123456789abcdef',
      accepted: true,
      code: null,
      answered_at: new Date(T0 * 1000).toISOString(),
    }
    const cases: [string, Record<string, unknown>][] = [
      ['answer-id-mismatch', { ...base, id: 'ffffffffffffffff' }],
      ['answer-shape', { ...base, extra: 1 }],
      ['answer-shape', { v: 1, id: '0123456789abcdef', accepted: true }],
      ['answer-version', { ...base, v: 2 }],
      ['answer-accepted', { ...base, accepted: 'yes' }],
      ['answer-code', { ...base, code: '12345' }],
      ['timeout', { ...base, answered_at: new Date((T0 + CONSENT_TTL_S) * 1000).toISOString() }],
      ['answer-time', { ...base, answered_at: 'not a time' }],
    ]
    for (const [reason, body] of cases) {
      const h = home()
      const c = start(h, 'pair-accept', '123456')
      answer(h, '0123456789abcdef', body)
      expect(c.poll(T0)).toEqual({ accepted: false, reason })
    }
  })

  it('wait polls until an answer, and gives pending on an abort without removing the request', async () => {
    const h = home()
    const c = start(h, 'pair-accept', '123456')
    const ac = new AbortController()
    let t = T0
    const sleep = (): Promise<void> => {
      t += 1
      if (t === T0 + 3) ac.abort()
      return Promise.resolve()
    }
    expect(await c.wait(ac.signal, sleep, () => t)).toBe('pending')
    expect(existsSync(join(dir(h), '0123456789abcdef.json'))).toBe(true) // kept for a resume
    answer(h, '0123456789abcdef', {
      v: 1,
      id: '0123456789abcdef',
      accepted: true,
      code: null,
      answered_at: new Date(T0 * 1000).toISOString(),
    })
    expect(
      await c.wait(
        new AbortController().signal,
        () => Promise.resolve(),
        () => t,
      ),
    ).toEqual({
      accepted: true,
      code: null,
    })
  })
})

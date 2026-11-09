import { MAX_ROOTS } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { ACCEPT_LIST_PATH, acceptRoots, syncAcceptList } from '../src/accept-list.ts'
import type { Fetch } from '../src/instance.ts'
import type { Session } from '../src/session.ts'

// The agent's accept list, client side: a faked instance answers 200, 304, 404, a refusal and a failure; the list is
// the accept-from record's roots, the org root first and once, and an answer that is not a list to sign is refused whole.

const ORIGIN = 'https://bag.acme.example'
const ROOT = `ed25519:${'a'.repeat(64)}`
const PARTNER = `ed25519:${'b'.repeat(64)}`
const session = (more: Partial<Session> = {}): Session =>
  ({
    state: 'live',
    domain: 'acme.example',
    instance: ORIGIN,
    access_token: 'accept-list-test-bearer',
    org: { domain: 'acme.example', root: ROOT, relays: [] },
    ...more,
  }) as unknown as Session

/** A faked instance answering each call with the next response, or throwing the next error. */
function instance(...answers: (Response | Error)[]) {
  const calls: { url: string; init: RequestInit }[] = []
  const fetch: Fetch = async (url, init) => {
    calls.push({ url, init })
    const next = answers.shift()
    if (next === undefined || next instanceof Error) throw next ?? new Error('no answer left')
    return next
  }
  return { fetch, calls }
}

const list = (accept: unknown, etag?: string, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(etag === undefined ? { accept } : { accept, etag }), { status: 200, headers })

describe('syncAcceptList', () => {
  it("keeps the instance's list with the org root first and once, with its etag, asked with the bearer", async () => {
    const lines: string[] = []
    const f = instance(list([PARTNER, ROOT, 'domain:okok.example'], 'e1'))
    const s = await syncAcceptList(session(), f.fetch, (l) => lines.push(l))
    expect([s.accept_roots, s.accept_etag, lines]).toEqual([[ROOT, PARTNER, 'domain:okok.example'], 'e1', []])
    expect(f.calls[0]?.url).toBe(`${ORIGIN}${ACCEPT_LIST_PATH}`)
    const h = new Headers(f.calls[0]?.init.headers)
    expect([h.get('authorization'), h.get('if-none-match'), f.calls[0]?.init.redirect]).toEqual([
      'Bearer accept-list-test-bearer',
      null,
      'error',
    ])
    expect(acceptRoots(s)).toEqual([ROOT, PARTNER, 'domain:okok.example'])
  })

  it('asks with If-None-Match, keeps the list on a 304, and takes the etag from the header when the body has none', async () => {
    const held = session({ accept_roots: [ROOT, PARTNER], accept_etag: 'e1' })
    const f = instance(new Response(null, { status: 304 }), list([ROOT], undefined, { etag: '"e2"' }))
    expect(await syncAcceptList(held, f.fetch, () => {})).toBe(held)
    expect(new Headers(f.calls[0]?.init.headers).get('if-none-match')).toBe('e1')
    expect(await syncAcceptList(held, f.fetch, () => {})).toMatchObject({
      accept_roots: [ROOT],
      accept_etag: '"e2"',
    })
    const none = instance(list([ROOT]))
    expect(await syncAcceptList(session(), none.fetch, () => {})).toEqual({
      ...session(),
      accept_roots: [ROOT],
    })
  })

  it('drops the list on a 404 (an older instance), so the record is the org root alone', async () => {
    const held = session({ accept_roots: [ROOT, PARTNER], accept_etag: 'e1' })
    const s = await syncAcceptList(held, instance(new Response('{}', { status: 404 })).fetch, () => {})
    expect(s).toEqual(session())
    expect(acceptRoots(s)).toEqual([ROOT])
  })

  it('keeps the list when the call fails, the instance refuses, or the session is not live', async () => {
    const held = session({ accept_roots: [ROOT, PARTNER], accept_etag: 'e1' })
    for (const a of [new Error('ECONNREFUSED'), new Response('{}', { status: 401 }), new Response('x')]) {
      expect(await syncAcceptList(held, instance(a).fetch, () => {})).toBe(held)
    }
    const paused = session({ state: 'paused' })
    const f = instance()
    expect(await syncAcceptList(paused, f.fetch, () => {})).toBe(paused)
    expect(await syncAcceptList(session(), undefined, () => {})).toEqual(session())
    expect(f.calls).toHaveLength(0)
  })

  it('refuses whole, with a line, a list with "*", an entry that is not a root, too many roots, or no list', async () => {
    const held = session({ accept_roots: [ROOT, PARTNER] })
    const many = Array.from({ length: MAX_ROOTS }, (_, i) => `domain:p${i}.example`)
    const cases: [unknown, string][] = [
      [['*'], 'it names "*"'],
      [[ROOT, 'sam-claude@okok.example'], 'an entry is not a root'],
      [[ROOT, 7], 'an entry is not a root'],
      [many, `${MAX_ROOTS + 1} roots; the cap is ${MAX_ROOTS}`],
      ['domain:okok.example', 'accept is not a list'],
    ]
    for (const [accept, why] of cases) {
      const lines: string[] = []
      expect(await syncAcceptList(held, instance(list(accept, 'e9')).fetch, (l) => lines.push(l))).toBe(held)
      expect(lines).toEqual([
        `bag: the accept list of acme.example was refused (${why}); the accept-from record keeps its roots`,
      ])
    }
  })
})

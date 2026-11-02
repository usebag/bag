import { hkdfSync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { RelayGuard } from '../src/net.ts'
import {
  CODE_WORDS,
  claimRendezvous,
  codeSecret,
  formatCode,
  newWords,
  openRendezvous,
  parseCode,
  WORDS,
  wordlist,
} from '../src/pair-code.ts'
import type { RelayClient } from '../src/ports.ts'
import { P } from './support/fixtures.ts'

// The word code's codec, its words and S, against the
// vectors in spec/vectors/pair-code.json; the pairing over it is pairing.test.ts, the HTTP calls
// http-relay.test.ts.

interface Vectors {
  codec: { cases: { code?: string; input?: string; nameplate: string; words: string[] }[] }
  s_derivation: { cases: { nameplate: string; words: string[]; invitation: string; s_hex: string }[] }
}
const V = JSON.parse(
  readFileSync(new URL('../../../spec/vectors/pair-code.json', import.meta.url), 'utf8'),
) as Vectors

/** An Rng that hands out the given bytes in order. */
const bytes = (...b: number[]) => ({ bytes: (n: number) => Uint8Array.from(b.splice(0, n)) })

describe('the word code: the codec and S (spec/vectors/pair-code.json)', () => {
  it('writes and reads the codec cases', () => {
    expect(V.codec.cases.length).toBeGreaterThan(0)
    for (const c of V.codec.cases) {
      const want = { nameplate: c.nameplate, words: c.words }
      expect(parseCode(c.code ?? (c.input as string))).toEqual(want)
      if (c.code !== undefined) expect(formatCode(want)).toBe(c.code)
    }
  })

  it('reads a code in any case, with spaces, hyphens or full-width digits between and around its parts', () => {
    const c = { nameplate: '472', words: ['tulip', 'orbit', 'cedar'] }
    for (const text of [
      ' 472 TULIP  orbit\n-cedar ',
      '４７２-tulip-orbit-cedar',
      '-472--tulip-orbit--cedar-',
    ]) {
      expect(parseCode(text)).toEqual(c)
    }
    expect(parseCode('100000000-tulip-orbit-cedar')?.nameplate).toBe('100000000')
  })

  it('reads a private rendezvous after the code: @<host>[:<port>], claimed at https://<host>', () => {
    const c = { nameplate: '472', words: ['tulip', 'orbit', 'cedar'] }
    expect(parseCode('472-tulip-orbit-cedar@relay.example')).toEqual({ ...c, at: 'https://relay.example' })
    expect(parseCode(' 472 Tulip orbit cedar @ Relay.Example:8443 ')).toEqual({
      ...c,
      at: 'https://relay.example:8443',
    })
    for (const text of [
      '472-tulip-orbit-cedar@',
      '472-tulip-orbit-cedar@-relay.example',
      '472-tulip-orbit-cedar@relay.example@other.example',
      '472-tulip-orbit-cedar@https://relay.example',
      '472-tulip-orbit-cedar@relay.example:123456',
      '472-tulip-orbit@relay.example',
    ]) {
      expect(parseCode(text)).toBeNull()
    }
  })

  it('reads nothing else as a code', () => {
    for (const text of [
      '',
      'ac-peer1:abc',
      'tulip-orbit-cedar',
      '472-tulip-orbit',
      '472-tulip-orbit-cedar-tulip',
      '0472-tulip-orbit-cedar',
      '0-tulip-orbit-cedar',
      '1000000000-tulip-orbit-cedar',
      '47a-tulip-orbit-cedar',
      '472-tulip-orbit-ced4r',
      '472-tulip-orbit-cédar',
      '472_tulip_orbit_cedar',
    ]) {
      expect(parseCode(text)).toBeNull()
    }
  })

  it('derives S as the vectors do: HKDF-SHA256 over the words, salt `<nameplate>|<I>`, 16 bytes', () => {
    expect(V.s_derivation.cases.length).toBeGreaterThan(0)
    for (const c of V.s_derivation.cases) {
      expect(codeSecret({ nameplate: c.nameplate, words: c.words }, c.invitation)).toBe(c.s_hex)
    }
    const c = { nameplate: '472', words: ['tulip', 'orbit', 'cedar'] }
    const salt = Buffer.from(`472|${P.bob.address}`)
    const want = Buffer.from(hkdfSync('sha256', 'tulip orbit cedar', salt, 'ac/peer-code/1', 16)).toString(
      'hex',
    )
    expect(codeSecret(c, P.bob.address)).toBe(want)
    expect(codeSecret({ ...c, words: ['TULIP', 'Orbit', 'cedar'] }, P.bob.address)).toBe(want)
    for (const other of [
      codeSecret({ ...c, nameplate: '473' }, P.bob.address),
      codeSecret(c, P.carol.address),
      codeSecret({ ...c, words: ['orbit', 'tulip', 'cedar'] }, P.bob.address),
      codeSecret({ nameplate: '47', words: ['2tulip', 'orbit', 'cedar'] }, P.bob.address),
    ]) {
      expect(other).not.toBe(want)
    }
  })
})

describe('the word code: its words and the rendezvous calls', () => {
  const [w0, w1, w2] = WORDS as [string, string, string]

  it('draws on a list of exactly 1296 distinct words of a to z, frozen, and refuses any other list', () => {
    expect(WORDS.length).toBe(1296)
    expect(new Set(WORDS).size).toBe(WORDS.length)
    expect(WORDS.filter((w) => !/^[a-z]+$/.test(w))).toEqual([])
    expect(Object.isFrozen(WORDS)).toBe(true)
    expect(wordlist([...WORDS])).toEqual(WORDS)
    for (const bad of [
      WORDS.slice(1),
      [...WORDS, 'zzzzzz'],
      [...WORDS.slice(1), w1],
      [...WORDS.slice(1), 'yo-yo'],
      [...WORDS.slice(1), 'Tulip'],
      [...WORDS.slice(1), 7],
      { length: 1296 },
      null,
    ]) {
      expect(() => wordlist(bad)).toThrow('not 1296 distinct words of a to z')
    }
  })

  it(`draws ${CODE_WORDS} words uniformly: two bytes each, those past the last whole multiple of the list drawn again`, () => {
    const top = WORDS.length * Math.floor(65_536 / WORDS.length)
    expect(newWords(bytes(0, 0, 0, 1, 0, 2))).toEqual([w0, w1, w2])
    const draw = newWords(
      bytes(0xff, 0xff, (top - 1) >> 8, (top - 1) & 0xff, top >> 8, top & 0xff, 0, 2, 0, 3),
    )
    expect(draw).toEqual([WORDS[(top - 1) % WORDS.length], w2, WORDS[3]])
    const many = newWords({ bytes: (n) => crypto.getRandomValues(new Uint8Array(n)) })
    expect(many.length).toBe(CODE_WORDS)
    expect(many.every((w) => WORDS.includes(w))).toBe(true)
  })

  it('opens and claims through the client, and answers null when the client offers no pair call', async () => {
    const base = { inviter: P.bob.address, invitation: P.carol.address, relays: ['http://r1.test'] }
    const [open, reach] = [
      { ...base, ttl: 600, sig: 'ab'.repeat(64) },
      { ...base, exp: 1 },
    ]
    const calls: string[] = []
    const client = {
      pairOpen: async (url: string, o: unknown) => {
        calls.push(`open ${url} ${JSON.stringify(o)}`)
        return '472'
      },
      pairClaim: async (url: string, n: string) => {
        calls.push(`claim ${url} ${n}`)
        return reach
      },
    } as unknown as RelayClient
    expect(await openRendezvous(client, 'http://r1.test', open)).toBe('472')
    expect(await claimRendezvous(client, 'http://r1.test', '472')).toEqual(reach)
    expect(calls).toEqual([`open http://r1.test ${JSON.stringify(open)}`, 'claim http://r1.test 472'])
    const none = {} as RelayClient
    expect(await openRendezvous(none, 'http://r1.test', open)).toBeNull()
    expect(await claimRendezvous(none, 'http://r1.test', '472')).toBeNull()
    // The guard (spec/SPEC.md §9 item 11): a rendezvous on a loopback, link-local, private (v4 or v6) or unique-local
    // address, or a name that resolves to one, is resolve-failed before any request, unless it is one of the edge's
    // relays or private relays are allowed.
    calls.length = 0
    const guard = new RelayGuard({ own: ['https://meet.example'], lookup: async () => ['10.1.2.3'] })
    for (const url of [
      'https://127.0.0.1:8080',
      'https://169.254.169.254',
      'https://10.0.0.1',
      'https://172.16.0.1',
      'https://192.168.1.1',
      'https://[::1]',
      'https://[fe80::1]',
      'https://[fd00::1]',
      'https://localhost',
      'https://lan.example',
    ]) {
      await expect(openRendezvous(client, url, open, guard)).rejects.toMatchObject({ code: 'resolve-failed' })
      await expect(claimRendezvous(client, url, '472', guard)).rejects.toMatchObject({
        code: 'resolve-failed',
      })
    }
    expect(calls).toEqual([])
    expect(await openRendezvous(client, 'https://meet.example', open, guard)).toBe('472')
    const allowed = new RelayGuard({ own: [], allowPrivate: true })
    expect(await claimRendezvous(client, 'https://127.0.0.1:8080', '472', allowed)).toEqual(reach)
    expect(calls.map((c) => c.split(' ')[1])).toEqual(['https://meet.example', 'https://127.0.0.1:8080'])
  })
})

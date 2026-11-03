import { hkdfSync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { canonical, sha256, toHex, verifyPreimage } from '@usebag/core'
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
import { inviteText, macOf, pairingCode, readInvite } from '../src/pairing.ts'
import type { RelayClient } from '../src/ports.ts'
import { P } from './support/fixtures.ts'

// The word code's codec, its words and S, against the
// vectors in spec/vectors/pair-code.json; the pairing over it is pairing.test.ts, the HTTP calls
// http-relay.test.ts.

/** The fields every generated pairing case shares (spec/SPEC.md §8.10). */
interface Pairing {
  name: string
  inviter: string
  invitation: string
  requester: string
  sealing: string
  s_hex: string
  canonical: string
}
interface Vectors {
  codec: { cases: { code?: string; input?: string; nameplate: string; words: string[] }[] }
  s_derivation: { cases: { nameplate: string; words: string[]; invitation: string; s_hex: string }[] }
  check_digits: { cases: (Pairing & { sha256: string; first4_be: number; digits: string; shown: string })[] }
  request_mac: { cases: (Pairing & { exp: number; mac: string })[] }
  invite_string: { cases: (Omit<Pairing, 'requester' | 'sealing'> & { relay: string; invite: string })[] }
  pair_open: {
    cases: {
      name: string
      inviter: string
      invitation: string
      relays: string[]
      ttl: number
      canonical: string
      sha256: string
      sig: string
      body: string
    }[]
  }
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

describe('the check digits, the request mac, the invite string and pair/open (spec/vectors/pair-code.json)', () => {
  const RELAY = 'https://relay.acme.example'
  const text = (v: Parameters<typeof canonical>[0]) => Buffer.from(canonical(v)).toString()

  it('shows the check digits of every case: sha256 of the canonical preimage, 4 bytes big-endian mod 10^6', () => {
    expect(V.check_digits.cases.length).toBeGreaterThan(2)
    for (const c of V.check_digits.cases) {
      const pre = ['ac/peer-code/1', c.inviter, c.invitation, c.requester, c.sealing, c.s_hex]
      expect(text(pre), c.name).toBe(c.canonical)
      expect(toHex(sha256(canonical(pre))), c.name).toBe(c.sha256)
      const v = { inviter: c.inviter, i: c.invitation, relay: RELAY, secret: c.s_hex }
      expect(pairingCode(v, c.requester, c.sealing), c.name).toBe(c.shown)
      expect(c.shown.replace(' ', ''), c.name).toBe(c.digits)
      expect(String(c.first4_be % 1_000_000).padStart(6, '0'), c.name).toBe(c.digits)
    }
    expect(V.check_digits.cases.some((c) => c.digits.startsWith('0'))).toBe(true)
    const word = V.check_digits.cases[0] as Pairing
    expect(codeSecret({ nameplate: '472', words: ['tulip', 'orbit', 'cedar'] }, word.invitation)).toBe(
      word.s_hex,
    )
  })

  it('macs every request case as HMAC-SHA256 under the 16 bytes of S, in lowercase hex', () => {
    expect(V.request_mac.cases.length).toBeGreaterThan(0)
    for (const c of V.request_mac.cases) {
      const pre = ['ac/peer-request/1', c.inviter, c.invitation, c.requester, c.sealing, c.exp]
      expect(text(pre), c.name).toBe(c.canonical)
      const v = { inviter: c.inviter, i: c.invitation, relay: RELAY, secret: c.s_hex }
      expect(macOf(v, c.requester, c.sealing, c.exp), c.name).toBe(c.mac)
    }
  })

  it('writes and reads every invite string: ac-peer1: and base64url, no padding, of the canonical preimage', () => {
    expect(V.invite_string.cases.length).toBeGreaterThan(0)
    for (const c of V.invite_string.cases) {
      const v = { inviter: c.inviter, i: c.invitation, relay: c.relay, secret: c.s_hex }
      expect(text(['ac/peer-invite/1', c.inviter, c.invitation, c.relay, c.s_hex]), c.name).toBe(c.canonical)
      expect(inviteText(v), c.name).toBe(c.invite)
      expect(readInvite(c.invite), c.name).toEqual(v)
      expect(c.invite).not.toContain('=')
    }
  })

  it('signs every pair/open case with the invitation key over its canonical preimage', () => {
    expect(V.pair_open.cases.length).toBeGreaterThan(0)
    for (const c of V.pair_open.cases) {
      const pre = ['ac/pair-open/1', c.inviter, c.invitation, c.relays, c.ttl]
      expect(text(pre), c.name).toBe(c.canonical)
      expect(toHex(sha256(canonical(pre))), c.name).toBe(c.sha256)
      expect(verifyPreimage(c.invitation, pre, c.sig), c.name).toBe(true)
      expect(verifyPreimage(c.invitation, [...pre.slice(0, 4), c.ttl - 1], c.sig), c.name).toBe(false)
      const { inviter, invitation, relays, ttl, sig } = c
      expect(JSON.parse(c.body), c.name).toEqual({ inviter, invitation, relays, ttl, sig })
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

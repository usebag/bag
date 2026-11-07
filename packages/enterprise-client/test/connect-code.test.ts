import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { CONNECT_CODE, connectCodeOf, isLoopbackOrigin, parseConnectCode } from '../src/connect-code.ts'
import { EnterpriseError } from '../src/instance.ts'
import { bindNonce } from '../src/layer-auth.ts'

// src/connect-code.ts mirrors the instance's connect code parser, which this package cannot import, so the instance's
// verdicts are pinned in test/fixtures/connect-codes.json: the string minted for each payload, the verdict on each of
// the 19 strings, the parts, and the binding's nonce over the whole string (23 strings in all).

interface Minted {
  readonly instance: string
  readonly domain: string
  readonly code: string
  readonly bind_nonce: string
}
interface Case {
  readonly name: string
  readonly text: string
  readonly outcome: string
}
const F = JSON.parse(readFileSync(new URL('./fixtures/connect-codes.json', import.meta.url), 'utf8')) as {
  secret: string
  minted: Minted[]
  cases: Case[]
}
const SECRET = 'connect-test-secret-only-for-these-tests-00'
const PREFIX = 'usage: this is not a connect code from the console: '
const verdict = (text: string): string => {
  try {
    const c = parseConnectCode(text)
    return `${c.origin} ${c.domain}`
  } catch {
    return 'refused'
  }
}
/** The refusal's detail; the refusal is usage, exit 2. */
const reason = (text: string): string => {
  try {
    parseConnectCode(text)
  } catch (e) {
    expect(e).toBeInstanceOf(EnterpriseError)
    expect((e as EnterpriseError).exit).toBe(2)
    expect((e as Error).message.startsWith(PREFIX)).toBe(true)
    return (e as Error).message.slice(PREFIX.length)
  }
  throw new Error('parsed')
}

describe("the connect code, against the instance's pinned verdicts", () => {
  it('holds 23 strings: 4 minted codes and 19 cases, of the fixed test secret', () => {
    expect(F.secret).toBe(SECRET)
    expect([F.minted.length, F.cases.length]).toEqual([4, 19])
  })

  it('mints the same string, reads the same parts, and binds over the whole string', () => {
    for (const m of F.minted) {
      const code = connectCodeOf({ instance: m.instance, domain: m.domain }, SECRET)
      expect(code).toBe(m.code)
      expect(verdict(code)).toBe(`${m.instance} ${m.domain}`)
      expect(parseConnectCode(code)).toEqual({ origin: m.instance, domain: m.domain, code })
      expect(bindNonce(code)).toBe(m.bind_nonce)
      expect(createHash('sha256').update(`bag-ent/bind-nonce/1\n${code}`).digest('hex')).toBe(m.bind_nonce)
    }
  })

  it('refuses what the instance refuses, and takes only the minted code', () => {
    for (const c of F.cases) expect(verdict(c.text), c.name).toBe(c.outcome)
    const code = connectCodeOf({ instance: 'https://ent.example.test', domain: 'acme.example' }, SECRET)
    expect(F.cases.filter((c) => c.outcome !== 'refused').map((c) => c.text)).toEqual([code])
  })

  it("names each refusal's reason, never the code or its secret part", () => {
    const by = new Map(F.cases.map((c) => [c.name, c.text]))
    const said = (name: string) => reason(by.get(name) as string)
    expect(said('901 characters')).toBe('it is too long')
    expect(said('the empty string')).toBe(`it does not start with ${CONNECT_CODE.prefix}`)
    expect(said('a bare console code, no payload')).toBe('it names no instance (copy the whole code)')
    expect(said('the secret cut by one')).toBe('it is cut short or changed')
    expect(said('version 2')).toBe('it is not of version 1')
    expect(said('a domain that is not a host')).toBe('it names no domain')
    expect(said('http on a host that is not loopback')).toBe(
      'its instance: the instance is https, or http on a loopback host',
    )
    expect(said('an origin with a trailing slash')).toBe('its instance: not an exact origin')
    expect(said('the keys in another order')).toBe('it is not in its one spelling')
    for (const c of F.cases.filter((x) => x.outcome === 'refused' && x.text !== '')) {
      const message = reason(c.text)
      expect(message, c.name).not.toContain(SECRET)
      expect(message, c.name).not.toContain(c.text)
    }
  })

  it('refuses a payload that does not decode, names no instance, or names an instance that is not an origin', () => {
    const raw = (payload: string) => `bagcode_${Buffer.from(payload).toString('base64url')}.${SECRET}`
    expect(reason(raw('not json'))).toBe('it does not decode')
    expect(reason(raw('[1]'))).toBe('it does not decode')
    expect(reason(raw('{"v":1,"instance":5,"domain":"acme.example"}'))).toBe('it names no instance')
    expect(reason(raw('{"v":1,"instance":"no origin","domain":"acme.example"}'))).toBe(
      'its instance: not an origin',
    )
    expect(isLoopbackOrigin('http://127.0.0.1:8788')).toBe(true)
    expect(isLoopbackOrigin('https://ent.example.test')).toBe(false)
  })
})

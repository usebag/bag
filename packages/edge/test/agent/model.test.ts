import {
  AcError,
  canonical,
  type Hop,
  isAcError,
  MAX_ENVELOPE_BYTES,
  sha256hex,
  signHop,
  utf8,
  verifyPreimage,
} from '@usebag/core'
import { describe, expect, it } from 'vitest'
import {
  AGENT_CODES,
  AGENT_TAG,
  AgentError,
  argsHash,
  buildRequest,
  codeOf,
  MIN_CAVEATS,
  NONCE_BYTES,
  OPENS_PER_MINUTE,
  parseRequest,
  requestPreimage,
  SEQ_MAX,
  SIGNS_PER_MINUTE,
  THREADS_PER_SESSION,
  WINDOW_MAX,
} from '../../src/agent/index.ts'
import { P, T0 } from '../support/fixtures.ts'

// The agent's request (its fields, its preimage, its refusals), its codes and its caps, with no agent and no
// socket.

const NONCE = 'ab'.repeat(32)
const ID = 'cd'.repeat(32)
const THREAD = 'ef'.repeat(32)
const S = P.session.address

/** A request as JSON text with any members, for the malformed cases. */
function raw(o: Record<string, unknown>): string {
  return JSON.stringify({ seq: 0, session: S, op: 'register', args: [THREAD], sig: '00'.repeat(64), ...o })
}

function code(f: () => unknown): string {
  try {
    f()
  } catch (e) {
    return isAcError(e) ? e.code : String(e)
  }
  return 'no error'
}

describe('the caps and codes', () => {
  it('holds the Appendix B defaults and the two local codes', () => {
    expect(WINDOW_MAX).toBe(8 * 3600)
    expect([MIN_CAVEATS, OPENS_PER_MINUTE, SIGNS_PER_MINUTE]).toEqual([1, 600, 60])
    expect([THREADS_PER_SESSION, SEQ_MAX, NONCE_BYTES]).toEqual([4096, 1_000_000, 32])
    expect(AGENT_CODES).toEqual(['agent-locked', 'not-in-grant'])
    expect(AGENT_TAG).toBe('ac/agent/1')
  })

  it('reads the code of a refusal and rethrows anything else as a fault', () => {
    const e = new AgentError('not-in-grant', 'why')
    expect([e.code, e.name, e.message]).toEqual(['not-in-grant', 'AgentError', 'not-in-grant: why'])
    expect(codeOf(e)).toBe('not-in-grant')
    expect(codeOf(new AcError('bad-sig'))).toBe('bad-sig')
    const fault = new Error('disk')
    expect(() => codeOf(fault)).toThrow(fault)
  })
})

describe('the request preimage', () => {
  it('is the tag, the nonce, seq, session, op and the args hash', () => {
    const args = [S, ['type=a'], T0]
    expect(argsHash(args)).toBe(sha256hex(utf8(canonical(args))))
    const r = { seq: 3, session: S, op: 'sign' as const, argsHash: argsHash(args) }
    expect(requestPreimage(NONCE, r)).toEqual(['ac/agent/1', NONCE, 3, S, 'sign', argsHash(args)])
  })

  it('is what buildRequest signs with the session key', () => {
    const text = buildRequest(P.session.signing, NONCE, 7, 'register', [THREAD])
    const req = parseRequest(text)
    expect(req).toMatchObject({ op: 'register', seq: 7, session: S, thread: THREAD, chain: null })
    expect(verifyPreimage(S, requestPreimage(NONCE, req), req.sig)).toBe(true)
    expect(verifyPreimage(S, requestPreimage('00'.repeat(32), req), req.sig)).toBe(false)
  })
})

describe('parseRequest', () => {
  const hop: Hop = signHop(P.jane.signing, S, ['type=a'], T0 + 60)

  it('reads each op with its args, from text or bytes, and the chain when sent', () => {
    const B = P.bob.address
    const J = P.jane.address
    const sign = buildRequest(P.session.signing, NONCE, 0, 'sign', [B, ['x'], T0], { chain: [hop] })
    expect(parseRequest(sign)).toMatchObject({ op: 'sign', sub: B, caveats: ['x'], exp: T0, chain: [hop] })
    const open = buildRequest(P.session.signing, NONCE, 1, 'open', [J, ID], { envelope: '{}' })
    expect(parseRequest(utf8(open))).toMatchObject({ op: 'open', mailbox: J, id: ID, envelope: '{}' })
    const register = { op: 'register', thread: THREAD, argsHash: argsHash([THREAD]) }
    expect(parseRequest(raw({}))).toMatchObject(register)
  })

  it('refuses anything that is not a request object, bad-shape', () => {
    for (const text of ['not json', '[]', 'null', '7', '"x"']) {
      expect(code(() => parseRequest(text))).toBe('bad-shape')
    }
  })

  it('refuses an op outside the closed set, bad-shape and never a sign', () => {
    for (const op of ['grant', 'resign', 'record', 'rotate', 'handle', 'policy', 'gkey', '', 7]) {
      expect(code(() => parseRequest(raw({ op })))).toBe('bad-shape')
    }
  })

  it('refuses a missing member, an extra one, and an envelope on anything but open', () => {
    const { sig: _sig, ...noSig } = JSON.parse(raw({})) as Record<string, unknown>
    expect(code(() => parseRequest(JSON.stringify(noSig)))).toBe('bad-shape')
    expect(code(() => parseRequest(raw({ nonce: NONCE })))).toBe('bad-shape')
    expect(code(() => parseRequest(raw({ envelope: '{}' })))).toBe('bad-shape')
  })

  it('refuses a bad seq, session, sig or args, bad-shape', () => {
    for (const o of [
      { seq: -1 },
      { seq: 1.5 },
      { seq: '0' },
      { session: 'ed25519:00' },
      { sig: 'ab' },
      { args: 'x' },
    ]) {
      expect(code(() => parseRequest(raw(o)))).toBe('bad-shape')
    }
  })

  it('refuses malformed sign args, a sub that is not an address included, bad-shape', () => {
    for (const args of [
      [S, ['x']],
      [7, ['x'], T0],
      ['x', ['x'], T0],
      [`${S}${'0'.repeat(1 << 20)}`, ['x'], T0],
      [S, 'x', T0],
      [S, ['x', 7], T0],
      [S, ['x'], 1.5],
      [S, ['x'], -1],
    ]) {
      expect(code(() => parseRequest(raw({ op: 'sign', args })))).toBe('bad-shape')
    }
  })

  it('refuses an envelope over the cap envelope-too-large while parsing, before any signature', () => {
    const big = raw({ op: 'open', args: [P.jane.address, ID], envelope: ' '.repeat(MAX_ENVELOPE_BYTES + 1) })
    expect(code(() => parseRequest(big))).toBe('envelope-too-large')
    const fits = raw({ op: 'open', args: [P.jane.address, ID], envelope: ' '.repeat(MAX_ENVELOPE_BYTES) })
    expect(parseRequest(fits)).toMatchObject({ op: 'open' })
  })

  it('refuses malformed open and register args, bad-shape', () => {
    const J = P.jane.address
    const cases: Record<string, unknown>[] = [
      { op: 'open', args: [J], envelope: '{}' },
      { op: 'open', args: ['x', ID], envelope: '{}' },
      { op: 'open', args: [J, 'x'], envelope: '{}' },
      { op: 'open', args: [J, ID] },
      { op: 'open', args: [J, ID], envelope: 7 },
      { args: ['ab'] },
      { args: [THREAD, THREAD] },
    ]
    for (const o of cases) expect(code(() => parseRequest(raw(o)))).toBe('bad-shape')
  })

  it("gives a malformed chain the chain's own shape codes", () => {
    expect(code(() => parseRequest(raw({ chain: 'x' })))).toBe('bad-shape')
    expect(code(() => parseRequest(raw({ chain: [{ iss: 'x' }] })))).toBe('bad-hop')
    expect(code(() => parseRequest(raw({ chain: Array(9).fill(hop) })))).toBe('too-many-hops')
  })
})

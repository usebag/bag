import { describe, expect, it } from 'vitest'
import { canonical } from '../src/canonical.ts'
import { sha256hex } from '../src/hash.ts'
import {
  AUDIT_GENESIS,
  type AuditFields,
  auditHash,
  auditPreimage,
  FETCH_TAG,
  fetchAuthPreimage,
  SUBSCRIBE_TAG,
  signFetchAuth,
  signSubscribe,
  subscribePreimage,
  verifyFetchAuth,
  verifySubscribe,
} from '../src/proofs.ts'
import { P, T0 } from './support/fixtures.ts'

const id = 'ab'.repeat(32)
const nonce = 'cd'.repeat(32)
const relay = 'https://relay.acme.example'

describe('the fetch proof', () => {
  it('signs ["ac/fetch/1", signer, id, ts, audience]', () => {
    expect(fetchAuthPreimage(P.bob.address, id, T0, relay)).toEqual([FETCH_TAG, P.bob.address, id, T0, relay])
    const sig = signFetchAuth(P.bob.key, id, T0, relay)
    expect(verifyFetchAuth(P.bob.address, id, T0, relay, sig)).toBe(true)
    expect(verifyFetchAuth(P.carol.address, id, T0, relay, sig)).toBe(false)
    expect(verifyFetchAuth(P.bob.address, id, T0 + 1, relay, sig)).toBe(false)
    expect(verifyFetchAuth(P.bob.address, 'cd'.repeat(32), T0, relay, sig)).toBe(false)
  })

  it('binds the audience byte for byte: another relay, a trailing slash or an uppercase host does not verify', () => {
    const sig = signFetchAuth(P.bob.key, id, T0, relay)
    for (const other of [
      'https://relay.globex.example',
      `${relay}/`,
      'https://RELAY.acme.example',
      `${relay}:443`,
    ]) {
      expect(verifyFetchAuth(P.bob.address, id, T0, other, sig)).toBe(false)
    }
  })
})

describe('the subscribe response', () => {
  it('signs ["ac/sub/1", nonce, signer, mailbox, cursor or null]', () => {
    expect(subscribePreimage(nonce, P.session.address, P.jane.address, 7)).toEqual([
      SUBSCRIBE_TAG,
      nonce,
      P.session.address,
      P.jane.address,
      7,
    ])
    const sig = signSubscribe(P.session.key, nonce, P.jane.address, 7)
    expect(verifySubscribe(P.session.address, nonce, P.jane.address, 7, sig)).toBe(true)
    expect(verifySubscribe(P.session.address, nonce, P.jane.address, null, sig)).toBe(false)
    expect(verifySubscribe(P.session.address, nonce, P.bob.address, 7, sig)).toBe(false)
    const fromAck = signSubscribe(P.jane.key, nonce, P.jane.address, null)
    expect(verifySubscribe(P.jane.address, nonce, P.jane.address, null, fromAck)).toBe(true)
  })
})

describe('the audit line', () => {
  it('hashes [seq, prev, ts, event, decision, reason, id, from, root, detail] into a chain', () => {
    const first: AuditFields = {
      seq: 1,
      prev: AUDIT_GENESIS,
      ts: T0,
      event: 'verify',
      decision: 'accept',
      reason: 'ok',
      id,
      from: P.session.address,
      root: P.org.address,
      detail: '{"bytes":1808}',
    }
    expect(AUDIT_GENESIS).toBe('0'.repeat(64))
    expect(auditPreimage(first)).toEqual([
      1,
      AUDIT_GENESIS,
      T0,
      'verify',
      'accept',
      'ok',
      id,
      P.session.address,
      P.org.address,
      '{"bytes":1808}',
    ])
    expect(auditHash(first)).toBe(sha256hex(canonical(auditPreimage(first))))
    const second: AuditFields = {
      ...first,
      seq: 2,
      prev: auditHash(first),
      id: null,
      from: null,
      root: null,
      detail: null,
    }
    expect(auditHash(second)).not.toBe(auditHash({ ...second, prev: AUDIT_GENESIS }))
  })
})

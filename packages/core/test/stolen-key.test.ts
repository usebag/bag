import { describe, expect, it } from 'vitest'
import { toHex, utf8 } from '../src/hex.ts'
import { hpkeSeal } from '../src/hpke.ts'
import { SealingKey } from '../src/keys.ts'
import { openSealed, SEAL_INFO, type SealedContent, sealTo } from '../src/seal.ts'
import { newThread } from '../src/thread.ts'
import { expectAcError } from './support/assert.ts'
import { P, seed } from './support/fixtures.ts'
import { xorshiftRng } from './support/rng.ts'

// Forward secrecy (spec/SPEC.md §7.4): a content key is HPKE-sealed to the recipient's current epoch (key-record)
// sealing key. The recipient deletes each epoch's private key after its horizon, so past mail sealed to a deleted
// epoch key can no longer be opened: not by the recipient's long-term key and not by its next epoch's key. Only the
// deleted epoch key could have opened it. The deletion lifecycle is the edge's; this proves the crypto in core.

describe('forward secrecy: a content key sealed to an epoch sealing key', () => {
  const address = P.jane.address
  const epoch = new SealingKey(seed(0x31)) // the epoch key E, deleted after its horizon
  const current = new SealingKey(seed(0x32)) // the recipient's next epoch key, different from E
  const longTerm = new SealingKey(seed(0x33)) // a long-term X25519 key, also not E
  const contentKey = new Uint8Array(32).fill(0x55)
  const info = utf8(SEAL_INFO)
  const aad = utf8(address)
  const { enc, ct } = hpkeSeal(epoch.publicKey, info, aad, contentKey, seed(0x41))

  it('the epoch key E opens the wrap (the control)', () => {
    expect(toHex(epoch.open(enc, info, aad, ct))).toBe(toHex(contentKey))
  })

  it('once E is deleted, a different X25519 key cannot open it (open-failed)', () => {
    // The recipient's next epoch key and its long-term key are both present; neither is E.
    expectAcError(() => current.open(enc, info, aad, ct), 'open-failed')
    expectAcError(() => longTerm.open(enc, info, aad, ct), 'open-failed')
  })

  it('without E the content key never comes back: each wrong key fails, E alone succeeds', () => {
    for (const wrong of [current, longTerm]) {
      expectAcError(() => wrong.open(enc, info, aad, ct), 'open-failed')
    }
    expect(toHex(epoch.open(enc, info, aad, ct))).toBe(toHex(contentKey))
  })
})

describe('forward secrecy: openSealed on an envelope sealed to an epoch key', () => {
  const epoch = new SealingKey(seed(0x31))
  const other = new SealingKey(seed(0x32))
  const content: SealedContent = {
    type: 'coding.task.v1',
    thread: newThread(xorshiftRng(7)),
    body: { repo: 'acme/api' },
  }
  const from = P.bob.address
  const to = P.jane.address
  const sealed = sealTo([{ address: to, sealingKey: epoch.publicKey }], from, content, xorshiftRng(9))
  const envelope = { to: [to], from, sealed }

  it('the epoch key opens the envelope (the control)', () => {
    expect(openSealed(envelope, { address: to, key: epoch })).toEqual(content)
  })

  it('a different X25519 key at the same address fails open-failed', () => {
    expectAcError(() => openSealed(envelope, { address: to, key: other }), 'open-failed')
  })
})

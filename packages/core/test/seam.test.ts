import { describe, expect, it } from 'vitest'
import { assembleHop, hopPreimage, signHop } from '../src/chain.ts'
import {
  assembleEnvelope,
  buildEnvelope,
  type Envelope,
  envelopeId,
  envelopeIdPreimage,
  MAX_ENVELOPE_BYTES,
  splitEnvelope,
} from '../src/envelope.ts'
import { openGroupKey, sealGroupKey, signGroupRecord, signMembership } from '../src/groups.ts'
import { signHandleRecord, type UnsignedHandleRecord } from '../src/handles.ts'
import { type OpenerLike, SealingKey, type SignerLike, SigningKey, signPreimage } from '../src/keys.ts'
import { signPolicyRecord, type UnsignedMembersRecord, type UnsignedPolicyRecord } from '../src/policy.ts'
import { signFetchAuth, signSubscribe } from '../src/proofs.ts'
import {
  type AddressRecord,
  assembleRecord,
  assembleRotation,
  countersignRotation,
  recordPreimage,
  signRecord,
  type UnsignedAcceptFromRecord,
  type UnsignedAddressRecord,
  type UnsignedKeyRecord,
} from '../src/records.ts'
import { openSealed } from '../src/seal.ts'
import { newThread } from '../src/thread.ts'
import { expectAcError } from './support/assert.ts'
import { DAY, HOUR, opener, P, recipient, seed, T0 } from './support/fixtures.ts'
import { xorshiftRng } from './support/rng.ts'

// The core's functions take a structural signer and opener (a type-only
// change, shown here by byte-identical output from plain objects), and the assemblers are the sign paths' last steps.

const signer = (k: SigningKey): SignerLike => ({ address: k.address, sign: (m) => k.sign(m) })
const openerOf = (k: SealingKey): OpenerLike => ({ open: (enc, info, aad, ct) => k.open(enc, info, aad, ct) })

const org = P.org.key
const plain = signer(org)
const hop = signHop(org, P.jane.address, ['type=coding.*'], T0 + DAY)
const unsignedHop = { iss: hop.iss, sub: hop.sub, caveats: hop.caveats, exp: hop.exp }

const addressUnsigned: UnsignedAddressRecord = {
  kind: 'address',
  key: P.org.address,
  sealing_key: null,
  relays: ['https://relay.acme.example'],
  rotation_key: P.rotation.address,
  revoked: [],
  ttl: DAY,
  iat: T0,
  rotated_from: null,
}
const acceptUnsigned: UnsignedAcceptFromRecord = {
  kind: 'accept-from',
  owner: P.org.address,
  roots: ['*'],
  max_bytes: 65_536,
  ttl: DAY,
  iat: T0,
}
const keyUnsigned: UnsignedKeyRecord = {
  kind: 'key',
  key: P.org.address,
  sealing_key: '11'.repeat(32),
  iat: T0,
  exp: T0 + HOUR,
}
const rotationUnsigned: UnsignedAddressRecord = {
  ...addressUnsigned,
  key: P.orgNext.address,
  iat: T0 + DAY,
  rotated_from: P.org.address,
}
const rotationNext = signRecord(P.orgNext.key, rotationUnsigned)

function base() {
  return {
    from: P.session.key,
    to: [recipient(P.bob)],
    auth: [hop],
    type: 'coding.task.v1',
    thread: newThread(xorshiftRng(1)),
    body: { repo: 'acme/api' },
    ts: T0,
    rng: xorshiftRng(2),
  }
}

describe('a structural signer and opener (type only)', () => {
  it('is a plain object, not the class', () => {
    expect(plain).not.toBeInstanceOf(SigningKey)
    expect(openerOf(new SealingKey(seed(0x12)))).not.toBeInstanceOf(SealingKey)
  })

  it('gives the sign functions byte-identical output to the class', () => {
    expect(signHop(plain, P.jane.address, ['type=coding.*'], T0 + DAY)).toEqual(hop)
    expect(signMembership(plain, P.bob.address, T0 + DAY)).toEqual(
      signMembership(org, P.bob.address, T0 + DAY),
    )
    expect(signRecord(plain, addressUnsigned)).toEqual(signRecord(org, addressUnsigned))
    expect(signRecord(plain, acceptUnsigned)).toEqual(signRecord(org, acceptUnsigned))
    expect(signRecord(plain, keyUnsigned)).toEqual(signRecord(org, keyUnsigned))
    expect(countersignRotation(plain, rotationNext)).toEqual(countersignRotation(org, rotationNext))
    const relay = 'https://relay.acme.example'
    expect(signFetchAuth(plain, 'ab'.repeat(32), T0, relay)).toBe(
      signFetchAuth(org, 'ab'.repeat(32), T0, relay),
    )
    expect(signSubscribe(plain, 'cd'.repeat(32), P.bob.address, 7)).toBe(
      signSubscribe(org, 'cd'.repeat(32), P.bob.address, 7),
    )
    expect(signPreimage(plain, ['x', 1])).toBe(signPreimage(org, ['x', 1]))
    const handle: UnsignedHandleRecord = {
      kind: 'handle',
      org: P.org.address,
      handle: 'jane@acme.example',
      address: P.jane.address,
      iat: T0,
      ttl: DAY,
    }
    expect(signHandleRecord(plain, handle)).toEqual(signHandleRecord(org, handle))
    const policy: UnsignedPolicyRecord = {
      kind: 'policy',
      key: P.org.address,
      scopes: [{ match: '*', accept_types: ['chat.*'], max_bytes: 65_536 }],
      external: null,
      inspection: null,
      iat: T0,
    }
    expect(signPolicyRecord(plain, policy)).toEqual(signPolicyRecord(org, policy))
    const members: UnsignedMembersRecord = {
      kind: 'policy-members',
      key: P.org.address,
      roots: { mode: 'allow', list: [P.bob.address], unknown: 'quarantine' },
      rates: null,
      outbound: null,
      moderation: null,
      iat: T0,
    }
    expect(signPolicyRecord(plain, members)).toEqual(signPolicyRecord(org, members))
  })

  it('gives buildEnvelope and the group functions byte-identical output to the class', () => {
    const viaClass = buildEnvelope({ ...base(), from: P.session.key })
    const viaPlain = buildEnvelope({ ...base(), from: signer(P.session.key) })
    expect(viaPlain.bytes).toEqual(viaClass.bytes)
    expect(viaPlain.envelope).toEqual(viaClass.envelope)
    const rec = { relays: ['https://relay.acme.example'], iat: T0, sealingKey: new Uint8Array(32).fill(7) }
    expect(signGroupRecord({ group: plain, ...rec })).toEqual(signGroupRecord({ group: org, ...rec }))
    const generation = new SealingKey(seed(0x33))
    // The group's own copy: hop null, the holder the group itself.
    const holder = { address: P.org.address, sealingKey: (P.jane.sealing as SealingKey).publicKey }
    const input = { generation: 1, key: generation, holder, hop: null, iat: T0 }
    const sealed = sealGroupKey({ ...input, group: org, rng: xorshiftRng(7) })
    expect(sealGroupKey({ ...input, group: plain, rng: xorshiftRng(7) })).toEqual(sealed)
    const own = { address: P.org.address, key: openerOf(P.jane.sealing as SealingKey) }
    expect(openGroupKey(sealed, own, T0).key.publicKey).toEqual(generation.publicKey)
  })

  it('opens a sealed part through a plain opener to the same content', () => {
    const { envelope } = buildEnvelope({ ...base(), to: [recipient(P.bob)] })
    const viaClass = openSealed(envelope, opener(P.bob))
    const viaPlain = openSealed(envelope, {
      address: P.bob.address,
      key: openerOf(P.bob.sealing as SealingKey),
    })
    expect(viaPlain).toEqual(viaClass)
  })
})

describe('assembleHop', () => {
  it('is the last step of signHop: the unsigned form and the signature of its preimage', () => {
    const sig = signPreimage(org, hopPreimage(unsignedHop))
    expect(assembleHop(unsignedHop, sig)).toEqual(hop)
    expect(assembleHop(unsignedHop, sig).sig).toBe(hop.sig)
  })

  it('applies the shape codes: a signature that is not 64 bytes of hex is bad-hop', () => {
    expectAcError(() => assembleHop(unsignedHop, 'ab'), 'bad-hop')
    expectAcError(() => assembleHop({ ...unsignedHop, caveats: [''] }, hop.sig), 'bad-hop')
  })
})

describe('assembleRecord', () => {
  it('is the last step of signRecord for an address, an accept-from and a key record', () => {
    for (const unsigned of [addressUnsigned, acceptUnsigned, keyUnsigned]) {
      const sig = signPreimage(org, recordPreimage(unsigned))
      expect(assembleRecord(unsigned, sig)).toEqual(signRecord(org, unsigned))
    }
    expect(assembleRecord(addressUnsigned, 'ab'.repeat(64)).rotation_sig).toBeNull()
  })

  it('applies checkRecord: a bad signature or a bad form is bad-record', () => {
    expectAcError(() => assembleRecord(keyUnsigned, 'zz'), 'bad-record')
    expectAcError(() => assembleRecord({ ...acceptUnsigned, roots: [] }, 'ab'.repeat(64)), 'bad-record')
  })
})

describe('assembleRotation', () => {
  it('is the last step of countersignRotation, under the previous key or its rotation key', () => {
    for (const key of [org, P.rotation.key]) {
      const sig = signPreimage(key, recordPreimage(rotationNext))
      expect(assembleRotation(rotationNext, sig)).toEqual(countersignRotation(key, rotationNext))
    }
  })

  it('refuses a record that is not a rotation and a bad signature (both bad-record)', () => {
    const plainRecord = signRecord(org, addressUnsigned)
    expectAcError(() => assembleRotation(plainRecord, hop.sig), 'bad-record')
    const accept = signRecord(org, acceptUnsigned) as unknown as AddressRecord
    expectAcError(() => assembleRotation(accept, hop.sig), 'bad-record')
    expectAcError(() => assembleRotation(rotationNext, 'ab'), 'bad-record')
    expectAcError(() => assembleRotation(rotationNext, 7 as never), 'bad-record')
    expectAcError(() => assembleRotation(rotationNext, 'AB'.repeat(64)), 'bad-record')
  })

  it("checks the record before the signature, so a bad record keeps checkRecord's code", () => {
    const revoked = Array.from({ length: 1025 }, () => P.bob.address)
    const many = { ...rotationNext, revoked } as AddressRecord
    expectAcError(() => assembleRotation(many, 'ab'), 'too-many-revoked')
    expectAcError(() => assembleRotation(many, hop.sig), 'too-many-revoked')
  })

  it('refuses a null record or signature as bad-record, not a TypeError', () => {
    expectAcError(() => assembleRotation(null as never, hop.sig), 'bad-record')
    expectAcError(() => assembleRotation(rotationNext, null as never), 'bad-record')
  })
})

describe('assembleEnvelope and splitEnvelope', () => {
  const built = buildEnvelope(base())
  const split = splitEnvelope(built.envelope)

  it('split an envelope into its unsigned form, its id and the signed one', () => {
    expect(Object.keys(split.unsigned)).toEqual(['v', 'to', 'from', 'auth', 'suite', 'ts', 'sealed'])
    expect(split.id).toBe(built.envelope.id)
    expect(split.id).toBe(envelopeId(split.unsigned))
    expect(split.signed).toBe(built.envelope)
  })

  it('assemble the built envelope from the unsigned form and the signature of its id preimage', () => {
    const sig = signPreimage(P.session.key, envelopeIdPreimage(split.unsigned))
    const again = assembleEnvelope(split.unsigned, sig)
    expect(sig).toBe(built.envelope.sig)
    expect(again.envelope).toEqual(built.envelope)
    expect(again.bytes).toEqual(built.bytes)
    expect(assembleEnvelope(split.unsigned, split.signed.sig)).toEqual(again)
  })

  it('round-trip through the split: the id of the unsigned form is the id of the signed one', () => {
    const rebuilt: Envelope = assembleEnvelope(split.unsigned, split.signed.sig).envelope
    expect(splitEnvelope(rebuilt)).toEqual(split)
  })

  it('refuse a bad signature (bad-hex) and a result over the cap (envelope-too-large)', () => {
    expectAcError(() => assembleEnvelope(split.unsigned, 'ab'), 'bad-hex')
    const { sealed } = split.unsigned
    const huge = { ...split.unsigned, sealed: { ...sealed, ct: 'ab'.repeat(MAX_ENVELOPE_BYTES) } }
    expectAcError(() => assembleEnvelope(huge, split.signed.sig), 'envelope-too-large')
  })
})

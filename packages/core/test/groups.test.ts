import { describe, expect, it } from 'vitest'
import { canonical } from '../src/canonical.ts'
import { evaluateCaveats } from '../src/caveats.ts'
import { type Hop, signHop } from '../src/chain.ts'
import {
  checkGroupKeyBody,
  checkMembership,
  evaluateGroupCaveat,
  GROUP_CAVEAT_PREFIX,
  GROUP_KEY_TAG,
  GROUP_KEY_TYPE,
  GROUP_RECORD_TTL,
  type GroupKeyBody,
  groupCaveat,
  groupEvaluator,
  groupKeyPreimage,
  MEMBERSHIP_SECONDS,
  openGroupKey,
  sealGroupKey,
  signGroupRecord,
  signMembership,
} from '../src/groups.ts'
import { sha256hex } from '../src/hash.ts'
import { toHex, utf8 } from '../src/hex.ts'
import { hpkeSeal } from '../src/hpke.ts'
import { SealingKey, SigningKey, signPreimage, verifyPreimage } from '../src/keys.ts'
import { codingEvaluator } from '../src/profiles/coding.ts'
import { verifyRecord } from '../src/records.ts'
import { openSealed, sealTo } from '../src/seal.ts'
import { newThread } from '../src/thread.ts'
import { expectAcError } from './support/assert.ts'
import { DAY, P, seed, T0 } from './support/fixtures.ts'
import { xorshiftRng } from './support/rng.ts'

// The group's caveat, membership chains, the group-key statement and its wrap, and one
// sealed part opened by twenty holders of one generation. Every seed is test data by construction.

const group = new SigningKey(seed(0x31))
const memberKey = new SigningKey(seed(0x32))
const memberSeal = new SealingKey(seed(0x34))
const member = { address: memberKey.address, key: memberSeal }
const holder = { address: memberKey.address, sealingKey: memberSeal.publicKey }
const generation = new SealingKey(seed(0x33))
// A 7-day hop (the later default), so the pinned body and signatures stay those of 2026-10-26.
const hop = signMembership(group, member.address, T0 + 604_800)

const BODY_TEXT =
  '{"group":"ed25519:48075a597e721a156e2e0799de5cc0c5324dc6e7eaf1cdd46250868ec53215dd","generation":1,"sealing_key":"7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14","member":"ed25519:5e212c0980e4b39fc09721134aa02109374edfd260c0d3d03cb501c8d65457a9","iat":1800000000,"sig":"196ff7563df142199e0b92488a0b862aacd80ed808ed9fa748883a80091ec35ffb3186efae266f055267044e26345e5be6868456b630d0a04ea698e545e87004","enc":"e8a442cacc0be17d45394c379925f4fbb2fd2c1082e6ddcc532b0b32fe41f963","ct":"34864260b98ca975ea02eeed9f5fab0257a65e4aaacfe07017c5af07ca168d86e7b976ce387e36212c0a25ad1e7d3a3d","hop":{"iss":"ed25519:48075a597e721a156e2e0799de5cc0c5324dc6e7eaf1cdd46250868ec53215dd","sub":"ed25519:5e212c0980e4b39fc09721134aa02109374edfd260c0d3d03cb501c8d65457a9","caveats":["group=ed25519:48075a597e721a156e2e0799de5cc0c5324dc6e7eaf1cdd46250868ec53215dd"],"exp":1800604800,"sig":"9c54df27b5dac77a15cad4eb9a055835b510f24ac7c70c684ed275e956e1af0de4802541ff07546762c09672ece78e2efe2887cc406503f7b9c48eb80fdd8606"}}'

function body(iat = T0, rngSeed = 7): GroupKeyBody {
  return sealGroupKey({ group, generation: 1, key: generation, holder, hop, iat, rng: xorshiftRng(rngSeed) })
}

function resigned(b: GroupKeyBody, key: SigningKey = group): GroupKeyBody {
  return { ...b, sig: signPreimage(key, groupKeyPreimage(b)) }
}

describe('the groups profile', () => {
  it('names its constants', () => {
    expect([
      GROUP_KEY_TYPE,
      GROUP_KEY_TAG,
      GROUP_CAVEAT_PREFIX,
      MEMBERSHIP_SECONDS,
      GROUP_RECORD_TTL,
    ]).toEqual(['group-key.v1', 'ac/gkey/1', 'group=', 604_800, 3_600])
    expect(groupCaveat(group.address)).toBe(`group=${group.address}`)
  })

  it('holds group=<address> only when to is exactly the group, fails it otherwise, and knows nothing else', () => {
    const ctx = { from: member.address, to: [group.address], ts: T0, root: group.address }
    expect(evaluateGroupCaveat(groupCaveat(group.address), ctx)).toBe('hold')
    expect(evaluateGroupCaveat(groupCaveat(P.bob.address), ctx)).toBe('fail')
    // The group alone, never the group beside anyone else.
    const beside = { ...ctx, to: [group.address, P.bob.address] }
    expect(evaluateGroupCaveat(groupCaveat(group.address), beside)).toBe('fail')
    expect(
      evaluateGroupCaveat(groupCaveat(group.address), { ...ctx, to: [P.bob.address, group.address] }),
    ).toBe('fail')
    expect(evaluateCaveats([groupCaveat(group.address)], [codingEvaluator, groupEvaluator], beside)).toEqual({
      ok: false,
      code: 'caveat-failed',
      caveat: groupCaveat(group.address),
    })
    expect(evaluateGroupCaveat('group=team', ctx)).toBe('unknown')
    expect(evaluateGroupCaveat('type=chat.v1', ctx)).toBe('unknown')
    expect(evaluateCaveats([groupCaveat(group.address)], [codingEvaluator, groupEvaluator], ctx)).toEqual({
      ok: true,
    })
    expect(evaluateCaveats([groupCaveat(group.address)], [codingEvaluator], ctx)).toEqual({
      ok: false,
      code: 'unknown-caveat',
      caveat: groupCaveat(group.address),
    })
    expect(groupEvaluator.name).toBe('groups')
  })
})

describe('membership', () => {
  it('is a hop from the group key that carries the group caveat', () => {
    expect(hop).toMatchObject({
      iss: group.address,
      sub: member.address,
      caveats: [groupCaveat(group.address)],
    })
    const session = new SigningKey(seed(0x35))
    const chain: Hop[] = [hop, signHop(memberKey, session.address, [], T0 + DAY)]
    expect(checkMembership(chain, group.address, session.address, T0)).toEqual({
      root: group.address,
      principal: member.address,
      caveats: [groupCaveat(group.address)],
      member: member.address,
      exp: T0 + DAY,
    })
  })

  it('refuses a chain not rooted at the group, one without the caveat, and a chain that fails its own rules', () => {
    expectAcError(() => checkMembership([], group.address, group.address, T0), 'untrusted-root')
    const other = signHop(P.mallory.key, member.address, [groupCaveat(group.address)], T0 + DAY)
    expectAcError(() => checkMembership([other], group.address, member.address, T0), 'untrusted-root')
    const bare = signHop(group, member.address, [], T0 + DAY)
    expectAcError(() => checkMembership([bare], group.address, member.address, T0), 'caveat-failed')
    expectAcError(() => checkMembership([hop], group.address, member.address, hop.exp + 1), 'hop-expired')
  })
})

describe('the group-key statement', () => {
  it('pins its canonical text, digest and signature (the constants vectors pin when the draft is promoted)', () => {
    const statement = {
      group: group.address,
      generation: 1,
      sealing_key: toHex(generation.publicKey),
      member: member.address,
      iat: T0,
    }
    expect(group.address).toBe('ed25519:48075a597e721a156e2e0799de5cc0c5324dc6e7eaf1cdd46250868ec53215dd')
    expect(member.address).toBe('ed25519:5e212c0980e4b39fc09721134aa02109374edfd260c0d3d03cb501c8d65457a9')
    expect(statement.sealing_key).toBe('7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14')
    const text = canonical(groupKeyPreimage(statement))
    expect(text).toBe(
      `["ac/gkey/1","${group.address}",1,"${statement.sealing_key}","${member.address}",1800000000]`,
    )
    expect(sha256hex(text)).toBe('36e167a2f5cc2d5d67953d8eef16fc3509c66797e3e290f06ee963d5c625c2a1')
    expect(signPreimage(group, groupKeyPreimage(statement))).toBe(
      '196ff7563df142199e0b92488a0b862aacd80ed808ed9fa748883a80091ec35ffb3186efae266f055267044e26345e5be6868456b630d0a04ea698e545e87004',
    )
    expect(hop.sig).toBe(
      '9c54df27b5dac77a15cad4eb9a055835b510f24ac7c70c684ed275e956e1af0de4802541ff07546762c09672ece78e2efe2887cc406503f7b9c48eb80fdd8606',
    )
    expect(body()).toMatchObject({ ...statement, sig: signPreimage(group, groupKeyPreimage(statement)), hop })
    // The body as JSON text, with the wrap from xorshiftRng(7): the text the Rust core's tests read on 2026-10-26, before
    // its groups module left the Rust core.
    expect(JSON.stringify(body())).toBe(BODY_TEXT)
  })
})

describe('a group-key body', () => {
  it('has exactly nine members of their forms, the hop null only in the group own copy', () => {
    const b = body()
    expect(Object.keys(b)).toEqual([
      'group',
      'generation',
      'sealing_key',
      'member',
      'iat',
      'sig',
      'enc',
      'ct',
      'hop',
    ])
    expect(checkGroupKeyBody(JSON.parse(JSON.stringify(b)))).toEqual(b)
    const own = sealGroupKey({
      group,
      generation: 2,
      key: generation,
      holder: { address: group.address, sealingKey: memberSeal.publicKey },
      hop: null,
      iat: T0,
      rng: xorshiftRng(8),
    })
    expect([own.member, own.hop]).toEqual([group.address, null])
    const mine = openGroupKey(own, { address: group.address, key: memberSeal }, T0)
    expect(mine.key.publicKey).toEqual(generation.publicKey)
    const bad: unknown[] = [
      null,
      [],
      'body',
      { ...b, extra: 1 },
      Object.fromEntries(Object.entries(b).filter(([k]) => k !== 'hop')),
      { ...b, group: 'team' },
      { ...b, generation: 0 },
      { ...b, generation: 1.5 },
      { ...b, sealing_key: b.sealing_key.slice(2) },
      { ...b, member: 7 },
      { ...b, iat: -1 },
      { ...b, sig: b.sig.toUpperCase() },
      { ...b, enc: b.ct },
      { ...b, ct: b.enc },
      { ...b, hop: null },
      { ...b, hop: { ...hop, sig: 'x' } },
      { ...b, hop: [hop] },
    ]
    for (const v of bad) expectAcError(() => checkGroupKeyBody(v), 'bad-content')
  })
})

describe('sealGroupKey and openGroupKey', () => {
  it('wrap the generation to the holder, whose key opens it to the same key, and no plaintext key in the body', () => {
    const b = body()
    const opened = openGroupKey(b, member, T0)
    expect(opened.body).toEqual(b)
    expect(opened.key.publicKey).toEqual(generation.publicKey)
    expect(JSON.stringify(b).includes(toHex(generation.exportSeed()))).toBe(false)
    expect(verifyPreimage(group.address, groupKeyPreimage(b), b.sig)).toBe(true)
  })

  it('refuse in the order of the verification steps, each with its code', () => {
    const b = body()
    expectAcError(() => openGroupKey({ ...b, hop: 'x' }, member, T0), 'bad-content')
    expectAcError(() => openGroupKey(b, { address: P.bob.address, key: memberSeal }, T0), 'not-recipient')
    expectAcError(() => openGroupKey(resigned(b, P.mallory.key), member, T0), 'bad-record-sig')
    expectAcError(() => openGroupKey({ ...b, iat: T0 + 301 }, member, T0), 'bad-record-sig')
    expectAcError(() => openGroupKey(resigned({ ...b, iat: T0 + 301 }), member, T0), 'future-iat')
    expect(openGroupKey(body(T0 + 300), member, T0).body.iat).toBe(T0 + 300)
    const late = resigned({ ...b, iat: hop.exp + 1 })
    expectAcError(() => openGroupKey(late, member, hop.exp + 1), 'hop-expired')
    const forged = {
      ...hop,
      sig: signPreimage(P.mallory.key, ['ac/hop/1', hop.iss, hop.sub, hop.caveats, hop.exp]),
    }
    expectAcError(() => openGroupKey({ ...b, hop: forged }, member, T0), 'bad-hop-sig')
    const notTheGroup = signHop(P.mallory.key, member.address, [groupCaveat(group.address)], T0 + DAY)
    expectAcError(() => openGroupKey({ ...b, hop: notTheGroup }, member, T0), 'untrusted-root')
    const bare = signHop(group, member.address, [], T0 + DAY)
    expectAcError(() => openGroupKey({ ...b, hop: bare }, member, T0), 'caveat-failed')
    const tampered = `${b.ct.slice(0, -2)}${b.ct.endsWith('00') ? '01' : '00'}`
    expectAcError(() => openGroupKey({ ...b, ct: tampered }, member, T0), 'open-failed')
    expectAcError(
      () => openGroupKey(b, { address: member.address, key: new SealingKey(seed(0x36)) }, T0),
      'open-failed',
    )
  })

  it('refuse a validly signed statement whose wrapped key is not the key of its sealing_key, bad-key', () => {
    const other = new SealingKey(seed(0x37))
    const statement = {
      group: group.address,
      generation: 1,
      sealing_key: toHex(other.publicKey),
      member: member.address,
      iat: T0,
    }
    const preimage = groupKeyPreimage(statement)
    const aad = utf8(canonical(preimage))
    const wrap = hpkeSeal(memberSeal.publicKey, utf8(GROUP_KEY_TAG), aad, generation.exportSeed(), seed(0x38))
    const b = {
      ...statement,
      sig: signPreimage(group, preimage),
      enc: toHex(wrap.enc),
      ct: toHex(wrap.ct),
      hop,
    }
    expectAcError(() => openGroupKey(b, member, T0), 'bad-key')
  })

  it('let twenty holders of one generation open one sealed part with one wrap, above the cap of 16', () => {
    const content = { type: 'chat.v1', thread: newThread(xorshiftRng(9)), body: { text: 'to the group' } }
    const sealed = sealTo(
      [{ address: group.address, sealingKey: generation.publicKey }],
      P.jane.address,
      content,
      xorshiftRng(10),
    )
    expect(sealed.wraps.length).toBe(1)
    const opened = Array.from({ length: 20 }, (_, i) => {
      const key = new SigningKey(seed(0x40 + i))
      const seal = new SealingKey(seed(0x60 + i))
      const h = { address: key.address, sealingKey: seal.publicKey }
      const b = sealGroupKey({
        group,
        generation: 1,
        key: generation,
        holder: h,
        hop: signMembership(group, key.address, T0 + DAY),
        iat: T0,
        rng: xorshiftRng(100 + i),
      })
      const k = openGroupKey(b, { address: key.address, key: seal }, T0).key
      return openSealed(
        { to: [group.address], from: P.jane.address, sealed },
        { address: group.address, key: k },
      )
    })
    expect(new Set(opened.map((c) => JSON.stringify(c))).size).toBe(1)
    expect(opened[0]).toEqual(content)
  })
})

describe('the group record', () => {
  it('is the group key address record, naming the generation public key', () => {
    const r = signGroupRecord({
      group,
      sealingKey: generation.publicKey,
      relays: ['https://relay.example'],
      iat: T0,
    })
    expect(verifyRecord(r, T0)).toMatchObject({
      key: group.address,
      sealing_key: toHex(generation.publicKey),
      relays: ['https://relay.example'],
      rotation_key: null,
      revoked: [],
      ttl: GROUP_RECORD_TTL,
      rotated_from: null,
      rotation_sig: null,
    })
    const later = signGroupRecord({
      group,
      sealingKey: memberSeal.publicKey,
      relays: [],
      revoked: [P.carol.address],
      ttl: 600,
      iat: T0 + 1,
      rotationKey: P.rotation.address,
    })
    expect([later.revoked, later.ttl, later.rotation_key, later.iat]).toEqual([
      [P.carol.address],
      600,
      P.rotation.address,
      T0 + 1,
    ])
  })
})

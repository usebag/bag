import { chmodSync, mkdirSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  decodeAddress,
  GROUP_KEY_TYPE,
  type GroupKeyBody,
  isAcError,
  newThread,
  openSealed,
  SealingKey,
  sealGroupKey,
  sealTo,
  signMembership,
  toHex,
} from '@usebag/core'
import { afterEach, describe, expect, it } from 'vitest'
import { Audit } from '../src/audit.ts'
import { GroupKeyStore } from '../src/custody/groups.ts'
import {
  acceptGroupKey,
  GENERATIONS_TRIED,
  GroupOpener,
  groupOpener,
  memberKeys,
  membershipHop,
} from '../src/groups/member.ts'
import type { InboundMessage } from '../src/ports.ts'
import { DAY, FakeClock, MemoryAuditSink, party, seed, seededRng, T0, tempDir } from './support/fixtures.ts'
import { forms, occurrences } from './support/security.ts'

// A member's side, the opener of the current and the previous generation, and the
// acceptance of a group-key.v1 message with its audit line. Seeds are test data by construction.

const group = party('group', 0x31)
const bob = party('bob', 0x32)
const alice = party('alice', 0x33)
const gens = [0x41, 0x42, 0x43].map((b) => new SealingKey(seed(b)))
const seeded = seededRng('groups-member')
const rng = (length: number): Uint8Array => seeded.bytes(length)

function body(generation: number, iat = T0, to = bob): GroupKeyBody {
  return sealGroupKey({
    group: group.signing,
    generation,
    key: gens[generation - 1] as SealingKey,
    holder: { address: to.address, sealingKey: to.sealing.publicKey },
    hop: signMembership(group.signing, to.address, T0 + DAY + iat - T0),
    iat,
    rng,
  })
}

function sealedTo(key: SealingKey, text: string) {
  const content = { type: 'chat.v1', thread: newThread(rng), body: { text } }
  const to = [group.address]
  return {
    to,
    from: alice.address,
    sealed: sealTo([{ address: group.address, sealingKey: key.publicKey }], alice.address, content, rng),
  }
}

const dirs: { cleanup(): void }[] = []
afterEach(() => {
  for (const d of dirs.splice(0)) d.cleanup()
})

function store(): { readonly store: GroupKeyStore; readonly dir: string; readonly keysDir: string } {
  const t = tempDir('groups-member')
  dirs.push(t)
  const keysDir = join(t.dir, 'keys', 'groups')
  return { store: new GroupKeyStore(join(t.dir, 'groups'), keysDir), dir: join(t.dir, 'groups'), keysDir }
}

function code(fn: () => unknown): string {
  try {
    fn()
    return 'ok'
  } catch (e) {
    return isAcError(e) ? e.code : String((e as NodeJS.ErrnoException).code ?? e)
  }
}

function message(b: unknown, type = GROUP_KEY_TYPE): InboundMessage {
  return {
    id: 'ab'.repeat(32),
    from: group.address,
    principal: group.address,
    root: group.address,
    to: [bob.address],
    ts: T0,
    type,
    thread: newThread(rng),
    body: b,
    caveats: [],
    relay: 'http://home.test',
  }
}

describe('GroupOpener', () => {
  it('needs a generation, tries each key in order, and fails as the first key failed', () => {
    expect(code(() => new GroupOpener(() => []))).toBe('ENOENT')
    let keys: SealingKey[] = [gens[1] as SealingKey, gens[0] as SealingKey]
    const opener = new GroupOpener(() => keys)
    expect(opener.publicKey).toEqual(gens[1]?.publicKey)
    expect(opener).toBeInstanceOf(SealingKey)
    const me = { address: group.address, key: opener }
    expect(openSealed(sealedTo(gens[0] as SealingKey, 'one'), me).body).toEqual({ text: 'one' })
    expect(openSealed(sealedTo(gens[1] as SealingKey, 'two'), me).body).toEqual({ text: 'two' })
    expect(code(() => openSealed(sealedTo(gens[2] as SealingKey, 'three'), me))).toBe('open-failed')
    keys = []
    expect(code(() => openSealed(sealedTo(gens[0] as SealingKey, 'none'), me))).toBe('open-failed')
  })
})

describe("a member's keys", () => {
  it('open the current and the previous generation held, each body verified once, and not an older one', () => {
    const { store: s } = store()
    const clock = new FakeClock()
    expect(code(() => memberKeys(s, group.address, bob.keys, clock))).toBe('ENOENT')
    s.put(body(1))
    const keys = memberKeys(s, group.address, bob.keys, clock)
    expect(keys.signing).toBe(bob.signing)
    const me = { address: group.address, key: keys.sealing }
    expect(openSealed(sealedTo(gens[0] as SealingKey, 'g1'), me).body).toEqual({ text: 'g1' })
    s.put(body(2))
    expect(openSealed(sealedTo(gens[1] as SealingKey, 'g2'), me).body).toEqual({ text: 'g2' })
    expect(openSealed(sealedTo(gens[0] as SealingKey, 'g1 again'), me).body).toEqual({ text: 'g1 again' })
    s.put(body(3))
    expect(GENERATIONS_TRIED).toBe(2)
    expect(code(() => openSealed(sealedTo(gens[0] as SealingKey, 'too old'), me))).toBe('open-failed')
    const all = groupOpener(s, group.address, { address: bob.address, key: bob.sealing }, clock, 3)
    expect(
      openSealed(sealedTo(gens[0] as SealingKey, 'all'), { address: group.address, key: all }).body,
    ).toEqual({
      text: 'all',
    })
  })

  it("give the newest generation's hop, and none for the admin's own copy", () => {
    const { store: s } = store()
    expect(code(() => membershipHop(s, group.address))).toBe('ENOENT')
    s.put(body(1))
    expect(membershipHop(s, group.address)).toMatchObject({ iss: group.address, sub: bob.address })
    const own = sealGroupKey({
      group: group.signing,
      generation: 2,
      key: gens[1] as SealingKey,
      holder: { address: group.address, sealingKey: group.sealing.publicKey },
      hop: null,
      iat: T0,
      rng,
    })
    s.put(own)
    expect(code(() => membershipHop(s, group.address))).toBe('ENOENT')
  })
})

describe('acceptGroupKey', () => {
  it('keeps a verified generation and writes one rotate line of public data', () => {
    const { store: s } = store()
    const sink = new MemoryAuditSink()
    const clock = new FakeClock()
    const o = { keys: bob.keys, store: s, clock, audit: new Audit(sink, clock) }
    const b = body(1)
    expect(acceptGroupKey(message(b), o)).toEqual({ body: b, kept: 'new' })
    expect(acceptGroupKey(message(b), o).kept).toBe('held')
    expect(acceptGroupKey(message(body(1, T0 + 1)), o).kept).toBe('renewed')
    expect(sink.steps()).toEqual(['rotate accept ok', 'rotate accept ok', 'rotate accept ok'])
    const line = JSON.parse(sink.lines[0] as string) as {
      id: string
      from: string
      root: string
      detail: string
    }
    expect([line.id, line.from, line.root]).toEqual(['ab'.repeat(32), group.address, group.address])
    expect(JSON.parse(line.detail)).toEqual({
      subject: `group:${group.address}`,
      generation: 1,
      sealing_key: b.sealing_key,
      hop_exp: T0 + DAY,
      kept: 'new',
    })
    expect(
      occurrences(sink.lines.join('\n'), [...forms(gens[0]?.exportSeed() as Uint8Array), ...bob.secrets]),
    ).toBe(0)
    const own = sealGroupKey({
      group: group.signing,
      generation: 1,
      key: gens[0] as SealingKey,
      holder: { address: group.address, sealingKey: group.sealing.publicKey },
      hop: null,
      iat: T0,
      rng,
    })
    const mine = { keys: group.keys, store: store().store, clock, audit: new Audit(sink, clock) }
    expect(acceptGroupKey(message(own), mine).kept).toBe('new')
    const last = JSON.parse(sink.lines.at(-1) as string) as { detail: string }
    expect(JSON.parse(last.detail)).toMatchObject({ hop_exp: null, kept: 'new' })
  })

  it('refuses another type and an unverified body with a rotate reject line, and lets a local fault through', () => {
    const { store: s, dir } = store()
    const sink = new MemoryAuditSink()
    const clock = new FakeClock()
    const o = { keys: bob.keys, store: s, clock, audit: new Audit(sink, clock) }
    expect(code(() => acceptGroupKey(message(body(1), 'chat.v1'), o))).toBe('type-not-accepted')
    expect(code(() => acceptGroupKey(message(body(1, T0, alice)), o))).toBe('not-recipient')
    expect(code(() => acceptGroupKey(message({ group: group.address }), o))).toBe('bad-content')
    expect(code(() => acceptGroupKey(message(body(1, T0 + 1)), { ...o, skew: 0 }))).toBe('future-iat')
    expect(sink.steps()).toEqual([
      'rotate reject type-not-accepted',
      'rotate reject not-recipient',
      'rotate reject bad-content',
      'rotate reject future-iat',
    ])
    s.put(body(2))
    chmodSync(dir, 0o755)
    expect(code(() => acceptGroupKey(message(body(1)), o))).toMatch(/mode 0755/)
    expect(sink.lines.length).toBe(4)
    expect(s.generations(group.address)).toEqual([2])
  })
})

describe('forward secrecy: a kept generation key outlives the epoch sealing key', () => {
  it('opens a generation it accepted after the epoch sealing key is deleted; a body with no kept key cannot', () => {
    const { store: s, keysDir } = store()
    const sink = new MemoryAuditSink()
    const clock = new FakeClock()
    // bob accepts generation 1 while the delivering (epoch) sealing key is still live.
    acceptGroupKey(message(body(1)), { keys: bob.keys, store: s, clock, audit: new Audit(sink, clock) })

    // The epoch sealing key is rotated and deleted past its horizon: a stand-in that cannot open the body's wrap
    // stands for the deleted key. The kept generation key still opens mail sealed to that generation.
    const dead = new SealingKey(seed(0x99))
    const opener = memberKeys(s, group.address, { signing: bob.signing, sealing: dead }, clock).sealing
    expect(
      openSealed(sealedTo(gens[0] as SealingKey, 'after deletion'), { address: group.address, key: opener })
        .body,
    ).toEqual({ text: 'after deletion' })

    // The kept generation key is a 0600 file under the keys root, and no key material reached the audit log.
    const file = join(keysDir, toHex(decodeAddress(group.address)), 'g1.key')
    expect(statSync(file).mode & 0o777).toBe(0o600)
    expect(occurrences(sink.lines.join('\n'), forms(gens[0]?.exportSeed() as Uint8Array))).toBe(0)

    // Without a kept key (a body put with no accept), the deleted epoch key can no longer open the generation. The
    // opener's key() is eager (GroupOpener's constructor), so the open-failed is thrown when memberKeys builds it.
    const { store: s2 } = store()
    s2.put(body(1))
    expect(
      code(() => memberKeys(s2, group.address, { signing: bob.signing, sealing: dead }, clock).sealing),
    ).toBe('open-failed')
  })

  it('refuses a kept key file that is not a 32-byte seed', () => {
    const { store: s, keysDir } = store()
    const dir = join(keysDir, toHex(decodeAddress(group.address)))
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const file = join(dir, 'g1.key')
    writeFileSync(file, 'not-a-seed', { mode: 0o600 })
    chmodSync(file, 0o600)
    expect(code(() => s.heldKey(group.address, 1))).toBe('bad-content')
  })
})

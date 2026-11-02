import { chmodSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  type GroupKeyBody,
  isAcError,
  openGroupKey,
  SealingKey,
  sealGroupKey,
  signMembership,
} from '@usebag/core'
import { afterEach, describe, expect, it } from 'vitest'
import { GroupKeyStore, type GroupState } from '../src/custody/groups.ts'
import { DAY, party, seed, T0, tempDir } from './support/fixtures.ts'
import { forms, occurrences } from './support/security.ts'

// The group store on temporary directories. Seeds are test data by construction.

const group = party('group', 0x31)
const bob = party('bob', 0x32)
const gen1 = new SealingKey(seed(0x41))
const gen2 = new SealingKey(seed(0x42))
const holder = { address: bob.address, key: bob.sealing }
let n = 0

function body(generation = 1, key = gen1, iat = T0, exp = T0 + DAY): GroupKeyBody {
  return sealGroupKey({
    group: group.signing,
    generation,
    key,
    holder: { address: bob.address, sealingKey: bob.sealing.publicKey },
    hop: signMembership(group.signing, bob.address, exp),
    iat,
    rng: () => seed(0x50 + n++),
  })
}

const dirs: { cleanup(): void }[] = []
afterEach(() => {
  for (const d of dirs.splice(0)) d.cleanup()
})

function store(): { readonly store: GroupKeyStore; readonly dir: string; readonly groupDir: string } {
  const t = tempDir('groups')
  dirs.push(t)
  const dir = join(t.dir, 'groups')
  return { store: new GroupKeyStore(dir), dir, groupDir: join(dir, group.address.slice('ed25519:'.length)) }
}

const mode = (path: string): string => (statSync(path).mode & 0o777).toString(8)

function code(fn: () => unknown): string {
  try {
    fn()
    return 'ok'
  } catch (e) {
    return isAcError(e) ? e.code : String((e as NodeJS.ErrnoException).code ?? e)
  }
}

describe('GroupKeyStore', () => {
  it('keeps a generation once, 0600 in 0700, as its body, which holds no plaintext key', () => {
    const { store: s, dir, groupDir } = store()
    expect(s.generations(group.address)).toEqual([])
    const b = body()
    expect(s.put(b)).toBe('new')
    expect([mode(dir), mode(groupDir), mode(join(groupDir, 'g1.json'))]).toEqual(['700', '700', '600'])
    expect(s.body(group.address, 1)).toEqual(b)
    expect(s.generations(group.address)).toEqual([1])
    const text = readFileSync(join(groupDir, 'g1.json'), 'utf8')
    expect(text).toBe(JSON.stringify(b))
    expect(occurrences(text, forms(gen1.exportSeed()))).toBe(0)
    expect(openGroupKey(s.body(group.address, 1), holder, T0).key.publicKey).toEqual(gen1.publicKey)
  })

  it('replaces a renewal with a later iat, keeps an older one, and refuses another key at a held generation', () => {
    const { store: s, groupDir } = store()
    s.put(body())
    expect(s.put(body())).toBe('held')
    const renewal = body(1, gen1, T0 + 10, T0 + 2 * DAY)
    expect(s.put(renewal)).toBe('renewed')
    expect(s.body(group.address, 1).hop?.exp).toBe(T0 + 2 * DAY)
    expect(s.put(body(1, gen1, T0 + 5))).toBe('held')
    expect(code(() => s.put(body(1, gen2, T0 + 20)))).toBe('bad-key')
    expect(s.body(group.address, 1)).toEqual(renewal)
    expect(s.put(body(2, gen2))).toBe('new')
    expect(s.generations(group.address)).toEqual([2, 1])
    expect(readdirSync(groupDir).sort()).toEqual(['g1.json', 'g2.json'])
    const own = sealGroupKey({
      group: group.signing,
      generation: 3,
      key: gen2,
      holder: { address: group.address, sealingKey: group.sealing.publicKey },
      hop: null,
      iat: T0,
      rng: () => seed(0x60),
    })
    expect([s.put(own), s.put(own)]).toEqual(['new', 'held'])
  })

  it('refuses a file of another form, a file in another place, an open mode, and a missing generation', () => {
    const { store: s, groupDir } = store()
    s.put(body())
    expect(code(() => s.body(group.address, 2))).toBe('ENOENT')
    const file = join(groupDir, 'g1.json')
    const text = readFileSync(file, 'utf8')
    writeFileSync(join(groupDir, 'g3.json'), text, { mode: 0o600 })
    expect(code(() => s.body(group.address, 3))).toBe('bad-content')
    writeFileSync(join(groupDir, 'g4.json'), text.replace('{"group"', `{"generation":4,"group"`), {
      mode: 0o600,
    })
    expect(code(() => s.body(group.address, 4))).toBe('bad-content')
    writeFileSync(join(groupDir, 'g01.json'), text, { mode: 0o600 })
    expect(s.generations(group.address)).toEqual([4, 3, 1])
    chmodSync(file, 0o644)
    expect(code(() => s.body(group.address, 1))).toMatch(/mode 0644/)
    chmodSync(groupDir, 0o755)
    expect(code(() => s.generations(group.address))).toMatch(/mode 0755/)
    expect(code(() => s.put(body(2, gen2)))).toMatch(/mode 0755/)
    expect(code(() => new GroupKeyStore(groupDir).generations('team'))).toBe('bad-address')
  })

  it("keeps the admin's state, replacing it whole, and refuses a state of another group", () => {
    const { store: s, groupDir } = store()
    expect(s.state(group.address)).toBeNull()
    const state: GroupState = {
      group: group.address,
      generation: 1,
      iat: T0,
      relays: ['http://home.test'],
      ttl: 3600,
      rotationKey: party('group-rotation', 0x37).address,
      members: [{ address: bob.address, exp: T0 + DAY, relays: [] }],
      revoked: [],
    }
    s.saveState(state)
    expect(s.state(group.address)).toEqual(state)
    s.saveState({ ...state, generation: 2 })
    expect(s.state(group.address)?.generation).toBe(2)
    expect(mode(join(groupDir, 'state.json'))).toBe('600')
    expect(readdirSync(groupDir)).toEqual(['state.json'])
    writeFileSync(join(groupDir, 'state.json'), JSON.stringify({ ...state, group: bob.address }), {
      mode: 0o600,
    })
    expect(code(() => s.state(group.address))).toBe('bad-json')
  })
})

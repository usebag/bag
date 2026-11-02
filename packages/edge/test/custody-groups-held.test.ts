import { chmodSync, mkdirSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { type GroupKeyBody, SealingKey, sealGroupKey, signMembership } from '@usebag/core'
import { afterEach, describe, expect, it } from 'vitest'
import { GroupKeyStore } from '../src/custody/groups.ts'
import { DAY, type Party, party, seed, T0, tempDir } from './support/fixtures.ts'
import { forms, occurrences } from './support/security.ts'

// GroupKeyStore.groups(), the bodies `ac login` replays into P's agent. Seeds are test data.

const [one, two, bob] = [party('one', 0x31), party('two', 0x33), party('bob', 0x32)]
const keys = [0x41, 0x42, 0x43].map((b) => new SealingKey(seed(b)))
let n = 0

// A body with no hop is the group's own copy (the group-key form: hop null only when the member is the group),
// so it is held by the group itself; a body with a hop is held by bob.
function body(group: Party, generation: number, member = true): GroupKeyBody {
  const holder = member ? bob : group
  return sealGroupKey({
    group: group.signing,
    generation,
    key: keys[generation - 1] as SealingKey,
    holder: { address: holder.address, sealingKey: holder.sealing.publicKey },
    hop: member ? signMembership(group.signing, bob.address, T0 + DAY) : null,
    iat: T0,
    rng: () => seed(0x50 + n++),
  })
}

const dirs: { cleanup(): void }[] = []
afterEach(() => {
  for (const d of dirs.splice(0)) d.cleanup()
})

function home(): string {
  const t = tempDir('groups-held')
  dirs.push(t)
  return t.dir
}

describe('GroupKeyStore.groups', () => {
  it('lists none for a store that does not exist or holds nothing', () => {
    const dir = join(home(), 'groups', 'bob')
    expect(new GroupKeyStore(dir).groups()).toEqual([])
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    expect(new GroupKeyStore(dir).groups()).toEqual([])
  })

  it('lists exactly the stored bodies with a hop, by group, newest first, and no key', () => {
    const store = new GroupKeyStore(join(home(), 'groups', 'bob'))
    const kept = [body(one, 1), body(one, 2), body(two, 1)]
    for (const b of kept) store.put(b)
    store.put(body(party('admin', 0x34), 1, false))
    const byGroup = (g: Party) => kept.filter((b) => b.group === g.address).reverse()
    const [first, second] = one.address < two.address ? [one, two] : [two, one]
    const listed = store.groups()
    expect(listed).toEqual([...byGroup(first), ...byGroup(second)])
    const text = JSON.stringify(listed)
    for (const k of keys) expect(occurrences(text, forms(k.exportSeed()))).toBe(0)
    for (const secret of bob.secrets) expect(text).not.toContain(secret)
  })

  it('refuses a symlinked store, and a loose mode on the store, a group directory or a body, as strict() does', () => {
    const h = home()
    const dir = join(h, 'groups', 'bob')
    const store = new GroupKeyStore(dir)
    store.put(body(one, 1))
    symlinkSync(dir, join(h, 'link'))
    expect(() => new GroupKeyStore(join(h, 'link')).groups()).toThrow(/is not a directory/)
    const groupDir = join(dir, one.address.slice('ed25519:'.length))
    for (const [path, loose, tight] of [
      [dir, 0o755, 0o700],
      [groupDir, 0o750, 0o700],
      [join(groupDir, 'g1.json'), 0o644, 0o600],
    ] as const) {
      chmodSync(path, loose)
      expect(() => store.groups()).toThrow(/has mode 0[0-7]{3}; it must be/)
      chmodSync(path, tight)
    }
    expect(store.groups()).toHaveLength(1)
  })
})

import { randomBytes } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { buildEnvelope, newThread } from '@usebag/core'
import { type EdgeKeys, generateEdgeKeys, HomeCustody, systemRng } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  consumeRemoved,
  forgetRemoved,
  pairs,
  peersPath,
  readRemoved,
  recordRemoved,
  removedPath,
  removedRefused,
  writeWhole,
} from '../src/index.ts'
import { folder, homeWith } from './support.ts'

// run/removed.json, the record of a served identity remove: its writers, and the CLI's consume with no service.

const rng = (n: number): Uint8Array => new Uint8Array(randomBytes(n))

/** An envelope from `from` to `to`, held in the spool of key name `name`. */
function holdIn(home: string, name: string, from: EdgeKeys, to: EdgeKeys): string {
  const { envelope, bytes } = buildEnvelope({
    from: from.signing,
    to: [{ address: to.signing.address, sealingKey: to.sealing.publicKey }],
    type: 'chat.v1',
    thread: newThread(rng),
    body: { text: 'held' },
    ts: 1,
    rng,
  })
  const dir = join(home, 'state', name, 'local-spool', 'held')
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, `${envelope.id}.env`), bytes)
  return envelope.id
}

const heldFile = (home: string, name: string, id: string): string =>
  join(home, 'state', name, 'local-spool', 'held', `${id}.env`)

/** The audit lines of `name`, each [event, decision, id, detail]. */
const audit = (home: string, name: string): unknown[][] => {
  const file = join(home, 'state', name, 'audit.jsonl')
  if (!existsSync(file)) return []
  return readFileSync(file, 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l) as Record<string, unknown>)
    .map((l) => [l.event, l.decision, l.id, JSON.parse(String(l.detail))])
}

/** A home where jane was removed by a served remove: her key moved out, kim's mail to her held, the row left. */
function served() {
  const { home, keys } = homeWith('jane', 'kim')
  const [jane, kim] = [keys.jane, keys.kim] as [EdgeKeys, EdgeKeys]
  const id = holdIn(home, 'kim', kim, jane)
  const row = {
    a: 'kim',
    b: 'jane',
    a_addr: kim.signing.address,
    b_addr: jane.signing.address,
    added_at: 1,
    state: 'requested',
    held: [id],
  }
  writeWhole(home, peersPath(home), { version: 1, pairs: [row] })
  recordRemoved(home, { label: 'jane', key: 'jane', address: jane.signing.address, at: 1 })
  const away = join(folder(), 'keys')
  mkdirSync(away)
  renameSync(join(home, 'keys', 'jane.json'), join(away, 'jane.json'))
  return { home, jane, kim, id, row, away }
}

describe('run/removed.json', () => {
  it('is 0600 in a 0700 run/, one entry per label and address, and goes when its last entry goes', () => {
    const home = folder()
    recordRemoved(home, { label: 'jane', key: 'jane', address: 'ed25519:aa', at: 1 })
    recordRemoved(home, { label: 'jane', key: 'jane', address: 'ed25519:aa', at: 2 })
    recordRemoved(home, { label: 'jane', key: 'jane2', address: 'ed25519:bb', at: 3 })
    expect(statSync(removedPath(home)).mode & 0o777).toBe(0o600)
    expect(statSync(join(home, 'run')).mode & 0o777).toBe(0o700)
    expect(readRemoved(home).map((e) => [e.address, e.at])).toEqual([
      ['ed25519:aa', 2],
      ['ed25519:bb', 3],
    ])
    forgetRemoved(home, (e) => e.address === 'ed25519:aa')
    expect(readRemoved(home).map((e) => e.key)).toEqual(['jane2'])
    forgetRemoved(home, () => true)
    expect(existsSync(removedPath(home))).toBe(false)
    expect(existsSync(join(home, 'run', 'removed.lock'))).toBe(false)
    writeFileSync(removedPath(home), '{not json')
    expect(readRemoved(home)).toEqual([])
  })
})

describe('consumeRemoved, the CLI with no bag service', () => {
  it("fails the held mail sent to the removed address in its sender's audit, deletes it, and drops the pair", () => {
    const w = served()
    expect(consumeRemoved(w.home, () => 5)).toEqual([`failed held mail ${w.id} to kim`])
    expect(audit(w.home, 'kim')).toEqual([
      [
        'publish',
        'reject',
        w.id,
        { relay: 'local:', delivery: 'failed-local', reason: 'identity removed', to: 'jane' },
      ],
    ])
    expect(existsSync(heldFile(w.home, 'kim', w.id))).toBe(false)
    expect(pairs(w.home)).toEqual([])
    expect(readRemoved(w.home)).toEqual([])
    // Consumed once: a second run has nothing to do.
    expect(consumeRemoved(w.home, () => 6)).toEqual([])
  })

  it('drops an entry unfailed when its address is again an identity of the home: the same key restored', () => {
    const w = served()
    renameSync(join(w.away, 'jane.json'), join(w.home, 'keys', 'jane.json'))
    expect(consumeRemoved(w.home, () => 5)).toEqual([])
    expect(readRemoved(w.home)).toEqual([])
    expect(existsSync(heldFile(w.home, 'kim', w.id))).toBe(true)
    expect(pairs(w.home)).toEqual([w.row])
    expect(audit(w.home, 'kim')).toEqual([])
  })

  it('re-added with a new key: the old held mail fails, the new pair and its held mail stay', () => {
    const w = served()
    const again = generateEdgeKeys(systemRng)
    new HomeCustody(w.home).create('jane', again, { custody: 'file' })
    const fresh = holdIn(w.home, 'jane', w.kim, again)
    const row = { ...w.row, b_addr: again.signing.address, added_at: 2, held: [fresh] }
    writeWhole(w.home, peersPath(w.home), { version: 1, pairs: [w.row, row] })
    expect(consumeRemoved(w.home, () => 5)).toEqual([`failed held mail ${w.id} to kim`])
    expect(existsSync(heldFile(w.home, 'kim', w.id))).toBe(false)
    expect(existsSync(heldFile(w.home, 'jane', fresh))).toBe(true)
    expect(pairs(w.home)).toEqual([row])
    expect(audit(w.home, 'kim').map((l) => l[2])).toEqual([w.id])
  })
})

describe('a record that is not what its writers make is refused: nothing failed, the held mail kept', () => {
  const cases: [string, string, (home: string) => void][] = [
    [
      'a symlinked removed.json',
      'run/removed.json is not a 0600 regular file of this user',
      (home) => {
        const real = join(folder(), 'removed.json')
        renameSync(removedPath(home), real)
        symlinkSync(real, removedPath(home))
      },
    ],
    [
      'a 0644 removed.json',
      'run/removed.json is not a 0600 regular file of this user',
      (home) => chmodSync(removedPath(home), 0o644),
    ],
    [
      'a directory in its place',
      'run/removed.json is not a 0600 regular file of this user',
      (home) => {
        rmSync(removedPath(home))
        mkdirSync(removedPath(home))
      },
    ],
    [
      'run/ as a symlink',
      'run/ is not a 0700 directory of this user',
      (home) => {
        const real = join(folder(), 'run')
        renameSync(join(home, 'run'), real)
        symlinkSync(real, join(home, 'run'))
      },
    ],
  ]
  for (const [what, why, spoil] of cases)
    it(`${what}: the line says why, and nothing is failed or written`, () => {
      const w = served()
      spoil(w.home)
      expect(removedRefused(w.home)).toBe(why)
      expect(readRemoved(w.home)).toEqual([])
      const lines = consumeRemoved(w.home, () => 5)
      expect(lines).toHaveLength(1)
      expect(lines[0]).toContain(`${why}: the record of removed identities is not read`)
      expect(existsSync(heldFile(w.home, 'kim', w.id))).toBe(true)
      expect(audit(w.home, 'kim')).toEqual([])
      expect(pairs(w.home)).toEqual([w.row])
      // Never written over: a writer refuses, unsafe-path.
      expect(() => recordRemoved(w.home, { label: 'amy', key: 'amy', address: 'ed25519:cc', at: 9 })).toThrow(
        'unsafe-path',
      )
    })
})

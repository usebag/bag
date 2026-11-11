import { mkdirSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type AcceptFromRecord, signRecord } from '@usebag/core'
import { afterAll, describe, expect, it } from 'vitest'
import { acceptCopy, heldAccept, keepAcceptCopy } from '../src/custody/key-records.ts'
import { P, T0, tempDir } from './support/fixtures.ts'

// The copy of an identity's accept-from record in its home, and what it holds when a relay strands it: the roots go on,
// so a re-sign or a pairing rollback never rebuilds them from nothing (the 2026-11-11 collapse to [owner], decision 83c).

const tmp = tempDir('accept-copy')
afterAll(() => tmp.cleanup())
let n = 0
const home = (): string => join(tmp.dir, `home-${n++}`)
const [bob, name] = [P.bob.address, 'bob']
const accept = (roots: readonly string[], iat = T0): AcceptFromRecord =>
  signRecord(P.bob.signing, { kind: 'accept-from', owner: bob, roots, max_bytes: 65_536, ttl: 604_800, iat })

describe('the copy of an accept-from record in a home', () => {
  it('reads back what it kept, whole: no temporary file left, the copy 0600, newer stays', () => {
    const dir = home()
    expect(acceptCopy(dir, name, bob)).toBeNull()
    keepAcceptCopy(dir, name, accept([P.carol.address]))
    keepAcceptCopy(dir, name, accept([P.carol.address, P.jane.address], T0 + 1))
    expect(acceptCopy(dir, name, bob)).toMatchObject({
      iat: T0 + 1,
      roots: [P.carol.address, P.jane.address],
    })
    expect(readdirSync(join(dir, 'records'))).toEqual(['bob.accept.json'])
    expect(statSync(join(dir, 'records', 'bob.accept.json')).mode & 0o777).toBe(0o600)
    // An older copy never replaces a newer one.
    keepAcceptCopy(dir, name, accept([P.carol.address], T0))
    expect(acceptCopy(dir, name, bob)?.iat).toBe(T0 + 1)
  })

  it("keeps nothing that does not check: junk, or another owner's record under this name", () => {
    const dir = home()
    mkdirSync(join(dir, 'records'), { recursive: true })
    writeFileSync(join(dir, 'records', 'bob.accept.json'), 'not a record')
    expect(acceptCopy(dir, name, bob)).toBeNull()
    keepAcceptCopy(dir, name, acceptFromJane())
    expect(acceptCopy(dir, name, bob)).toBeNull()
  })
})

describe('heldAccept: what an identity holds when a relay strands its accept-from', () => {
  it('is the relay record, the copy when a relay holds an older one or none, null for neither', () => {
    const dir = home()
    expect(heldAccept(null, dir, name, bob)).toBeNull()
    keepAcceptCopy(dir, name, accept([P.carol.address], T0 + 2))
    // A rotation stranded the relay copy (none held there): the home copy carries the roots.
    expect(heldAccept(null, dir, name, bob)?.roots).toEqual([P.carol.address])
    // A relay replaying an older record rolls nothing back: the newer copy wins.
    expect(heldAccept(accept([P.jane.address], T0 + 1), dir, name, bob)?.roots).toEqual([P.carol.address])
    // A relay holding a newer record wins (a person's republish since).
    const newer = accept([P.jane.address], T0 + 9)
    expect(heldAccept(newer, dir, name, bob)).toBe(newer)
  })
})

function acceptFromJane(): AcceptFromRecord {
  return signRecord(P.jane.signing, {
    kind: 'accept-from',
    owner: P.jane.address,
    roots: ['*'],
    max_bytes: 65_536,
    ttl: 604_800,
    iat: T0,
  })
}

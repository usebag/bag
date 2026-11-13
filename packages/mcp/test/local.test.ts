import { mkdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { KeyEpochStore, keepAddressCopy } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { relayUrl } from '../src/config.ts'
import {
  LOCAL_DELIVERY_DEFAULT,
  type LocalPair,
  localDelivery,
  localPairs,
  localPeersOf,
  localPeersPath,
  localRootsOf,
  localSealingKey,
  localWord,
  localWordPath,
  type Own,
  pairsFromText,
  spool,
  spoolDir,
  spooled,
  stateOf,
  unspool,
  writeLocalWord,
  writePairs,
} from '../src/local.ts'
import { addressRecord, P, tempDir } from './support/fixtures.ts'

// The bag service's local files (spec/SPEC.md 9.2): the home word, the local trust table (M1: never trust.json), the
// spool (M6) and the recipient's sealing key from the home's own files.

/** An allowed pair of x and y, once (the service's own writes are its; this writes the file as it would). */
function addLocalPair(h: string, x: Own, y: Own, at: number): void {
  const rows = localPairs(h).filter(
    (p) => !((p.a === x.label || p.b === x.label) && (p.a === y.label || p.b === y.label)),
  )
  const row = { a: x.label, b: y.label, a_addr: x.address, b_addr: y.address, added_at: at }
  writePairs(h, [...rows, { ...row, state: 'allowed' }])
}

let tmp: ReturnType<typeof tempDir>
let home: string
beforeEach(() => {
  tmp = tempDir('local-')
  home = tmp.dir
})
afterEach(() => tmp.cleanup())

const personal = { label: 'personal', address: P.alice.address }
const research = { label: 'research', address: P.carol.address }
const side = { label: 'side', address: P.jane.address }

function word(text: string, mode = 0o600): void {
  mkdirSync(join(home, 'run'), { recursive: true })
  rmSync(localWordPath(home), { force: true })
  writeFileSync(localWordPath(home), text, { mode })
}

describe('the home word', () => {
  it('is LOCAL_DELIVERY_DEFAULT (on) with no file; a file is on only for local_delivery "on" in version 1 or 2', () => {
    expect(LOCAL_DELIVERY_DEFAULT).toBe(true)
    expect(localWord(home)).toEqual({ on: true, set: false, hidden: [], why: null })
    for (const [text, on] of [
      ['{"version":1,"local_delivery":"on"}', true],
      ['{"version":1,"local_delivery":"off"}', false],
      ['{"version":2,"local_delivery":"on"}', true],
      ['{"version":3,"local_delivery":"on"}', false],
      ['{"version":1,"local_delivery":true}', false],
      ['not json', false],
    ] as const) {
      word(text)
      expect([text, localDelivery(home)]).toEqual([text, on])
    }
  })
})

describe('the word file (C1) and hidden (decision 103)', () => {
  it('reads only a 0600 regular file: another mode or a symlink is off, with why', () => {
    word('{"version":2,"local_delivery":"on"}', 0o644)
    expect(localWord(home)).toMatchObject({ on: false, set: true, why: expect.stringContaining('0600') })
    rmSync(localWordPath(home))
    writeFileSync(join(home, 'elsewhere.json'), '{"version":2,"local_delivery":"on"}', { mode: 0o600 })
    symlinkSync(join(home, 'elsewhere.json'), localWordPath(home))
    expect(localWord(home)).toMatchObject({ on: false, why: expect.stringContaining('regular file') })
  })

  it('version 2 lists the hidden labels; writeLocalWord writes them whole, 0600', () => {
    writeLocalWord(home, true, ['side', 'research', 'side'])
    expect(JSON.parse(readFileSync(localWordPath(home), 'utf8'))).toEqual({
      version: 2,
      local_delivery: 'on',
      hidden: ['research', 'side'],
    })
    expect(statSync(localWordPath(home)).mode & 0o777).toBe(0o600)
    expect(localWord(home)).toEqual({ on: true, set: true, hidden: ['research', 'side'], why: null })
  })

  it('a hidden identity trusts no local root and is trusted by none (symmetric)', () => {
    writeLocalWord(home, true, [])
    addLocalPair(home, personal, research, 5)
    expect(localRootsOf(home, research)).toEqual([P.alice.address])
    writeLocalWord(home, true, ['personal'])
    expect([localRootsOf(home, research), localRootsOf(home, personal)]).toEqual([[], []])
  })
})

describe('the local trust table (M1)', () => {
  it('is written whole, 0600, under run/, never trust.json; pairs by label and current address', () => {
    addLocalPair(home, personal, research, 5)
    addLocalPair(home, personal, research, 6)
    expect(statSync(localPeersPath(home)).mode & 0o777).toBe(0o600)
    expect(localPairs(home)).toEqual([
      {
        a: 'personal',
        b: 'research',
        a_addr: P.alice.address,
        b_addr: P.carol.address,
        added_at: 6,
        state: 'allowed',
      },
    ])
    expect(localPeersOf(home, research)).toEqual(['personal'])
    // A label whose key changed is not the identity that was paired.
    expect(localPeersOf(home, { label: 'research', address: P.bob.address })).toEqual([])
    addLocalPair(home, side, research, 7)
    // Each sees only its own pairs.
    expect(localPeersOf(home, personal)).toEqual(['research'])
    expect(localPeersOf(home, research).sort()).toEqual(['personal', 'side'])
    expect(localPeersOf(home, side)).toEqual(['research'])
    expect(() => readFileSync(join(home, 'trust.json'))).toThrow()
    expect(() => readFileSync(join(home, 'names.json'))).toThrow()
  })

  it('gives a receiver its local roots only with the word on', () => {
    addLocalPair(home, personal, research, 5)
    word('{"version":1,"local_delivery":"off"}')
    expect(localRootsOf(home, research)).toEqual([])
    word('{"version":1,"local_delivery":"on"}')
    expect(localRootsOf(home, research)).toEqual([P.alice.address])
    expect(localRootsOf(home, side)).toEqual([])
  })

  it('one state reader for both directions: a row with no state, or an unknown one, is none (item k)', () => {
    writeLocalWord(home, true, [])
    const row = {
      a: 'personal',
      b: 'research',
      a_addr: P.alice.address,
      b_addr: P.carol.address,
      added_at: 5,
    }
    for (const [state, read] of [
      [undefined, 'none'],
      ['allowed', 'allowed'],
      ['requested', 'requested'],
      ['granted', 'none'],
    ] as const) {
      const p = (state === undefined ? row : { ...row, state }) as LocalPair
      writePairs(home, [p])
      expect(stateOf(localPairs(home)[0], 0)).toBe(read)
      // The receiver trusts exactly the rows the reader calls allowed.
      expect(localRootsOf(home, research)).toEqual(read === 'allowed' ? [P.alice.address] : [])
    }
    expect(stateOf({ ...row, state: 'declined', until: 10 }, 9)).toBe('declined')
    expect(stateOf({ ...row, state: 'declined', until: 10 }, 10)).toBe('none')
    expect(stateOf(undefined)).toBe('none')
  })

  it('pairsFromText parses the very text it is given: one read for the rows and the compared text (t1)', () => {
    const row = {
      a: 'personal',
      b: 'research',
      a_addr: P.alice.address,
      b_addr: P.carol.address,
      added_at: 5,
    }
    const text = JSON.stringify({ version: 1, pairs: [row, null, { a: 1 }] })
    expect(pairsFromText(text)).toEqual([row])
    for (const bad of ['', 'nope', '{"version":2,"pairs":[]}', '{"version":1}'])
      expect(pairsFromText(bad)).toEqual([])
    // localPairs is the same parse of the file's text.
    writePairs(home, [row])
    expect(localPairs(home)).toEqual(pairsFromText(readFileSync(localPeersPath(home), 'utf8')))
  })

  it('a file that does not read holds no pair', () => {
    mkdirSync(join(home, 'run'), { recursive: true })
    for (const text of ['nope', '{"version":2,"pairs":[]}', '{"version":1,"pairs":[{"a":1}]}']) {
      writeFileSync(localPeersPath(home), text)
      expect(localPairs(home)).toEqual([])
    }
  })
})

describe('the spool (M6)', () => {
  it('keeps each envelope 0600 by its id; unspool removes it, or keeps a failed one as .failed and lists it no more', () => {
    const [a, b] = ['a'.repeat(64), 'b'.repeat(64)]
    spool(home, 'carol', b, new Uint8Array([2]))
    spool(home, 'carol', a, new Uint8Array([1]))
    const files = spooled(home, 'carol')
    expect(files.map((f) => [f.file, [...f.bytes]])).toEqual([
      [join(spoolDir(home, 'carol'), `${a}.env`), [1]],
      [join(spoolDir(home, 'carol'), `${b}.env`), [2]],
    ])
    expect(statSync(files[0]?.file as string).mode & 0o777).toBe(0o600)
    unspool(files[0]?.file as string, false)
    unspool(files[1]?.file as string, true)
    expect(spooled(home, 'carol')).toEqual([])
    expect(statSync(`${files[1]?.file}.failed`).isFile()).toBe(true)
  })
})

describe('the sealing key of a local recipient', () => {
  it('comes from the home: the newest held epoch key, else the verified address copy of that address, else none', () => {
    expect(localSealingKey(home, 'carol', P.carol.address)).toBeNull()
    keepAddressCopy(home, 'carol', addressRecord(P.carol))
    expect(localSealingKey(home, 'carol', P.carol.address)).toEqual(P.carol.keys.sealing.publicKey)
    // A copy of another address is not this identity's.
    expect(localSealingKey(home, 'carol', P.bob.address)).toBeNull()
    const epochs = new KeyEpochStore(join(home, 'key-records'))
    epochs.put(P.carol.address, 1, P.bob.keys.sealing, 1, 2)
    expect(localSealingKey(home, 'carol', P.carol.address)).toEqual(P.bob.keys.sealing.publicKey)
  })
})

describe('LOCAL_RELAY (M2)', () => {
  it('is no relay URL: --relay local: is refused, so no configured relay can equal it', () => {
    expect(() => relayUrl('local:')).toThrow('is not an http or https URL')
  })
})

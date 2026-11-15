import { randomBytes } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { buildEnvelope, newThread } from '@usebag/core'
import { acquireLock, type EdgeKeys, storeLockPath } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  dropLocalPairs,
  failHeldToSender,
  type HeldMail,
  heldMailOf,
  identitiesOf,
  LOCAL_DELIVERY_DEFAULT,
  labelsByName,
  localDeliveryOn,
  needPairsTable,
  pairedLocally,
  pairs,
  pairsRefused,
  peersPath,
  readWord,
  saveIdentities,
  senderBusy,
  setLocalDelivery,
  spooledCount,
  visibleLine,
  wordPath,
  writeWhole,
} from '../src/index.ts'
import { fakeIo, folder, homeWith } from './support.ts'

// Local delivery's files: the home word, the bag service's table of local pairs, and the mail a pair holds.

const row = (a: string, b: string, more: Record<string, unknown> = {}) => ({
  a,
  b,
  a_addr: `addr-${a}`,
  b_addr: `addr-${b}`,
  added_at: 1,
  ...more,
})
const table = (home: string, rows: unknown[], mode = 0o600): void => {
  writeWhole(home, peersPath(home), { version: 1, pairs: rows })
  if (mode !== 0o600) chmodSync(peersPath(home), mode)
}

describe('the home word', () => {
  it('is the default with no file, off with why for a refused or unreadable one, and as written otherwise', () => {
    const home = folder()
    expect(readWord(home)).toEqual({ on: LOCAL_DELIVERY_DEFAULT, hidden: [], why: null })
    expect(localDeliveryOn(home)).toBe(LOCAL_DELIVERY_DEFAULT)
    writeWhole(home, wordPath(home), { version: 2, local_delivery: 'on', hidden: ['kim', 7] })
    expect(statSync(wordPath(home)).mode & 0o777).toBe(0o600)
    expect(statSync(join(home, 'run')).mode & 0o777).toBe(0o700)
    expect(readWord(home)).toEqual({ on: true, hidden: ['kim'], why: null })
    writeWhole(home, wordPath(home), { version: 1, local_delivery: 'off', hidden: ['kim'] })
    expect(readWord(home)).toEqual({ on: false, hidden: [], why: null })
    writeWhole(home, wordPath(home), { version: 3 })
    expect(readWord(home)).toEqual({ on: false, hidden: [], why: 'run/local.json does not read' })
    chmodSync(wordPath(home), 0o644)
    expect(readWord(home)).toEqual({
      on: false,
      hidden: [],
      why: 'run/local.json is not a 0600 regular file of this user',
    })
  })

  it("says how to keep a new identity apart, and names the home's key file and keychain identities", () => {
    expect(visibleLine('kim')).toBe(
      'kim is visible to your other identities on this machine; to keep it apart: bag local-delivery hide kim',
    )
    const { home } = homeWith('jane', 'kim')
    mkdirSync(join(home, 'keychain'), { mode: 0o700 })
    writeFileSync(join(home, 'keychain', 'amy.json'), '{}')
    expect(identitiesOf(home)).toEqual(['amy', 'jane', 'kim'])
    expect(identitiesOf(folder())).toEqual([])
  })

  it("maps each name to the service's label: an entry's label or key name, an identity on disk its own", () => {
    const { home } = homeWith('jane', 'kim')
    writeFileSync(join(home, 'keys', 'jane.service.json'), '{}')
    expect(labelsByName(home)).toEqual(
      new Map([
        ['jane', 'jane'],
        ['kim', 'kim'],
      ]),
    )
    saveIdentities(join(home, 'identities.json'), {
      version: 1,
      identities: [{ label: 'lab', key: 'kim', home, relays: ['https://r1.example'] }],
    })
    const by = labelsByName(home)
    expect([by.get('kim'), by.get('lab'), by.get('jane')]).toEqual(['lab', 'lab', 'jane'])
  })
})

describe('the table of local pairs', () => {
  it('reads its pairs, skipping a malformed row; none when absent, unreadable or refused', () => {
    const home = folder()
    expect(pairs(home)).toEqual([])
    expect(pairsRefused(home)).toBeNull()
    table(home, [row('a', 'b'), null, { a: 'x' }, row('c', 'd', { added_at: 'then' })])
    expect(pairs(home)).toEqual([row('a', 'b')])
    expect(pairedLocally(home, 'addr-b', 'addr-a')).toBe(true)
    expect(pairedLocally(home, 'addr-a', 'addr-c')).toBe(false)
    writeWhole(home, peersPath(home), { version: 2, pairs: [row('a', 'b')] })
    expect(pairs(home)).toEqual([])
    writeFileSync(peersPath(home), '{')
    expect(pairs(home)).toEqual([])
    table(home, [row('a', 'b')], 0o644)
    expect(pairsRefused(home)).toBe('run/local-peers.json is not a 0600 regular file of this user')
    expect(pairs(home)).toEqual([])
    expect(() => needPairsTable(home)).toThrow(/^unsafe-path: .*chmod 600/)
    expect(() => dropLocalPairs(home, () => true)).toThrow('unsafe-path')
  })

  it('refuses a link in place of the table', () => {
    const home = folder()
    table(home, [row('a', 'b')])
    const other = join(folder(), 'peers.json')
    writeFileSync(other, readFileSync(peersPath(home)), { mode: 0o600 })
    const linked = folder()
    mkdirSync(join(linked, 'run'), { mode: 0o700 })
    symlinkSync(other, peersPath(linked))
    expect(pairsRefused(linked)).not.toBeNull()
  })

  it('drops the pairs named, writing the rest back as read; nothing written when none is named', () => {
    const home = folder()
    table(home, [row('a', 'b', { held: [] }), row('c', 'd')])
    const before = statSync(peersPath(home)).mtimeMs
    expect(dropLocalPairs(home, () => false)).toBe(0)
    expect(statSync(peersPath(home)).mtimeMs).toBe(before)
    expect(dropLocalPairs(home, (p) => p.a === 'a')).toBe(1)
    expect(JSON.parse(readFileSync(peersPath(home), 'utf8'))).toEqual({ version: 1, pairs: [row('c', 'd')] })
  })

  it('counts the envelopes waiting in a spool', () => {
    const home = folder()
    expect(spooledCount(home, 'jane')).toBe(0)
    mkdirSync(join(home, 'state', 'jane', 'local-spool'), { recursive: true })
    writeFileSync(join(home, 'state', 'jane', 'local-spool', `${'a'.repeat(64)}.env`), '')
    writeFileSync(join(home, 'state', 'jane', 'local-spool', 'other.env'), '')
    expect(spooledCount(home, 'jane')).toBe(1)
  })
})

describe("a dropped pair's spooled mail", () => {
  const rng = (n: number): Uint8Array => new Uint8Array(randomBytes(n))
  /** An envelope from `from` to `to`, spooled (not held) in `to`'s spool under key name `name`. */
  const spoolIn = (home: string, name: string, from: EdgeKeys, to: EdgeKeys): string => {
    const { envelope, bytes } = buildEnvelope({
      from: from.signing,
      to: [{ address: to.signing.address, sealingKey: to.sealing.publicKey }],
      type: 'chat.v1',
      thread: newThread(rng),
      body: { text: 'spooled' },
      ts: 1,
      rng,
    })
    const dir = join(home, 'state', name, 'local-spool')
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, `${envelope.id}.env`), bytes)
    return envelope.id
  }
  const pair = (a: string, b: string, keys: Record<string, EdgeKeys>) => ({
    a,
    b,
    a_addr: keys[a]?.signing.address,
    b_addr: keys[b]?.signing.address,
    added_at: 1,
    state: 'allowed',
  })

  it("is failed to its sender in the sender's own audit log and deleted; another pair's spool stays", () => {
    const { home, keys } = homeWith('jane', 'kim', 'amy')
    const [jane, kim, amy] = [keys.jane, keys.kim, keys.amy] as [EdgeKeys, EdgeKeys, EdgeKeys]
    table(home, [pair('jane', 'kim', keys), pair('amy', 'kim', keys)])
    const toKim = spoolIn(home, 'kim', jane, kim)
    const toJane = spoolIn(home, 'jane', kim, jane)
    const fromAmy = spoolIn(home, 'kim', amy, kim)
    writeFileSync(join(home, 'state', 'kim', 'local-spool', `${'f'.repeat(64)}.env`), 'not an envelope')
    const ours = (p: { a: string; b: string }) => p.a === 'jane' || p.b === 'jane'
    expect(dropLocalPairs(home, ours, () => 1_800_000_000)).toBe(1)
    expect(pairs(home).map((p) => [p.a, p.b])).toEqual([['amy', 'kim']])
    const spool = (n: string, id: string) => join(home, 'state', n, 'local-spool', `${id}.env`)
    expect([existsSync(spool('kim', toKim)), existsSync(spool('jane', toJane))]).toEqual([false, false])
    expect([existsSync(spool('kim', fromAmy)), existsSync(spool('kim', 'f'.repeat(64)))]).toEqual([
      true,
      true,
    ])
    const lines = (n: string) =>
      readFileSync(join(home, 'state', n, 'audit.jsonl'), 'utf8')
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l) as Record<string, unknown>)
        .map((l) => [l.event, l.decision, l.id, l.from, JSON.parse(String(l.detail))])
    expect(lines('jane')).toEqual([
      [
        'publish',
        'reject',
        toKim,
        jane.signing.address,
        { relay: 'local:', delivery: 'failed-local', reason: 'unpaired', to: 'kim' },
      ],
    ])
    expect(lines('kim')).toEqual([
      [
        'publish',
        'reject',
        toJane,
        kim.signing.address,
        { relay: 'local:', delivery: 'failed-local', reason: 'unpaired', to: 'jane' },
      ],
    ])
    expect(existsSync(join(home, 'state', 'amy', 'audit.jsonl'))).toBe(false)
  })

  it('refuses held while a sender of it is busy, before the table is written: nothing was changed', () => {
    const { home, keys } = homeWith('jane', 'kim')
    table(home, [pair('jane', 'kim', keys)])
    const id = spoolIn(home, 'kim', keys.jane as EdgeKeys, keys.kim as EdgeKeys)
    const before = readFileSync(peersPath(home), 'utf8')
    mkdirSync(join(home, 'state', 'jane'), { recursive: true })
    const release = acquireLock(storeLockPath(join(home, 'state', 'jane', 'edge.sqlite')))
    try {
      expect(() => dropLocalPairs(home, () => true)).toThrow(/^held: jane has local mail spooled for kim/)
    } finally {
      release()
    }
    expect(readFileSync(peersPath(home), 'utf8')).toBe(before)
    expect(existsSync(join(home, 'state', 'kim', 'local-spool', `${id}.env`))).toBe(true)
  })
})

describe('the held mail of a pair', () => {
  const id = 'b'.repeat(64)

  it("finds each held id in either side's spool held/, skipping one that is not a file or not there", () => {
    const home = folder()
    table(home, [row('jane', 'kim', { held: [id, 'not-an-id', 7] }), row('x', 'y', { held: [id] })])
    expect(heldMailOf(home, 'addr-jane', (l) => l, [])).toEqual([])
    const held = join(home, 'state', 'kim', 'local-spool', 'held')
    mkdirSync(held, { recursive: true })
    writeFileSync(join(held, `${id}.env`), 'not an envelope')
    mkdirSync(join(home, 'state', 'jane', 'local-spool', 'held', `${id}.env`), { recursive: true })
    const found = heldMailOf(home, 'addr-jane', (l) => l, [{ name: 'jane', address: 'addr-jane' }])
    expect(found).toEqual([
      { id, file: join(held, `${id}.env`), in: 'kim', other: 'jane', sender: null, from: null, to: 'kim' },
    ])
  })

  it("asks whether a sender's store can take its writer: free, absent, or busy with the holder", () => {
    const home = folder()
    expect(senderBusy(home, 'jane')).toBeNull()
    const dir = join(home, 'state', 'jane')
    mkdirSync(dir, { recursive: true })
    expect(senderBusy(home, 'jane')).toBeNull()
    const release = acquireLock(storeLockPath(join(dir, 'edge.sqlite')))
    try {
      expect(senderBusy(home, 'jane')).toEqual(expect.any(String))
    } finally {
      release()
    }
  })

  it("fails a held envelope in its sender's own audit log; one with no sender is not logged", () => {
    const home = folder()
    const m: HeldMail = { id, file: 'f', in: 'kim', other: 'jane', sender: null, from: null, to: 'kim' }
    failHeldToSender(home, m, 'identity removed', () => 5)
    expect(existsSync(join(home, 'state'))).toBe(false)
    failHeldToSender(home, { ...m, sender: 'jane', from: 'addr-jane' }, 'identity removed', () => 5)
    const line = JSON.parse(readFileSync(join(home, 'state', 'jane', 'audit.jsonl'), 'utf8').trim())
    expect(line).toMatchObject({ event: 'publish', decision: 'reject', id })
  })
})

describe('local-delivery, the act', () => {
  it('asks for on and show only, by default; in a window for every word; and names the labels a wrong name may take', async () => {
    const { home } = homeWith('jane', 'kim')
    const io = fakeIo()
    await setLocalDelivery(io, home, 'off')
    await setLocalDelivery(io, home, 'hide', 'kim')
    expect(io.asked).toEqual([])
    await setLocalDelivery(io, home, 'show', 'kim')
    await setLocalDelivery(io, home, 'on')
    expect(io.asked[0]).toBe(
      "show kim to this home's other identities again? They can then message it on this machine.",
    )
    expect(io.asked[1]).toContain('let jane, kim, and any identity you add later, find and')
    expect(io.said).toEqual([
      `local_delivery off: ${wordPath(home)}`,
      `hidden kim: ${wordPath(home)}`,
      `shown kim: ${wordPath(home)}`,
      `local_delivery on: ${wordPath(home)}`,
    ])
    const window = fakeIo()
    await setLocalDelivery(window, home, 'off', undefined, { askEvery: true })
    await setLocalDelivery(window, home, 'hide', 'jane', { askEvery: true })
    expect(window.asked).toEqual([
      "turn local delivery off? This home's identities stop finding and messaging each other on this machine.",
      "hide jane from this home's other identities? It then sees none of them, and none of them reaches it.",
    ])
    expect(readWord(home)).toEqual({ on: false, hidden: ['jane'], why: null })
    await expect(setLocalDelivery(fakeIo({ answer: false }), home, 'on')).rejects.toThrow(
      'declined: nothing was changed',
    )
    await expect(setLocalDelivery(io, home, 'hide', 'amy')).rejects.toThrow(
      `ENOENT: no identity amy in ${home}: nothing was changed; hide takes one of: jane, kim`,
    )
    await expect(setLocalDelivery(io, folder(), 'show', 'amy')).rejects.toThrow(
      'none, this home has no identity',
    )
    chmodSync(wordPath(home), 0o644)
    const warned = fakeIo()
    await setLocalDelivery(warned, home, 'off')
    expect(warned.warned).toEqual([
      'local-delivery: run/local.json is not a 0600 regular file of this user, so it reads as off; this writes it whole',
    ])
  })
})

import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  buildEnvelope,
  fromHex,
  newThread,
  SealingKey,
  SigningKey,
  serializeHandleRecord,
  serializeRecord,
  signHandleRecord,
  signHop,
  signRecord,
  toHex,
} from '@usebag/core'
import type { InboxRow } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { fromLabel, rowLine } from '../src/commands/inbox.ts'
import { NameBook, short } from '../src/names.ts'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// Handles on the command line (spec/SPEC.md §12.4): send --to jane@acme.test resolves the handle through
// the domain's TXT record, its org record and the handle record, lookup <handle> prints each step, and inbox shows a
// sender's verified handle after the petname. The org, jane and jane's session are fixed keys of this test; their
// records are served from the test io's maps: no DNS, no fetch.

const tmp = tempDir('handles')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
const DOMAIN = 'acme.test'
const ORIGIN = `bag.${DOMAIN}`
const JANE = `jane@${DOMAIN}`
const seed = (n: number) => new Uint8Array(32).fill(n)
const ORG = new SigningKey(seed(0x31))
const jane = { signing: new SigningKey(seed(0x32)), sealing: new SealingKey(seed(0x33)) }
const SESSION = new SigningKey(seed(0x34))
let n = 0

async function world() {
  const relay = new MemoryRelay()
  const io = testIo(relay)
  const dir = join(tmp.dir, `home-${n++}`)
  const bob = (await cli(io, 'keygen', 'bob', '--dir', dir)).out[0] as string
  const file = join(dir, 'bob.address.json')
  await cli(io, 'record', 'address', 'bob', '--relay', RELAY, '--sealing-key', '--out', file, '--dir', dir)
  await cli(io, 'publish', RELAY, file)
  const bobSeal = fromHex((JSON.parse(readFileSync(file, 'utf8')) as { sealing_key: string }).sealing_key, 32)
  // acme.test's TXT names its key and its origin; its org record and jane's handle record are served there.
  io.txt.set(`_bag.${DOMAIN}`, [[`v=ac1; key=${ORG.address}; host=bag`]])
  const org = {
    kind: 'address',
    key: ORG.address,
    sealing_key: null,
    relays: [RELAY],
    rotation_key: null,
  } as const
  const orgRecord = { ...org, revoked: [], ttl: 86_400, iat: T0, rotated_from: null }
  io.wellKnown.set(ORIGIN, serializeRecord(signRecord(ORG, orgRecord)))
  // A root trusted by key that delegates keeps its record at its recipients' relays (spec/SPEC.md §9 item 5).
  await relay.publish(RELAY, serializeRecord(signRecord(ORG, orgRecord)))
  const handle = { kind: 'handle', org: ORG.address, handle: JANE, address: jane.signing.address } as const
  io.handles.set(
    `${ORIGIN} ${JANE}`,
    serializeHandleRecord(signHandleRecord(ORG, { ...handle, iat: T0, ttl: 3600 })),
  )
  // jane's own address record, at the org's relay.
  const janeRecord = signRecord(jane.signing, {
    kind: 'address',
    key: jane.signing.address,
    sealing_key: toHex(jane.sealing.publicKey),
    relays: [RELAY],
    rotation_key: null,
    revoked: [],
    ttl: 86_400,
    iat: T0,
    rotated_from: null,
  })
  await relay.publish(RELAY, serializeRecord(janeRecord))
  return { relay, io, dir, bob, bobSeal }
}

type World = Awaited<ReturnType<typeof world>>

/** A message from jane's session, under the chain org → jane → session, sealed to bob. */
async function fromJane(w: World, body: unknown): Promise<string> {
  const auth = [
    signHop(ORG, jane.signing.address, [], T0 + 3600),
    signHop(jane.signing, SESSION.address, [], T0 + 3600),
  ]
  const rng = (length: number) => new Uint8Array(randomBytes(length))
  const { envelope, bytes } = buildEnvelope({
    from: SESSION,
    to: [{ address: w.bob, sealingKey: w.bobSeal }],
    auth,
    type: 'chat.v1',
    thread: newThread(rng),
    body,
    ts: T0,
    rng,
  })
  await w.relay.publish(RELAY, bytes)
  return envelope.id
}

const inbox = (w: World) =>
  cli(w.io, 'inbox', '--as', 'bob', '--relay', RELAY, '--once', '--trust-root', ORG.address, '--dir', w.dir)

describe('send --to <handle>, lookup <handle>, and the verified handle in the inbox line', () => {
  it('sends to jane@acme.test at the relay her org names, and shows her handle on her messages once resolved', async () => {
    const w = await world()
    const id = await fromJane(w, { n: 1 })
    // Before bob resolved the handle, nothing shows it.
    expect((await inbox(w)).out).toEqual([`accept ${id} ${SESSION.address} ${ORG.address} chat.v1 {"n":1}`])
    const sent = await cli(
      w.io,
      'send',
      '--as',
      'bob',
      '--to',
      JANE,
      '--relay',
      RELAY,
      '--type',
      'chat.v1',
      '--body',
      '{"hi":1}',
      '--dir',
      w.dir,
    )
    expect(sent.code).toBe(0)
    expect(sent.out[1]).toBe(`published ${RELAY} tries=1`)
    expect(w.relay.box(jane.signing.address)).toHaveLength(1)
    const later = await fromJane(w, { n: 2 })
    expect((await inbox(w)).out).toEqual([
      `accept ${later} ${JANE} (${short(SESSION.address)}) ${ORG.address} chat.v1 {"n":2}`,
    ])
    const audit = readFileSync(join(w.dir, 'state', 'bob', 'audit.jsonl'), 'utf8')
    // The detail is JSON text inside the line: the resolve names the handle and the address.
    expect(audit).toContain(`\\"subject\\":\\"handle:${JANE}\\"`)
    expect(audit).toContain(`\\"address\\":\\"${jane.signing.address}\\"`)
  })

  it('names the step that failed: no such handle, a TXT the core refuses', async () => {
    const w = await world()
    const send = (to: string) =>
      cli(
        w.io,
        'send',
        '--as',
        'bob',
        '--to',
        to,
        '--relay',
        RELAY,
        '--type',
        't',
        '--body',
        '1',
        '--dir',
        w.dir,
      )
    expect((await send(`nobody@${DOMAIN}`)).err).toEqual([
      `bag: resolve-failed: handle:nobody@${DOMAIN} from handle: no such handle at ${ORIGIN}`,
    ])
    w.io.txt.set('_bag.globex.test', [['v=ac1; rec=https://x.test']])
    expect((await send('ann@globex.test')).err).toEqual([
      'bag: resolve-failed: handle:ann@globex.test from dns: the TXT names a rec: no URL is read from DNS',
    ])
  })

  it('lookup <handle> prints the TXT, the org record, the handle record and the address records', async () => {
    const w = await world()
    const look = await cli(w.io, 'lookup', JANE, '--as', 'bob', '--relay', RELAY, '--dir', w.dir)
    expect(look.out).toEqual([
      `cache handle:${JANE} none`,
      `_bag.${DOMAIN} found kind=txt key=${ORG.address} origin https://${ORIGIN}`,
      `https://${ORIGIN}/.well-known/bag/address.json found kind=address iat=${T0} valid_until=${T0 + 86_400} key=${ORG.address}`,
      `https://${ORIGIN}/.well-known/bag/handles/jane.json found kind=handle iat=${T0} valid_until=${T0 + 3600} key=${ORG.address} address ${jane.signing.address}`,
      `${RELAY} found kind=address iat=${T0} valid_until=${T0 + 86_400} key=${jane.signing.address}`,
      `${RELAY} none kind=key`,
    ])
    expect(
      (await cli(w.io, 'lookup', 'Jane@acme.test', '--as', 'bob', '--relay', RELAY, '--dir', w.dir)).err[0],
    ).toBe('bag: usage: "Jane@acme.test" is neither an address, domain:<host> nor a handle')
  })
})

describe('fromLabel and rowLine: petname, verified handle, address', () => {
  const home = join(tmp.dir, 'book')
  const book = NameBook.load(home)
  book.add('jane', jane.signing.address, T0)
  book.add('old', SESSION.address, T0)
  book.add('old', ORG.address, T0 + 5, true)

  it('puts the handle after the petname, and keeps the former-address warning last', () => {
    expect(fromLabel(book, jane.signing.address, null)).toBe(`jane (${short(jane.signing.address)})`)
    expect(fromLabel(book, jane.signing.address, JANE)).toBe(`jane ${JANE} (${short(jane.signing.address)})`)
    expect(fromLabel(book, SESSION.address, JANE)).toBe(
      `old? ${JANE} (${short(SESSION.address)}) WARNING: former address of old, replaced 2027-01-15T08:00:05Z`,
    )
    const stranger = new SigningKey(seed(0x40)).address
    expect(fromLabel(book, stranger, JANE)).toBe(`${JANE} (${short(stranger)})`)
  })

  it('asks the resolver for the principal and the root of the chain', async () => {
    const w = await world()
    const id = await fromJane(w, {})
    const row = { ...(w.relay.box(w.bob)[0] as { bytes: Uint8Array }) }
    const asked: string[][] = []
    const resolver = {
      handleOf: (address: string, root: string) => {
        asked.push([address, root])
        return { handle: JANE, domain: DOMAIN, verified: true as const }
      },
    }
    const inboxRow = {
      seq: 1,
      relay: RELAY,
      mailbox: w.bob,
      cursor: 1,
      bytes: row.bytes,
      receivedAt: T0,
      state: 'acked',
      id,
      reason: null,
      session: 'cli',
      content: JSON.stringify({ type: 'chat.v1', thread: { id: 'x', prev: [] }, body: {} }),
    } as unknown as InboxRow
    expect(rowLine(inboxRow, NameBook.load(join(tmp.dir, 'empty')), resolver)).toBe(
      `accept ${id} ${JANE} (${short(SESSION.address)}) ${ORG.address} chat.v1 {}`,
    )
    expect(asked).toEqual([[jane.signing.address, ORG.address]])
    // No handle for the principal: the sender's, under the same root (onboard's org -> agent chain, scenario 49).
    asked.length = 0
    const sender = {
      handleOf: (address: string, root: string) => {
        asked.push([address, root])
        return address === SESSION.address ? { handle: JANE, domain: DOMAIN, verified: true as const } : null
      },
    }
    expect(rowLine(inboxRow, NameBook.load(join(tmp.dir, 'empty')), sender)).toBe(
      `accept ${id} ${JANE} (${short(SESSION.address)}) ${ORG.address} chat.v1 {}`,
    )
    expect(asked).toEqual([
      [jane.signing.address, ORG.address],
      [SESSION.address, ORG.address],
    ])
    // Neither: the address, as before.
    expect(rowLine(inboxRow, NameBook.load(join(tmp.dir, 'empty')), { handleOf: () => null })).toBe(
      `accept ${id} ${SESSION.address} ${ORG.address} chat.v1 {}`,
    )
  })
})

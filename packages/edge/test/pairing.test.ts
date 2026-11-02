import { createHmac } from 'node:crypto'
import {
  type AcceptFromRecord,
  type AcRecord,
  type AddressRecord,
  buildEnvelope,
  canonical,
  fromHex,
  type KeyRecord,
  newThread,
  parseEnvelope,
  parseRecord,
  serializeRecord,
  signRecord,
  toHex,
  verifyPreimage,
} from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { systemRng } from '../src/adapters/system-clock.ts'
import { generateEdgeKeys } from '../src/edge.ts'
import { RelayGuard } from '../src/net.ts'
import type { Lagging } from '../src/offer.ts'
import { type Code, codeSecret, formatCode, parseCode, WORDS } from '../src/pair-code.ts'
import {
  acceptPeer,
  digitsMatch,
  INVITE_PREFIX,
  type Invite,
  type Inviter,
  inviteOf,
  invitePeer,
  inviteText,
  MAX_CODE_MISSES,
  MAX_DIGIT_TRIES,
  type PairingPorts,
  pairingCode,
  readInvite,
  refuseOtherInviter,
} from '../src/pairing.ts'
import {
  type EdgeKeys,
  type PairOpen,
  type PairReach,
  type PublishResult,
  RelayError,
  type Subscription,
} from '../src/ports.ts'
import { coreRng } from '../src/sender.ts'
import { T0 } from './support/fixtures.ts'
import { MemoryRelay } from './support/relays.ts'

// The `peer` grant's protocol: the invitation, the one request under S, the code, the grant, the wait for
// the other side's accept-from, the rollback and the close, on memory relays that refuse as spec/SPEC.md §8.2 does
// (409 stale-record, 403 root-not-accepted). The CLI's commands over it are packages/cli/test/peer.test.ts.
// Forward secrecy (2026-10-29): a side that passes its key record binds that
// record's sealing key in the code and the mac, and its address record keeps no sealing key; a side that passes none
// is the pre-FS path. The last describes cover both, and every mixed pair.

const [R1, R2, R3] = ['http://r1.test', 'http://r2.test', 'http://r3.test']
const END = T0 + 601

/** A memory relay that delivers an envelope only to a mailbox whose accept-from admits its root. */
class Relay extends MemoryRelay {
  override async publish(url: string, bytes: Uint8Array): Promise<PublishResult> {
    if ((JSON.parse(new TextDecoder().decode(bytes)) as { kind?: unknown }).kind === undefined) {
      const env = parseEnvelope(bytes)
      for (const to of env.to) {
        const held = this.records.get(`${url} ${to} accept-from`)
        if (held === undefined) throw new RelayError('not-hosted', 404, null, to)
        const { roots } = parseRecord(held) as AcceptFromRecord
        if (!roots.includes('*') && !roots.includes(env.from))
          throw new RelayError('root-not-accepted', 403, null, to)
      }
    }
    return super.publish(url, bytes)
  }

  record<R>(url: string, signer: string, kind: string): R | null {
    const bytes = this.records.get(`${url} ${signer} ${kind}`)
    return bytes === undefined ? null : (parseRecord(bytes) as R)
  }
}

interface Side {
  readonly keys: EdgeKeys
  readonly address: string
  readonly clock: { t: number; now(): number }
  readonly p: PairingPorts
  readonly log: string[]
  text: string | null
  /** Resolves with the invite text when the current invite run opens it; replaced by each `invite`. */
  ready: Promise<string>
  /** The current invite run, so waiting for its text also sees it end or throw first. */
  running: Promise<unknown> | null
}

function side(relay: Relay): Side {
  const clock = {
    t: T0,
    now() {
      return this.t
    },
  }
  const keys = generateEdgeKeys(systemRng)
  const p = { client: relay, clock, rng: systemRng, pollMs: 2 }
  return {
    keys,
    address: keys.signing.address,
    clock,
    p,
    log: [],
    text: null,
    ready: Promise.resolve(''),
    running: null,
  }
}

/** `relay` as a side's client whose reads of `owner`'s accept-from get no answer three times, after a first that does. */
function flakyReads(relay: Relay, owner: () => string): Relay {
  let reads = 0
  const fetchRecord: Relay['fetchRecord'] = (url, address, kind) => {
    const fails = address === owner() && kind === 'accept-from' && ++reads > 1 && reads <= 4
    if (fails) return Promise.reject(new RelayError(null, 0, null, 'unreachable'))
    return relay.fetchRecord(url, address, kind)
  }
  return Object.assign(Object.create(relay) as Relay, { fetchRecord })
}

/** Polls `test` on a count of polls (no wall-clock deadline), then asserts it, so a miss reads as that. */
async function until(test: () => boolean): Promise<void> {
  for (let i = 0; i < 3000 && !test(); i++) await new Promise((r) => setTimeout(r, 2))
  expect(test()).toBe(true)
}

/** Waits for a request in I's mailbox, gives the inviter a moment to drop it, and ends the invitation by the clock. */
async function dropped(relay: Relay, a: Side, i: string): Promise<void> {
  await until(() => relay.box(R1, i).length > 0)
  await new Promise((r) => setTimeout(r, 30))
  a.clock.t = END
}

/** The inviter's run, its steps logged; `ask` answers `yes` unless given. */
function invite(s: Side, relay: string, o: Partial<Inviter> & { yes?: boolean } = {}) {
  let open: (text: string) => void = () => {}
  s.text = null
  s.ready = new Promise<string>((r) => {
    open = r
  })
  const running = invitePeer(s.p, {
    relay,
    keys: s.keys,
    ttl: 600,
    opened: (text) => {
      s.text = text
      open(text)
    },
    refused: (from, code) => s.log.push(`refused ${from} ${code}`),
    ask: async (q) => {
      s.log.push(`ask ${q.from}`)
      return o.yes ?? true
    },
    leaked: (from) => s.log.push(`leaked ${from}`),
    write: (q) => s.log.push(`write ${q.from}`),
    ...o,
  })
  s.running = running
  return running
}

/** The acceptor's run, its steps logged; `ask` throws `declined` unless `yes`. */
function accept(s: Side, relay: string, text: string, yes = true, key?: KeyRecord) {
  return acceptPeer(s.p, s.keys, relay, readInvite(text), {
    ...(key === undefined ? {} : { key }),
    ask: async (code) => {
      s.log.push(`ask ${code}`)
      if (!yes) throw Object.assign(new Error('declined'), { code: 'declined' })
    },
    sent: () => s.log.push('sent'),
    write: () => s.log.push('write'),
  })
}

/** A key record of `s` over a fresh sealing key, as its edge publishes each epoch: from `iat`, a day by default. */
function keyOf(s: Side, iat = T0, exp = iat + 86_400): KeyRecord {
  const sealing = toHex(generateEdgeKeys(systemRng).sealing.publicKey)
  return signRecord(s.keys.signing, { kind: 'key', key: s.address, sealing_key: sealing, iat, exp })
}

/** An address record of `s`, signed by it: its sealing key (or none), relays, ttl and iat, and what else a held one has. */
function recordOf(
  s: Side,
  sealing: string | null,
  relays: string[],
  o: { ttl?: number; iat?: number; rotation?: string; revoked?: string[] } = {},
): AddressRecord {
  return signRecord(s.keys.signing, {
    kind: 'address',
    key: s.address,
    sealing_key: sealing,
    relays,
    rotation_key: o.rotation ?? null,
    revoked: o.revoked ?? [],
    ttl: o.ttl ?? 86_400,
    iat: o.iat ?? T0,
    rotated_from: null,
  })
}

const publish = (relay: Relay, url: string, r: AcRecord) => relay.publish(url, serializeRecord(r))
const sealingOf = (s: Side): string => toHex(s.keys.sealing.publicKey)

/** A request built by hand: `from` sends `body` to I as a peer.request.v1, which the inviter checks as any other. */
async function forge(relay: Relay, text: string, from: Side, body: unknown): Promise<void> {
  const v = readInvite(text)
  const rng = coreRng(systemRng)
  const address = relay.record<AddressRecord>(R1, v.i, 'address')
  const to = [{ address: v.i, sealingKey: Buffer.from(address?.sealing_key as string, 'hex') }]
  const type = 'peer.request.v1'
  const env = buildEnvelope({ from: from.keys.signing, to, type, thread: newThread(rng), body, ts: T0, rng })
  await relay.publish(R1, env.bytes)
}

/** The invite text, as soon as the run opens it; if the run ends or throws first, that surfaces instead. */
function opened(s: Side): Promise<string> {
  const ended = (s.running as Promise<unknown>).then(
    () => {
      throw new Error('the invite ended before it opened')
    },
    (e: unknown) => {
      throw e
    },
  )
  ended.catch(() => {})
  return Promise.race([s.ready, ended])
}

const hooks = {
  opened: () => {},
  refused: () => {},
  ask: async () => true,
  leaked: () => {},
  write: () => {},
}

const fail = async (p: Promise<unknown>): Promise<string> =>
  p.then(
    () => 'resolved',
    (e: { code?: string }) => e.code ?? String(e),
  )

describe('typed check digits', () => {
  it('takes the code with spaces and hyphens, and nothing else; three tries', () => {
    expect(MAX_DIGIT_TRIES).toBe(3)
    for (const typed of ['123 456', '123-456', '123456', ' 12 34-56 '])
      expect(digitsMatch(typed, '123 456')).toBe(true)
    for (const typed of ['123 457', '12345', '1234567', '']) expect(digitsMatch(typed, '123 456')).toBe(false)
  })
})

describe('the invite string and the code', () => {
  it('reads back what it writes, and refuses bad-invite for anything else', () => {
    const v: Invite = {
      inviter: side(new Relay()).address,
      i: side(new Relay()).address,
      relay: R1,
      secret: '0'.repeat(32),
    }
    expect(readInvite(inviteText(v))).toEqual(v)
    const list = (...l: unknown[]) => `ac-peer1:${Buffer.from(JSON.stringify(l)).toString('base64url')}`
    for (const text of [
      'x',
      inviteText(v).replace('ac-peer1:', 'ac-peer2:'),
      list('ac/peer-invite/2', v.inviter, v.i, R1, v.secret),
      list('ac/peer-invite/1', 'a', v.i, R1, v.secret),
      list('ac/peer-invite/1', v.inviter, 'i', R1, v.secret),
      list('ac/peer-invite/1', v.inviter, v.i, 'ftp://x', v.secret),
      list('ac/peer-invite/1', v.inviter, v.i, R1, '0'),
    ]) {
      expect(() => readInvite(text)).toThrow('bad-invite: not a string that peer invite printed')
    }
    const c = pairingCode(v, v.i, 'ab')
    expect(c).toMatch(/^\d{3} \d{3}$/)
    expect(pairingCode(v, v.i, 'ab')).toBe(c)
    expect(pairingCode({ ...v, secret: '1'.repeat(32) }, v.i, 'ab')).not.toBe(c)
  })
})

describe('invitePeer and acceptPeer', () => {
  it('pair: the same code on both sides, each admits the other, I stays open to its end, every step in order', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const inviting = invite(a, R1)
    const text = await opened(a)
    await accept(b, R2, text)
    const q = await inviting
    const { i } = readInvite(text)
    expect(q.from).toBe(b.address)
    expect(a.log).toEqual([`ask ${b.address}`, `write ${b.address}`])
    expect(b.log).toEqual([`ask ${q.code}`, 'sent', 'write'])
    expect(relay.record<AcceptFromRecord>(R1, a.address, 'accept-from')?.roots).toEqual([b.address])
    const theirs = relay.record<AcceptFromRecord>(R2, b.address, 'accept-from')
    expect([theirs?.roots, theirs?.max_bytes, theirs?.ttl]).toEqual([[a.address], 65_536, 604_800])
    expect(relay.record<AcceptFromRecord>(R1, i, 'accept-from')?.roots).toEqual(['*'])
    expect(relay.record<AddressRecord>(R1, i, 'address')?.ttl).toBe(600)
    expect(relay.record(R1, b.address, 'address')).not.toBeNull()
    expect(relay.record(R2, a.address, 'address')).not.toBeNull()
  })

  it('keeps a current address record and roots of ["*"], and a relay keeps a newer shared record', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const own = (s: Side, url: string, iat: number) =>
      signRecord(s.keys.signing, {
        kind: 'address',
        key: s.address,
        sealing_key: toHex(s.keys.sealing.publicKey),
        relays: [url],
        rotation_key: null,
        revoked: [],
        ttl: 86_400,
        iat,
        rotated_from: null,
      })
    await relay.publish(R1, serializeRecord(own(a, R1, T0)))
    await relay.publish(R1, serializeRecord(own(b, R2, T0 + 100)))
    const wild = {
      kind: 'accept-from',
      owner: b.address,
      roots: ['*'],
      max_bytes: 9000,
      ttl: 60,
      iat: T0,
    } as const
    await relay.publish(R2, serializeRecord(signRecord(b.keys.signing, wild)))
    const inviting = invite(a, R1)
    await accept(b, R2, await opened(a))
    await inviting
    expect(relay.record<AddressRecord>(R1, a.address, 'address')?.iat).toBe(T0)
    expect(relay.record<AddressRecord>(R1, b.address, 'address')?.iat).toBe(T0 + 100)
    const kept = relay.record<AcceptFromRecord>(R2, b.address, 'accept-from')
    expect([kept?.roots, kept?.max_bytes]).toEqual([['*'], 9000])
  })

  it('reads the newest record across relays, of the signer and kind asked, and re-signs an expired null one as null', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const addr = {
      kind: 'address',
      key: a.address,
      sealing_key: null,
      relays: [R1, R3],
      rotation_key: null,
      revoked: [b.address],
      ttl: 60,
      iat: T0 - 1000,
      rotated_from: null,
    } as const
    await relay.publish(R1, serializeRecord(signRecord(a.keys.signing, addr)))
    const accepts = (roots: string[], iat: number) =>
      serializeRecord(
        signRecord(a.keys.signing, {
          kind: 'accept-from',
          owner: a.address,
          roots,
          max_bytes: 100,
          ttl: 1,
          iat,
        }),
      )
    await relay.publish(R1, accepts([a.address], T0 + 5))
    await relay.publish(R3, accepts([b.address], T0))
    const inviting = invite(a, R1)
    const text = await opened(a)
    const { i } = readInvite(text)
    const own = relay.records.get(`${R1} ${i} address`) as Uint8Array
    for (const other of [`${R1} ${a.address} address`, `${R1} ${i} accept-from`]) {
      relay.records.set(`${R1} ${i} address`, relay.records.get(other) as Uint8Array)
      expect(await fail(accept(b, R2, text))).toBe('invite-expired')
    }
    relay.records.set(`${R1} ${i} address`, own)
    await accept(b, R2, text)
    await inviting
    const held = relay.record<AddressRecord>(R1, a.address, 'address')
    // The expired record named no sealing key, and a sealing key is never written back into one that has none.
    expect([held?.iat, held?.relays, held?.revoked, held?.sealing_key]).toEqual([
      T0,
      [R1, R3],
      [b.address],
      null,
    ])
    for (const url of [R1, R3]) {
      expect(relay.record<AcceptFromRecord>(url, a.address, 'accept-from')?.roots).toEqual([
        a.address,
        b.address,
      ])
    }
  })

  it('ends at its end with no request (invite-expired), and a request after it goes unconsumed: no-answer', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const inviting = invite(a, R1)
    const text = await opened(a)
    a.clock.t = END
    expect(await fail(inviting)).toBe('invite-expired')
    b.clock.t = T0 + 600
    expect(await fail(accept(b, R2, text))).toBe('no-answer')
    b.clock.t = T0 + 901
    expect(await fail(accept(b, R2, text))).toBe('invite-expired')
    const noSealing = {
      kind: 'address',
      key: b.address,
      sealing_key: null,
      relays: [R1],
      rotation_key: null,
    } as const
    const rec = { ...noSealing, revoked: [], ttl: 600, iat: T0, rotated_from: null } as const
    await relay.publish(R1, serializeRecord(signRecord(b.keys.signing, rec)))
    const v = { ...readInvite(text), i: b.address }
    expect(await fail(accept(b, R2, inviteText(v)))).toBe('invite-expired')
    expect(b.log).toEqual([expect.stringMatching(/^ask /), 'sent'])
  })

  it('tells a request under another secret (bad-mac), with no question, and it ends nothing', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const inviting = invite(a, R1)
    const v = readInvite(await opened(a))
    const accepting = accept(b, R2, inviteText({ ...v, secret: 'f'.repeat(32) }))
    await until(() => a.log.length > 0)
    a.clock.t = END
    expect(await fail(inviting)).toBe('invite-expired')
    expect(a.log).toEqual([`refused ${b.address} bad-mac`])
    b.clock.t = END
    expect(await fail(accepting)).toBe('no-answer')
    expect(relay.record(R1, a.address, 'accept-from')).toBeNull()
  })

  it('drops a request that is not one and a frame that is no envelope, unsaid, and neither ends it', async () => {
    for (const bad of ['type', 'frame']) {
      const relay = new Relay()
      const [a, b] = [side(relay), side(relay)]
      const inviting = invite(a, R1)
      const v = readInvite(await opened(a))
      if (bad === 'type') {
        const rng = coreRng(systemRng)
        const sealingKey = Buffer.from(
          relay.record<AddressRecord>(R1, v.i, 'address')?.sealing_key as string,
          'hex',
        )
        const to = [{ address: v.i, sealingKey }]
        const env = buildEnvelope({
          from: b.keys.signing,
          to,
          type: 'chat.v1',
          thread: newThread(rng),
          body: { record: 1 },
          ts: T0,
          rng,
        })
        await relay.publish(R1, env.bytes)
      } else {
        relay.box(R1, v.i).push({ cursor: 1, bytes: new TextEncoder().encode('{}') })
        for (const s of relay.subs) s.wake()
      }
      await dropped(relay, a, v.i)
      expect(await fail(inviting)).toBe('invite-expired')
      expect(a.log).toEqual([])
    }
  })

  it('drops a request with no sealing key of its own sender, unsaid', async () => {
    const relay = new Relay()
    const [a, b, c] = [side(relay), side(relay), side(relay)]
    const inviting = invite(a, R1)
    const v = readInvite(await opened(a))
    const rng = coreRng(systemRng)
    const sealingKey = Buffer.from(
      relay.record<AddressRecord>(R1, v.i, 'address')?.sealing_key as string,
      'hex',
    )
    const theirs = {
      kind: 'address',
      key: c.address,
      sealing_key: null,
      relays: [R1],
      rotation_key: null,
    } as const
    const record = signRecord(c.keys.signing, {
      ...theirs,
      revoked: [],
      ttl: 600,
      iat: T0,
      rotated_from: null,
    })
    const body = { record: new TextDecoder().decode(serializeRecord(record)), mac: '' }
    const thread = newThread(rng)
    const env = buildEnvelope({
      from: b.keys.signing,
      to: [{ address: v.i, sealingKey }],
      type: 'peer.request.v1',
      thread,
      body,
      ts: T0,
      rng,
    })
    await relay.publish(R1, env.bytes)
    await dropped(relay, a, v.i)
    expect(await fail(inviting)).toBe('invite-expired')
    expect(a.log).toEqual([])
  })

  it('skips a requester other than `only` (not-for), with no question, and pairs the named one', async () => {
    const relay = new Relay()
    const [a, b, m] = [side(relay), side(relay), side(relay)]
    const inviting = invite(a, R1, { only: b.address })
    const text = await opened(a)
    const racing = accept(m, R3, text)
    await until(() => a.log.length > 0)
    expect(a.log).toEqual([`refused ${m.address} not-for`])
    await accept(b, R2, text)
    expect((await inviting).from).toBe(b.address)
    m.clock.t = END
    expect(await fail(racing)).toBe('no-answer')
  })

  it('ends as leaked on a second request before the answer, and tells one after a yes', async () => {
    const relay = new Relay()
    const [a, b, m] = [side(relay), side(relay), side(relay)]
    // The second request's outcome, read at once, so its rejection is never left unhandled while `first` is awaited.
    let second: Promise<string> = Promise.resolve('')
    const inviting = invite(a, R1, {
      ask: async () => {
        second = fail(accept(b, R2, a.text as string))
        await until(() => relay.box(R1, readInvite(a.text as string).i).length === 2)
        return true
      },
    })
    const first = accept(m, R3, await opened(a))
    expect(await fail(inviting)).toBe('leaked')
    expect(a.log).toEqual([`leaked ${b.address}`])
    for (const s of [b, m]) s.clock.t = END
    expect([await fail(first), await second]).toEqual(['no-answer', 'no-answer'])
    expect(relay.record(R1, a.address, 'accept-from')).toBeNull()
    // After a yes: the inviter waits for b; a third party's request then is told and never answered.
    const relay2 = new Relay()
    const [x, y, z] = [side(relay2), side(relay2), side(relay2)]
    const slow = { ...y.p, pollMs: 200 }
    const inviting2 = invite(x, R1)
    const text = await opened(x)
    const accepting = acceptPeer(slow, y.keys, R2, readInvite(text), {
      ask: async () => {},
      sent: () => {},
      write: () => {},
    })
    await until(() => relay2.record<AcceptFromRecord>(R1, x.address, 'accept-from') !== null)
    const late = accept(z, R3, text)
    await until(() => relay2.box(R1, readInvite(text).i).length === 2)
    await accepting
    await inviting2
    expect(x.log).toEqual([`ask ${y.address}`, `write ${y.address}`, `leaked ${z.address}`])
    z.clock.t = END
    expect(await fail(late)).toBe('no-answer')
  })

  it('drops a copy of the request under the dialog and a frame that is no request: neither is a leak', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const inviting = invite(a, R1, {
      ask: async () => {
        const box = relay.box(R1, readInvite(a.text as string).i)
        const first = box[0] as (typeof box)[number]
        box.push({ cursor: first.cursor + 1, bytes: first.bytes })
        box.push({ cursor: first.cursor + 2, bytes: new TextEncoder().encode('{}') })
        for (const s of relay.subs) s.wake()
        await new Promise((r) => setTimeout(r, 30))
        return true
      },
    })
    await accept(b, R2, await opened(a))
    expect((await inviting).from).toBe(b.address)
    expect(a.log).toEqual([`write ${b.address}`])
  })

  it('takes a retry by the same requester under the dialog, a new envelope, for no leak', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    let retry: Promise<unknown> = Promise.resolve()
    const inviting = invite(a, R1, {
      ask: async () => {
        retry = accept(b, R2, a.text as string)
        await until(() => relay.box(R1, readInvite(a.text as string).i).length === 2)
        return true
      },
    })
    await accept(b, R2, await opened(a))
    await retry
    expect((await inviting).from).toBe(b.address)
    expect(a.log).toEqual([`write ${b.address}`])
  })

  it('declines on a no from either side, writing nothing', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const inviting = invite(a, R1, { yes: false })
    const accepting = accept(b, R2, await opened(a))
    expect(await fail(inviting)).toBe('declined')
    b.clock.t = END
    expect(await fail(accepting)).toBe('no-answer')
    const inviting2 = invite(a, R1)
    expect(await fail(accept(b, R2, await opened(a), false))).toBe('declined')
    a.clock.t = END + 600
    expect(await fail(inviting2)).toBe('invite-expired')
    expect([...a.log, ...b.log].filter((l) => l.startsWith('write'))).toEqual([])
  })

  it('takes its root out again when the requester never admits it, or cannot be read (no-answer)', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const inviting = invite(a, R1, {
      ask: async () => {
        relay.failingRecords.set(R2, new RelayError('body-too-large', 413, null, 'no'))
        return true
      },
    })
    expect(await fail(accept(b, R2, await opened(a)))).toBe('body-too-large')
    relay.failingFetches.set(R2, new RelayError(null, 0, null, 'unreachable'))
    a.clock.t = END
    expect(await fail(inviting)).toBe('no-answer')
    expect(relay.record<AcceptFromRecord>(R1, a.address, 'accept-from')?.roots).toEqual([a.address])
    expect(a.log).toEqual([])
  })

  const down = new RelayError(null, 0, null, 'unreachable')
  const full = new RelayError('body-too-large', 413, null, 'no')
  type Ending = {
    readonly options?: Partial<Inviter> & { yes?: boolean }
    readonly run: (relay: Relay, a: Side, b: Side, text: string) => Promise<unknown>
  }
  const endings: [string, Ending][] = [
    ['a pairing', { run: (_, __, b, text) => accept(b, R2, text) }],
    ['a refusal', { options: { yes: false }, run: async (_, __, b, text) => void fail(accept(b, R2, text)) }],
    [
      'no one coming',
      {
        run: async (_, a) => {
          a.clock.t = END
        },
      },
    ],
    [
      'an acceptor who never admits',
      {
        run: async (relay, a, b, text) => {
          relay.failingRecords.set(R2, full)
          await fail(accept(b, R2, text))
          relay.failingFetches.set(R2, down)
          a.clock.t = END
        },
      },
    ],
  ]

  it.each(endings)(
    "leaves I's public records as it opened them after %s; they lapse at I's end (ruling 9)",
    async (_, e) => {
      const relay = new Relay()
      const [a, b] = [side(relay), side(relay)]
      const inviting = invite(a, R1, e.options)
      const text = await opened(a)
      const { i } = readInvite(text)
      const served = () => ['address', 'accept-from'].map((kind) => relay.records.get(`${R1} ${i} ${kind}`))
      const open = served()
      await e.run(relay, a, b, text)
      await fail(inviting)
      expect(served()).toEqual(open)
      const r = relay.record<AcceptFromRecord>(R1, i, 'accept-from')
      expect([r?.roots, (r?.iat as number) + (r?.ttl as number)]).toEqual([['*'], T0 + 600])
      b.clock.t = END
    },
  )

  it("writes nothing to the inviter's own accept-from at a refusal, early or late (ruling 9)", async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const inviting = invite(a, R1, { yes: false })
    const text = await opened(a)
    const before = relay.records.get(`${R1} ${a.address} accept-from`)
    const accepting = fail(accept(b, R2, text))
    await fail(inviting)
    b.clock.t = END
    await accepting
    expect(relay.records.get(`${R1} ${a.address} accept-from`)).toBe(before)
  })

  it("takes a read that gets no answer as not yet, on the inviter's wait: it pairs (ruling 9)", async () => {
    const relay = new Relay()
    const flaky = flakyReads(relay, () => b.address)
    const [a, b] = [side(flaky), side(relay)]
    const inviting = invite(a, R1)
    await accept(b, R2, await opened(a))
    await inviting
    expect(relay.record<AcceptFromRecord>(R1, a.address, 'accept-from')?.roots).toContain(b.address)
  })

  it("takes a read that gets no answer as not yet, on the acceptor's wait: it pairs (ruling 9)", async () => {
    const relay = new Relay()
    const flaky = flakyReads(relay, () => a.address)
    const [a, b] = [side(relay), side(flaky)]
    const inviting = invite(a, R1)
    await accept(b, R2, await opened(a))
    await inviting
    expect(relay.record<AcceptFromRecord>(R2, b.address, 'accept-from')?.roots).toContain(a.address)
  })

  /** An acceptor waiting while each read of the inviter's records fails with `e`; the inviter has refused. */
  async function waitingOn(e: RelayError) {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const inviting = invite(a, R1, {
      ask: async () => {
        relay.failingFetches.set(R1, e)
        return false
      },
    })
    const accepting = accept(b, R2, await opened(a))
    void accepting.catch(() => {}) // A fatal end can come before the test looks.
    expect(await fail(inviting)).toBe('declined')
    return { b, accepting }
  }

  it.each([
    ['no answer', new RelayError(null, 0, null, 'fetch failed')],
    ['a relay in trouble', new RelayError('store-full', 503, null, 'answered 503')],
    ['a proxy that refuses', new RelayError(null, 403, null, 'answered 403')],
    ['a refusal with a code', new RelayError('bad-address', 400, null, 'answered 400')],
    ['a rate limit that names no wait', new RelayError('rate-limited', 429, null, 'answered 429')],
    ['a response over the cap', new RelayError(null, 200, null, 'a response over 65536 bytes')],
  ])('waits through %s to its own end, and hears no-answer (ruling 9)', async (_, e) => {
    const { b, accepting } = await waitingOn(e)
    let ended = false
    void accepting
      .catch(() => {})
      .finally(() => {
        ended = true
      })
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(ended).toBe(false)
    b.clock.t = END
    expect(await fail(accepting)).toBe('no-answer')
  })

  it("holds off for a relay's Retry-After, within the invitation's end, and ends there all the same (ruling 9)", async () => {
    const relay = new Relay()
    let [asked, limited] = [0, 0]
    const fetchRecord: Relay['fetchRecord'] = (url, address, kind) => {
      if (address !== a.address || kind !== 'accept-from' || ++asked === 1)
        return relay.fetchRecord(url, address, kind)
      limited++
      // One second left, and a relay that asks for an hour: without the bound this wait outlives the invitation.
      b.clock.t = Math.max(b.clock.t, T0 + 599)
      return Promise.reject(new RelayError('rate-limited', 429, 3600, 'answered 429'))
    }
    const [a, b] = [side(relay), side(Object.assign(Object.create(relay) as Relay, { fetchRecord }))]
    const inviting = invite(a, R1, { yes: false })
    const accepting = fail(accept(b, R2, await opened(a)))
    await fail(inviting)
    await until(() => limited === 1)
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(limited).toBe(1)
    b.clock.t = T0 + 600
    expect(await accepting).toBe('no-answer')
  })

  /** An accept-from of `s`, signed by it. */
  const acceptOf = (s: Side, iat: number): AcceptFromRecord =>
    signRecord(s.keys.signing, {
      kind: 'accept-from',
      owner: s.address,
      roots: [s.address],
      max_bytes: 65_536,
      ttl: 604_800,
      iat,
    })

  it.each<[string, string, (a: Side, b: Side) => Uint8Array]>([
    ['a record that does not parse', 'bad-record', () => new TextEncoder().encode('{"kind":"accept-from"}')],
    [
      'a forged signature',
      'bad-record-sig',
      (a, b) => serializeRecord({ ...acceptOf(a, T0 + 6), roots: [a.address, b.address] }),
    ],
    ["another identity's record", 'bad-record', (_, b) => serializeRecord(acceptOf(b, T0 + 6))],
    ['a replay older than one it has seen', 'stale-record', (a) => serializeRecord(acceptOf(a, T0 + 1))],
  ])(
    'ends a wait at once on %s: a delivered record that fails verification decides (ruling 9)',
    async (_, code, served) => {
      const relay = new Relay()
      const [a, b] = [side(relay), side(relay)]
      await publish(relay, R1, acceptOf(a, T0 + 5))
      const inviting = invite(a, R1, {
        ask: async () => {
          relay.records.set(`${R1} ${a.address} accept-from`, served(a, b))
          return false
        },
      })
      expect(await fail(accept(b, R2, await opened(a)))).toBe(code)
      expect(await fail(inviting)).toBe('declined')
    },
  )

  it('takes the record it first saw, served again, as not yet: that is a wait, no replay (ruling 9)', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    await publish(relay, R1, acceptOf(a, T0 + 5))
    const inviting = invite(a, R1, { yes: false })
    const accepting = fail(accept(b, R2, await opened(a)))
    await fail(inviting)
    await new Promise((resolve) => setTimeout(resolve, 20))
    b.clock.t = END
    expect(await accepting).toBe('no-answer')
  })

  it('ends with a relay refusal: the shared record refused, or the subscription failing; I is closed', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    relay.failingRecords.set(R1, new RelayError('body-too-large', 413, null, 'no'))
    expect(await fail(invite(a, R1))).toBe('body-too-large')
    relay.failingRecords.clear()
    const inviting = invite(a, R1, {
      ask: async () => {
        relay.failingRecords.set(R1, new RelayError('body-too-large', 413, null, 'no'))
        return true
      },
    })
    const accepting = accept(b, R2, await opened(a))
    expect(await fail(inviting)).toBe('body-too-large')
    b.clock.t = END
    expect(await fail(accepting)).toBe('no-answer')
    relay.failingRecords.clear()
    const broken = Object.assign(Object.create(relay) as Relay, {
      subscribe: (): Subscription => ({
        [Symbol.asyncIterator]: () => ({
          next: async () => Promise.reject(new RelayError('not-authorized', 401, null, 'no')),
        }),
        ack: () => {},
        close: () => {},
      }),
    })
    const c = side(relay)
    const failing = invitePeer({ ...c.p, client: broken }, { relay: R1, keys: c.keys, ttl: 600, ...hooks })
    expect(await fail(failing)).toBe('not-authorized')
    expect(relay.record<AcceptFromRecord>(R1, c.address, 'accept-from')).toBeNull()
  })

  it('pairs when the inviter relay has lost the inviter address record: nothing is shared', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const inviting = invite(a, R1, {
      ask: async () => {
        relay.records.delete(`${R1} ${a.address} address`)
        return true
      },
    })
    await accept(b, R2, await opened(a))
    await inviting
    expect(relay.record(R2, a.address, 'address')).toBeNull()
  })
})

describe('one listed relay down (spec/SPEC.md Appendix B 110)', () => {
  const DOWN = new RelayError(null, 0, null, 'no answer')
  const down = (relay: Relay, url: string): void => {
    relay.failing.set(url, DOWN)
    relay.failingRecords.set(url, DOWN)
    relay.failingFetches.set(url, DOWN)
  }
  /** Each relay that did not take a record of `s`, as `kind relay code`, and whether it carried a revoked list. */
  const heard = (s: Side): string[] => {
    const lines: string[] = []
    Object.assign(s.p, {
      lagging: (l: Lagging) => lines.push(`${l.kind} ${l.relay} ${l.code} ${l.revokes}`),
    })
    return lines
  }

  it('pairs once the rendezvous and one listed relay hold the records, and names the relay that lags', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    for (const s of [a, b]) await publish(relay, R1, recordOf(s, sealingOf(s), [R1, R2]))
    down(relay, R2)
    const [ofA, ofB] = [heard(a), heard(b)]
    const inviting = invite(a, R1)
    await accept(b, R1, await opened(a))
    await inviting
    expect(relay.record<AcceptFromRecord>(R1, a.address, 'accept-from')?.roots).toContain(b.address)
    expect(relay.record<AcceptFromRecord>(R1, b.address, 'accept-from')?.roots).toContain(a.address)
    expect([ofA, ofB]).toEqual([
      [`accept-from ${R2} unreachable false`],
      [`accept-from ${R2} unreachable false`],
    ])
    expect([a.log, b.log].map((l) => l.at(-1))).toEqual([`write ${b.address}`, 'write'])
  })

  it('does not wait out the invitation on a peer whose listed relay is down: the other shows the admit', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    await publish(relay, R1, recordOf(b, sealingOf(b), [R2, R1]))
    down(relay, R2)
    const inviting = invite(a, R1)
    await accept(b, R1, await opened(a))
    await inviting // read R2 first, each poll: a failure that ended the read would wait to no-answer
    expect(a.log.at(-1)).toBe(`write ${b.address}`)
  })

  it('takes no stale answer for the accept-from that adds the peer: no relay holds the root, so it stops', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    await publish(relay, R1, recordOf(a, sealingOf(a), [R1, R2]))
    const stale = new RelayError('stale-record', 409, null, 'not newer')
    const inviting = invite(a, R1, {
      ask: async () => {
        for (const url of [R1, R2]) relay.failingRecords.set(url, stale)
        return true
      },
    })
    const accepting = accept(b, R1, await opened(a))
    expect(await fail(inviting)).toBe('stale-record')
    relay.failingRecords.clear()
    expect(relay.record<AcceptFromRecord>(R1, a.address, 'accept-from')?.roots ?? []).not.toContain(b.address)
    b.clock.t = END
    expect(await fail(accepting)).toBe('no-answer')
  })

  it('fails closed with the rendezvous down, whatever else is up', async () => {
    const relay = new Relay()
    const a = side(relay)
    await publish(relay, R1, recordOf(a, sealingOf(a), [R1, R2]))
    down(relay, R1)
    expect(await fail(invite(a, R1))).not.toBe('resolved')
  })

  it('puts the invitation at the rendezvous: a first relay down fails no ceremony whose rendezvous is up', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const mine = recordOf(a, sealingOf(a), [R3, R2])
    await publish(relay, R2, mine)
    Object.assign(a.p, { continueFrom: (found: AddressRecord | null) => found ?? mine })
    down(relay, R3)
    const ofA = heard(a)
    const inviting = invite(a, R3, { rendezvous: R1 })
    const text = await opened(a)
    expect(readInvite(text).relay).toBe(R1)
    await accept(b, R1, text)
    await inviting
    // Listed at R3 and R2, it put its records at R1 for the acceptor, and R2 holds them.
    expect(relay.record<AddressRecord>(R1, a.address, 'address')?.key).toBe(a.address)
    for (const url of [R1, R2]) {
      expect(relay.record<AcceptFromRecord>(url, a.address, 'accept-from')?.roots).toContain(b.address)
    }
    expect(ofA).toEqual([`accept-from ${R3} unreachable false`])
  })

  it('reads its own records at the relays the copy lists when its first relay is down', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const mine = recordOf(b, sealingOf(b), [R3, R2])
    await publish(relay, R2, mine)
    Object.assign(b.p, { continueFrom: (found: AddressRecord | null) => found ?? mine })
    down(relay, R3)
    const ofB = heard(b)
    const inviting = invite(a, R1)
    await accept(b, R3, await opened(a))
    await inviting
    expect(relay.record<AcceptFromRecord>(R2, b.address, 'accept-from')?.roots).toContain(a.address)
    expect(ofB).toEqual([`accept-from ${R3} unreachable false`])
  })

  it('refuses with no copy to go on when the only relay it reads gives no answer', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    down(relay, R3)
    const inviting = invite(a, R1)
    expect(await fail(accept(b, R3, await opened(a)))).not.toBe('resolved')
    a.clock.t = END
    await inviting.catch(() => {})
  })

  it('marks a record that carries a revoked list, a gap the port can report as incomplete', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const old = T0 - 2 * 86_400
    const revoked = [side(relay).address]
    await publish(relay, R1, recordOf(a, sealingOf(a), [R1, R2], { iat: old, revoked }))
    await publish(relay, R1, recordOf(b, sealingOf(b), [R1]))
    down(relay, R2)
    const ofA = heard(a)
    const inviting = invite(a, R1)
    await accept(b, R1, await opened(a))
    await inviting
    expect(ofA).toEqual([`address ${R2} unreachable true`, `accept-from ${R2} unreachable false`])
  })

  it("never reports a peer's record that a relay of this side did not take", async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    await publish(relay, R1, recordOf(a, sealingOf(a), [R1, R2]))
    await publish(relay, R1, recordOf(b, sealingOf(b), [R1], { revoked: [side(relay).address] }))
    relay.failingRecords.set(R2, DOWN)
    const ofA = heard(a)
    const inviting = invite(a, R1)
    await accept(b, R1, await opened(a))
    await inviting
    expect(ofA).toEqual([`accept-from ${R2} unreachable false`])
  })
})

describe('forward secrecy: a side that passes its key record', () => {
  it('pairs on the key record of each side: the same code over its sealing key, both records shared, address records null', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const [ka, kb] = [keyOf(a), keyOf(b)]
    // Each side's relay holds its key record, as the CLI's rotation leaves it before a pairing.
    await publish(relay, R1, ka)
    await publish(relay, R2, kb)
    const inviting = invite(a, R1, { key: ka })
    const text = await opened(a)
    await accept(b, R2, text, true, kb)
    const q = await inviting
    const v = readInvite(text)
    const code = pairingCode(v, b.address, kb.sealing_key)
    expect([q.code, b.log[0]]).toEqual([code, `ask ${code}`])
    expect(code).not.toBe(pairingCode(v, b.address, sealingOf(b)))
    expect([q.from, q.key, q.record.sealing_key]).toEqual([b.address, kb, null])
    // The inviter shares the requester's address record and key record at its relay; the acceptor, the inviter's.
    expect(relay.record(R1, b.address, 'key')).toEqual(kb)
    expect(relay.record(R1, b.address, 'address')).toEqual(q.record)
    expect(relay.record(R2, a.address, 'key')).toEqual(ka)
    expect(relay.record<AddressRecord>(R2, a.address, 'address')?.relays).toEqual([R1])
    // No address record of either side names a sealing key, wherever it is held; I's still names I's own.
    for (const [url, s] of [
      [R1, a],
      [R2, b],
      [R1, b],
      [R2, a],
    ] as const) {
      expect(
        relay.record<AddressRecord>(url, s.address, 'address')?.sealing_key,
        `${url} ${s.address}`,
      ).toBeNull()
    }
    expect(relay.record<AddressRecord>(R1, v.i, 'address')?.sealing_key).toMatch(/^[0-9a-f]{64}$/)
    expect(relay.record<AcceptFromRecord>(R1, a.address, 'accept-from')?.roots).toEqual([b.address])
    expect(relay.record<AcceptFromRecord>(R2, b.address, 'accept-from')?.roots).toEqual([a.address])
  })

  it('pairs a requester with a key record and an inviter without one (pre-FS), and the reverse', async () => {
    // The requester has a key record: the code binds it; the inviter keeps its own sealing key and has no key to share.
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const kb = keyOf(b)
    await publish(relay, R2, kb)
    const inviting = invite(a, R1)
    const text = await opened(a)
    await accept(b, R2, text, true, kb)
    const q = await inviting
    expect(q.code).toBe(pairingCode(readInvite(text), b.address, kb.sealing_key))
    expect(q.key).toEqual(kb)
    expect(relay.record(R1, b.address, 'key')).toEqual(kb)
    expect(relay.record<AddressRecord>(R1, b.address, 'address')?.sealing_key).toBeNull()
    expect(relay.record<AddressRecord>(R1, a.address, 'address')?.sealing_key).toBe(sealingOf(a))
    expect(relay.record<AddressRecord>(R2, a.address, 'address')?.sealing_key).toBe(sealingOf(a))
    expect(relay.record(R2, a.address, 'key')).toBeNull()
    // The requester has none: the code binds its address record's sealing key; the inviter's key record is shared back.
    const relay2 = new Relay()
    const [c, d] = [side(relay2), side(relay2)]
    const kc = keyOf(c)
    await publish(relay2, R1, kc)
    const inviting2 = invite(c, R1, { key: kc })
    const text2 = await opened(c)
    await accept(d, R2, text2)
    const q2 = await inviting2
    expect(q2.code).toBe(pairingCode(readInvite(text2), d.address, sealingOf(d)))
    expect(q2.key).toBeNull()
    expect(relay2.record(R1, d.address, 'key')).toBeNull()
    expect(relay2.record<AddressRecord>(R1, d.address, 'address')?.sealing_key).toBe(sealingOf(d))
    expect(relay2.record<AddressRecord>(R1, c.address, 'address')?.sealing_key).toBeNull()
    expect(relay2.record<AddressRecord>(R2, c.address, 'address')?.sealing_key).toBeNull()
    expect(relay2.record(R2, c.address, 'key')).toEqual(kc)
  })

  it('drops a key record that is not the requester live key record, unsaid, with no question', async () => {
    const cases: [string, (b: Side, c: Side) => KeyRecord][] = [
      ['another address', (_b, c) => keyOf(c)],
      ['not a key record', (b) => recordOf(b, sealingOf(b), [R2]) as unknown as KeyRecord],
      ['past exp', (b) => keyOf(b, T0 - 100, T0 - 1)],
      ['early iat', (b) => keyOf(b, T0 + 1000, T0 + 2000)],
    ]
    for (const [label, make] of cases) {
      const relay = new Relay()
      const [a, b, c] = [side(relay), side(relay), side(relay)]
      const inviting = invite(a, R1)
      const text = await opened(a)
      const accepting = accept(b, R2, text, true, make(b, c))
      await dropped(relay, a, readInvite(text).i)
      expect(await fail(inviting), label).toBe('invite-expired')
      expect(a.log, label).toEqual([])
      b.clock.t = END
      expect(await fail(accepting), label).toBe('no-answer')
      expect(relay.record(R1, a.address, 'accept-from'), label).toBeNull()
      expect(relay.record(R1, b.address, 'key'), label).toBeNull()
    }
  })

  it('binds the key record sealing key in the mac: one over the address record is bad-mac, over the key record is asked', async () => {
    for (const bound of ['address', 'key'] as const) {
      const relay = new Relay()
      const [a, b] = [side(relay), side(relay)]
      const kb = keyOf(b)
      const inviting = invite(a, R1, { yes: false })
      const text = await opened(a)
      const v = readInvite(text)
      const sealing = bound === 'address' ? sealingOf(b) : kb.sealing_key
      const list = canonical(['ac/peer-request/1', v.inviter, v.i, b.address, sealing, T0 + 600])
      const mac = createHmac('sha256', fromHex(v.secret)).update(list).digest('hex')
      const record = new TextDecoder().decode(serializeRecord(recordOf(b, sealingOf(b), [R2])))
      const key = new TextDecoder().decode(serializeRecord(kb))
      await forge(relay, text, b, { record, key, mac })
      if (bound === 'address') {
        await until(() => a.log.length > 0)
        a.clock.t = END
      }
      expect(await fail(inviting), bound).toBe(bound === 'address' ? 'invite-expired' : 'declined')
      expect(a.log, bound).toEqual(
        bound === 'address' ? [`refused ${b.address} bad-mac`] : [`ask ${b.address}`],
      )
    }
  })
})

describe('a side with no key record and a null-sealing address record (pre-FS)', () => {
  it('keeps its record null as it is, and the inviter answers bad-request: no sealing key is bound', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    await publish(relay, R2, recordOf(b, null, [R2], { iat: T0 - 5 }))
    const held = relay.records.get(`${R2} ${b.address} address`)
    const inviting = invite(a, R1)
    const text = await opened(a)
    const accepting = accept(b, R2, text)
    await dropped(relay, a, readInvite(text).i)
    expect(await fail(inviting)).toBe('invite-expired')
    expect(a.log).toEqual([])
    expect(relay.records.get(`${R2} ${b.address} address`)).toEqual(held)
    expect(relay.recordPublishes.filter((r) => r === `${R2} ${b.address} address`)).toHaveLength(1)
    b.clock.t = END
    expect(await fail(accepting)).toBe('no-answer')
  })

  it('keeps a live null record of the inviter as it is (a sealing key is never written back) and pairs', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    await publish(relay, R1, recordOf(a, null, [R1], { iat: T0 - 5 }))
    const held = relay.records.get(`${R1} ${a.address} address`)
    const inviting = invite(a, R1)
    await accept(b, R2, await opened(a))
    await inviting
    expect(relay.records.get(`${R1} ${a.address} address`)).toEqual(held)
    expect(relay.recordPublishes.filter((r) => r === `${R1} ${a.address} address`)).toHaveLength(1)
    expect(relay.record<AddressRecord>(R2, a.address, 'address')?.sealing_key).toBeNull()
    expect(relay.record<AddressRecord>(R1, b.address, 'address')?.sealing_key).toBe(sealingOf(b))
  })
})

describe("ownAddress when the relay holds no record: the home's copy goes on (last-mile ruling 4)", () => {
  it('re-signs the copy with its rotation key, revoked list and relays, and keeps what it published', async () => {
    const relay = new Relay()
    const [a, b, c] = [side(relay), side(relay), side(relay)]
    const old = { ttl: 60, iat: T0 - 1000, rotation: c.address, revoked: [c.address] }
    const copy = recordOf(a, null, [R1, R3], old)
    const kept: AddressRecord[] = []
    const s = {
      ...a,
      p: { ...a.p, continueFrom: () => copy, keepAddress: (r: AddressRecord) => kept.push(r) },
    }
    const inviting = invite(s, R1, { key: keyOf(a) })
    await accept(b, R2, await opened(s), true, keyOf(b))
    await inviting
    const published = relay.record<AddressRecord>(R1, a.address, 'address')
    expect([published?.iat, published?.relays, published?.revoked, published?.rotation_key]).toEqual([
      T0,
      [R1, R3],
      [c.address],
      c.address,
    ])
    expect(kept).toEqual([published])
  })

  it('a relay that replays an older record rolls nothing back: the newer copy is re-signed, though the replay still stands', async () => {
    const relay = new Relay()
    const [a, b, c] = [side(relay), side(relay), side(relay)]
    await publish(relay, R1, recordOf(a, null, [R1], { iat: T0 - 100 }))
    const copy = recordOf(a, null, [R1], { iat: T0 - 50, rotation: c.address, revoked: [c.address] })
    const s = { ...a, p: { ...a.p, continueFrom: () => copy } }
    const inviting = invite(s, R1, { key: keyOf(a) })
    await accept(b, R2, await opened(s), true, keyOf(b))
    await inviting
    const published = relay.record<AddressRecord>(R1, a.address, 'address')
    expect([published?.iat, published?.revoked, published?.rotation_key]).toEqual([
      T0,
      [c.address],
      c.address,
    ])
  })

  it('goes on from a live record the relay holds, publishing nothing, when that is what the home says', async () => {
    const relay = new Relay()
    const [a, b] = [side(relay), side(relay)]
    const live = recordOf(a, null, [R1], { iat: T0 - 5 })
    await publish(relay, R1, live)
    const kept: AddressRecord[] = []
    const s = {
      ...a,
      p: {
        ...a.p,
        continueFrom: (f: AddressRecord | null) => f,
        keepAddress: (r: AddressRecord) => kept.push(r),
      },
    }
    const inviting = invite(s, R1, { key: keyOf(a) })
    await accept(b, R2, await opened(s), true, keyOf(b))
    await inviting
    expect(relay.record<AddressRecord>(R1, a.address, 'address')?.iat).toBe(T0 - 5)
    expect(kept).toEqual([])
  })

  it('publishes nothing when the copy is refused', async () => {
    const relay = new Relay()
    const a = side(relay)
    const lost = () => {
      throw new Error('no-held-record: nothing to continue from')
    }
    await expect(invite({ ...a, p: { ...a.p, continueFrom: lost } }, R1)).rejects.toThrow(/^no-held-record: /)
    expect(relay.record(R1, a.address, 'address')).toBeNull()
  })
})

describe('ownAddress under forward secrecy', () => {
  it('re-signs an expired null record and a live one naming a sealing key, with no sealing key and the held members', async () => {
    const relay = new Relay()
    const [a, b, c] = [side(relay), side(relay), side(relay)]
    const [ka, kb] = [keyOf(a), keyOf(b)]
    // a: an expired record with no sealing key; b: a live one that still names its sealing key.
    const old = { ttl: 60, iat: T0 - 1000, rotation: c.address, revoked: [c.address] }
    await publish(relay, R1, recordOf(a, null, [R1, R3], old))
    await publish(
      relay,
      R2,
      recordOf(b, sealingOf(b), [R2], { iat: T0 - 5, rotation: c.address, revoked: [c.address] }),
    )
    const inviting = invite(a, R1, { key: ka })
    await accept(b, R2, await opened(a), true, kb)
    await inviting
    const ra = relay.record<AddressRecord>(R1, a.address, 'address')
    expect([ra?.sealing_key, ra?.iat, ra?.ttl, ra?.relays, ra?.revoked, ra?.rotation_key]).toEqual([
      null,
      T0,
      86_400,
      [R1, R3],
      [c.address],
      c.address,
    ])
    const rb = relay.record<AddressRecord>(R2, b.address, 'address')
    expect([rb?.sealing_key, rb?.iat, rb?.relays, rb?.revoked, rb?.rotation_key]).toEqual([
      null,
      T0,
      [R2],
      [c.address],
      c.address,
    ])
  })
})

/**
 * A relay that also offers the pair rendezvous: an open signed by its invitation (else bad-sig), nameplates from 472 up,
 * each reach kept as it was opened, by "<url> <nameplate>".
 */
class PairRelay extends Relay {
  readonly plates = new Map<string, PairOpen>()

  async pairOpen(url: string, open: PairOpen): Promise<string | null> {
    const { inviter, invitation, relays, ttl, sig } = open
    if (!verifyPreimage(invitation, ['ac/pair-open/1', inviter, invitation, relays, ttl], sig)) {
      throw new RelayError('bad-sig', 422, null, url)
    }
    const n = String(472 + this.plates.size)
    this.plates.set(`${url} ${n}`, open)
    return n
  }

  async pairClaim(url: string, n: string): Promise<PairReach | null> {
    const o = this.plates.get(`${url} ${n}`)
    return o === undefined
      ? null
      : { inviter: o.inviter, invitation: o.invitation, relays: o.relays, exp: END }
  }
}

/** The acceptor's run on what its person typed: read (and claimed) at `claim`, then accepted from `relay`. */
async function acceptTyped(s: Side, claim: string, relay: string, typed: string) {
  const v = await inviteOf(s.p, claim, typed)
  return acceptPeer(s.p, s.keys, relay, v, {
    ask: async (code) => {
      s.log.push(`ask ${code}`)
    },
    sent: () => s.log.push('sent'),
    write: () => s.log.push('write'),
  })
}

describe('the word code', () => {
  it('pairs on the code typed back in any case and spacing: a reach opened for I, S from the words, the same six digits', async () => {
    const relay = new PairRelay()
    const [a, b] = [side(relay), side(relay)]
    const inviting = invite(a, R1)
    const text = await opened(a)
    expect(text).toMatch(/^472(-[^-\s]+){3}$/)
    const open = relay.plates.get(`${R1} 472`) as PairOpen
    const sig = expect.stringMatching(/^[0-9a-f]{128}$/)
    expect(open).toEqual({ inviter: a.address, invitation: expect.any(String), relays: [R1], ttl: 600, sig })
    await acceptTyped(b, R1, R2, ` ${text.toUpperCase().replaceAll('-', ' \n ')} `)
    const q = await inviting
    expect(q.from).toBe(b.address)
    expect(a.log).toEqual([`ask ${b.address}`, `write ${b.address}`])
    expect(b.log).toEqual([`ask ${q.code}`, 'sent', 'write'])
    const v = await inviteOf(b.p, R1, text)
    const secret = codeSecret(parseCode(text) as Code, open.invitation)
    expect(v).toEqual({ inviter: a.address, i: open.invitation, relay: R1, secret })
    expect(relay.record<AcceptFromRecord>(R1, v.i, 'accept-from')?.roots).toEqual(['*'])
  })

  it('under a code frames that are no request neither end it nor count: past the misses, the right side pairs', async () => {
    const relay = new PairRelay()
    const [a, b] = [side(relay), side(relay)]
    const inviting = invite(a, R1)
    const text = await opened(a)
    const open = relay.plates.get(`${R1} 472`) as PairOpen
    for (let cursor = 1; cursor <= MAX_CODE_MISSES; cursor++) {
      const bytes = new TextEncoder().encode(`{"n":${cursor}}`)
      relay.box(R1, open.invitation).push({ cursor, bytes })
    }
    for (const s of relay.subs) s.wake()
    await new Promise((r) => setTimeout(r, 30))
    expect(a.log).toEqual([])
    await acceptTyped(b, R1, R2, text)
    expect((await inviting).from).toBe(b.address)
  })

  it('refuses an inviter other than the one held (not-for) before the digits, and the code still pairs', async () => {
    const relay = new PairRelay()
    const [a, b, m] = [side(relay), side(relay), side(relay)]
    const inviting = invite(a, R1)
    const text = await opened(a)
    const v = await inviteOf(b.p, R1, text)
    expect(() => refuseOtherInviter(v, m.address)).toThrow(
      `not-for: that invitation is from ${a.address}, not ${m.address}: nothing was sent`,
    )
    expect(b.log).toEqual([])
    expect(() => refuseOtherInviter(v, a.address)).not.toThrow()
    expect(() => refuseOtherInviter(v, undefined)).not.toThrow()
    await acceptTyped(b, R1, R2, text)
    expect((await inviting).from).toBe(b.address)
  })

  it('refuses a request under other words bad-code and keeps the invitation open, then pairs the right one', async () => {
    const relay = new PairRelay()
    const [a, b, m] = [side(relay), side(relay), side(relay)]
    const inviting = invite(a, R1)
    const text = await opened(a)
    const c = parseCode(text) as Code
    const wrong = formatCode({
      ...c,
      words: c.words.map((w) => (w === WORDS[0] ? WORDS[1] : WORDS[0]) as string),
    })
    const guessing = acceptTyped(m, R1, R2, wrong)
    await until(() => a.log.includes(`refused ${m.address} bad-code`))
    await acceptTyped(b, R1, R2, text)
    expect((await inviting).from).toBe(b.address)
    expect(a.log).toEqual([`refused ${m.address} bad-code`, `ask ${b.address}`, `write ${b.address}`])
    m.clock.t = END
    expect(await fail(guessing)).toBe('no-answer')
  })

  it('pairs two relays through a shared rendezvous: the open and the claim there, I and the request there too, the records of each side at its own relay', async () => {
    const relay = new PairRelay()
    const [a, b] = [side(relay), side(relay)]
    const inviting = invite(a, R1, { rendezvous: R3 })
    const text = await opened(a)
    expect([...relay.plates.keys()]).toEqual([`${R3} 472`])
    expect(await fail(inviteOf(b.p, R2, text))).toBe('invite-expired')
    await acceptTyped(b, R3, R2, text)
    expect((await inviting).from).toBe(b.address)
    expect(b.log).toEqual([expect.stringMatching(/^ask \d{3} \d{3}$/), 'sent', 'write'])
  })

  it('claims at the host a code names (`@<host>`), whatever the acceptor rendezvous', async () => {
    const relay = new PairRelay()
    const [a, b] = [side(relay), side(relay)]
    const inviting = invite(a, R1, { rendezvous: 'https://meet.example' })
    const text = await opened(a)
    await acceptTyped(b, R2, R2, `${text}@meet.example`)
    expect((await inviting).from).toBe(b.address)
  })

  it('guards the rendezvous: a private one it was not given is resolve-failed for the open and for a code@host claim', async () => {
    const relay = new PairRelay()
    const [a, b, g] = [side(relay), side(relay), side(relay)]
    const guarded = { ...g, p: { ...g.p, guard: new RelayGuard({ own: [R1] }) } }
    expect(await fail(invite(guarded, R1, { rendezvous: 'https://10.0.0.1' }))).toBe('resolve-failed')
    const inviting = invite(a, R1, { rendezvous: 'https://127.0.0.1:8080' })
    const text = await opened(a)
    const typed = `${text}@127.0.0.1:8080`
    expect(await fail(inviteOf({ ...b.p, guard: new RelayGuard({ own: [R2] }) }, R2, typed))).toBe(
      'resolve-failed',
    )
    const own = new RelayGuard({ own: [R2, 'https://127.0.0.1:8080'] })
    expect((await inviteOf({ ...b.p, guard: own }, R2, typed)).inviter).toBe(a.address)
    const allowed = new RelayGuard({ own: [R2], allowPrivate: true })
    expect((await inviteOf({ ...b.p, guard: allowed }, R2, typed)).inviter).toBe(a.address)
    a.clock.t = END
    expect(await fail(inviting)).toBe('invite-expired')
  })

  it("guards the inviter's relay in acceptPeer: a private one it was not given is resolve-failed before any request", async () => {
    const relay = new Relay()
    const b = side(relay)
    const v = { inviter: b.address, i: b.address, relay: 'http://192.168.1.10', secret: '0'.repeat(32) }
    const p = { ...b.p, guard: new RelayGuard({ own: [R2] }) }
    expect(
      await fail(acceptPeer(p, b.keys, R2, v, { ask: async () => {}, sent: () => {}, write: () => {} })),
    ).toBe('resolve-failed')
    expect(relay.records.size).toBe(0)
  })

  it(`ends the invitation on the ${MAX_CODE_MISSES}th bad-code request, after skipping the ones before it`, async () => {
    const relay = new PairRelay()
    const a = side(relay)
    const inviting = invite(a, R1)
    const c = parseCode(await opened(a)) as Code
    const wrong = formatCode({
      ...c,
      words: c.words.map((w) => (w === WORDS[0] ? WORDS[1] : WORDS[0]) as string),
    })
    const guessers = Array.from({ length: MAX_CODE_MISSES }, () => side(relay))
    const runs: Promise<string>[] = []
    for (const [k, m] of guessers.entries()) {
      runs.push(fail(acceptTyped(m, R1, R2, wrong)))
      await until(() => a.log.length === k + 1)
    }
    expect(await fail(inviting)).toBe('bad-code')
    expect(a.log).toEqual(guessers.map((m) => `refused ${m.address} bad-code`))
    for (const m of guessers) m.clock.t = END
    expect(new Set(await Promise.all(runs))).toEqual(new Set(['no-answer']))
  })

  it('opens nothing when the rendezvous refuses the open signature (bad-sig), and the invite ends with it', async () => {
    class Unsigned extends PairRelay {
      override async pairOpen(url: string, open: PairOpen): Promise<string | null> {
        return super.pairOpen(url, { ...open, sig: 'ab'.repeat(64) })
      }
    }
    const a = side(new Unsigned())
    expect(await fail(invite(a, R1))).toBe('bad-sig')
  })

  it('gives out the invite string when the relay answers pair/open with no nameplate', async () => {
    class NoPair extends PairRelay {
      override async pairOpen(): Promise<string | null> {
        return null
      }
    }
    const a = side(new NoPair())
    const inviting = invite(a, R1)
    expect((await opened(a)).startsWith(INVITE_PREFIX)).toBe(true)
    a.clock.t = END
    expect(await fail(inviting)).toBe('invite-expired')
  })

  it('reads a pasted string with its line breaks; bad-code for neither; invite-expired for no open nameplate or a bad reach', async () => {
    const relay = new PairRelay()
    const b = side(relay)
    const v: Invite = { inviter: b.address, i: b.address, relay: R1, secret: '0'.repeat(32) }
    const s = inviteText(v)
    expect(await inviteOf(b.p, R1, ` ${s.slice(0, 20)}\r\n  ${s.slice(20)}\n`)).toEqual(v)
    expect(await fail(inviteOf(b.p, R1, 'ac-peer1:x'))).toBe('bad-invite')
    const [w0, w1, w2] = WORDS as [string, string, string]
    for (const t of ['nonsense', `472-${w0}-${w1}`, `0472-${w0}-${w1}-${w2}`, `472-${w0}-${w1}-zzzzzz`, '']) {
      expect(await fail(inviteOf(b.p, R1, t))).toBe('bad-code')
    }
    const code = `472-${w0}-${w1}-${w2}`
    expect(await fail(inviteOf(b.p, R1, code))).toBe('invite-expired')
    const good = { inviter: b.address, invitation: b.address, relays: [R1], ttl: 600, sig: '' }
    for (const bad of [{ inviter: 'x' }, { invitation: 'x' }, { relays: [] }, { relays: ['ftp://x'] }]) {
      relay.plates.set(`${R1} 472`, { ...good, ...bad })
      expect(await fail(inviteOf(b.p, R1, code))).toBe('invite-expired')
    }
    expect(await fail(inviteOf(side(new Relay()).p, R1, code))).toBe('invite-expired')
  })
})

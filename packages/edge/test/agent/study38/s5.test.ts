import { join } from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import { type AcRecord, type RecordKind, signRecord, verifyRecord } from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { AgentClient, buildRequest, WINDOW_MAX } from '../../../src/agent/index.ts'
import { addressRecord, keyRecord, P, T0, tempDir } from '../../support/fixtures.ts'
import { session, setup } from '../support.ts'
import { bootServer, closeAll, exchange, measure, track } from './support-b.ts'

// S5, `resign`: (a) the re-signed record equals the last in every
// member but `iat`; (b) no changed member, rotation, handle, policy or gkey statement is signed through it, from a
// session or the keep-alive client; (c) a second `resign` of one kind inside half a ttl is `rate-limited`; (d) no
// window open is `agent-locked`, and a session's `resign` is refused. A changed member signed is red.

const tmp = tempDir('s38-s5')
afterAll(() => tmp.cleanup())
afterEach(closeAll)
let n = 0
const home = (): string => join(tmp.dir, `s${n++}`)

/** The record's members without its signature. */
const members = (r: AcRecord): Record<string, unknown> => {
  const { sig: _sig, ...rest } = r
  return rest
}

/** Half the record's ttl, or half a key record's life: the least time between two `resign`s of one kind. */
const halfOf = (r: AcRecord): number => (r.kind === 'key' ? r.exp - r.iat : r.ttl) / 2

const KINDS: readonly RecordKind[] = ['address', 'accept-from', 'key']

/** The record the principal's dialog last approved, per kind: an address record with members set, an accept-from of two hours, a key record of an hour. */
function held(kind: RecordKind): AcRecord {
  if (kind === 'address') {
    return addressRecord(P.jane, { revoked: [P.bob.address], relays: ['http://r.test'], ttl: 3600 })
  }
  if (kind === 'key') return keyRecord(P.jane, T0 + 3600)
  return signRecord(P.jane.signing, {
    kind: 'accept-from',
    owner: P.jane.address,
    roots: ['*'],
    max_bytes: 65_536,
    ttl: 7200,
    iat: T0,
  })
}

describe('S5 (a): resign re-signs the last record with every member equal and iat moved', () => {
  it('address, accept-from and key: the same members, iat at max(now, last iat + 1), the same bytes a fresh signature gives', async () => {
    const out: string[] = []
    for (const kind of KINDS) {
      const m = await bootServer(home())
      const last = held(kind)
      m.records.set(kind, last)
      m.clock.advance(halfOf(last))
      const now = m.clock.now()
      const record = await track(new AgentClient(m.path)).resign(kind)
      const iat = Math.max(now, last.iat + 1)
      const expected = signRecord(P.jane.signing, { ...last, iat })
      const equalMembers = isDeepStrictEqual(members(record), members(expected))
      const bytes = record.sig === expected.sig
      expect(members(record)).toEqual({ ...members(last), iat })
      expect(verifyRecord(record, iat)).toEqual(record)
      expect(m.records.get(kind)).toEqual(record)
      expect(bytes).toBe(true)
      out.push(
        `${kind} members equal but iat ${equalMembers && record.iat === iat}, signature byte-equal ${bytes}`,
      )
    }
    measure('S5', 'a', `3 of 3 kinds signed; ${out.join('; ')}`)
  })
})

describe('S5 (b): a changed member or another statement is never signed through resign', () => {
  const CHANGES: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['relays', { relays: ['http://evil.test'] }],
    ['revoked', { revoked: [P.mallory.address] }],
    ['sealing_key', { sealing_key: 'ab'.repeat(32) }],
    ['rotation_key', { rotation_key: P.rotation.address }],
    ['ttl', { ttl: 1 }],
    ['rotation', { rotated_from: P.org.address }],
  ]
  const OTHER = ['rotate', 'rotation', 'record', 'handle', 'policy', 'policy-members', 'gkey', 'revoke']

  it('the keep-alive client: a frame carrying a changed member signs the held record unchanged, or is refused; 0 changed members signed', async () => {
    let served = 0
    let refused = 0
    let changed = 0
    for (const [name, c] of CHANGES) {
      for (const shape of ['beside args', 'in args']) {
        const m = await bootServer(home())
        const last = held('address')
        m.records.set('address', last)
        m.clock.advance(halfOf(last))
        const line =
          shape === 'beside args'
            ? JSON.stringify({ op: 'resign', args: ['address'], ...c })
            : JSON.stringify({ op: 'resign', args: ['address', c] })
        const [reply] = (await exchange(m.path, () => [line])) as Array<{
          ok: boolean
          record?: AcRecord
          code?: string
        }>
        if (reply?.ok === true && reply.record !== undefined) {
          served++
          const same = isDeepStrictEqual(members(reply.record), { ...members(last), iat: reply.record.iat })
          if (!same) changed++
          expect(members(reply.record), `${name} ${shape}`).toEqual({ ...members(last), iat: m.clock.now() })
        } else {
          refused++
        }
      }
    }
    measure(
      'S5',
      'b (changed members, keep-alive client)',
      `${CHANGES.length * 2} frames, ${served} served unchanged (the extra content ignored), ${refused} refused, changed members signed ${changed}`,
    )
    expect(changed).toBe(0)
  })

  it('the keep-alive client: an op that is a rotation, handle, policy or gkey statement is bad-shape, 0 signed', async () => {
    const m = await bootServer(home())
    const last = held('address')
    m.records.set('address', last)
    m.clock.advance(halfOf(last))
    const replies = (await exchange(m.path, () =>
      OTHER.map((op) => JSON.stringify({ op, args: ['address'] })),
    )) as Array<{ ok: boolean; code?: string }>
    const codes = replies.map((r) => (r.ok ? 'signed' : r.code))
    measure(
      'S5',
      'b (other statements, keep-alive client)',
      `${OTHER.length} ops, signed ${codes.filter((c) => c === 'signed').length}, bad-shape ${codes.filter((c) => c === 'bad-shape').length}`,
    )
    expect(codes).toEqual(OTHER.map(() => 'bad-shape'))
    expect(m.records.get('address')).toEqual(last)
  })

  it('a session: every op outside the closed set, a resign among them, is bad-shape at the session handler, 0 signed', () => {
    const { agent, sink } = setup()
    const s = session(agent)
    const lines = sink.lines.length
    const replies = ['resign', ...OTHER].map((op) => s.send(op as never, ['address']))
    const codes = replies.map((r) => (r.ok ? 'signed' : r.code))
    measure(
      'S5',
      'b (session)',
      `${replies.length} ops, signed ${codes.filter((c) => c === 'signed').length}, bad-shape ${codes.filter((c) => c === 'bad-shape').length}, audit lines added ${sink.lines.length - lines}`,
    )
    expect(codes).toEqual(replies.map(() => 'bad-shape'))
  })

  it('records, not asserted: a session-signed resign frame sent over the socket reaches the uid-only handler', async () => {
    const m = await bootServer(home())
    const last = held('address')
    m.records.set('address', last)
    m.clock.advance(halfOf(last))
    const [reply] = (await exchange(m.path, (nonce) => [
      buildRequest(P.session.signing, nonce, 0, 'resign' as never, ['address']),
    ])) as Array<{ ok: boolean; record?: AcRecord; code?: string }>
    const unchanged =
      reply?.record !== undefined &&
      isDeepStrictEqual(members(reply.record), { ...members(last), iat: reply.record.iat })
    measure(
      'S5',
      'b (session frame over the socket)',
      `a session-signed resign frame: ${reply?.ok ? 'served' : `refused ${reply?.code}`}; record unchanged but iat ${unchanged}. The socket proves a uid, not a session; the session handler refuses it (the arm above)`,
    )
    if (reply?.ok === true) expect(unchanged).toBe(true)
  })
})

describe('S5 (c): a second resign of one kind inside half a ttl is rate-limited', () => {
  it('per kind: served at half, refused at once, refused one second short of the next half, served at it', async () => {
    const out: string[] = []
    for (const kind of KINDS) {
      const m = await bootServer(home())
      const last = held(kind)
      m.records.set(kind, last)
      const client = track(new AgentClient(m.path))
      await expect(client.resign(kind)).rejects.toMatchObject({ code: 'rate-limited' })
      m.clock.advance(halfOf(last) - 1)
      await expect(client.resign(kind)).rejects.toMatchObject({ code: 'rate-limited' })
      m.clock.advance(1)
      const first = await client.resign(kind)
      await expect(client.resign(kind)).rejects.toMatchObject({ code: 'rate-limited' })
      m.clock.advance(halfOf(first) - 1)
      await expect(client.resign(kind)).rejects.toMatchObject({ code: 'rate-limited' })
      m.clock.advance(1)
      const second = await client.resign(kind)
      expect(second.iat).toBeGreaterThan(first.iat)
      out.push(`${kind} 2 signed, 4 rate-limited`)
    }
    measure('S5', 'c', out.join('; '))
  })
})

describe('S5 (d): no window open is agent-locked', () => {
  it('never logged in, logged out, and past the window end: 0 signed, each agent-locked', async () => {
    const results: string[] = []
    const probe = async (
      label: string,
      prepare: (m: Awaited<ReturnType<typeof bootServer>>) => void | Promise<void>,
      window = true,
    ) => {
      const m = await bootServer(home(), { window })
      const last = held('address')
      m.records.set('address', last)
      m.clock.advance(halfOf(last))
      await prepare(m)
      let code = 'signed'
      try {
        await track(new AgentClient(m.path)).resign('address')
      } catch (e) {
        code = String((e as { code?: unknown }).code)
      }
      results.push(`${label} ${code}`)
      expect(code, label).toBe('agent-locked')
    }
    await probe('no window opened', () => {}, false)
    await probe('after ac logout', (m) => void m.server.logout())
    await probe('past the window end', (m) => m.clock.advance(WINDOW_MAX))
    measure('S5', 'd', `${results.length} arms, signed 0, ${results.join('; ')}`)
  })
})

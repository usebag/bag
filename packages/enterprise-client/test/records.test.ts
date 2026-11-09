import {
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { parseRecord, verifyRecord } from '@usebag/core'
import { FsKeyStore, generateEdgeKeys } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import {
  ACCEPT_TTL,
  ADDRESS_TTL,
  outcomeLine,
  publishAgentRecords,
  readRecordsCopy,
  recordsDue,
  recordsPath,
} from '../src/records.ts'
import type { Session } from '../src/session.ts'
import { seededRng, T0, tempDir } from './support/fixtures.ts'

// The agent's own records at the org's relays: signed by A, published at each relay the grant
// names, again at half the address record's ttl or when the relays change, and retried while a relay fails.

const tmp = tempDir('records')
afterAll(() => tmp.cleanup())
let n = 0
const RELAYS = ['http://127.0.0.1:47860', 'https://relay2.acme.example']

function setup(relays: string[] = RELAYS) {
  const home = join(tmp.dir, `home-${n++}`)
  mkdirSync(join(home, 'enterprise'), { recursive: true, mode: 0o700 })
  const keys = generateEdgeKeys(seededRng(`agent-${n}`))
  const root = generateEdgeKeys(seededRng(`root-${n}`)).signing.address
  const session = {
    state: 'live',
    name: 'acme-example',
    agent_address: keys.signing.address,
    org: { domain: 'acme.example', root, relays },
  } as unknown as Session
  const sent: Array<{ url: string; body: string }> = []
  const down = new Set<string>()
  const publisher = {
    async publish(url: string, bytes: Uint8Array) {
      if (down.has(url)) throw Object.assign(new Error('no answer'), { status: 0 })
      sent.push({ url, body: Buffer.from(bytes).toString('utf8') })
      return {} as never
    },
  }
  return { home, keys, root, session, sent, down, publisher }
}

describe('publishAgentRecords', () => {
  it('publishes the address record and the accept-from at every relay, signed by A, with the org root accepted', async () => {
    const w = setup()
    const out = await publishAgentRecords({ ...w, now: T0 })
    expect(out.map((o) => `${o.kind} ${o.relay} ${o.ok}`)).toEqual([
      `address ${RELAYS[0]} true`,
      `accept-from ${RELAYS[0]} true`,
      `address ${RELAYS[1]} true`,
      `accept-from ${RELAYS[1]} true`,
    ])
    const address = verifyRecord(parseRecord(w.sent[0]?.body ?? ''), T0)
    const accept = verifyRecord(parseRecord(w.sent[1]?.body ?? ''), T0)
    expect(address).toMatchObject({
      kind: 'address',
      key: w.keys.signing.address,
      relays: RELAYS,
      ttl: ADDRESS_TTL,
    })
    expect((address as { sealing_key: string | null }).sealing_key).toMatch(/^[0-9a-f]{64}$/)
    expect(accept).toMatchObject({
      kind: 'accept-from',
      owner: w.keys.signing.address,
      roots: [w.root],
      ttl: ACCEPT_TTL,
    })
    expect(readRecordsCopy(w.home)).toEqual({
      v: 1,
      agent_address: w.keys.signing.address,
      iat: T0,
      relays: RELAYS,
      roots: [w.root],
    })
    expect(statSync(recordsPath(w.home)).mode & 0o777).toBe(0o600)
  })

  it('writes the copy through a new file of a random name: a link planted at the old fixed tmp name is not followed', async () => {
    const w = setup()
    const target = join(w.home, 'elsewhere.txt')
    writeFileSync(target, 'untouched\n')
    symlinkSync(target, `${recordsPath(w.home)}.tmp`)
    await publishAgentRecords({ ...w, now: T0 })
    expect(readFileSync(target, 'utf8')).toBe('untouched\n')
    expect(lstatSync(`${recordsPath(w.home)}.tmp`).isSymbolicLink()).toBe(true)
    expect(lstatSync(recordsPath(w.home)).isFile()).toBe(true)
    expect(statSync(recordsPath(w.home)).mode & 0o777).toBe(0o600)
    expect(readRecordsCopy(w.home)?.iat).toBe(T0)
    // No temporary file is left beside it.
    const dir = join(w.home, 'enterprise')
    expect(readdirSync(dir).filter((f) => f.startsWith('records.json.') && f !== 'records.json.tmp')).toEqual(
      [],
    )
  })

  it('is not due again until half the ttl, then republishes with a newer iat', async () => {
    const w = setup()
    await publishAgentRecords({ ...w, now: T0 })
    expect(await publishAgentRecords({ ...w, now: T0 + ADDRESS_TTL / 2 - 1 })).toEqual([])
    const again = await publishAgentRecords({ ...w, now: T0 + ADDRESS_TTL / 2 })
    expect(again).toHaveLength(4)
    expect(readRecordsCopy(w.home)?.iat).toBe(T0 + ADDRESS_TTL / 2)
  })

  it('republishes at once when the relays change', async () => {
    const w = setup()
    await publishAgentRecords({ ...w, now: T0 })
    const moved = { ...w.session, org: { ...w.session.org, relays: [RELAYS[0] as string] } } as Session
    expect(recordsDue(moved, readRecordsCopy(w.home), T0 + 1)).toBe(true)
    const out = await publishAgentRecords({ ...w, session: moved, now: T0 + 1 })
    expect(out).toHaveLength(2)
    expect(readRecordsCopy(w.home)?.relays).toEqual([RELAYS[0]])
  })

  it("signs the accept list's roots and republishes at once when they change; a copy with no roots reads as the org root", async () => {
    const w = setup()
    await publishAgentRecords({ ...w, now: T0 })
    const partner = generateEdgeKeys(seededRng('partner')).signing.address
    const listed = { ...w.session, accept_roots: [w.root, partner, 'domain:okok.example'] } as Session
    expect(recordsDue(listed, readRecordsCopy(w.home), T0 + 1)).toBe(true)
    expect(await publishAgentRecords({ ...w, session: listed, now: T0 + 1 })).toHaveLength(4)
    const accept = verifyRecord(parseRecord(w.sent.at(-1)?.body ?? ''), T0 + 1)
    expect((accept as unknown as { roots: string[] }).roots).toEqual([w.root, partner, 'domain:okok.example'])
    expect(readRecordsCopy(w.home)?.roots).toEqual([w.root, partner, 'domain:okok.example'])
    expect(recordsDue(listed, readRecordsCopy(w.home), T0 + 2)).toBe(false)
    // A copy written before the accept list (no roots) is not due for the org root alone, and is for a list.
    const old = { v: 1 as const, agent_address: w.keys.signing.address, iat: T0, relays: RELAYS }
    expect(recordsDue(w.session, old, T0 + 2)).toBe(false)
    expect(recordsDue(listed, old, T0 + 2)).toBe(true)
    writeFileSync(recordsPath(w.home), JSON.stringify({ ...old, roots: [1] }))
    expect(readRecordsCopy(w.home)).toBeNull()
  })

  it('keeps no copy while a relay fails, so the next tick tries again', async () => {
    const w = setup()
    w.down.add(RELAYS[1] as string)
    const out = await publishAgentRecords({ ...w, now: T0 })
    expect(out.filter((o) => !o.ok).map((o) => `${o.kind} ${o.code}`)).toEqual([
      'address unreachable',
      'accept-from unreachable',
    ])
    expect(readRecordsCopy(w.home)).toBeNull()
    w.down.clear()
    expect(await publishAgentRecords({ ...w, now: T0 + 5 })).toHaveLength(4)
  })

  it('does nothing for a session that is not live or names no relay', async () => {
    const none = setup([])
    expect(await publishAgentRecords({ ...none, now: T0 })).toEqual([])
    const frozen = setup()
    const s = { ...frozen.session, state: 'frozen' } as Session
    expect(await publishAgentRecords({ ...frozen, session: s, now: T0 })).toEqual([])
    expect(frozen.sent).toEqual([])
  })

  it('names each failure by its code, its status or error; publishes nothing under keys not the agent', async () => {
    const w = setup()
    const errors: unknown[] = [
      Object.assign(new Error('x'), { code: 'resolve-failed' }),
      { status: 403 },
      null,
    ]
    let i = 0
    const failing = {
      async publish(): Promise<never> {
        throw errors[Math.floor(i++ / 2)]
      },
    }
    const relays = ['https://a.example', 'https://b.example', 'https://c.example']
    const s = { ...w.session, org: { ...w.session.org, relays } } as Session
    const out = await publishAgentRecords({ ...w, session: s, publisher: failing, now: T0 })
    expect(out.map(outcomeLine)).toEqual([
      'records address https://a.example failed resolve-failed',
      'records accept-from https://a.example failed resolve-failed',
      'records address https://b.example failed http-403',
      'records accept-from https://b.example failed http-403',
      'records address https://c.example failed error',
      'records accept-from https://c.example failed error',
    ])
    const other = generateEdgeKeys(seededRng('another agent'))
    expect(await publishAgentRecords({ ...w, keys: other, now: T0 })).toEqual([])
    expect(w.sent).toEqual([])
  })

  it('reads no copy from a file that is not one: a fresh publish follows', async () => {
    const w = setup()
    for (const text of ['{', '{"v":2}', '{"v":1,"agent_address":"x","iat":1,"relays":[1]}']) {
      writeFileSync(recordsPath(w.home), text, { mode: 0o600 })
      expect(readRecordsCopy(w.home)).toBeNull()
    }
    expect(await publishAgentRecords({ ...w, now: T0 })).toHaveLength(4)
  })

  it('a published record holds no key seed', async () => {
    const w = setup()
    new FsKeyStore(join(w.home, 'keys')).create('agent', w.keys)
    const seed = JSON.parse(readFileSync(join(w.home, 'keys', 'agent.json'), 'utf8')).sign_seed as string
    expect(seed).toMatch(/^[0-9a-f]{64}$/)
    await publishAgentRecords({ ...w, now: T0 })
    for (const { body } of w.sent) expect(body).not.toContain(seed)
  })
})

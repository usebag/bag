import { existsSync } from 'node:fs'
import { join } from 'node:path'
import {
  acceptCopy,
  addressCopy,
  RelayError,
  readAuditLines,
  SqliteStore,
  verifyAuditLog,
} from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { CLI_AUDIT, createIdentity, OFFERED_AGAIN, publishFirstRecords } from '../src/index.ts'
import { client, FakeRelay, fakeIo, folder } from './support.ts'

// A new identity's first records at its relays, as onboard makes them: the first epoch's key record, a null-sealing
// address record, and an accept-from naming only itself; the home's copies kept. A key file only: no Keychain.

const R1 = 'https://r1.example'
const R2 = 'https://r2.example'
const FILE = { into: { custody: 'file' as const }, defaulted: false, allowNew: true }

/** The cli-audit.jsonl lines of jane in `home`, as written. */
const janeAudit = (home: string): string[] => readAuditLines(join(home, 'state', 'jane', CLI_AUDIT))

/** A line's event, decision and parsed detail. */
const eventOf = (l: string): { event: string; decision: string; detail: unknown } => {
  const v = JSON.parse(l) as { event: string; decision: string; detail: string | null }
  return { event: v.event, decision: v.decision, detail: v.detail === null ? null : JSON.parse(v.detail) }
}

/** The policy line one publish of `record` at `relay` writes, its outcome ok or the failure's code. */
const published = (record: string, relay: string, outcome = 'ok') => ({
  event: 'policy',
  decision: outcome === 'ok' ? 'accept' : 'reject',
  detail: { step: 'publish', record, relay, outcome },
})

/** A home holding the key file of jane, made with its service entry naming R1 and R2. */
function jane(net: FakeRelay): { home: string; address: string; io: ReturnType<typeof fakeIo> } {
  const home = folder()
  const io = fakeIo({ relay: net })
  const address = createIdentity(io, home, 'jane', { ...FILE, relays: [R1, R2] })
  return { home, address, io: fakeIo({ relay: net }) }
}

describe('publishFirstRecords', () => {
  it('publishes the key, address and accept-from records to each named relay, one line each, and keeps the copies', async () => {
    const net = new FakeRelay()
    const { home, address, io } = jane(net)
    await publishFirstRecords(io, home, 'jane', [R1, R2], client(net))
    expect(io.said).toEqual(
      ['key', 'address', 'accept-from'].flatMap((k) => [R1, R2].map((u) => `published ${k} ${address} ${u}`)),
    )
    for (const url of [R1, R2])
      for (const kind of ['key', 'address', 'accept-from'])
        expect([url, kind, net.records.has(`${url} ${address} ${kind}`)]).toEqual([url, kind, true])
    expect(addressCopy(home, 'jane', address)?.relays).toEqual([R1, R2])
    expect(addressCopy(home, 'jane', address)?.sealing_key).toBeNull()
    expect(acceptCopy(home, 'jane', address)?.roots).toEqual([address])
    expect(net.rootsAt(R1, address)).toEqual([address])
    // The trace the command line leaves for the same act, in cli-audit.jsonl, anchored, verified: one policy line per
    // address and accept-from publish per relay, and the rotation's line.
    const state = join(home, 'state', 'jane')
    const lines = janeAudit(home)
    expect(lines.map((l) => (JSON.parse(l) as { event: string }).event)).toEqual([
      'policy',
      'policy',
      'rotate',
      'policy',
      'policy',
    ])
    expect(lines[2]).toContain(`"from":"${address}"`)
    expect(lines.map(eventOf).filter((l) => l.event === 'policy')).toEqual([
      published('address', R1),
      published('address', R2),
      published('accept-from', R1),
      published('accept-from', R2),
    ])
    const store = new SqliteStore(join(state, 'edge.sqlite'), { lock: false })
    const anchor = store.auditAnchorGet(CLI_AUDIT)
    store.close()
    expect(anchor).toMatchObject({ seq: 5 })
    expect(verifyAuditLog(lines, anchor)).toMatchObject({ ok: true })
  })

  it('a relay that does not take them is a failed line, and the others hold them: done', async () => {
    const net = new FakeRelay()
    net.down.add(R2)
    const { home, address, io } = jane(net)
    await publishFirstRecords(io, home, 'jane', [R1, R2], client(net))
    expect(io.said).toEqual([
      `published key ${address} ${R1}`,
      `failed key ${address} ${R2} unreachable: ${OFFERED_AGAIN}`,
      `published address ${address} ${R1}`,
      `failed address ${address} ${R2} unreachable`,
      `published accept-from ${address} ${R1}`,
      `failed accept-from ${address} ${R2} unreachable`,
    ])
    expect(addressCopy(home, 'jane', address)).not.toBeNull()
  })

  it('audits each address and accept-from publish, a failed one as reject with its code, and the file verifies', async () => {
    const net = new FakeRelay()
    net.down.add(R2)
    const { home, io } = jane(net)
    await publishFirstRecords(io, home, 'jane', [R1, R2], client(net))
    const lines = janeAudit(home)
    expect(lines.map(eventOf).filter((l) => l.event === 'policy')).toEqual([
      published('address', R1),
      published('address', R2, 'unreachable'),
      published('accept-from', R1),
      published('accept-from', R2, 'unreachable'),
    ])
    const store = new SqliteStore(join(home, 'state', 'jane', 'edge.sqlite'), { lock: false })
    const anchor = store.auditAnchorGet(CLI_AUDIT)
    store.close()
    expect(anchor).toMatchObject({ seq: lines.length })
    expect(verifyAuditLog(lines, anchor)).toMatchObject({ ok: true })
  })

  it('the failed key line says the epoch key will be offered again', () => {
    expect(OFFERED_AGAIN).toBe('will be offered again at the next rotation')
  })

  it('no relay taking them refuses with the relay code, and the identity stays, as onboard keeps its keys', async () => {
    const net = new FakeRelay()
    net.down.add(R1)
    net.down.add(R2)
    const { home, io } = jane(net)
    const e = await publishFirstRecords(io, home, 'jane', [R1, R2], client(net)).catch((x: unknown) => x)
    expect(e).toMatchObject({ code: 'unreachable' })
    expect(String((e as Error).message)).toContain(
      'jane is made, but no relay took its key and address record',
    )
    expect(e).not.toBeInstanceOf(RelayError)
    expect(existsSync(join(home, 'keys', 'jane.json'))).toBe(true)
    expect(existsSync(join(home, 'records', 'jane.address.json'))).toBe(false)
  })
})

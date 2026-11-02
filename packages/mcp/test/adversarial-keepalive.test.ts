import { randomBytes } from 'node:crypto'
import { join } from 'node:path'
import {
  type AcceptFromRecord,
  type AddressRecord,
  generateSealingKey,
  type KeyRecord,
  parseRecord,
  recordSigner,
  serializeRecord,
  signRecord,
  toHex,
} from '@usebag/core'
import { KeyEpochStore, type PublishResult, RelayError } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ConfigError, parseConfig } from '../src/config.ts'
import { EPOCH_DUE } from '../src/open.ts'
import {
  FakeClock,
  ManualTimers,
  P,
  RELAY,
  saveKeys,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The keep-alive of the server's own records (packages/mcp/src/keepalive.ts). A record that
// names rotated_from is never re-signed (outcome `rotation`, line 125); a session cannot run it (parseConfig refuses
// --keep-alive-records with --auth or --chain-cmd, config.ts lines 199 to 204); a record not signed by the server's own
// key is not kept (line 175); and a re-signed record that is not newer than the one the relay holds meets 409
// stale-record (spec/SPEC.md §8, line 479, and Appendix A line 841). The relay here is the MCP tests' memory relay with
// that one rule of the real relay's added (StaleRelay: a record whose iat is not newer than the stored one's is 409
// stale-record, as crates/ac-relay/src/policy.rs line 28 states): this runs in process, so the Rust relay's own check
// is the e2e set's, not exercised here. Forward secrecy: the server publishes an epoch of its own at its first
// cycle when none is held, which re-signs the address record; the cases that are not about it start from a home that
// already holds a fresh epoch 1, as a server of an identity that has run before does, so that only the keep-alive's own
// re-sign meets the relay's order (the last case here is the rotation's own, on that relay).

const TTL = 600
const SECOND = 'http://second.test'

/** The memory relay with the relay's record order: a record not newer than the stored one is 409 stale-record. */
class StaleRelay extends MemoryRelay {
  readonly refused: string[] = []
  readonly recordPublishes: string[] = []
  /** A record a person publishes at the relay the moment the next address record arrives (a race), then cleared. */
  race: AddressRecord | null = null

  override async publish(url: string, bytes: Uint8Array): Promise<PublishResult> {
    const v = JSON.parse(new TextDecoder().decode(bytes)) as { kind?: unknown }
    if (v.kind !== undefined) {
      const r = parseRecord(bytes)
      this.recordPublishes.push(`${r.kind}@${r.iat - T0}`)
      if (this.race !== null && r.kind === 'address') {
        const person = this.race
        this.race = null
        this.records.set(`${url} ${recordSigner(person)} address`, serializeRecord(person))
      }
      const stored = this.records.get(`${url} ${recordSigner(r)} ${r.kind}`)
      if (stored !== undefined && parseRecord(stored).iat >= r.iat) {
        this.refused.push(`${r.kind}@${r.iat - T0}`)
        throw new RelayError('stale-record', 409, null, 'a record not newer than the stored one')
      }
    }
    return super.publish(url, bytes)
  }
}

let tmp: ReturnType<typeof tempDir>
let relay: StaleRelay
let clock: FakeClock
let timers: ManualTimers
const servers: TestServer[] = []
const stdout = watchStdout()

function address(o: { iat?: number; relays?: string[]; rotatedFrom?: string } = {}): AddressRecord {
  return signRecord(P.alice.keys.signing, {
    kind: 'address',
    key: P.alice.address,
    sealing_key: toHex(P.alice.keys.sealing.publicKey),
    relays: o.relays ?? [RELAY],
    rotation_key: null,
    revoked: [],
    ttl: TTL,
    iat: o.iat ?? T0,
    rotated_from: o.rotatedFrom ?? null,
  })
}

function accept(iat = T0): AcceptFromRecord {
  return signRecord(P.alice.keys.signing, {
    kind: 'accept-from',
    owner: P.alice.address,
    roots: [P.bob.address],
    max_bytes: 65_536,
    ttl: 86_400,
    iat,
  })
}

const stored = (kind: 'address' | 'accept-from'): AddressRecord =>
  parseRecord(relay.records.get(`${RELAY} ${P.alice.address} ${kind}`) as Uint8Array) as AddressRecord

async function alice(): Promise<TestServer> {
  const s = await testServer({
    home: join(tmp.dir, 'alice'),
    name: 'alice',
    relay,
    clock,
    timers,
    args: ['--keep-alive-records', '--trust-root', P.bob.address],
    pid: 1,
  })
  servers.push(s)
  await s.running.kept
  return s
}

const lastCycle = async (s: TestServer): Promise<Record<string, unknown>> =>
  ((await s.call('status')).value.keep_alive as { last: Record<string, unknown> }).last

/** Moves the clock to `t` and runs the keep-alive's pending cycle. */
async function cycle(s: TestServer, t: number): Promise<void> {
  const before = s.log.lines.filter((l) => l.event === 'keep-alive').length
  clock.t = t
  timers.fire()
  await until('the cycle', () => s.log.lines.filter((l) => l.event === 'keep-alive').length > before)
}

beforeEach(() => {
  stdout.start()
  tmp = tempDir('adversarial-keepalive')
  relay = new StaleRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
  saveKeys(join(tmp.dir, 'alice'), P.alice)
})

/** Alice's epoch store, as the server finds it in her home. */
const epochStore = (): KeyEpochStore => new KeyEpochStore(join(tmp.dir, 'alice', 'key-records'))

/** Epoch 1, issued at T0: the identity has run under forward secrecy, and its next epoch is 11 hours off. */
function heldEpoch(): void {
  const rng = (length: number): Uint8Array => new Uint8Array(randomBytes(length))
  epochStore().put(P.alice.address, 1, generateSealingKey(rng), T0, T0 + 86_400)
  epochStore().markPublished(P.alice.address, 1) // a published epoch (put keeps it unpublished)
}

afterEach(async () => {
  for (const s of servers.splice(0)) await s.close()
  tmp.cleanup()
  stdout.check()
})

describe('the keep-alive re-signs only its own records, never a rotation, never for a session', () => {
  it('a session cannot run the keep-alive: --keep-alive-records with --auth or --chain-cmd is usage at start', () => {
    // V1: the flag alone, on a self-rooted identity, parses.
    expect(
      parseConfig(['--as', 'alice', '--dir', tmp.dir, '--relay', RELAY, '--keep-alive-records'], {}),
    ).toMatchObject({
      keepAliveRecords: true,
    })
    const refusals: string[] = []
    for (const source of [
      ['--auth', 'chain.json'],
      ['--chain-cmd', 'print-chain'],
    ]) {
      let code = 'parsed'
      try {
        parseConfig(
          [
            '--as',
            's',
            '--dir',
            tmp.dir,
            '--relay',
            RELAY,
            ...source,
            '--mailbox',
            P.jane.address,
            '--keep-alive-records',
          ],
          {},
        )
      } catch (e) {
        expect(e).toBeInstanceOf(ConfigError)
        expect((e as Error).message).toBe(
          "usage: --keep-alive-records re-signs this identity's own records: a session cannot sign its principal's",
        )
        code = (e as ConfigError).code
      }
      refusals.push(`${source[0]}: ${code}`)
    }
    expect(refusals).toEqual(['--auth: usage', '--chain-cmd: usage'])
    console.log(`MEASURE (session): ${refusals.join('; ')}`)
  })

  it('a record that names rotated_from is never re-signed, past half its ttl and after; only the key record goes out, once', async () => {
    heldEpoch()
    await relay.publish(RELAY, serializeRecord(address({ rotatedFrom: P.carol.address })))
    const s = await alice()
    const outcomes = [(await lastCycle(s)).outcome]
    for (const t of [T0 + 60, T0 + 180, T0 + 420, T0 + 900]) {
      await cycle(s, t)
      outcomes.push((await lastCycle(s)).outcome)
    }
    expect(outcomes).toEqual(['rotation', 'rotation', 'rotation', 'rotation', 'rotation'])
    // The test's own put, then the epoch's key record at the first cycle; every cycle after reads it back (Appendix B 110).
    expect(relay.recordPublishes).toEqual(['address@0', 'key@0'])
    expect(stored('address').rotated_from).toBe(P.carol.address)
    expect(stored('address').iat).toBe(T0)
    console.log(
      `MEASURE (rotation): ${outcomes.length} cycles to ts + 900 (half the ttl is ts + 300) -> rotation each, 0 address records published`,
    )
  })

  it("a record in the server's slot that its own key did not sign is not kept: no-record, only the key record offered", async () => {
    heldEpoch()
    // The genuine record with its relays edited (its sig kept), and bob's own record, in alice's slot at the relay.
    const edited = { ...address(), relays: [RELAY, 'https://elsewhere.test'] }
    const outcomes: unknown[] = []
    for (const bytes of [
      new TextEncoder().encode(JSON.stringify(edited)),
      serializeRecord(
        signRecord(P.bob.keys.signing, {
          kind: 'address',
          key: P.bob.address,
          sealing_key: toHex(P.bob.keys.sealing.publicKey),
          relays: [RELAY],
          rotation_key: null,
          revoked: [],
          ttl: TTL,
          iat: T0,
          rotated_from: null,
        }),
      ),
    ]) {
      relay.records.set(`${RELAY} ${P.alice.address} address`, bytes)
      const s = await alice()
      outcomes.push((await lastCycle(s)).outcome)
      await s.close()
      servers.splice(servers.indexOf(s), 1)
    }
    expect(outcomes).toEqual(['no-record', 'no-record'])
    expect(relay.recordPublishes).toEqual(['key@0'])
    console.log(
      `MEASURE (not its own): an edited record and bob's record in alice's slot -> ${outcomes.join(', ')}; 0 address records published`,
    )
  })

  it('a re-signed record not newer than the one the relay holds is 409 stale-record; the newer record is kept alive after', async () => {
    heldEpoch()
    await relay.publish(RELAY, serializeRecord(address()))
    await relay.publish(RELAY, serializeRecord(accept()))
    const s = await alice()
    expect(await lastCycle(s)).toMatchObject({ outcome: 'not-due' })
    // V1: the relay's rule refuses a replay of the stored record, and takes a newer one.
    await expect(relay.publish(RELAY, serializeRecord(address()))).rejects.toMatchObject({
      code: 'stale-record',
      status: 409,
    })
    relay.refused.length = 0
    // At half the ttl the keeper re-signs with iat ts + 300; a person's republish (a second relay listed) lands at
    // the relay first, with the same iat.
    relay.race = address({ iat: T0 + TTL / 2, relays: [RELAY, SECOND] })
    await cycle(s, T0 + TTL / 2)
    const raced = await lastCycle(s)
    expect(relay.refused).toEqual([`address@${TTL / 2}`])
    expect(raced).toMatchObject({ outcome: 'publish-failed', published: 1, failed: 1 })
    expect(stored('address').relays).toEqual([RELAY, SECOND])
    expect(stored('address').iat).toBe(T0 + TTL / 2)
    // The next cycle reads the person's newer record and keeps it alive: due at its own half ttl, then re-signed.
    await cycle(s, T0 + TTL / 2 + 60)
    expect(await lastCycle(s)).toMatchObject({ outcome: 'not-due' })
    await cycle(s, T0 + TTL)
    const kept = await lastCycle(s)
    expect(kept).toMatchObject({ outcome: 're-signed', published: 2, failed: 0 })
    expect([stored('address').relays, stored('address').iat]).toEqual([[RELAY, SECOND], T0 + TTL])
    expect(relay.refused).toEqual([`address@${TTL / 2}`])
    console.log(
      `MEASURE (stale): the re-sign at ts + ${TTL / 2} met 409 stale-record (${relay.refused.length} refusal) -> ${raced.outcome}; ` +
        `the person's record stayed; at ts + ${TTL} its content was re-signed (${kept.outcome})`,
    )
  })

  it('a relay that holds the key record is not offered it; one that gave no answer to the read is, and its stale-record counts as held', async () => {
    heldEpoch()
    await relay.publish(RELAY, serializeRecord(address()))
    await relay.publish(RELAY, serializeRecord(accept()))
    const s = await alice()
    relay.recordPublishes.length = 0
    await cycle(s, T0 + 10)
    expect(relay.recordPublishes).toEqual([])
    const read = relay.fetchRecord.bind(relay)
    const fetch = vi.spyOn(relay, 'fetchRecord').mockImplementation(async (url, at, kind) => {
      if (kind === 'key') throw new RelayError(null, 0, null, 'connection refused')
      return read(url, at, kind)
    })
    await cycle(s, T0 + 20)
    fetch.mockRestore()
    expect(relay.refused).toEqual(['key@0'])
    const last = await lastCycle(s)
    expect(last).toMatchObject({ outcome: 'not-due', published: 0, failed: 0 })
    expect(last).not.toHaveProperty('lagging')
  })

  it('a rotation on the relay that orders records: the key record, then the address record with no sealing key, none refused', async () => {
    // A record from before forward secrecy, an epoch due at once, and a clock a second on: the rotation's re-sign is
    // newer than the stored record, so the relay takes both of its records, and the keep-alive goes on from the new one.
    await relay.publish(RELAY, serializeRecord(address()))
    await relay.publish(RELAY, serializeRecord(accept()))
    relay.refused.length = 0
    const before = relay.recordPublishes.length
    clock.t = T0 + 1
    const s = await alice()
    const published = relay.recordPublishes.slice(before)
    // The relay took both from the rotation, so the cycle after it offers neither again.
    expect(published).toEqual(['key@1', 'address@1'])
    expect(relay.refused).toEqual([])
    const key = parseRecord(relay.records.get(`${RELAY} ${P.alice.address} key`) as Uint8Array) as KeyRecord
    expect([key.iat, key.exp, key.sealing_key === toHex(P.alice.keys.sealing.publicKey)]).toEqual([
      T0 + 1,
      T0 + 1 + 86_400,
      false,
    ])
    expect(stored('address')).toMatchObject({ sealing_key: null, iat: T0 + 1, relays: [RELAY] })
    const after = await lastCycle(s)
    expect(after).toMatchObject({ outcome: 'not-due', published: 0, failed: 0 })
    expect(after).not.toHaveProperty('lagging')
    expect(s.running.opened.epochs?.dueAt()).toBe(T0 + 1 + EPOCH_DUE)
    console.log(
      `MEASURE (epoch): a pre-forward-secrecy record at ts met the first cycle at ts + 1: ${published.join(', ')} published, ${relay.refused.length} refused; the record served names no sealing key`,
    )
  })
})

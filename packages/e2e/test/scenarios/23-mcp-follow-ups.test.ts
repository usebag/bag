import { randomBytes } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { performance } from 'node:perf_hooks'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import {
  type AcceptFromRecord,
  type AddressRecord,
  generateSealingKey,
  type Hop,
  type KeyRecord,
  parseRecord,
  serializeRecord,
  signHop,
  signRecord,
  toHex,
  verifyRecord,
} from '@usebag/core'
import { type EdgeKeys, FsKeyStore, KeyEpochStore, readAuditLines, verifyAuditLog } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  holdsNoSecret,
  now,
  type Party,
  party,
  REPO,
  rawPublish,
  sleep,
  untilSecond,
  world,
} from '../harness.ts'

// Scenario 23-mcp: the MCP follow-ups through the real relay, servers as child
// processes (`node packages/mcp/src/main.ts`) driven by the SDK's Client, on real SQLite homes and real time. Three
// flows run at once: (L1) an ask that the 25 s window cuts short and a resume that returns the answer sent between the
// calls; (L2) a session whose chain, from --chain-cmd, is renewed before its last hop expires and keeps sending after
// that expiry, beside a control session on a file that is never renewed and is refused hop-expired; (L4) a short-ttl
// address record that the keep-alive re-signs at half its ttl, read back at the relay, and a peer that resolves it
// after the first record's expiry. Carol's identity has run under forward secrecy: her home holds epoch 1, whose key
// record is published beside an address record with no sealing key, so the keep-alive keeps that record alive and
// rotates nothing for 12 hours; a record from before forward secrecy meets the rotation in packages/mcp/test.

const MAIN = join(REPO, 'packages', 'mcp', 'src', 'main.ts')

type Json = Record<string, unknown>

interface Server {
  readonly name: string
  readonly client: Client
  readonly stderr: string[]
  readonly results: string[]
  call(tool: string, args?: Json): Promise<{ readonly isError: boolean; readonly value: Json }>
  close(): Promise<void>
}

async function server(name: string, home: string, url: string, args: readonly string[]): Promise<Server> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [MAIN, '--as', name, '--dir', home, '--relay', url, ...args],
    cwd: REPO,
    stderr: 'pipe',
  })
  const stderr: string[] = []
  transport.stderr?.on('data', (c: Buffer) => stderr.push(c.toString('utf8')))
  const client = new Client({ name: `e2e-${name}`, version: '0.0.0' })
  await client.connect(transport)
  const results: string[] = []
  return {
    name,
    client,
    stderr,
    results,
    async call(tool, a = {}) {
      const r = await client.callTool({ name: tool, arguments: a }, undefined, { timeout: 60_000 })
      const text = (r.content as { text: string }[])[0]?.text ?? ''
      results.push(text)
      return { isError: r.isError === true, value: JSON.parse(text) as Json }
    },
    close: () => client.close(),
  }
}

/** A key file in a home of its own: the party's keys, or a session's signing key with its principal's sealing key. */
function saveKeys(home: string, name: string, keys: EdgeKeys): void {
  new FsKeyStore(join(home, 'keys')).save(name, keys)
}

async function publish(
  url: string,
  ...records: (AddressRecord | AcceptFromRecord | KeyRecord)[]
): Promise<void> {
  for (const r of records) expect((await rawPublish(url, serializeRecord(r))).status).toBe(200)
}

/** A party's record of a kind as the relay serves it now (spec/SPEC.md §8.4). */
async function relayRecord(url: string, p: Party, kind: 'address' | 'accept-from'): Promise<Json> {
  const res = await fetch(`${url}/v0/fetch/record/${p.address}/${kind}`)
  expect(res.status).toBe(200)
  return parseRecord(new Uint8Array(await res.arrayBuffer())) as unknown as Json
}

const writeChain = (file: string, hops: readonly Hop[]): void =>
  writeFileSync(file, `${JSON.stringify(hops)}\n`)

describe('e2e scenario 23-mcp: host-safe waits, chain renewal and record keep-alive through the real relay', () => {
  it('(23) L1: an unanswered ask returns pending at the 25 s window and ask with resume alone returns the answer sent between the calls; L2: a session renewed through --chain-cmd before its last hop expires sends after that expiry and Bob accepts it, while a control session on a file is refused hop-expired with the advice to re-send under a renewed chain; L4: the keep-alive re-signs a 20 s address record and its accept-from record at half the ttl, the relay serves them, and Bob resolves the identity after the first record expired; every audit log verifies and no key appears in any output', async () => {
    const w = await world('s23')
    const A = party('alice')
    const B = party('bob')
    const C = party('carol')
    const org = party('org')
    const jane = party('jane')
    const S = party('session')
    const K = party('control')
    const homes = Object.fromEntries(
      ['alice', 'bob', 'carol', 'session', 'control'].map((n) => [n, join(w.dir, `${n}-home`)]),
    ) as Record<'alice' | 'bob' | 'carol' | 'session' | 'control', string>
    saveKeys(homes.alice, 'alice', A.keys)
    saveKeys(homes.bob, 'bob', B.keys)
    saveKeys(homes.carol, 'carol', C.keys)
    saveKeys(homes.session, 'session', { signing: S.signing, sealing: jane.sealing })
    saveKeys(homes.control, 'control', { signing: K.signing, sealing: jane.sealing })

    // The records: Alice, Bob, org and jane for an hour; Carol's address record for 20 s, for the keep-alive, with her
    // epoch 1 (a key record and the key in her home) and no sealing key in the address record.
    const t0 = now()
    await publish(
      w.url,
      addressRecord(A, { relays: [w.url] }),
      acceptFrom(A, [B.address]),
      addressRecord(B, { relays: [w.url] }),
      acceptFrom(B, [A.address, org.address, C.address]),
      addressRecord(org, { relays: [w.url] }),
      addressRecord(jane, { relays: [w.url] }),
      acceptFrom(jane, [B.address]),
    )
    // Carol's 20 s record is anchored on tc, read right before it is published; her server is the next one started
    // (below), so the half-ttl point tc + 10 is ahead of her keep-alive's first cycle by a server start, not by five.
    const tc = now()
    const carolRecord = addressRecord(C, { relays: [w.url], ttl: 20, iat: tc, sealing: false })
    const carolAccept = acceptFrom(C, [B.address])
    const epoch = generateSealingKey((length) => new Uint8Array(randomBytes(length)))
    new KeyEpochStore(join(homes.carol, 'key-records')).put(C.address, 1, epoch, tc, tc + 86_400)
    new KeyEpochStore(join(homes.carol, 'key-records')).markPublished(C.address, 1) // a published epoch (put keeps it unpublished)
    const carolKey = signRecord(C.signing, {
      kind: 'key',
      key: C.address,
      sealing_key: toHex(epoch.publicKey),
      iat: tc,
      exp: tc + 86_400,
    })
    await publish(w.url, carolKey, carolRecord, carolAccept)
    const carol = await server('carol', homes.carol, w.url, [
      '--trust-root',
      B.address,
      '--keep-alive-records',
    ])
    // The keep-alive reports its own schedule (status keep_alive.next_at, from its clock). Its first cycle is not
    // awaited by the server's start, so wait for the schedule to appear, then it must be the half-ttl point: the
    // re-sign is scheduled at tc + 10 whatever the machine does after this line.
    try {
      let carolSchedule: Json | null = null
      for (let i = 0; i < 100 && carolSchedule === null; i++) {
        const keepAlive = (await carol.call('status')).value.keep_alive as Json
        if (keepAlive.next_at === null) await sleep(50)
        else carolSchedule = keepAlive
      }
      expect(carolSchedule).toMatchObject({
        address_iat: tc,
        next_at: new Date((tc + 10) * 1000).toISOString(),
      })
    } catch (e) {
      await carol.close()
      throw e
    }
    // The chains: A and the control's end at t0 + 30; B, the renewal, at t0 + 3000.
    const toJane = signHop(org.signing, jane.address, [], t0 + 3600)
    const chainA = [toJane, signHop(jane.signing, S.address, [], t0 + 30)]
    const chainB = [toJane, signHop(jane.signing, S.address, [], t0 + 3000)]
    const command = join(w.dir, 'session-chain.json')
    const controlFile = join(w.dir, 'control-chain.json')
    writeChain(command, chainA)
    writeChain(controlFile, [toJane, signHop(jane.signing, K.address, [], t0 + 30)])

    const alice = await server('alice', homes.alice, w.url, ['--trust-root', B.address])
    const bob = await server('bob', homes.bob, w.url, [
      '--trust-root',
      A.address,
      '--trust-root',
      org.address,
      '--trust-root',
      C.address,
    ])
    const sessionStart = performance.now()
    const session = await server('session', homes.session, w.url, [
      '--chain-cmd',
      `cat '${command}'`,
      '--mailbox',
      jane.address,
      '--trust-root',
      B.address,
    ])
    const control = await server('control', homes.control, w.url, [
      '--auth',
      controlFile,
      '--mailbox',
      jane.address,
    ])
    const servers = [alice, bob, carol, session, control]
    const measures: string[] = []
    try {
      // The renewal is on the command's file from now on; the session reads it at its next re-read.
      writeChain(command, chainB)

      const l1 = async (): Promise<void> => {
        const t = performance.now()
        const asked = await alice.call('ask', { to: B.address, body: { q: 'still there?' }, timeout_s: 60 })
        const window = (performance.now() - t) / 1000
        expect(asked.value).toMatchObject({
          timed_out: false,
          pending: true,
          resume: expect.any(String),
          question: { targets: [{ status: 'published' }] },
        })
        // The window on the server's own clock: it blocked 25 s from a deadline 60 s ahead, and says what is left
        // (whole seconds, so 35 less up to two of floor and timer lateness). The client wall time is a lower bound
        // (a timer is never early) and a loose backstop (a hung call is not the window), not the claim.
        expect(asked.value.remaining_s).toBeGreaterThanOrEqual(33)
        expect(asked.value.remaining_s).toBeLessThanOrEqual(35)
        expect(window).toBeGreaterThanOrEqual(24)
        expect(window).toBeLessThan(55)
        // Between the calls: Bob reads the question and answers it, and Alice's server receives the answer.
        const question = ((await bob.call('inbox')).value.messages as Json[]).find(
          (m) => m.type === 'question.v1',
        )
        expect(question).toMatchObject({ from: A.address, body: { q: 'still there?' } })
        const answer = await bob.call('send', {
          ...(question?.reply as Json),
          type: 'answer.v1',
          body: { a: 'yes' },
        })
        expect(answer.value).toMatchObject({ targets: [{ status: 'published' }] })
        for (let i = 0; i < 100; i++) {
          const s = (await alice.call('status')).value as { counts: { accepted: number } }
          if (s.counts.accepted >= 1) break
          if (i === 99) throw new Error('the answer did not reach Alice')
          await sleep(50)
        }
        const r = performance.now()
        const resumed = await alice.call('ask', { resume: asked.value.resume })
        const resumeS = (performance.now() - r) / 1000
        expect(resumed.value).toMatchObject({
          answer: { id: answer.value.id, type: 'answer.v1', body: { a: 'yes' }, trust: { root: B.address } },
        })
        expect(resumeS).toBeLessThan(2)
        measures.push(`L1 window ${window.toFixed(2)} s, resumed ask ${(resumeS * 1000).toFixed(1)} ms`)
      }

      const l2 = async (): Promise<void> => {
        let renewedAt = 0
        for (let i = 0; i < 400; i++) {
          const chain = (await session.call('status')).value.chain as { renewals: number }
          if (chain.renewals === 1) {
            renewedAt = (performance.now() - sessionStart) / 1000
            break
          }
          await sleep(100)
        }
        expect((await session.call('status')).value.chain).toMatchObject({
          source: 'command',
          hops: 2,
          earliest_exp: t0 + 3000,
          renewals: 1,
          last_reread: { outcome: 'renewed' },
        })
        // Past the first chain's last hop: the relay refuses a ts after t0 + 30.
        await untilSecond(t0 + 31)
        const sentAt = now() - (t0 + 30)
        const sent = await session.call('send', {
          to: [B.address],
          type: 'chat.v1',
          body: 'after the expiry',
        })
        expect(sent.value).toMatchObject({ targets: [{ status: 'published' }] })
        const refused = await control.call('send', { to: [B.address], type: 'chat.v1', body: 'control' })
        expect(refused).toMatchObject({
          isError: true,
          value: {
            error: 'hop-expired',
            detail: expect.stringMatching(/re-send it under a renewed chain once one is in place/),
          },
        })
        for (let i = 0; i < 100; i++) {
          const messages = (await bob.call('inbox', { limit: 100 })).value.messages as Json[]
          const got = messages.find((m) => m.id === sent.value.id)
          if (got !== undefined) {
            expect(got).toMatchObject({
              from: S.address,
              principal: jane.address,
              root: org.address,
              trust: { root: org.address, chain_hops: 2 },
              body: 'after the expiry',
            })
            break
          }
          if (i === 99) throw new Error("the session's message did not reach Bob")
          await sleep(50)
        }
        measures.push(
          `L2 renewed ${renewedAt.toFixed(2)} s after the session's start; sent ${sentAt} s past the first chain's exp`,
        )
      }

      const l4 = async (): Promise<void> => {
        let next: Json = {}
        for (let i = 0; i < 400; i++) {
          next = await relayRecord(w.url, C, 'address')
          if ((next.iat as number) > tc) break
          await sleep(100)
        }
        // The schedule (tc + 10) was asserted from the keeper's own status above; here the re-sign is never before
        // the half-ttl point and comes before the first record's expiry at tc + 20, whatever its timer's lateness.
        const delta = (next.iat as number) - tc
        expect(delta).toBeGreaterThanOrEqual(10)
        expect(delta).toBeLessThan(20)
        expect(verifyRecord(next as never, next.iat as number)).toEqual(next)
        expect({ ...next, iat: 0, sig: '' }).toEqual({ ...carolRecord, iat: 0, sig: '' })
        const accept = await relayRecord(w.url, C, 'accept-from')
        expect((accept.iat as number) > carolAccept.iat).toBe(true)
        expect({ ...accept, iat: 0, sig: '' }).toEqual({ ...carolAccept, iat: 0, sig: '' })
        expect((await carol.call('status')).value.keep_alive).toMatchObject({
          address_iat: next.iat,
          last: { outcome: 're-signed', published: 2, failed: 0 },
        })
        // Past the first record's expiry, Bob resolves Carol through the re-signed record.
        await untilSecond(tc + 21)
        const sent = await bob.call('send', { to: [C.address], type: 'chat.v1', body: 'resolved' })
        expect(sent.value).toMatchObject({ targets: [{ status: 'published' }] })
        for (let i = 0; i < 100; i++) {
          const counts = ((await carol.call('status')).value as { counts: { accepted: number } }).counts
          if (counts.accepted === 1) break
          if (i === 99) throw new Error('Carol did not receive the message')
          await sleep(50)
        }
        measures.push(`L4 re-signed at iat tc + ${delta} s (ttl 20 s)`)
      }

      await Promise.all([l1(), l2(), l4()])
      console.log(`e2e 23-mcp: ${measures.join('; ')}`)
    } finally {
      for (const s of servers) await s.close()
    }
    for (const [name, home] of Object.entries(homes)) {
      const lines = readAuditLines(join(home, 'state', name, 'audit.jsonl'))
      expect(verifyAuditLog(lines)).toEqual({ ok: true, lines: lines.length })
    }
    const printed = servers.flatMap((s) => [...s.stderr, ...s.results]).join('\n')
    expect(holdsNoSecret(printed, [A, B, C, org, jane, S, K])).toBe(true)
  }, 120_000)
})

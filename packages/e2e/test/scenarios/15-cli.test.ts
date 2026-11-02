import { readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { isAddress, parseRecord, verifyRecord } from '@usebag/core'
import { FsKeyStore } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { type CliRun, cliProcess, homeSecrets, now, storedAck, world } from '../harness.ts'

const lines = (text: string): string[] => text.split('\n').filter((l) => l !== '')
const outputs: string[] = []

/** One CLI process (harness.cliProcess), its raw output kept for the check that no seed was printed. */
const cli = (...args: string[]): Promise<CliRun> => cliProcess(args, outputs)

describe('e2e scenario 15: the CLI end to end, in child processes', () => {
  it("(15) the CLI in child processes against the relay: keygen prints addresses only and never overwrites a key; signed records are written and published; health is ok; send prints the id and a published target, or fails with the relay's code; inbox --once prints the accepted message with its body and the untrusted one with untrusted-root, acks both, and prints nothing new on a second run; audit verify reads the log as ok and finds an edited copy; no seed appears in any output", async () => {
    const w = await world('s15')
    const home = join(w.dir, 'cli-home')
    const dir = ['--dir', home]
    const made = await Promise.all(['alice', 'bob', 'carol'].map((name) => cli('keygen', name, ...dir)))
    for (const m of made) expect([m.code, m.out.length, isAddress(m.out[0]), m.err]).toEqual([0, 1, true, []])
    const [alice, bob, carol] = made.map((m) => m.out[0] as string) as [string, string, string]
    const again = await cli('keygen', 'alice', ...dir)
    expect([again.code, again.out]).toEqual([1, []])
    expect(again.err).toEqual([
      expect.stringMatching(/^bag: EEXIST: file already exists, open '.*alice\.json'$/),
    ])
    expect(await cli('address', 'alice', ...dir)).toEqual({ code: 0, out: [alice], err: [] })
    expect(statSync(join(home, 'keys')).mode & 0o777).toBe(0o700)
    expect(statSync(join(home, 'keys', 'bob.json')).mode & 0o777).toBe(0o600)

    const bobAddress = join(home, 'bob.address.json')
    const record = await cli(
      'record',
      'address',
      'bob',
      '--relay',
      w.url,
      '--sealing-key',
      '--ttl',
      '3600',
      ...dir,
      '--out',
      bobAddress,
    )
    expect(record).toEqual({ code: 0, out: [], err: [] })
    expect(verifyRecord(parseRecord(readFileSync(bobAddress, 'utf8')), now())).toMatchObject({
      kind: 'address',
      key: bob,
      relays: [w.url],
      ttl: 3600,
    })
    const accept = await cli(
      'record',
      'accept-from',
      'bob',
      '--root',
      alice,
      '--root',
      carol,
      '--max-bytes',
      '65536',
      '--ttl',
      '86400',
      ...dir,
    )
    expect([accept.code, accept.out.length]).toEqual([0, 1])
    const bobAccept = join(home, 'bob.accept.json')
    writeFileSync(bobAccept, `${accept.out[0]}\n`)
    expect(await cli('publish', w.url, bobAddress)).toEqual({ code: 0, out: [`ok address ${bob}`], err: [] })
    expect(await cli('publish', w.url, bobAccept)).toEqual({
      code: 0,
      out: [`ok accept-from ${bob}`],
      err: [],
    })
    expect(await cli('health', w.url)).toEqual({ code: 0, out: ['ok'], err: [] })

    const body = '{"text":"hello from the cli","n":1}'
    const sent = await cli(
      'send',
      '--as',
      'alice',
      '--to',
      bob,
      '--relay',
      w.url,
      '--type',
      'chat.v1',
      '--body',
      body,
      ...dir,
    )
    expect([sent.code, sent.out.length, sent.out[1], sent.err]).toEqual([
      0,
      2,
      `published ${w.url} tries=1`,
      [],
    ])
    const id = sent.out[0] as string
    expect(id).toMatch(/^[0-9a-f]{64}$/)
    const fromCarol = await cli(
      'send',
      '--as',
      'carol',
      '--to',
      bob,
      '--relay',
      w.url,
      '--type',
      'chat.v1',
      '--body',
      '{}',
      ...dir,
    )
    expect(fromCarol.code).toBe(0)
    const refused = await cli(
      'send',
      '--as',
      'bob',
      '--to',
      bob,
      '--relay',
      w.url,
      '--type',
      'chat.v1',
      '--body',
      '{}',
      ...dir,
    )
    expect([refused.code, refused.out[1], refused.err]).toEqual([
      1,
      `failed ${w.url} tries=1 reason=root-not-accepted`,
      [
        `bag: root-not-accepted: ${w.url} failed; the bytes stay in the outbox, and resend --id ${refused.out[0]} sends them; the recipient does not accept this identity's root yet: ask them to add ${bob} (or your org's domain root) to their accept-from record, or send under a chain from a root they accept (send --auth / delegate)`,
      ],
    ])

    const inbox = [
      'inbox',
      '--as',
      'bob',
      '--relay',
      w.url,
      '--once',
      '--trust-root',
      alice,
      '--accept-type',
      'chat.v1',
      ...dir,
    ]
    expect(await cli(...inbox)).toEqual({
      code: 0,
      out: [`accept ${id} ${alice} ${alice} chat.v1 ${body}`, `reject ${fromCarol.out[0]} untrusted-root`],
      err: [],
    })
    expect(await cli(...inbox)).toEqual({ code: 0, out: [], err: [] })
    const bobKey = new FsKeyStore(join(home, 'keys')).load('bob').signing
    expect(await storedAck(w.url, bobKey)).toBe(2)

    const log = join(home, 'state', 'bob', 'audit.jsonl')
    const verified = await cli('audit', 'verify', log)
    expect([verified.code, verified.err]).toEqual([0, []])
    expect(verified.out).toEqual([`ok ${lines(readFileSync(log, 'utf8')).length} lines`])
    const edited = join(w.dir, 'edited.jsonl')
    writeFileSync(edited, readFileSync(log, 'utf8').replace('"route"', '"verify"'))
    const broken = await cli('audit', 'verify', edited)
    expect([broken.code, broken.out]).toEqual([
      1,
      [expect.stringMatching(/^bad line \d+: the hash does not recompute$/)],
    ])

    const seeds = homeSecrets(home, ['alice', 'bob', 'carol'])
    const printed = outputs.join('\n')
    expect(seeds.every((s) => s.length === 64 && !printed.includes(s))).toBe(true)
    expect(seeds.every((s) => !readFileSync(log, 'utf8').includes(s))).toBe(true)
  }, 90_000)
})

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { verifyChain } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { type CliRun, cliProcess, homeSecrets, now, sleep, world } from '../harness.ts'

const outputs: string[] = []
const cli = (...args: string[]): Promise<CliRun> => cliProcess(args, outputs)

describe('e2e scenario 16: delegation with the CLI on one machine', () => {
  it("(16) delegation through the CLI in child processes, with Alice's home and Bob's apart: a send before Bob's accept-from is 403 not-hosted; delegate writes alice -> alice-session under type=chat.v1 and prints the subject and its caveats; the session's send under the chain is accepted by Bob's inbox trusting alice and honoring coding, with from the session and root alice; without --trust-root it is untrusted-root, without --honor unknown-caveat, under type=other.v1 caveat-failed; a hop of +1 s sent 2 s later is the relay's 422 hop-expired and reaches no one; alice herself needs no chain; Bob's audit log verifies with 26 lines; no key appears in any output", async () => {
    const w = await world('s16')
    const R = w.url
    const aliceHome = join(w.dir, 'alice-home')
    const bobHome = join(w.dir, 'bob-home')
    const A = ['--dir', aliceHome]
    const B = ['--dir', bobHome]
    const ok = (r: CliRun): string[] => {
      expect([r.code, r.err]).toEqual([0, []])
      return r.out
    }
    const [alice, session, bob] = (
      await Promise.all([
        cli('keygen', 'alice', ...A),
        cli('keygen', 'alice-session', ...A),
        cli('keygen', 'bob', ...B),
      ])
    ).map((r) => ok(r)[0] as string) as [string, string, string]
    const publish = async (home: string, ...record: string[]): Promise<string> => {
      const file = join(home, `${record[1]}.${record[0]}.json`)
      ok(await cli('record', ...record, '--out', file, '--dir', home))
      return ok(await cli('publish', R, file))[0] as string
    }
    const send = (as: string, body: string, ...more: string[]) =>
      cli('send', '--as', as, '--to', bob, '--relay', R, '--type', 'chat.v1', '--body', body, ...more, ...A)
    const sent = async (as: string, body: string, ...more: string[]): Promise<string> => {
      const out = ok(await send(as, body, ...more))
      expect(out[1]).toBe(`published ${R} tries=1`)
      return out[0] as string
    }
    const inbox = async (...flags: string[]): Promise<string[]> =>
      ok(await cli('inbox', '--as', 'bob', '--relay', R, '--once', ...flags, ...B))
    const delegate = async (file: string, caveat: string, exp: string): Promise<string[]> =>
      ok(
        await cli(
          'delegate',
          '--from',
          'alice',
          '--to',
          session,
          '--caveat',
          caveat,
          '--exp',
          exp,
          '--out',
          file,
          ...A,
        ),
      )

    expect(await publish(bobHome, 'address', 'bob', '--relay', R, '--sealing-key')).toBe(`ok address ${bob}`)
    // L2 (a): no accept-from record for bob yet, so the relay refuses the envelope: 403 not-hosted.
    const early = await send('alice', '{"text":"L2 before accept-from"}')
    expect([early.code, early.out[1], early.err]).toEqual([
      1,
      `failed ${R} tries=1 reason=not-hosted`,
      [
        `bag: not-hosted: ${R} failed; the bytes stay in the outbox, and resend --id ${early.out[0]} sends them`,
      ],
    ])
    // Alice's address record: Bob's edge reads it for her revoked list once a chain names her (Appendix B 38).
    expect(await publish(aliceHome, 'address', 'alice', '--relay', R)).toBe(`ok address ${alice}`)
    expect(
      await publish(bobHome, 'accept-from', 'bob', '--root', alice, '--max-bytes', '65536', '--ttl', '86400'),
    ).toBe(`ok accept-from ${bob}`)

    const chain = join(aliceHome, 'session.chain.json')
    // The CLI reads its own clock somewhere between these two reads, after its process start-up, so exp - 600 is
    // bracketed by them with no assumption on how long the start-up takes.
    const t = now()
    const made = await delegate(chain, 'type=chat.v1', '+600')
    const after = now()
    expect(made[0]).toBe(session)
    const exp = Number(/ exp (\d+) /.exec(made[1] as string)?.[1])
    expect(exp - 600).toBeGreaterThanOrEqual(t)
    expect(exp - 600).toBeLessThanOrEqual(after)
    expect(made[1]).toBe(`root ${alice} hops 1 exp ${exp} caveats ["type=chat.v1"]`)
    expect(verifyChain(JSON.parse(readFileSync(chain, 'utf8')), session, t)).toMatchObject({ root: alice })

    // L1: the session signs under alice's chain; bob trusts alice and honors the coding profile.
    const l1 = await sent('alice-session', '{"text":"L1 from the session"}', '--auth', chain)
    expect(await inbox('--trust-root', alice, '--honor', 'coding')).toEqual([
      `accept ${l1} ${session} ${alice} chat.v1 {"text":"L1 from the session"}`,
    ])
    // L3 (b): no trusted root.
    const l3 = await sent('alice-session', '{"text":"L3"}', '--auth', chain)
    expect(await inbox('--honor', 'coding')).toEqual([`reject ${l3} untrusted-root`])
    // L4 (c): the coding profile not honored, so its caveat is unknown and fails closed.
    const l4 = await sent('alice-session', '{"text":"L4"}', '--auth', chain)
    expect(await inbox('--trust-root', alice)).toEqual([`reject ${l4} unknown-caveat`])
    // L5 (d): a caveat that does not hold for the sealed type.
    const other = join(aliceHome, 'other.chain.json')
    expect((await delegate(other, 'type=other.v1', '+600'))[1]).toMatch(/ caveats \["type=other\.v1"\]$/)
    const l5 = await sent('alice-session', '{"text":"L5"}', '--auth', other)
    expect(await inbox('--trust-root', alice, '--honor', 'coding')).toEqual([`reject ${l5} caveat-failed`])
    // L6 (e): the hop expires before the envelope's ts, and the relay refuses it: 422 hop-expired.
    const short = join(aliceHome, 'short.chain.json')
    await delegate(short, 'type=chat.v1', '+1')
    await sleep(2000)
    const late = await send('alice-session', '{"text":"L6 too late"}', '--auth', short)
    expect([late.code, late.out[1], late.err]).toEqual([
      1,
      `failed ${R} tries=1 reason=hop-expired`,
      [
        `bag: hop-expired: ${R} failed; the bytes stay in the outbox, and resend --id ${late.out[0]} sends them`,
      ],
    ])
    expect(await inbox('--trust-root', alice, '--honor', 'coding')).toEqual([])
    // L7 (f): alice herself, self-rooted, needs no chain.
    const l7 = await sent('alice', '{"text":"L7 from alice"}')
    expect(await inbox('--trust-root', alice, '--honor', 'coding')).toEqual([
      `accept ${l7} ${alice} ${alice} chat.v1 {"text":"L7 from alice"}`,
    ])
    // L8: Bob's audit log verifies; 8 + 2 + 5 + 5 + 0 + 6 lines.
    expect(await cli('audit', 'verify', join(bobHome, 'state', 'bob', 'audit.jsonl'))).toEqual({
      code: 0,
      out: ['ok 26 lines'],
      err: [],
    })

    if (w.relay.spawned) {
      const refused = w.relay
        .stderr()
        .split('\n')
        .filter((l) => l.includes('"publish-refused"'))
        .map((l) => JSON.parse(l).fields as { status: number; code: string })
      expect(refused.map((f) => [f.status, f.code])).toEqual([
        [403, 'not-hosted'],
        [422, 'hop-expired'],
      ])
    }
    const keys = [...homeSecrets(aliceHome, ['alice', 'alice-session']), ...homeSecrets(bobHome, ['bob'])]
    const printed = outputs.join('\n')
    expect(keys.every((k) => k.length === 64 && !printed.includes(k))).toBe(true)
  }, 120_000)
})

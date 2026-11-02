import { realpathSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { type CliRun, cliProcess, homeSecrets, world } from '../harness.ts'

// e2e scenario 43: the CLI's `status` reports a subscription the
// release relay refused three times in a row. Through the CLI in child processes, on one home: the admin makes the
// group team and adds carol; carol's `inbox --group` reads the group's mailbox once, and `status` prints only its
// first line, `doorbell <path>` (carol's `<home>/state/carol/doorbell`); the
// admin removes carol, so the group's new address record revokes her key; her next `inbox --group` is refused
// `revoked` at the group's mailbox three times in a row, her edge ends the subscription (`subscribe reject revoked`
// with `subscription-ended` in her audit log) and the CLI exits 1; `status` then prints the refusal line second.

const outputs: string[] = []
const cli = (...args: string[]): Promise<CliRun> => cliProcess(args, outputs)

describe('e2e scenario 43: the CLI status line for a subscription the relay refused three times', () => {
  it('(43) status prints only the doorbell line while carol reads the group, then, after her removal and a refused inbox --group, a second line: mailbox refused: revoked at the relay after 3 refusals, edge errors 3; her audit log verifies; no key in any output', async () => {
    const w = await world('s43')
    const home = join(w.dir, 'cli-home')
    const dir = ['--dir', home]
    const made = await Promise.all(['team', 'carol', 'cold'].map((name) => cli('keygen', name, ...dir)))
    for (const m of made) expect([m.code, m.err]).toEqual([0, []])
    const [team, carol, cold] = made.map((m) => m.out[0] as string) as [string, string, string]

    // carol publishes her address record with her sealing key, and an accept-from record that accepts the group.
    const address = join(home, 'carol.address.json')
    const record = ['record', 'address', 'carol', '--relay', w.url, '--sealing-key', '--out', address, ...dir]
    expect((await cli(...record)).code).toBe(0)
    expect((await cli('publish', w.url, address)).out).toEqual([`ok address ${carol}`])
    const accept = await cli(
      'record',
      'accept-from',
      'carol',
      '--root',
      team,
      '--max-bytes',
      '65536',
      '--ttl',
      '86400',
      ...dir,
    )
    expect([accept.code, accept.out.length, accept.err]).toEqual([0, 1, []])
    const acceptFile = join(home, 'carol.accept.json')
    writeFileSync(acceptFile, `${accept.out[0]}\n`)
    expect((await cli('publish', w.url, acceptFile)).out).toEqual([`ok accept-from ${carol}`])

    // The group, and carol in it; her inbox --group keeps generation 1 and reads the group's mailbox once.
    const created = await cli('group', 'create', 'team', '--relay', w.url, '--rotation-key', cold, ...dir)
    expect([created.code, created.out[0]]).toEqual([0, `group ${team} generation 1`])
    const added = await cli('group', 'add', 'team', carol, ...dir)
    expect([added.code, added.err]).toEqual([0, []])
    const inbox = ['inbox', '--as', 'carol', '--relay', w.url, '--group', team, '--once', ...dir]
    const first = await cli(...inbox)
    expect([first.code, first.err]).toEqual([0, []])
    expect(first.out.filter((l) => l.startsWith('group-key '))).toHaveLength(1)
    const status = ['status', '--as', 'carol', ...dir]
    // The path under carol's state dir; the directory is compared by realpath, so the file need not exist yet.
    const doorbell = (line: string | undefined): boolean =>
      line?.startsWith('doorbell /') === true &&
      line.endsWith('/doorbell') &&
      realpathSync(dirname(line.slice('doorbell '.length))) === realpathSync(join(home, 'state', 'carol'))
    const before = await cli(...status)
    expect([before.code, before.out.length, before.err]).toEqual([0, 1, []])
    expect(doorbell(before.out[0])).toBe(true)

    // Her removal revokes her key in the group's record; the relay refuses her subscription to the group's mailbox.
    const removed = await cli('group', 'remove', 'team', carol, ...dir)
    expect([removed.code, removed.out[0]]).toEqual([
      0,
      expect.stringMatching(/^generation 2 sent 0 record iat \d+$/),
    ])
    const refused = await cli(...inbox)
    expect([refused.code, refused.err[0]]).toEqual([1, expect.stringMatching(/^bag: revoked: /)])
    const after = await cli(...status)
    const line = new RegExp(
      `^mailbox refused: revoked at ${w.url.replaceAll('.', '\\.')} after 3 refusals; edge errors 3, last revoked at \\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ$`,
    )
    expect([after.code, after.out.length, after.err]).toEqual([0, 2, []])
    expect(doorbell(after.out[0])).toBe(true)
    expect(after.out[1]).toMatch(line)
    const verified = await cli('audit', 'verify', join(home, 'state', 'carol', 'audit.jsonl'))
    expect([verified.code, verified.out[0]]).toEqual([0, expect.stringMatching(/^ok \d+ lines$/)])
    console.log(
      `MEASURE 43: status before the removal printed 1 line (${before.out[0]}); after the refused inbox --group: ${after.out[1]}`,
    )

    const secrets = homeSecrets(home, ['team', 'carol', 'cold'])
    for (const text of outputs) for (const s of secrets) expect(text).not.toContain(s)
  }, 60_000)
})

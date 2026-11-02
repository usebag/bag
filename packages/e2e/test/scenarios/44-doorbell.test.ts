import { realpathSync, statSync, utimesSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { type CliRun, cliProcess, homeSecrets, world } from '../harness.ts'

// e2e scenario 44: the doorbell, `<home>/state/<name>/doorbell`, an empty 0600 file
// whose mtime moves at most once per message the edge accepts into the inbox (a first delivery, a retry that ends
// accepted, `inbox release`) and never on a deferral, a refusal, a hold, a re-sent frame or a subscribe.
// Through the CLI in child processes against the release relay, on one home: alice sends to bob twice, and bob's
// `inbox --once --doorbell-path` prints `doorbell <path>` first each time; the second delivery moves the mtime off an
// old mtime the test set (utimesSync to 2001), so no clock resolution decides it. Then a message the relay admits and bob's edge refuses
// (carol, a root of bob's accept-from record but not his --trust-root: `reject <id> untrusted-root` on the inbox's
// stdout) moves nothing; a subscription the relay refuses, as in scenario 43 (bob removed from the group team, his
// `inbox --group` refused `revoked` three times), moves nothing; and `status` prints `doorbell <path>` as its first
// line.

const outputs: string[] = []
/** An mtime far in the past, in seconds and in ms: a file set to it is rung exactly when its mtime is later again. */
const OLD = 1_000_000_000
const OLD_MS = OLD * 1000
const cli = (...args: string[]): Promise<CliRun> => cliProcess(args, outputs)

describe('e2e scenario 44: the doorbell moves on delivery, not on a refused message or subscription', () => {
  it("(44) inbox --doorbell-path prints doorbell <path> under bob's state dir first; the file is empty, 0600 in a 0700 dir, with a non-zero mtime after a delivery and a later one after a second; a message bob's edge refuses (untrusted-root) leaves it; a refused inbox --group leaves it; status prints the same line first; no key in any output", async () => {
    const w = await world('s44')
    const home = join(w.dir, 'cli-home')
    const dir = ['--dir', home]
    const names = ['alice', 'bob', 'team', 'cold', 'carol']
    const made = await Promise.all(names.map((name) => cli('keygen', name, ...dir)))
    for (const m of made) expect([m.code, m.err]).toEqual([0, []])
    const keys = made.map((m) => m.out[0] as string)
    const [alice, bob, team, cold, carol] = keys as [string, string, string, string, string]
    const words = (s: string): string[] => s.split(' ')

    // bob publishes his address record with his sealing key, and an accept-from record for alice, carol and the group:
    // the relay admits carol's message, and only bob's edge, which trusts alice alone, refuses it.
    const address = join(home, 'bob.address.json')
    const record = await cli(
      ...words('record address bob --sealing-key --relay'),
      w.url,
      '--out',
      address,
      ...dir,
    )
    expect(record.code).toBe(0)
    expect((await cli('publish', w.url, address)).out).toEqual([`ok address ${bob}`])
    const roots = ['--root', alice, '--root', carol, '--root', team, ...dir]
    const accept = await cli(...words('record accept-from bob --max-bytes 65536 --ttl 86400'), ...roots)
    expect([accept.code, accept.out.length, accept.err]).toEqual([0, 1, []])
    const acceptFile = join(home, 'bob.accept.json')
    writeFileSync(acceptFile, `${accept.out[0]}\n`)
    expect((await cli('publish', w.url, acceptFile)).out).toEqual([`ok accept-from ${bob}`])

    // The printed path: absolute, `doorbell <path>`, the same file as <home>/state/bob/doorbell.
    const doorbell = join(home, 'state', 'bob', 'doorbell')
    const bell = (line: string | undefined): void => {
      expect(line?.startsWith('doorbell /')).toBe(true)
      expect(realpathSync((line as string).slice('doorbell '.length))).toBe(realpathSync(doorbell))
    }
    const inbox = [
      ...words('inbox --as bob --once --doorbell-path --relay'),
      w.url,
      '--trust-root',
      alice,
      ...dir,
    ]
    const ring = async (n: number): Promise<number> => {
      const body = `{"n":${n}}`
      const sent = await cli(
        ...words('send --as alice --type chat.v1 --relay'),
        w.url,
        '--to',
        bob,
        '--body',
        body,
        ...dir,
      )
      expect([sent.code, sent.err]).toEqual([0, []])
      const got = await cli(...inbox)
      expect([got.code, got.out.length, got.err]).toEqual([0, 2, []])
      bell(got.out[0])
      expect(got.out[1]).toBe(`accept ${sent.out[0]} ${alice} ${alice} chat.v1 ${body}`)
      const st = statSync(doorbell)
      const stateDir = statSync(join(home, 'state', 'bob')).mode & 0o777
      expect([st.size, st.mode & 0o777, stateDir]).toEqual([0, 0o600, 0o700])
      expect(st.mtimeMs).toBeGreaterThan(0)
      return st.mtimeMs
    }

    // Two deliveries: the doorbell is set back to an old mtime between them, so the second moves it strictly later
    // whatever the file system's mtime resolution and however fast the CLI runs.
    const first = await ring(1)
    utimesSync(doorbell, OLD, OLD)
    expect(statSync(doorbell).mtimeMs).toBe(OLD_MS)
    const second = await ring(2)
    expect(second).toBeGreaterThan(OLD_MS)

    // A message the relay admits and bob's edge refuses moves nothing: carol is a root of bob's accept-from record but
    // not his --trust-root. The mtime is set to the old one before her send and read again after the inbox printed her
    // reject line; a ring would show as a later mtime.
    expect(statSync(doorbell).mtimeMs).toBe(second)
    utimesSync(doorbell, OLD, OLD)
    const unrung = statSync(doorbell).mtimeMs
    expect(unrung).toBe(OLD_MS)
    const fromCarol = await cli(
      ...words('send --as carol --type chat.v1 --relay'),
      w.url,
      '--to',
      bob,
      '--body',
      '{"n":0}',
      ...dir,
    )
    expect([fromCarol.code, fromCarol.err]).toEqual([0, []])
    const rejected = await cli(...inbox)
    expect([rejected.code, rejected.out.length, rejected.err]).toEqual([0, 2, []])
    bell(rejected.out[0])
    expect(rejected.out[1]).toBe(`reject ${fromCarol.out[0]} untrusted-root`)
    expect(statSync(doorbell).mtimeMs).toBe(unrung)

    // A subscription the relay refuses moves nothing: scenario 43's group removal, with bob as the member.
    const created = await cli('group', 'create', 'team', '--relay', w.url, '--rotation-key', cold, ...dir)
    expect([created.code, created.out[0]]).toEqual([0, `group ${team} generation 1`])
    expect((await cli('group', 'add', 'team', bob, ...dir)).code).toBe(0)
    const group = ['inbox', '--as', 'bob', '--relay', w.url, '--group', team, '--once', ...dir]
    expect((await cli(...group)).code).toBe(0)
    utimesSync(doorbell, OLD, OLD)
    const kept = statSync(doorbell).mtimeMs
    expect(kept).toBe(OLD_MS)
    const removed = await cli('group', 'remove', 'team', bob, ...dir)
    expect([removed.code, removed.out[0]]).toEqual([
      0,
      expect.stringMatching(/^generation 2 sent 0 record iat \d+$/),
    ])
    const refused = await cli(...group)
    expect([refused.code, refused.err[0]]).toEqual([1, expect.stringMatching(/^bag: revoked: /)])
    expect(statSync(doorbell).mtimeMs).toBe(kept)

    // status names the doorbell first, then the refused mailbox (scenario 43's line).
    const status = await cli('status', '--as', 'bob', ...dir)
    expect([status.code, status.out.length, status.err]).toEqual([0, 2, []])
    bell(status.out[0])
    expect(status.out[1]).toMatch(/^mailbox refused: revoked at /)
    console.log(
      `MEASURE 44: mtimeMs ${first} then ${second} (+${(second - first).toFixed(3)} ms; the second moved the file off ${OLD_MS}); unchanged at ${unrung} across carol's refused message (untrusted-root); unchanged at ${kept} across the refused inbox --group (both set back to ${OLD_MS} first)`,
    )

    const secrets = homeSecrets(home, names)
    for (const text of outputs) for (const s of secrets) expect(text).not.toContain(s)
  }, 60_000)
})

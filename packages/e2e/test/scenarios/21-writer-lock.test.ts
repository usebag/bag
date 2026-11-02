import { type ChildProcess, spawn } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { auditHash } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { CLI_MAIN, type CliRun, cliProcess, homeSecrets, REPO, until, world } from '../harness.ts'

// e2e scenario 21: the writer lock and the audit anchor through the CLI in child processes.
// While `inbox --as bob` runs, `send --as bob` refuses with busy; `audit verify` reads the log beside the live
// edge; a stopped or killed inbox leaves bob's state to the next command; a log cut short is `truncated` and a
// rewritten one `diverged`, for `audit verify` and for an edge that would continue it.

const outputs: string[] = []
const cli = (...args: string[]): Promise<CliRun> => cliProcess(args, outputs)

/** A long-running CLI process, its stdout lines collected as they come. */
function running(args: readonly string[]): {
  child: ChildProcess
  lines: string[]
  exit: Promise<number | null>
} {
  const env: NodeJS.ProcessEnv = { ...process.env }
  delete env.AC_HOME
  const child = spawn(process.execPath, [CLI_MAIN, ...args], {
    cwd: REPO,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const lines: string[] = []
  let buffer = ''
  child.stdout?.on('data', (d: Buffer) => {
    buffer += d.toString()
    const parts = buffer.split('\n')
    buffer = parts.pop() as string
    lines.push(...parts)
    outputs.push(d.toString())
  })
  child.stderr?.on('data', (d: Buffer) => outputs.push(d.toString()))
  const exit = new Promise<number | null>((resolve) => child.once('exit', (code) => resolve(code)))
  return { child, lines, exit }
}

/** Line k of a log edited and every later line re-hashed: a rewrite whose chain still verifies. */
function rewrite(text: string, k: number): string {
  const lines = text.trim().split('\n')
  let prev = (JSON.parse(lines[k - 2] as string) as { hash: string }).hash
  const out = lines.slice(0, k - 1)
  for (const line of lines.slice(k - 1)) {
    const l = JSON.parse(line)
    if (l.seq === k) l.detail = '{"edited":true}'
    l.prev = prev
    l.hash = auditHash(l)
    prev = l.hash
    out.push(JSON.stringify(l))
  }
  return `${out.join('\n')}\n`
}

describe('e2e scenario 21: one writer per identity, and an audit log checked against its anchor', () => {
  it("(21) while inbox --as bob runs, send --as bob exits 1 with busy and audit verify reads bob's log as ok; once the inbox stops, or is killed, bob's next command runs; a log cut short is truncated and a rewritten one diverged, for audit verify and for inbox, which refuses to continue it; no key appears in any output", async () => {
    const w = await world('s21')
    const home = join(w.dir, 'home')
    const dir = ['--dir', home]
    const [alice, bob] = (await Promise.all(['alice', 'bob'].map((n) => cli('keygen', n, ...dir)))).map(
      (r) => r.out[0] as string,
    ) as [string, string]
    for (const [name, peer] of [
      ['alice', bob],
      ['bob', alice],
    ] as const) {
      const record = join(home, `${name}.address.json`)
      const accept = join(home, `${name}.accept.json`)
      await cli('record', 'address', name, '--relay', w.url, '--sealing-key', '--out', record, ...dir)
      await cli(
        'record',
        'accept-from',
        name,
        '--root',
        peer,
        '--max-bytes',
        '65536',
        '--ttl',
        '86400',
        '--out',
        accept,
        ...dir,
      )
      expect((await cli('publish', w.url, record)).code).toBe(0)
      expect((await cli('publish', w.url, accept)).code).toBe(0)
    }
    const send = (as: string, to: string, text: string) =>
      cli(
        'send',
        '--as',
        as,
        '--to',
        to,
        '--relay',
        w.url,
        '--type',
        'chat.v1',
        '--body',
        JSON.stringify({ text }),
        ...dir,
      )
    const inboxArgs = ['inbox', '--as', 'bob', '--relay', w.url, '--trust-root', alice, ...dir]
    const log = join(home, 'state', 'bob', 'audit.jsonl')

    // L5 (d): the inbox holds bob's state; a second writer for bob refuses with busy.
    const inbox = running(inboxArgs)
    const first = await send('alice', bob, 'one')
    expect(first.code).toBe(0)
    await until('the inbox prints the message', () =>
      inbox.lines.some((l) => l.startsWith(`accept ${first.out[0]}`)),
    )
    const busy = await send('bob', alice, 'while the inbox runs')
    expect([busy.code, busy.out]).toEqual([1, []])
    expect(busy.err).toEqual([
      expect.stringMatching(
        new RegExp(
          `^bag: busy: .*state/bob/audit\\.lock is held by the process with pid ${inbox.child.pid}, started `,
        ),
      ),
    ])
    // audit verify reads the log and its anchor beside the live edge, without the lock.
    const live = await cli('audit', 'verify', log)
    expect([live.code, live.out[0]]).toEqual([
      0,
      `ok ${readFileSync(log, 'utf8').trim().split('\n').length} lines`,
    ])
    inbox.child.kill('SIGTERM')
    expect(await inbox.exit).toBe(0)
    expect((await send('bob', alice, 'after the inbox stopped')).code).toBe(0)

    // L5 (c): a killed inbox releases nothing, and its stale lock is taken over.
    const killed = running(inboxArgs)
    const second = await send('alice', bob, 'two')
    await until('the second inbox prints the message', () =>
      killed.lines.some((l) => l.startsWith(`accept ${second.out[0]}`)),
    )
    killed.child.kill('SIGKILL')
    await killed.exit
    expect(JSON.parse(readFileSync(join(home, 'state', 'bob', 'audit.lock'), 'utf8')).pid).toBe(
      killed.child.pid,
    )
    expect((await cli(...inboxArgs, '--once')).code).toBe(0)

    // L4: the anchor sees a log cut short, and one rewritten with every hash recomputed.
    const intact = readFileSync(log, 'utf8')
    const n = intact.trim().split('\n').length
    expect(await cli('audit', 'verify', log)).toEqual({ code: 0, out: [`ok ${n} lines`], err: [] })
    writeFileSync(
      log,
      `${intact
        .trim()
        .split('\n')
        .slice(0, n - 2)
        .join('\n')}\n`,
    )
    const store = join(home, 'state', 'bob', 'edge.sqlite')
    expect(await cli('audit', 'verify', log)).toEqual({
      code: 1,
      out: [`truncated: the log has ${n - 2} lines; its anchor in ${store} is at line ${n}`],
      err: [],
    })
    const cut = await cli(...inboxArgs, '--once')
    expect([cut.code, cut.err]).toEqual([
      1,
      [`bag: truncated: the audit log audit.jsonl has ${n - 2} lines; its anchor is at line ${n}`],
    ])
    writeFileSync(log, rewrite(intact, 3))
    expect(await cli('audit', 'verify', log)).toEqual({
      code: 1,
      out: [`diverged: line ${n} of the log does not have the hash of its anchor in ${store}`],
      err: [],
    })
    const forged = await cli(...inboxArgs, '--once')
    expect([forged.code, forged.err]).toEqual([
      1,
      [`bag: diverged: line ${n} of the audit log audit.jsonl does not have its anchor's hash`],
    ])
    // The intact log back: bob's edge runs again, and its log verifies.
    writeFileSync(log, intact)
    expect((await cli(...inboxArgs, '--once')).code).toBe(0)
    expect((await cli('audit', 'verify', log)).code).toBe(0)
    console.log(
      `MEASURE L4/L5 (CLI): busy while inbox ran; truncated and diverged refused by audit verify and inbox; log of ${n} lines`,
    )

    const seeds = homeSecrets(home, ['alice', 'bob'])
    const printed = outputs.join('\n')
    expect(seeds.every((s) => s.length === 64 && !printed.includes(s))).toBe(true)
  }, 90_000)
})

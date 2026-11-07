import { spawn } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { CLI_MAIN, type CliRun, cliProcess, homeSecrets, now, REPO, world } from '../harness.ts'

// e2e scenario 59: a message refused for a trust failure is not used up. bob's home trusts only a domain that does
// not resolve (a special-use name), as a home whose trust file names its org's domain root before that domain has a
// record. alice's message is refused resolve-failed by bob's first `inbox --once`; bob's next `inbox --once`, right
// after it with alice's address as --trust-root, prints the accept line at once, with no new message from alice and
// no step by bob. Through the CLI in child processes against the release relay.

const outputs: string[] = []
const words = (s: string): string[] => s.split(' ')
const cli = (...args: string[]): Promise<CliRun> => cliProcess(args, outputs)

/** One CLI process, with the milliseconds from its spawn to the first stdout line that starts with `prefix`. */
function timedCli(
  args: readonly string[],
  prefix: string,
): Promise<CliRun & { readonly firstMs: number | null }> {
  const env: NodeJS.ProcessEnv = { ...process.env, DO_NOT_TRACK: '1' }
  delete env.AC_HOME
  const start = performance.now()
  let firstMs: number | null = null
  let stdout = ''
  let stderr = ''
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI_MAIN, ...args], { cwd: REPO, env, timeout: 30_000 })
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8')
      if (firstMs === null && stdout.split('\n').some((l) => l.startsWith(prefix))) {
        firstMs = performance.now() - start
      }
    })
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8')
    })
    child.on('close', (code) => {
      outputs.push(stdout, stderr)
      const lines = (t: string): string[] => t.split('\n').filter((l) => l !== '')
      const err = lines(stderr).filter((l) => !/ExperimentalWarning|--trace-warnings/.test(l))
      resolve({ code: code ?? -1, out: lines(stdout), err, firstMs })
    })
  })
}

describe('e2e scenario 59: a message refused for a trust failure is delivered by the next read once trust is fixed', () => {
  it("(59) bob's first inbox --once refuses alice's message resolve-failed (his only trusted root is a domain that does not resolve); his next inbox --once with --trust-root alice prints the accept line at once, with nothing new from alice; a third read prints nothing; no key in any output", async () => {
    const w = await world('s59')
    const home = join(w.dir, 'cli-home')
    const dir = ['--dir', home]
    const made = await Promise.all(['alice', 'bob'].map((name) => cli('keygen', name, ...dir)))
    for (const m of made) expect([m.code, m.err]).toEqual([0, []])
    const [alice, bob] = made.map((m) => m.out[0] as string) as [string, string]

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
    const accept = await cli(
      ...words('record accept-from bob --root'),
      alice,
      ...words('--max-bytes 65536 --ttl 86400'),
      ...dir,
    )
    expect(accept.code).toBe(0)
    const acceptFile = join(home, 'bob.accept.json')
    writeFileSync(acceptFile, `${accept.out[0]}\n`)
    expect((await cli('publish', w.url, acceptFile)).out).toEqual([`ok accept-from ${bob}`])
    // bob's trust file names only a domain root under a special-use name: it never resolves (spec/SPEC.md §12.2).
    const trust = { version: 1, roots: { 'domain:org.example.test': { added_at: now() } } }
    writeFileSync(join(home, 'trust.json'), `${JSON.stringify(trust, null, 2)}\n`, { mode: 0o600 })

    const body = '{"text":"hello bob"}'
    const sent = await cli(
      ...words('send --as alice --to'),
      bob,
      '--relay',
      w.url,
      ...words('--type chat.v1 --body'),
      body,
      ...dir,
    )
    expect([sent.code, sent.out[1], sent.err]).toEqual([0, `published ${w.url} tries=1`, []])
    const id = sent.out[0] as string

    const inbox = ['inbox', '--as', 'bob', '--relay', w.url, '--once', ...dir]
    const first = await cli(...inbox)
    expect([first.code, first.out, first.err]).toEqual([
      0,
      [`waiting ${id} resolve-failed: kept; the next read after the trust root is fixed delivers it`],
      [],
    ])

    const second = await timedCli([...inbox, '--trust-root', alice], 'accept ')
    expect([second.code, second.err]).toEqual([0, []])
    expect(second.out).toEqual([`accept ${id} ${alice} ${alice} chat.v1 ${body}`])
    const ms = second.firstMs as number
    // The line is printed by the read's start (recover()), before its subscription: about 0.2 s on an idle Mac. The
    // bound leaves room for a loaded machine; without the fix no accept line comes at all.
    expect(ms).toBeLessThan(3_000)

    const third = await cli(...inbox, '--trust-root', alice)
    expect([third.code, third.out, third.err]).toEqual([0, [], []])
    const printed = outputs.join('\n')
    expect(homeSecrets(home, ['alice', 'bob']).filter((s) => printed.includes(s))).toEqual([])
    console.log(
      `MEASURE 59: after a resolve-failed refusal, the next inbox --once with the root fixed printed the accept line ${Math.round(ms)} ms after its spawn (no resend)`,
    )
  })
})

import { spawn } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it, onTestFinished } from 'vitest'
import { CLI_MAIN, type CliRun, cliProcess, homeSecrets, REPO, until, world } from '../harness.ts'

// e2e scenario 45: `inbox --watch --exec` against the release relay,
// through the CLI in child processes on one home. bob's watch runs in the background with `--exec 'cat >> <file>;
// echo ran'`; carol, whom the relay admits and bob's watch does not trust, sends once; alice sends twice, the second
// once the first is in the file. The file holds two summary lines, `message <id> from <address>, type chat.v1`, and no
// body; bob's stdout is the doorbell line and the two accept lines only, the refusal and the command's own output on
// his stderr; SIGTERM ends bob with exit 0, and bob's next `inbox --once` is not refused busy.

const outputs: string[] = []
const words = (s: string): string[] => s.split(' ')
const cli = (...args: string[]): Promise<CliRun> => cliProcess(args, outputs)
const lines = (text: string): string[] => text.split('\n').filter((l) => l !== '')
const fileLines = (file: string): string[] => (existsSync(file) ? lines(readFileSync(file, 'utf8')) : [])

describe('e2e scenario 45: inbox --watch runs --exec once per accepted message and ends on SIGTERM', () => {
  it("(45) bob's inbox --watch --exec in the background; carol's untrusted message on his stderr only; alice's two messages as two summary lines in the file and two accept lines on his stdout; SIGTERM ends bob with exit 0 and frees his lock; no key in any output", async () => {
    const w = await world('s45')
    const home = join(w.dir, 'cli-home')
    const dir = ['--dir', home]
    const made = await Promise.all(['alice', 'bob', 'carol'].map((name) => cli('keygen', name, ...dir)))
    for (const m of made) expect([m.code, m.err]).toEqual([0, []])
    const [alice, bob, carol] = made.map((m) => m.out[0] as string) as [string, string, string]

    // bob publishes his address record with his sealing key, and an accept-from record for alice and carol.
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
    const roots = ['--root', alice, '--root', carol, ...dir]
    const accept = await cli(...words('record accept-from bob --max-bytes 65536 --ttl 86400'), ...roots)
    expect([accept.code, accept.out.length, accept.err]).toEqual([0, 1, []])
    const acceptFile = join(home, 'bob.accept.json')
    writeFileSync(acceptFile, `${accept.out[0]}\n`)
    expect((await cli('publish', w.url, acceptFile)).out).toEqual([`ok accept-from ${bob}`])

    // bob's watch, in the background, trusting alice only; its doorbell line says it has parsed its arguments.
    const file = join(w.dir, 'arrivals.txt')
    const inbox = [...words('inbox --as bob --relay'), w.url, '--trust-root', alice, ...dir]
    const env: NodeJS.ProcessEnv = { ...process.env }
    delete env.AC_HOME
    const exec = `cat >> '${file}'; echo ran`
    const args = [CLI_MAIN, ...inbox, '--doorbell-path', '--watch', '--exec', exec]
    const child = spawn(process.execPath, args, { cwd: REPO, env, stdio: ['ignore', 'pipe', 'pipe'] })
    let [stdout, stderr] = ['', '']
    child.stdout.on('data', (d: Buffer) => {
      stdout += d.toString()
    })
    child.stderr.on('data', (d: Buffer) => {
      stderr += d.toString()
    })
    // A failed assertion must not leave the watch running.
    onTestFinished(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL')
    })
    // 'close', not 'exit': Node may emit 'exit' before the last stderr data has arrived.
    const exit = new Promise<number | null>((resolve) => child.once('close', (code) => resolve(code)))
    await until('the doorbell line', () => stdout.startsWith('doorbell /'))

    const send = (as: string, body: string) =>
      cli(...words(`send --as ${as} --type chat.v1 --relay`), w.url, '--to', bob, '--body', body, ...dir)
    const refused = await send('carol', '{"n":0}')
    expect([refused.code, refused.err]).toEqual([0, []])
    await until('the refusal', () => lines(stderr).includes(`reject ${refused.out[0]} untrusted-root`))
    // alice sends twice; the wait for the first line in the file is the pause between the two.
    const sent: { id: string; body: string }[] = []
    for (const n of [1, 2]) {
      const body = `{"n":${n}}`
      const s = await send('alice', body)
      expect([s.code, s.err]).toEqual([0, []])
      await until(`arrival ${n} in the file`, () => fileLines(file).length === n)
      sent.push({ id: s.out[0] as string, body })
    }
    expect(fileLines(file)).toEqual(sent.map((s) => `message ${s.id} from ${alice}, type chat.v1`))
    const accepts = sent.map((s) => `accept ${s.id} ${alice} ${alice} chat.v1 ${s.body}`)
    expect(lines(stdout)).toEqual([expect.stringMatching(/^doorbell \//), ...accepts])

    child.kill('SIGTERM')
    expect(await exit).toBe(0)
    outputs.push(stdout, stderr)
    expect(lines(stderr).filter((l) => l === 'ran')).toHaveLength(2)
    expect(lines(stderr).filter((l) => l.startsWith('bag:'))).toEqual([])
    // The watch released bob's lock: his next inbox runs and is not refused busy.
    expect(await cli(...inbox, '--once')).toEqual({ code: 0, out: [], err: [] })

    const secrets = homeSecrets(home, ['alice', 'bob', 'carol'])
    for (const text of outputs) for (const s of secrets) expect(text).not.toContain(s)
  }, 60_000)
})

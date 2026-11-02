import { randomBytes } from 'node:crypto'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { toHex, utf8 } from '@usebag/core'
import { KeychainCustody, runSecurity } from '@usebag/edge'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'
import { forms, occurrences } from './support/security.ts'

// Lines L2 (d) and L3 for the CLI on the real /usr/bin/security: a temporary keychain made here (a random password
// on `security -i`'s stdin only), deleted after the test even when it fails; every spawn goes through a pass-through
// spy of node:child_process that refuses any spawn not naming this keychain file, so no test touches the default
// keychain or the search list. On a system without /usr/bin/security the one test says so.

const spy = vi.hoisted(() => ({
  keychain: '',
  calls: [] as { file: string; args: string[]; env: Record<string, string>; input: string | null }[],
}))

vi.mock('node:child_process', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:child_process')>()
  const spawnSync = (
    file: string,
    args: string[],
    options: { input?: Uint8Array; env?: Record<string, string> },
  ) => {
    const input = options.input === undefined ? null : Buffer.from(options.input).toString('utf8')
    if (
      spy.keychain === '' ||
      !(args.includes(spy.keychain) || (input ?? '').includes(`"${spy.keychain}"`))
    ) {
      throw new Error('custody-live: refused a spawn that does not name the temporary keychain')
    }
    spy.calls.push({ file, args: [...args], env: { ...options.env }, input })
    return real.spawnSync(file, args, options)
  }
  return { ...real, spawnSync }
})

const darwin = process.platform === 'darwin' && existsSync('/usr/bin/security')
const root = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), 'bag-cli-custody-live-'))
spy.keychain = join(root, 'test.keychain-db')
const RELAY = 'http://127.0.0.1:9'
const kc = ['--custody', 'keychain', '--keychain', spy.keychain, '--keychain-access', 'security']

afterAll(() => {
  try {
    if (darwin && existsSync(spy.keychain))
      expect(runSecurity(['delete-keychain', spy.keychain]).status).toBe(0)
    expect(existsSync(spy.keychain)).toBe(false)
  } finally {
    if (process.env.AC_KEEP_TMP !== '1') rmSync(root, { recursive: true, force: true })
  }
})

// One of the two describes exists on a system, never both, so neither is ever a skipped test.
const live = darwin ? describe : (_name: string, _body: () => void): void => {}
const absent = darwin ? (_name: string, _body: () => void): void => {} : describe

absent('keygen --custody keychain without /usr/bin/security (not macOS)', () => {
  it('refuses ENOENT, naming the program it needs', async () => {
    const r = await cli(
      { ...testIo(new MemoryRelay()), security: runSecurity },
      'keygen',
      'a',
      ...kc,
      '--dir',
      root,
    )
    expect([r.code, r.err[0]]).toEqual([
      1,
      'bag: ENOENT: keychain: adding the item of a: there is no /usr/bin/security (macOS only)',
    ])
  })
})

live('the CLI on /usr/bin/security and a temporary keychain (L2 (d), L3)', () => {
  beforeAll(() => {
    const password = randomBytes(32).toString('hex')
    for (const line of [
      `create-keychain -p ${password} "${spy.keychain}"`,
      `unlock-keychain -p ${password} "${spy.keychain}"`,
    ]) {
      expect(runSecurity(['-i'], utf8(`${line}\n`)).status).toBe(0)
    }
    expect(runSecurity(['set-keychain-settings', spy.keychain]).status).toBe(0)
  })

  it('keygen, keys list, address, record, publish, send and inbox as keychain identities; no seed anywhere', async () => {
    const io = { ...testIo(new MemoryRelay()), security: runSecurity }
    const dir = join(root, 'home')
    const runs: { out: string[]; err: string[] }[] = []
    const run = async (...argv: string[]): Promise<string[]> => {
      const r = await cli(io, ...argv)
      runs.push(r)
      expect(r.code, argv.slice(0, 2).join(' ')).toBe(0)
      return r.out
    }
    const [alice] = (await run('keygen', 'alice', ...kc, '--dir', dir)) as [string]
    const [bob] = (await run('keygen', 'bob', ...kc, '--dir', dir)) as [string]
    expect((await run('keys', 'list', '--dir', dir)).map((l) => l.split(' ').slice(0, 3).join(' '))).toEqual([
      `alice ${alice} keychain`,
      `bob ${bob} keychain`,
    ])
    const before = spy.calls.length
    expect(await run('address', 'alice', '--dir', dir)).toEqual([alice])
    expect(spy.calls.length).toBe(before)
    const file = join(root, 'bob.address.json')
    await run('record', 'address', 'bob', '--relay', RELAY, '--sealing-key', '--out', file, '--dir', dir)
    await run('publish', RELAY, file)
    const body = '{"text":"from the keychain"}'
    const [id] = (await run(
      'send',
      '--as',
      'alice',
      '--to',
      bob,
      '--relay',
      RELAY,
      '--type',
      'chat.v1',
      '--body',
      body,
      '--dir',
      dir,
    )) as [string]
    expect(
      await run('inbox', '--as', 'bob', '--relay', RELAY, '--once', '--trust-root', alice, '--dir', dir),
    ).toEqual([`accept ${id} ${alice} ${alice} chat.v1 ${body}`])
    // The seeds, read back through the custody for the count only.
    const reader = new KeychainCustody({ dir: join(dir, 'keychain') })
    const seeds = [alice, bob].flatMap((a) => [reader.signer(a).exportSeed(), reader.opener(a).exportSeed()])
    const texts = [alice, bob].map((a) =>
      JSON.stringify({
        suite: 1,
        sign_seed: toHex(reader.signer(a).exportSeed()),
        seal_priv: toHex(reader.opener(a).exportSeed()),
      }),
    )
    const needles = [...seeds.flatMap(forms), ...texts, ...texts.map((t) => toHex(utf8(t)))]
    const printed = occurrences(runs.flatMap((r) => [...r.out, ...r.err]).join('\n'), needles)
    const files = readdirSync(root, { recursive: true, withFileTypes: true }).filter((f) => f.isFile())
    let inFiles = 0
    for (const f of files) {
      const bytes = readFileSync(join(f.parentPath, f.name))
      inFiles += occurrences(bytes.toString('latin1'), needles)
      for (const s of seeds) if (bytes.indexOf(s) >= 0) inFiles++
    }
    const audits = files.filter((f) => f.name === 'audit.jsonl').length
    const inArgs = spy.calls.reduce((n, c) => n + occurrences(c.args.join('\n'), needles), 0)
    const inEnv = spy.calls.reduce((n, c) => n + occurrences(Object.values(c.env).join('\n'), needles), 0)
    const onStdin = texts.map((t) => spy.calls.filter((c) => (c.input ?? '').includes(toHex(utf8(t)))).length)
    console.log(
      `MEASURE L2(d), L3 (CLI): ${runs.length} commands, ${spy.calls.length} spawns of /usr/bin/security; seeds in output ${printed}, in arguments ${inArgs}, in environments ${inEnv}, in ${files.length} files (${audits} audit logs) ${inFiles}; key texts on security -i's stdin ${onStdin.join(', ')}`,
    )
    expect([printed, inArgs, inEnv, inFiles]).toEqual([0, 0, 0, 0])
    expect(audits).toBe(2)
    expect(onStdin).toEqual([1, 1])
  })
})

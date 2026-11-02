import { type ChildProcess, execFile, spawn } from 'node:child_process'
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { NO_RECOVERY } from '@usebag/cli'
import {
  type AcRecord,
  type AddressRecord,
  checkDiscovered,
  discover,
  parseRecord,
  parseTxtPresentation,
  verifyHandleRecord,
  verifyRecord,
} from '@usebag/core'
import { parseAuditLine, readAuditLines } from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  CLI_MAIN,
  type CliRun,
  cliProcess,
  homeSecrets,
  now,
  REPO,
  until,
  untilSecond,
  world,
} from '../harness.ts'

// e2e scenario 24: records and unreachable through the CLI in child
// processes and the release relay. record keep --once makes the relay serve the identity's records signed again with
// a newer iat and nothing else changed; a running keep republishes until SIGTERM; deploy/make-org-records.sh writes
// rotation_key and revoked, which the relay serves and keep keeps. Once the relay has stopped, a send to a recipient
// whose record the sender's edge holds is reason=unreachable with its retry scheduled, while a 403 before it kept its
// code, and the sender's audit log, whose line reads unreachable and names the cause, still verifies. And (24c)
// deploy/make-handle-record.sh signs a handle record under the org key of the org record beside
// it, which the core's verifyHandleRecord accepts under that key, and refuses a local part outside spec/SPEC.md §12.3.
// And (24d) its --domain form signs <local>@<domain> for a two-label, a three-label and an xn-- name,
// keeps the usuals label form as it was, and refuses a trailing dot, an IDN and the other names the core refuses.
// And (24e) --out <dir> puts the record in <dir>/<local>.json, the same bytes as the default form
// (the signing time and the signature aside), mode 0644, nothing under deploy/well-known/ and no temporary file left,
// replaces a regular file that exists, and refuses a link, a directory in its place, a missing directory, an empty
// value and a missing value. And (24f) make-org-records.sh --domain writes a two-label org record
// to --out <dir>/address.json (mode 0644, verified by the core) and a three-label one to public/<domain>/, under which
// make-handle-record.sh --domain signs with no copy, prints the DNS TXT line that discover reads back to the record
// key, replaces a regular file, and refuses one label, a missing relay URL, a link and --out without --domain.

const outputs: string[] = []
const cli = (...args: string[]): Promise<CliRun> => cliProcess(args, outputs)

/** A long-running CLI process, its stdout lines collected as they come; killed at the end if still running. */
function running(args: readonly string[]): {
  lines: string[]
  child: ChildProcess
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
  onTestFinished(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL')
  })
  return { lines, child, exit }
}

/** The record of `kind` the relay serves for `address`, read over HTTP. */
async function served(url: string, address: string, kind: string): Promise<AcRecord> {
  const res = await fetch(`${url}/v0/fetch/record/${address}/${kind}`)
  expect(res.status, `${kind} of ${address}`).toBe(200)
  return parseRecord(new Uint8Array(await res.arrayBuffer()))
}

/** A record's content: everything but its iat and its signature. */
const content = (r: AcRecord) => ({ ...r, iat: 0, sig: '' })

/** One process, as execFile runs it, with its exit code and output. */
function exec(file: string, args: readonly string[], env: NodeJS.ProcessEnv): Promise<CliRun> {
  return new Promise((resolve) => {
    execFile(file, args, { env, timeout: 30_000 }, (error, stdout, stderr) => {
      outputs.push(stdout, stderr)
      const code = error === null ? 0 : typeof error.code === 'number' ? error.code : -1
      const split = (t: string) =>
        t
          .split('\n')
          .filter((l) => l !== '' && l !== NO_RECOVERY && !/ExperimentalWarning|trace-warnings/.test(l))
      resolve({ code, out: split(stdout), err: split(stderr) })
    })
  })
}

describe('e2e scenario 24: records kept alive, revocations written, and unreachable relays named', () => {
  it('(24a) record keep --once makes the relay serve both records with a newer iat and nothing else changed, a running keep republishes until SIGTERM, and make-org-records.sh writes rotation_key and revoked, which keep keeps; no key appears in any output', async () => {
    const w = await world('s24a')
    const home = join(w.dir, 'cli-home')
    const dir = ['--dir', home]
    const [bob, alice] = (await Promise.all(['bob', 'alice'].map((n) => cli('keygen', n, ...dir)))).map(
      (r) => r.out[0] as string,
    ) as [string, string]
    const record = join(home, 'bob.address.json')
    const accept = join(home, 'bob.accept.json')
    await cli(
      'record',
      'address',
      'bob',
      '--relay',
      w.url,
      '--sealing-key',
      '--ttl',
      '3600',
      '--out',
      record,
      ...dir,
    )
    await cli(
      'record',
      'accept-from',
      'bob',
      '--root',
      alice,
      '--max-bytes',
      '65536',
      '--ttl',
      '86400',
      '--out',
      accept,
      ...dir,
    )
    expect(await cli('publish', w.url, record)).toEqual({ code: 0, out: [`ok address ${bob}`], err: [] })
    expect(await cli('publish', w.url, accept)).toEqual({ code: 0, out: [`ok accept-from ${bob}`], err: [] })
    const first = await served(w.url, bob, 'address')
    const firstAccept = await served(w.url, bob, 'accept-from')

    // The record was made with a sealing key (before forward secrecy), so keep publishes epoch 1 first, which re-signs it
    // with no sealing key at the clock's second; the relay takes it only when that is later than the stored iat.
    await untilSecond(first.iat + 1)
    const once = await cli('record', 'keep', '--as', 'bob', '--relay', w.url, '--once', ...dir)
    expect([once.code, once.err]).toEqual([0, []])
    const iat = Number(
      / iat (\d+) /.exec(once.out.find((l) => l.startsWith('republished address')) as string)?.[1],
    )
    expect(once.out).toEqual([
      `published key ${bob} ${w.url}`,
      `published address ${bob} ${w.url}`,
      `republished address ${bob} iat ${iat} ${w.url}`,
      `republished accept-from ${bob} iat ${iat} ${w.url}`,
    ])
    const second = verifyRecord(await served(w.url, bob, 'address'), now())
    const secondAccept = verifyRecord(await served(w.url, bob, 'accept-from'), now())
    expect([second.iat, secondAccept.iat]).toEqual([iat, iat])
    expect(iat).toBeGreaterThan(first.iat)
    // Nothing else changed but the sealing key, which epoch 1 took out of the record.
    expect([content(second), content(secondAccept)]).toEqual([
      { ...content(first), sealing_key: null },
      content(firstAccept),
    ])

    // A running keep, every second: two republishes, then SIGTERM ends it with 0.
    const keep = running(['record', 'keep', '--as', 'bob', '--relay', w.url, '--every', '1', ...dir])
    await until(
      'two republishes',
      () => keep.lines.filter((l) => l.startsWith('republished address')).length >= 2,
    )
    keep.child.kill('SIGTERM')
    expect(await keep.exit).toBe(0)
    const iats = keep.lines
      .filter((l) => l.startsWith('republished address'))
      .map((l) => Number(l.split(' ')[4]))
    expect(iats[0]).toBeGreaterThan(iat)
    expect(iats[1]).toBeGreaterThan(iats[0] as number)
    expect((await served(w.url, bob, 'address')).iat).toBe(iats.at(-1))
    expect(keep.lines[0]).toMatch(/^next \d+$/)

    // make-org-records.sh from a scratch copy of its directory, so nothing under deploy/well-known/public/ changes.
    const scratch = join(w.dir, 'script')
    mkdirSync(join(scratch, 'deploy'), { recursive: true })
    copyFileSync(join(REPO, 'deploy', 'make-org-records.sh'), join(scratch, 'deploy', 'make-org-records.sh'))
    const links = [join(scratch, 'packages'), join(scratch, 'node_modules')]
    symlinkSync(join(REPO, 'packages'), links[0] as string)
    symlinkSync(join(REPO, 'node_modules'), links[1] as string)
    const orgHome = join(w.dir, 'org-home')
    mkdirSync(orgHome, { mode: 0o700 })
    const rotation = (await cli('keygen', 'org-rot', '--dir', orgHome)).out[0] as string
    let made: CliRun
    try {
      made = await exec(
        'bash',
        [
          join(scratch, 'deploy', 'make-org-records.sh'),
          's24org',
          w.url,
          '--ttl',
          '3600',
          '--rotation-key',
          rotation,
          '--revoke',
          alice,
          '--revoke',
          bob,
        ],
        { ...process.env, AC_HOME: orgHome },
      )
    } finally {
      for (const link of links) unlinkSync(link)
    }
    expect([made.code, made.err]).toEqual([0, []])
    const org = (/^key org-s24org (\S+) new$/.exec(made.out[0] as string)?.[1] ?? '') as string
    const out = 'deploy/well-known/public/s24org/.well-known/bag/address.json'
    expect(made.out[1]).toMatch(
      new RegExp(
        `^record s24org key ${org} relays ${w.url} ttl 3600 iat \\d+ exp \\d+ rotated_from - rotation_key ${rotation} revoked 2 out ${out}$`,
      ),
    )
    expect(existsSync(join(REPO, 'deploy', 'well-known', 'public', 's24org'))).toBe(false)
    const orgFile = join(scratch, out)
    const orgRecord = verifyRecord(parseRecord(readFileSync(orgFile, 'utf8')), now()) as AddressRecord
    expect(orgRecord).toMatchObject({ key: org, rotation_key: rotation, revoked: [alice, bob], ttl: 3600 })
    expect(await cli('publish', w.url, orgFile)).toEqual({ code: 0, out: [`ok address ${org}`], err: [] })
    await untilSecond(orgRecord.iat + 1)
    const kept = await cli(
      'record',
      'keep',
      '--as',
      'org-s24org',
      '--relay',
      w.url,
      '--once',
      '--dir',
      orgHome,
    )
    expect([kept.code, kept.err]).toEqual([0, []])
    expect(kept.out).toEqual([
      `published key ${org} ${w.url}`,
      `published address ${org} ${w.url}`,
      expect.stringMatching(new RegExp(`^republished address ${org} iat \\d+ ${w.url}$`)),
    ])
    const orgServed = verifyRecord(await served(w.url, org, 'address'), now()) as AddressRecord
    expect(orgServed).toMatchObject({ rotation_key: rotation, revoked: [alice, bob], sealing_key: null })
    expect(orgServed.iat).toBeGreaterThan(orgRecord.iat)

    const secrets = [
      ...homeSecrets(home, ['bob', 'alice']),
      ...homeSecrets(orgHome, ['org-s24org', 'org-rot']),
    ]
    const all = outputs.join('\n')
    expect(secrets.filter((s) => all.includes(s))).toEqual([])
    console.log(
      `MEASURE L3(e): keep --once -> the relay serves iat ${iat - first.iat} s newer, content unchanged but for the sealing key epoch 1 took out; a running keep republished ${iats.length} times and exited 0 on SIGTERM`,
    )
    console.log(
      `MEASURE L1(e): make-org-records.sh wrote rotation_key and ${orgRecord.revoked.length} revoked, the core verified them, keep --once kept them through epoch 1`,
    )
  })

  it("(24b) once the relay has stopped, a send to a recipient whose record the sender holds is reason=unreachable with its retry scheduled, a 403 before it kept its code, keep --once is unreachable, and the sender's audit line reads unreachable, names the cause and verifies", async () => {
    const w = await world('s24b')
    const home = join(w.dir, 'cli-home')
    const dir = ['--dir', home]
    const [alice, bob] = (
      await Promise.all(['alice', 'bob', 'carol'].map((n) => cli('keygen', n, ...dir)))
    ).map((r) => r.out[0] as string) as [string, string, string]
    const record = join(home, 'bob.address.json')
    const accept = join(home, 'bob.accept.json')
    await cli(
      'record',
      'address',
      'bob',
      '--relay',
      w.url,
      '--sealing-key',
      '--ttl',
      '3600',
      '--out',
      record,
      ...dir,
    )
    await cli(
      'record',
      'accept-from',
      'bob',
      '--root',
      alice,
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
    const send = (as: string) =>
      cli('send', '--as', as, '--to', bob, '--relay', w.url, '--type', 'chat.v1', '--body', '{"n":1}', ...dir)
    const sent = await send('alice')
    expect([sent.code, sent.out[1]]).toEqual([0, `published ${w.url} tries=1`])
    // The hint names the sender's root: carol signs as her own root, so her address.
    const carol = (await cli('address', 'carol', ...dir)).out[0] as string
    const refused = await send('carol')
    expect([refused.code, refused.out[1], refused.err]).toEqual([
      1,
      `failed ${w.url} tries=1 reason=root-not-accepted`,
      [
        `bag: root-not-accepted: ${w.url} failed; the bytes stay in the outbox, and resend --id ${refused.out[0]} sends them; the recipient does not accept this identity's root yet: ask them to add ${carol} (or your org's domain root) to their accept-from record, or send under a chain from a root they accept (send --auth / delegate)`,
      ],
    ])
    if (!w.relay.spawned) return // under AC_RELAY_URL the harness cannot stop the relay
    await w.relay.stop()
    const before = now()
    const lost = await send('alice')
    const after = now()
    expect([lost.code, lost.err]).toEqual([
      1,
      [
        `bag: unreachable: ${w.url} retry; the bytes stay in the outbox, and resend --id ${lost.out[0]} sends them`,
      ],
    ])
    const m = /^retry (\S+) tries=1 reason=unreachable next_at=(\d+)$/.exec(lost.out[1] as string)
    expect(m?.[1]).toBe(w.url)
    expect(Number(m?.[2])).toBeGreaterThanOrEqual(before + 1)
    expect(Number(m?.[2])).toBeLessThanOrEqual(after + 1)
    const keep = await cli('record', 'keep', '--as', 'bob', '--relay', w.url, '--once', ...dir)
    expect([keep.code, keep.out]).toEqual([1, []])
    expect(keep.err[0]).toMatch(/^bag: unreachable: no response: /)
    const log = join(home, 'state', 'alice', 'audit.jsonl')
    const line = readAuditLines(log)
      .map(parseAuditLine)
      .filter((l) => l.event === 'publish' && l.id === lost.out[0])
    expect(line.map((l) => [l.decision, l.reason, JSON.parse(l.detail as string)])).toEqual([
      [
        'retry',
        'unreachable',
        { relay: w.url, tries: 1, status: 0, next_at: Number(m?.[2]), cause: 'unreachable' },
      ],
    ])
    expect((await cli('audit', 'verify', log)).out[0]).toMatch(/^ok \d+ lines$/)
    console.log(
      `MEASURE L4(e): after the relay stopped: "${lost.out[1]}"; before it, a 403 kept root-not-accepted`,
    )
  })

  it('(24c) make-handle-record.sh writes a handle record beside the org record that the core verifies under the org key and no other, refuses a local part outside §12.3 with exit 2 and writes nothing for it, and prints no key', async () => {
    const w = await world('s24c')
    // Both scripts from a scratch copy of their directory, so nothing under deploy/well-known/public/ changes.
    const scratch = join(w.dir, 'script')
    mkdirSync(join(scratch, 'deploy'), { recursive: true })
    for (const name of ['make-org-records.sh', 'make-handle-record.sh']) {
      copyFileSync(join(REPO, 'deploy', name), join(scratch, 'deploy', name))
    }
    const links = [join(scratch, 'packages'), join(scratch, 'node_modules')]
    symlinkSync(join(REPO, 'packages'), links[0] as string)
    symlinkSync(join(REPO, 'node_modules'), links[1] as string)
    const home = join(w.dir, 'cli-home')
    const alice = (await cli('keygen', 'alice', '--dir', home)).out[0] as string
    const orgHome = join(w.dir, 'org-home')
    mkdirSync(orgHome, { mode: 0o700 })
    const env = { ...process.env, AC_HOME: orgHome }
    const script = (name: string, ...args: string[]) =>
      exec('bash', [join(scratch, 'deploy', name), ...args], env)
    let made: CliRun
    let handled: CliRun
    let refused: CliRun
    try {
      made = await script('make-org-records.sh', 's24h', w.url, '--ttl', '3600')
      handled = await script('make-handle-record.sh', 's24h', 'alice19', alice, '--ttl', '3600')
      refused = await script('make-handle-record.sh', 's24h', 'Alice', alice)
    } finally {
      for (const link of links) unlinkSync(link)
    }
    expect([made.code, made.err]).toEqual([0, []])
    const org = (/^key org-s24h (\S+) new$/.exec(made.out[0] as string)?.[1] ?? '') as string
    const handle = 'alice19@s24h.usuals.now'
    const dir = 'deploy/well-known/public/s24h/.well-known/bag'
    expect([handled.code, handled.out[0], handled.err]).toEqual([0, `handle ${handle} address ${alice}`, []])
    expect(handled.out[1]).toMatch(
      new RegExp(`^record handle org ${org} iat \\d+ ttl 3600 exp \\d+ out ${dir}/handles/alice19\\.json$`),
    )
    expect(handled.out).toHaveLength(2)
    const written = JSON.parse(readFileSync(join(scratch, dir, 'handles', 'alice19.json'), 'utf8'))
    const orgRecord = parseRecord(readFileSync(join(scratch, dir, 'address.json'))) as AddressRecord
    expect(orgRecord.key).toBe(org)
    const r = verifyHandleRecord(written, { org, handle, revoked: orgRecord.revoked }, now())
    expect(r).toMatchObject({ kind: 'handle', org, handle, address: alice, ttl: 3600 })
    expect(r.iat).toBeGreaterThanOrEqual(orgRecord.iat)
    expect(() => verifyHandleRecord(written, { org: alice, handle }, now())).toThrow(/^resolve-failed/)
    expect(() => verifyHandleRecord(written, { org, handle: 'bob@s24h.usuals.now' }, now())).toThrow(
      /^resolve-failed/,
    )

    expect([refused.code, refused.out, refused.err]).toEqual([
      2,
      [],
      [
        'make-handle-record: the local part is 1 to 64 of a-z, 0-9, ., - and _, from and to a letter or a digit (spec/SPEC.md §12.3), not Alice',
      ],
    ])
    expect(readdirSync(join(scratch, dir, 'handles'))).toEqual(['alice19.json'])
    expect(existsSync(join(REPO, 'deploy', 'well-known', 'public', 's24h'))).toBe(false)

    const secrets = [...homeSecrets(home, ['alice']), ...homeSecrets(orgHome, ['org-s24h'])]
    const all = outputs.join('\n')
    expect(secrets.filter((s) => all.includes(s))).toEqual([])
    console.log(
      `MEASURE L5(e): make-handle-record.sh wrote ${handle} -> ${alice.slice(0, 16)}..., ttl ${r.ttl}, verified under the org key and refused under another; Alice refused, exit 2`,
    )
  })

  it('(24d) make-handle-record.sh --domain signs <local>@<domain> for a two-label, a three-label and an xn-- name under the org record placed for it, writes the usuals form to the same file as the label form, and refuses a trailing dot, an IDN and the names the core does not read as a handle domain with exit 2 and writes nothing', async () => {
    const w = await world('s24d')
    const scratch = join(w.dir, 'script')
    mkdirSync(join(scratch, 'deploy'), { recursive: true })
    for (const name of ['make-org-records.sh', 'make-handle-record.sh']) {
      copyFileSync(join(REPO, 'deploy', name), join(scratch, 'deploy', name))
    }
    const links = [join(scratch, 'packages'), join(scratch, 'node_modules')]
    symlinkSync(join(REPO, 'packages'), links[0] as string)
    symlinkSync(join(REPO, 'node_modules'), links[1] as string)
    const home = join(w.dir, 'cli-home')
    const alice = (await cli('keygen', 'alice', '--dir', home)).out[0] as string
    const orgHome = join(w.dir, 'org-home')
    mkdirSync(orgHome, { mode: 0o700 })
    const env = { ...process.env, AC_HOME: orgHome }
    const script = (name: string, ...args: string[]) =>
      exec('bash', [join(scratch, 'deploy', name), ...args], env)
    const pub = join(scratch, 'deploy', 'well-known', 'public')
    const wk = '.well-known/bag'
    // make-org-records.sh writes the label form only: the org's record is copied to each other domain.
    const domains = ['acme-s24d.example', 'mail.acme-s24d.example', 'xn--bcher-kva.example']
    const refused = [
      'acme-s24d.example.', // a trailing dot
      'bücher.example', // an IDN, never decoded
      '例え.example',
      'Acme-s24d.example', // upper case
      'acme', // one label
      '127.0.0.1', // an IP literal
      '10.0.0.1',
      'acme-s24d.internal', // special-use last labels
      'acme-s24d.local',
      '-acme.example', // a label that starts with a hyphen
      'a..example', // an empty label
      '.acme.example',
      `${'a'.repeat(64)}.example`, // a label of 64
      `${Array(5).fill('a'.repeat(62)).join('.')}.example`, // over 253 characters
    ]
    const runs: CliRun[] = []
    // The length limits: a label of 64, a local part of 65 refused; a local part of 64 accepted.
    const longLabel = 'b'.repeat(64)
    const local64 = 'a'.repeat(64)
    const local65 = 'a'.repeat(65)
    let made: CliRun
    let two: CliRun
    let three: CliRun
    let xn: CliRun
    let usuals: CliRun
    let label: CliRun
    let max: CliRun
    let labelOver: CliRun
    let localOverLabel: CliRun
    let localOverDomain: CliRun
    try {
      made = await script('make-org-records.sh', 's24d', w.url, '--ttl', '3600')
      const orgFile = join(pub, 's24d', wk, 'address.json')
      for (const d of domains) {
        mkdirSync(join(pub, d, wk), { recursive: true })
        copyFileSync(orgFile, join(pub, d, wk, 'address.json'))
      }
      const sign = (d: string) =>
        script('make-handle-record.sh', '--domain', d, 'alice', alice, '--ttl', '3600', '--key', 'org-s24d')
      two = await sign(domains[0] as string)
      three = await sign(domains[1] as string)
      xn = await sign(domains[2] as string)
      // The usuals default: the label form, and --domain <label>.usuals.now, which is the same label.
      usuals = await script('make-handle-record.sh', '--domain', 's24d.usuals.now', 'bob', alice)
      label = await script('make-handle-record.sh', 's24d', 'bob', alice)
      for (const d of refused) {
        runs.push(await script('make-handle-record.sh', '--domain', d, 'alice', alice, '--key', 'org-s24d'))
      }
      const domain = domains[0] as string
      const keyed = ['--key', 'org-s24d']
      const ttl = ['--ttl', '3600']
      max = await script('make-handle-record.sh', '--domain', domain, local64, alice, ...ttl, ...keyed)
      labelOver = await script('make-handle-record.sh', longLabel, 'alice', alice)
      localOverLabel = await script('make-handle-record.sh', 's24d', local65, alice)
      localOverDomain = await script('make-handle-record.sh', '--domain', domain, local65, alice, ...keyed)
    } finally {
      for (const link of links) unlinkSync(link)
    }
    expect([made.code, made.err]).toEqual([0, []])
    const org = (/^key org-s24d (\S+) new$/.exec(made.out[0] as string)?.[1] ?? '') as string
    const orgRecord = parseRecord(readFileSync(join(pub, 's24d', wk, 'address.json'))) as AddressRecord
    expect(orgRecord.key).toBe(org)
    const checked = (run: CliRun, name: string, local: string, handle: string, ttl: number) => {
      expect([run.code, run.out[0], run.err]).toEqual([0, `handle ${handle} address ${alice}`, []])
      expect(run.out).toHaveLength(2)
      const m = /^record handle org (\S+) iat \d+ ttl (\d+) exp \d+ out (\S+)$/.exec(run.out[1] as string)
      expect([m?.[1], m?.[2], m?.[3]]).toEqual([
        org,
        String(ttl),
        `deploy/well-known/public/${name}/${wk}/handles/${local}.json`,
      ])
      const written = JSON.parse(readFileSync(join(pub, name, wk, 'handles', `${local}.json`), 'utf8'))
      expect(verifyHandleRecord(written, { org, handle, revoked: orgRecord.revoked }, now())).toMatchObject({
        kind: 'handle',
        org,
        handle,
        address: alice,
        ttl,
      })
      return written
    }
    const w2 = checked(two, domains[0] as string, 'alice', 'alice@acme-s24d.example', 3600)
    const w3 = checked(three, domains[1] as string, 'alice', 'alice@mail.acme-s24d.example', 3600)
    checked(xn, domains[2] as string, 'alice', 'alice@xn--bcher-kva.example', 3600)
    // A record is bound to its handle's domain, the local part and the domain both (§12.4 item 3).
    const asTwo = { org, handle: 'alice@acme-s24d.example', revoked: orgRecord.revoked }
    expect(() => verifyHandleRecord(w3, asTwo, now())).toThrow(/^resolve-failed/)
    const asThree = { org, handle: 'alice@mail.acme-s24d.example', revoked: orgRecord.revoked }
    expect(() => verifyHandleRecord(w2, asThree, now())).toThrow(/^resolve-failed/)
    // The usuals default: the label form and --domain <label>.usuals.now are one handle in one file.
    checked(label, 's24d', 'bob', 'bob@s24d.usuals.now', 86400)
    const bobLine = `handle bob@s24d.usuals.now address ${alice}`
    expect([usuals.code, usuals.out[0], usuals.err]).toEqual([0, bobLine, []])
    expect(usuals.out[1]).toMatch(new RegExp(`out deploy/well-known/public/s24d/${wk}/handles/bob\\.json$`))

    const reasons = runs.map((r, i) => [refused[i], r.code, r.out, r.err.length])
    expect(reasons).toEqual(refused.map((d) => [d, 2, [], 1]))
    for (const r of runs) expect(r.err[0]).toMatch(/^make-handle-record: the domain/)
    expect(runs[0]?.err[0]).toMatch(/^make-handle-record: the domain has no trailing dot/)
    const ascii = /^make-handle-record: the domain is ASCII; give an internationalized name in its xn-- form/
    expect(runs[1]?.err[0]).toMatch(ascii)
    expect(runs[2]?.err[0]).toMatch(ascii)
    // The length limits (§12.3 item 1): a local part of 64 is signed, one of 65 and a label of 64 are not.
    checked(max, domains[0] as string, local64, `${local64}@acme-s24d.example`, 3600)
    const overLabel = `make-handle-record: the label is one DNS label, such as acme, not ${longLabel}`
    const overLocal = `make-handle-record: the local part is 1 to 64 of a-z, 0-9, ., - and _, from and to a letter or a digit (spec/SPEC.md §12.3), not ${local65}`
    expect([labelOver.code, labelOver.out, labelOver.err]).toEqual([2, [], [overLabel]])
    expect([localOverLabel.code, localOverLabel.out, localOverLabel.err]).toEqual([2, [], [overLocal]])
    expect([localOverDomain.code, localOverDomain.out, localOverDomain.err]).toEqual([2, [], [overLocal]])
    // Nothing was written for a refused name: only the four directories made above, each with its own files.
    expect(readdirSync(pub).sort()).toEqual(['s24d', ...domains].sort())
    expect(readdirSync(join(pub, domains[0] as string, wk, 'handles')).sort()).toEqual(
      [`${local64}.json`, 'alice.json'].sort(),
    )
    for (const d of domains.slice(1)) expect(readdirSync(join(pub, d, wk, 'handles'))).toEqual(['alice.json'])
    expect(readdirSync(join(pub, 's24d', wk, 'handles'))).toEqual(['bob.json'])
    expect(existsSync(join(REPO, 'deploy', 'well-known', 'public', 's24d'))).toBe(false)

    const secrets = [...homeSecrets(home, ['alice']), ...homeSecrets(orgHome, ['org-s24d'])]
    const all = outputs.join('\n')
    expect(secrets.filter((s) => all.includes(s))).toEqual([])
    console.log(
      `MEASURE 24d: make-handle-record.sh --domain wrote a two-label, a three-label and an xn-- handle, each verified under the org key and bound to its own domain; the usuals label form unchanged; ${refused.length} names refused, a 64-character local part signed, a 64-character label and a 65-character local part refused, exit 2, nothing written`,
    )
  }, 90_000)

  it('(24e) make-handle-record.sh --out <dir> writes <dir>/<local>.json with the bytes of the default form (iat and sig aside) and mode 0644, verified under the org key, for the label form and a relative <dir> with --domain, writes nothing under deploy/well-known/ and leaves no temporary file, replaces an existing regular file, and refuses a link, a directory in its place, a missing directory, a missing org record, an empty and a missing value with exit 2 and writes nothing', async () => {
    const w = await world('s24e')
    const scratch = join(w.dir, 'script')
    mkdirSync(join(scratch, 'deploy'), { recursive: true })
    for (const name of ['make-org-records.sh', 'make-handle-record.sh']) {
      copyFileSync(join(REPO, 'deploy', name), join(scratch, 'deploy', name))
    }
    const links = [join(scratch, 'packages'), join(scratch, 'node_modules')]
    symlinkSync(join(REPO, 'packages'), links[0] as string)
    symlinkSync(join(REPO, 'node_modules'), links[1] as string)
    const home = join(w.dir, 'cli-home')
    const alice = (await cli('keygen', 'alice', '--dir', home)).out[0] as string
    const orgHome = join(w.dir, 'org-home')
    mkdirSync(orgHome, { mode: 0o700 })
    // The signing runs take their scratch space from a directory of ours, which must be empty after each one.
    const tmp = join(w.dir, 'tmp')
    mkdirSync(tmp)
    const env = { ...process.env, AC_HOME: orgHome }
    const script = (name: string, ...args: string[]) =>
      exec('bash', [join(scratch, 'deploy', name), ...args], env)
    const sh = join(scratch, 'deploy', 'make-handle-record.sh')
    const tmpEnv = { ...env, TMPDIR: tmp }
    const handle = (...args: string[]) => exec('bash', [sh, ...args], tmpEnv)
    // The script run from the world's directory, so that a relative <dir> is read against it.
    const cdRun = 'cd "$1" && shift && exec bash "$@"'
    const fromHere = (...args: string[]) => exec('bash', ['-c', cdRun, 'x', w.dir, sh, ...args], tmpEnv)
    const pub = join(scratch, 'deploy', 'well-known', 'public')
    const wk = '.well-known/bag'
    const handles = join(pub, 's24e', wk, 'handles')
    const served = join(w.dir, 'served')
    const relative = join(w.dir, 'served-rel')
    const domain = 'acme-s24e.example'
    mkdirSync(served)
    mkdirSync(relative)
    const dangling = join(served, 'frank.json')
    symlinkSync(join(w.dir, 'nowhere.json'), dangling)
    mkdirSync(join(served, 'gina.json'))
    const missing = join(w.dir, 'no-such-dir')
    let made: CliRun
    let plain: CliRun
    let outed: CliRun
    let outedDomain: CliRun
    let again: CliRun
    let toDir: CliRun
    let noOrg: CliRun
    let toMissing: CliRun
    let toDangling: CliRun
    let toEmpty: CliRun
    let toNothing: CliRun
    let before = ''
    let afterReplaced = ''
    let handlesExistAfterOut = true
    try {
      made = await script('make-org-records.sh', 's24e', w.url, '--ttl', '3600')
      mkdirSync(join(pub, domain, wk), { recursive: true })
      copyFileSync(join(pub, 's24e', wk, 'address.json'), join(pub, domain, wk, 'address.json'))
      // The --out form first, so that a stray write to the default path would show; then the default form.
      outed = await handle('s24e', 'carol', alice, '--out', served)
      before = readFileSync(join(served, 'carol.json'), 'utf8')
      handlesExistAfterOut = existsSync(handles)
      plain = await handle('s24e', 'carol', alice)
      // A second handle with --out, the --domain form and a relative <dir>.
      const domainArgs = ['--domain', domain, 'dave', alice, '--ttl', '3600', '--key', 'org-s24e']
      outedDomain = await fromHere(...domainArgs, '--out', 'served-rel')
      // The same handle again with another ttl: the existing regular file is replaced.
      again = await handle('s24e', 'carol', alice, '--ttl', '3600', '--out', served)
      afterReplaced = readFileSync(join(served, 'carol.json'), 'utf8')
      // The refusals.
      toMissing = await handle('s24e', 'erin', alice, '--out', missing)
      toDangling = await handle('s24e', 'frank', alice, '--out', served)
      toEmpty = await handle('s24e', 'erin', alice, '--out', '')
      toNothing = await handle('s24e', 'erin', alice, '--out')
      toDir = await handle('s24e', 'gina', alice, '--out', served)
      noOrg = await handle('nolabel', 'erin', alice, '--out', served)
    } finally {
      for (const link of links) unlinkSync(link)
    }
    expect([made.code, made.err]).toEqual([0, []])
    const org = (/^key org-s24e (\S+) new$/.exec(made.out[0] as string)?.[1] ?? '') as string
    const orgRecord = parseRecord(readFileSync(join(pub, 's24e', wk, 'address.json'))) as AddressRecord
    expect(orgRecord.key).toBe(org)

    // The default form is as before: the file under deploy/well-known/, named on the last line.
    const carolLine = `handle carol@s24e.usuals.now address ${alice}`
    expect([plain.code, plain.out[0], plain.err]).toEqual([0, carolLine, []])
    const defaultPath = `out deploy/well-known/public/s24e/${wk}/handles/carol.json`
    expect((plain.out[1] as string).endsWith(defaultPath)).toBe(true)
    // --out: the same two lines but for the path, the file at that path, with the bytes of the default form.
    expect([outed.code, outed.out[0], outed.err]).toEqual([0, carolLine, []])
    expect(outed.out).toHaveLength(2)
    const m = /^record handle org (\S+) iat \d+ ttl (\d+) exp \d+ out (\S+)$/.exec(outed.out[1] as string)
    expect([m?.[1], m?.[2], m?.[3]]).toEqual([org, '86400', join(served, 'carol.json')])
    const reference = readFileSync(join(handles, 'carol.json'), 'utf8')
    const bare = (text: string) =>
      text.replace(/"iat":\s*\d+/, '"iat": 0').replace(/"sig":\s*"[^"]*"/, '"sig": ""')
    expect(before.endsWith('\n')).toBe(true)
    expect(bare(before)).toBe(bare(reference))
    expect(before).not.toBe(bare(before))
    const carol = verifyHandleRecord(
      JSON.parse(before),
      { org, handle: 'carol@s24e.usuals.now', revoked: orgRecord.revoked },
      now(),
    )
    expect(carol).toMatchObject({
      kind: 'handle',
      org,
      handle: 'carol@s24e.usuals.now',
      address: alice,
      ttl: 86400,
    })
    expect(statSync(join(served, 'carol.json')).mode & 0o777).toBe(0o644)
    // --out wrote nothing under deploy/well-known/ (the default run came after); no temporary file is left.
    expect(handlesExistAfterOut).toBe(false)
    expect(readdirSync(tmp)).toEqual([])

    // The --domain form with a relative <dir>: read against where it was run, the absolute path printed.
    const daveHandle = `dave@${domain}`
    expect([outedDomain.code, outedDomain.out[0], outedDomain.err]).toEqual([
      0,
      `handle ${daveHandle} address ${alice}`,
      [],
    ])
    const daveLine = outedDomain.out[1] as string
    expect(daveLine.startsWith(`record handle org ${org} iat `)).toBe(true)
    expect(daveLine).toContain(' ttl 3600 exp ')
    expect(daveLine.endsWith(` out ${join(relative, 'dave.json')}`)).toBe(true)
    const daveText = readFileSync(join(relative, 'dave.json'), 'utf8')
    const dave = verifyHandleRecord(
      JSON.parse(daveText),
      { org, handle: daveHandle, revoked: orgRecord.revoked },
      now(),
    )
    expect(dave).toMatchObject({ kind: 'handle', org, handle: daveHandle, address: alice, ttl: 3600 })
    expect(statSync(join(relative, 'dave.json')).mode & 0o777).toBe(0o644)
    expect(readdirSync(join(pub, domain, wk))).toEqual(['address.json'])

    // The replacement: the same name, the new record (ttl 3600), mode 0644, verified under the org key.
    expect([again.code, again.out[0], again.err]).toEqual([0, carolLine, []])
    expect(again.out[1]).toContain(' ttl 3600 exp ')
    expect(afterReplaced).not.toBe(before)
    const replaced = verifyHandleRecord(
      JSON.parse(afterReplaced),
      { org, handle: 'carol@s24e.usuals.now', revoked: orgRecord.revoked },
      now(),
    )
    expect(replaced).toMatchObject({
      kind: 'handle',
      org,
      handle: 'carol@s24e.usuals.now',
      address: alice,
      ttl: 3600,
    })
    expect(statSync(join(served, 'carol.json')).mode & 0o777).toBe(0o644)

    // The refusals: exit 2, nothing on stdout, one line on stderr, and nothing written.
    const lines = (r: CliRun) => [r.code, r.out, r.err]
    const refusal = (f: string) =>
      `make-handle-record: refusing to replace ${f}: it is a link or not a regular file`
    expect(lines(toMissing)).toEqual([
      2,
      [],
      [`make-handle-record: the --out directory does not exist (it is never made): ${missing}`],
    ])
    expect(existsSync(missing)).toBe(false)
    expect(lines(toDangling)).toEqual([2, [], [refusal(dangling)]])
    expect(lines(toDir)).toEqual([2, [], [refusal(join(served, 'gina.json'))]])
    expect(statSync(join(served, 'gina.json')).isDirectory()).toBe(true)
    expect(readdirSync(join(served, 'gina.json'))).toEqual([])
    // A die after the scratch directory was made: the exit trap removes it, and nothing lands in <dir>.
    expect([noOrg.code, noOrg.out]).toEqual([2, []])
    expect(noOrg.err.join('\n')).toContain('no org record at')
    expect(existsSync(join(w.dir, 'nowhere.json'))).toBe(false)
    const emptyOut = 'make-handle-record: --out takes the directory to write <local>.json in'
    expect(lines(toEmpty)).toEqual([2, [], [emptyOut]])
    expect([toNothing.code, toNothing.out]).toEqual([2, []])
    expect(toNothing.err[0]).toMatch(/^usage: AC_HOME=<home> deploy\/make-handle-record\.sh /)
    expect(readdirSync(served).sort()).toEqual(['carol.json', 'frank.json', 'gina.json'])
    expect(readdirSync(relative)).toEqual(['dave.json'])
    expect(readdirSync(handles)).toEqual(['carol.json'])
    expect(readdirSync(tmp)).toEqual([])
    expect(existsSync(join(REPO, 'deploy', 'well-known', 'public', 's24e'))).toBe(false)

    const secrets = [...homeSecrets(home, ['alice']), ...homeSecrets(orgHome, ['org-s24e'])]
    const all = [...outputs, before, afterReplaced, daveText].join('\n')
    expect(secrets.filter((s) => all.includes(s))).toEqual([])
    console.log(
      'MEASURE 24e: make-handle-record.sh --out <dir> wrote <local>.json with the bytes of the default form (iat and sig aside), mode 0644, verified under the org key, for the label form and for --domain with a relative <dir>; nothing under deploy/well-known/, no temporary file; an existing regular file replaced; a link, a directory in its place, a missing directory, a missing org record, an empty and a missing value refused, exit 2, nothing written',
    )
  }, 90_000)

  it('(24f) make-org-records.sh --domain <domain> --out <dir> writes <dir>/address.json, mode 0644, which the core verifies, with its sealing key, and prints the TXT line of spec/SPEC.md §12.2, which discover reads back to the record key; it replaces a regular file there; without --out a three-label domain goes to public/<domain>/, where make-handle-record.sh --domain signs under it with no copy; a one-label domain, a missing relay URL, a link at the output and --out without --domain are refused with exit 2 and write nothing; no key in any output', async () => {
    const w = await world('s24f')
    const scratch = join(w.dir, 'script')
    mkdirSync(join(scratch, 'deploy'), { recursive: true })
    for (const name of ['make-org-records.sh', 'make-handle-record.sh']) {
      copyFileSync(join(REPO, 'deploy', name), join(scratch, 'deploy', name))
    }
    const links = [join(scratch, 'packages'), join(scratch, 'node_modules')]
    symlinkSync(join(REPO, 'packages'), links[0] as string)
    symlinkSync(join(REPO, 'node_modules'), links[1] as string)
    const home = join(w.dir, 'cli-home')
    const alice = (await cli('keygen', 'alice', '--dir', home)).out[0] as string
    const orgHome = join(w.dir, 'org-home')
    mkdirSync(orgHome, { mode: 0o700 })
    // The signing runs take their scratch space from a directory of ours, which must be empty after each one.
    const tmp = join(w.dir, 'tmp')
    mkdirSync(tmp)
    const env = { ...process.env, AC_HOME: orgHome, TMPDIR: tmp }
    const script = (name: string, ...args: string[]) =>
      exec('bash', [join(scratch, 'deploy', name), ...args], env)
    const org = (...args: string[]) => script('make-org-records.sh', ...args)
    const pub = join(scratch, 'deploy', 'well-known', 'public')
    const wk = '.well-known/bag'
    const two = 'acme-s24f.example'
    const three = 'mail.acme-s24f.example'
    const served = join(w.dir, 'served')
    mkdirSync(served)
    // A link at the output: one to a file of ours, which must not change, and a dangling one.
    const linked = join(w.dir, 'linked')
    const dangling = join(w.dir, 'dangling')
    mkdirSync(linked)
    mkdirSync(dangling)
    const target = join(w.dir, 'target.json')
    writeFileSync(target, 'not a record\n')
    symlinkSync(target, join(linked, 'address.json'))
    symlinkSync(join(w.dir, 'nowhere.json'), join(dangling, 'address.json'))
    let outed: CliRun
    let again: CliRun
    let tree: CliRun
    let handled: CliRun
    let oneLabel: CliRun
    let noRelay: CliRun
    let toLink: CliRun
    let toDangling: CliRun
    let outNoDomain: CliRun
    let first = ''
    let afterAgain = ''
    try {
      outed = await org('--domain', two, w.url, '--ttl', '3600', '--out', served)
      first = readFileSync(join(served, 'address.json'), 'utf8')
      // The daily re-sign: the same domain and <dir> again, the default ttl.
      again = await org('--domain', two, w.url, '--out', served)
      afterAgain = readFileSync(join(served, 'address.json'), 'utf8')
      // Without --out: the label form's tree, public/<domain>/, which make-handle-record.sh --domain reads.
      tree = await org('--domain', three, w.url, '--ttl', '3600')
      handled = await script('make-handle-record.sh', '--domain', three, 'alice', alice, '--ttl', '3600')
      // The refusals.
      oneLabel = await org('--domain', 'acme', w.url, '--out', served)
      noRelay = await org('--domain', 'other-s24f.example', '--out', served)
      toLink = await org('--domain', two, w.url, '--out', linked)
      toDangling = await org('--domain', two, w.url, '--out', dangling)
      outNoDomain = await org('s24f', w.url, '--out', served)
    } finally {
      for (const link of links) unlinkSync(link)
    }
    // The TXT line, spec/SPEC.md §12.2's zone-file form; the core's discover reads it back to the key.
    const txtLine = (run: CliRun, domain: string, orgKey: string) => {
      expect(run.out[2]).toBe(`dns _bag.${domain}.  IN  TXT  "v=ac1; key=${orgKey}"`)
      const text = (run.out[2] as string).split('  TXT  ')[1] as string
      const found = discover([parseTxtPresentation(text)], domain)
      expect(found).toEqual({
        key: orgKey,
        origin: `https://${domain}`,
        url: `https://${domain}/${wk}/address.json`,
      })
      return found
    }

    // --out: three lines (the key made, the record and the TXT line), the record at <dir>/address.json.
    expect([outed.code, outed.err, outed.out.length]).toEqual([0, [], 3])
    const key = (/^key org-acme-s24f\.example (\S+) new$/.exec(outed.out[0] as string)?.[1] ?? '') as string
    expect(key).toMatch(/^ed25519:[0-9a-f]{64}$/)
    expect(outed.out[1]).toMatch(
      new RegExp(
        `^record ${two} key ${key} relays ${w.url} ttl 3600 iat \\d+ exp \\d+ rotated_from - rotation_key - revoked 0 out ${join(served, 'address.json')}$`,
      ),
    )
    const record = verifyRecord(parseRecord(first), now()) as AddressRecord
    expect(record).toMatchObject({ kind: 'address', key, relays: [w.url], ttl: 3600, revoked: [] })
    // The org record carries its sealing key, as the label form's does (spec/SPEC.md §7.2: a key or null).
    expect(record.sealing_key).toMatch(/^[0-9a-f]{64}$/)
    expect(first.endsWith('\n')).toBe(true)
    expect(statSync(join(served, 'address.json')).mode & 0o777).toBe(0o644)
    checkDiscovered(record, txtLine(outed, two, key))
    // Nothing under deploy/well-known/ for it, and no temporary file in <dir> or in TMPDIR.
    expect(existsSync(join(pub, two))).toBe(false)
    expect(readdirSync(tmp)).toEqual([])

    // The re-sign: the key kept, the regular file replaced by the new record, verified, mode 0644.
    expect([again.code, again.err, again.out[0]]).toEqual([0, [], `key org-${two} ${key} existing`])
    expect(again.out[1]).toContain(' ttl 86400 iat ')
    const replaced = readFileSync(join(served, 'address.json'), 'utf8')
    expect(replaced).not.toBe(first)
    expect(verifyRecord(parseRecord(replaced), now())).toMatchObject({ key, ttl: 86400 })
    expect(statSync(join(served, 'address.json')).mode & 0o777).toBe(0o644)
    txtLine(again, two, key)

    // Without --out: the default key org-<domain>, the record under public/<domain>/, a handle signed there.
    expect([tree.code, tree.err, tree.out.length]).toEqual([0, [], 3])
    const made3 = /^key org-mail\.acme-s24f\.example (\S+) new$/.exec(tree.out[0] as string)
    const key3 = (made3?.[1] ?? '') as string
    const treePath = `deploy/well-known/public/${three}/${wk}/address.json`
    const treeLine = tree.out[1] as string
    expect(treeLine.startsWith(`record ${three} key ${key3} relays ${w.url} ttl 3600 iat `)).toBe(true)
    expect(treeLine.endsWith(` out ${treePath}`)).toBe(true)
    const text3 = readFileSync(join(scratch, treePath), 'utf8')
    const record3 = verifyRecord(parseRecord(text3), now()) as AddressRecord
    expect(record3.key).toBe(key3)
    checkDiscovered(record3, txtLine(tree, three, key3))
    const handle = `alice@${three}`
    expect([handled.code, handled.out[0], handled.err]).toEqual([0, `handle ${handle} address ${alice}`, []])
    const written = JSON.parse(readFileSync(join(pub, three, wk, 'handles', 'alice.json'), 'utf8'))
    const bound = { org: key3, handle, revoked: record3.revoked }
    expect(verifyHandleRecord(written, bound, now())).toMatchObject({
      kind: 'handle',
      org: key3,
      handle,
      address: alice,
      ttl: 3600,
    })

    // The refusals: exit 2, nothing on stdout, one line on stderr, and nothing written.
    const lines = (r: CliRun) => [r.code, r.out, r.err]
    const shape =
      'make-org-records: the domain is a lower-case host of two or more DNS labels, each 1 to 63 of a-z, 0-9 and - from and to a letter or a digit, at most 253 characters, not acme'
    expect(lines(oneLabel)).toEqual([2, [], [shape]])
    const relayNeeded =
      'make-org-records: the relay URL is required with --domain other-s24f.example (the default is for <label>.usuals.now only)'
    expect(lines(noRelay)).toEqual([2, [], [relayNeeded]])
    const refusal = (dir: string) =>
      `make-org-records: refusing to replace ${join(dir, 'address.json')}: it is a link or not a regular file`
    expect(lines(toLink)).toEqual([2, [], [refusal(linked)]])
    expect(lines(toDangling)).toEqual([2, [], [refusal(dangling)]])
    expect(readFileSync(target, 'utf8')).toBe('not a record\n')
    expect(lstatSync(join(linked, 'address.json')).isSymbolicLink()).toBe(true)
    expect(existsSync(join(w.dir, 'nowhere.json'))).toBe(false)
    expect(readdirSync(linked)).toEqual(['address.json'])
    expect(readdirSync(dangling)).toEqual(['address.json'])
    // --out without --domain: the label form reads that argv as it did before, a usage error.
    expect([outNoDomain.code, outNoDomain.out, outNoDomain.err.length]).toEqual([2, [], 1])
    expect(outNoDomain.err[0]).toMatch(/^usage: AC_HOME=<home> deploy\/make-org-records\.sh <label> /)
    expect(existsSync(join(orgHome, 'keys', 'org-s24f.json'))).toBe(false)
    expect(existsSync(join(orgHome, 'keys', 'org-other-s24f.example.json'))).toBe(false)
    // The one-label refusal wrote nothing: the served record is the re-sign's, and no key org-acme was made.
    expect(readFileSync(join(served, 'address.json'), 'utf8')).toBe(afterAgain)
    expect(existsSync(join(orgHome, 'keys', 'org-acme.json'))).toBe(false)
    expect(readdirSync(served)).toEqual(['address.json'])
    expect(readdirSync(pub)).toEqual([three])
    expect(readdirSync(tmp)).toEqual([])
    expect(existsSync(join(REPO, 'deploy', 'well-known', 'public', two))).toBe(false)
    expect(existsSync(join(REPO, 'deploy', 'well-known', 'public', three))).toBe(false)

    const secrets = [...homeSecrets(home, ['alice']), ...homeSecrets(orgHome, [`org-${two}`, `org-${three}`])]
    const all = [...outputs, first, replaced, text3, JSON.stringify(written)].join('\n')
    expect(secrets.filter((s) => all.includes(s))).toEqual([])
    console.log(
      'MEASURE 24f: make-org-records.sh --domain wrote a two-label org record to --out <dir>/address.json (mode 0644, verified by the core, sealing key kept) and replaced it on a re-sign, a three-label one to public/<domain>/ under which make-handle-record.sh --domain signed with no copy; each TXT line read back by discover to the record key; a one-label domain, a missing relay URL, two links and --out without --domain refused, exit 2, nothing written',
    )
  }, 90_000)
})

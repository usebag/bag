import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { join } from 'node:path'
import { HomeCustody } from '@usebag/edge'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { RELAY as AGENT_RELAY, loggedIn, publishRecord } from './support/agent.ts'
import { tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'
import { FakeSecurity, forms, occurrences } from './support/security.ts'

// The CLI on the custody port: keygen chooses a custody, every other command
// finds it, a keychain identity is read once per command that signs, and naming one reads nothing.

const tmp = tempDir('custody')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
let n = 0
const home = (): string => join(tmp.dir, `home-${n++}`)

describe('keygen --custody, and the commands on a keychain identity (fake security)', () => {
  it('refuses a custody, a keychain access and keychain options it does not know', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    for (const [args, err] of [
      [['--custody', 'vault'], 'bag: usage: --custody is file, keychain or agent, not "vault"'],
      [['--keychain', '/tmp/k'], 'bag: usage: --keychain and --keychain-access go with --custody keychain'],
      [
        ['--keychain-access', 'prompt'],
        'bag: usage: --keychain and --keychain-access go with --custody keychain',
      ],
      [
        ['--custody', 'keychain', '--keychain-access', 'sometimes'],
        'bag: usage: --keychain-access is prompt or security, not "sometimes"',
      ],
    ] as const) {
      const r = await cli(io, 'keygen', 'alice', ...args, '--dir', dir)
      expect([r.code, r.err[0]]).toEqual([1, err])
    }
    expect(existsSync(dir)).toBe(false)
  })

  it('refuses the keychain with an io that runs no security, and leaves no pointer behind', async () => {
    const io = testIo(new MemoryRelay())
    const dir = home()
    const r = await cli(io, 'keygen', 'alice', '--custody', 'keychain', '--dir', dir)
    expect([r.code, r.err[0]]).toEqual([1, 'bag: ENOENT: keychain: this io runs no /usr/bin/security'])
    expect(existsSync(join(dir, 'keychain', 'alice.json'))).toBe(false)
    expect((await cli(io, 'keys', 'list', '--dir', dir)).out).toEqual([])
  })

  it('makes a prompt item by default, refuses a name the other custody holds, and names an identity with no read', async () => {
    const fake = new FakeSecurity()
    const io = { ...testIo(new MemoryRelay()), security: fake.run }
    const dir = home()
    const bob = (await cli(io, 'keygen', 'bob', '--custody', 'keychain', '--dir', dir)).out[0]
    expect(fake.calls[0]?.input).toContain(' -T "" -X ')
    expect(fake.calls[0]?.input?.trim().endsWith('"')).toBe(false)
    expect((await cli(io, 'keygen', 'alice', '--dir', dir)).code).toBe(0)
    const taken = await cli(io, 'keygen', 'bob', '--dir', dir)
    expect([taken.code, taken.err[0]]).toEqual([
      1,
      `bag: EEXIST: bob is held already, by ${join(dir, 'keychain', 'bob.json')}`,
    ])
    const other = await cli(io, 'keygen', 'alice', '--custody', 'keychain', '--dir', dir)
    expect([other.code, other.err[0]]).toEqual([
      1,
      `bag: EEXIST: alice is held already, by ${join(dir, 'keys', 'alice.json')}`,
    ])
    expect(fake.calls).toHaveLength(1)
    expect(await cli(io, 'address', 'bob', '--dir', dir)).toEqual({ code: 0, out: [bob], err: [] })
    expect(fake.calls).toHaveLength(1)
  })

  it('signs records, sends and receives as keychain identities, one read per command that signs, no key printed', async () => {
    const fake = new FakeSecurity()
    const relay = new MemoryRelay()
    const io = { ...testIo(relay), security: fake.run }
    const dir = home()
    const kc = [
      '--custody',
      'keychain',
      '--keychain',
      '/tmp/bag-test.keychain-db',
      '--keychain-access',
      'security',
    ]
    const alice = (await cli(io, 'keygen', 'alice', ...kc, '--dir', dir)).out[0] as string
    const bob = (await cli(io, 'keygen', 'bob', ...kc, '--dir', dir)).out[0] as string
    const reads = (): number => fake.calls.filter((c) => c.args[0] === 'find-generic-password').length
    const file = join(dir, 'bob.address.json')
    const steps = [
      ['record', 'address', 'bob', '--relay', RELAY, '--sealing-key', '--out', file, '--dir', dir],
      ['publish', RELAY, file],
      [
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
        '{"text":"hi"}',
        '--dir',
        dir,
      ],
      ['inbox', '--as', 'bob', '--relay', RELAY, '--once', '--trust-root', alice, '--dir', dir],
    ]
    const ran = []
    for (const step of steps) {
      const before = reads()
      const r = await cli(io, ...step)
      expect(r.code, step.join(' ')).toBe(0)
      ran.push({ r, reads: reads() - before })
    }
    expect(ran.map((x) => x.reads)).toEqual([1, 0, 1, 1])
    expect(ran[3]?.r.out).toEqual([`accept ${ran[2]?.r.out[0]} ${alice} ${alice} chat.v1 {"text":"hi"}`])
    expect(fake.calls.find((c) => c.args[0] === 'find-generic-password')?.args.at(-1)).toBe(
      '/tmp/bag-test.keychain-db',
    )
    const printed = ran.flatMap((x) => [...x.r.out, ...x.r.err]).join('\n')
    expect(occurrences(printed, fake.seeds().flatMap(forms))).toBe(0)
  })
})

describe('keygen --custody agent, and the records of a principal whose login window is open', () => {
  // A test that fails with a window open leaves no agent behind: the signal ends it as a terminal's hangup would.
  afterEach(() => {
    process.emit('SIGHUP')
  })

  /** A home (0700, as the agent's socket needs) with the key file jane-keys, and the pointer jane made over it. */
  async function janeHome() {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = join(tmp.dir, `j${n++}`) // short: a Unix socket path holds about 100 bytes
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const address = (await cli(io, 'keygen', 'jane-keys', '--dir', dir)).out[0] as string
    const agent = ['--custody', 'agent', '--principal', 'jane-keys']
    const made = await cli(io, 'keygen', 'jane', ...agent, '--dir', dir)
    return { relay, io, dir, address, made }
  }
  const record = (dir: string, name = 'jane-keys', ...more: string[]) => [
    'record',
    'address',
    name,
    '--relay',
    AGENT_RELAY,
    '--dir',
    dir,
    ...more,
  ]

  it('writes the pointer of a file identity: its address, no new key, no seed; and refuses what it cannot', async () => {
    const { io, dir, address, made } = await janeHome()
    expect(made).toEqual({ code: 0, out: [address], err: [] })
    expect(statSync(join(dir, 'agent', 'jane.json')).mode & 0o777).toBe(0o600)
    const text = readFileSync(join(dir, 'keys', 'jane-keys.json'), 'utf8')
    const keyFile = JSON.parse(text) as Record<string, string>
    const seeds = [keyFile.sign_seed, keyFile.seal_priv].map((h) => Buffer.from(h as string, 'hex'))
    const pointer = readFileSync(join(dir, 'agent', 'jane.json'), 'utf8')
    expect(occurrences(pointer, seeds.flatMap(forms))).toBe(0)
    expect(JSON.parse(pointer)).toMatchObject({ custody: 'agent', address })
    expect((await cli(io, 'address', 'jane', '--dir', dir)).out).toEqual([address])
    const listed = (await cli(io, 'keys', 'list', '--dir', dir)).out.map((l) => l.split(' ').slice(0, 3))
    expect(listed).toEqual([
      ['jane', address, 'agent'],
      ['jane-keys', address, 'file'],
    ])
    const refuse = async (...args: string[]) => (await cli(io, 'keygen', ...args, '--dir', dir)).err[0]
    expect(await refuse('x', '--custody', 'agent')).toBe(
      'bag: usage: --custody agent needs --principal <identity>',
    )
    expect(await refuse('x', '--principal', 'jane-keys')).toBe(
      'bag: usage: --principal and --recovery go with --custody agent',
    )
    const agent = ['--custody', 'agent', '--principal']
    expect(await refuse('x', ...agent, 'jane-keys', '--keychain', '/tmp/k')).toBe(
      'bag: usage: --keychain and --keychain-access go with --custody keychain',
    )
    expect(await refuse('x', ...agent, 'nobody')).toMatch(/^bag: ENOENT: /)
    expect(await refuse('jane-keys', ...agent, 'jane-keys')).toBe(
      `bag: EEXIST: jane-keys is held already, by ${join(dir, 'keys', 'jane-keys.json')}`,
    )
    expect(await refuse('jane', ...agent, 'jane-keys')).toMatch(/^bag: EEXIST: /)
    expect(await refuse('x', ...agent, 'jane')).toBe(
      "bag: not-authorized: jane is held by the agent, which signs a session's hops only",
    )
    expect(existsSync(join(dir, 'agent', 'x.json'))).toBe(false)
  })

  it('refuses record address, record keep and publish of an address record while the window is open, and then allows them', async () => {
    const { relay, io, dir, address } = await janeHome()
    const keys = new HomeCustody(dir).keys('jane-keys')
    const h = { dir, keys, address }
    publishRecord(relay, h)
    const file = join(dir, 'before.json')
    expect((await cli(io, ...record(dir, 'jane-keys', '--out', file))).code).toBe(0)
    const login = await loggedIn(relay, h)
    expect(login.io.stdout[0]).toContain(`login ${address} until `)
    const closed = 'bag: window-open: a login window holds jane: run ac logout first'
    const snap = () => [relay.published.length, [...relay.records.values()]]
    const refused = async (...args: string[]) => {
      const before = snap()
      const err = (await cli(io, ...args)).err[0]
      expect(snap(), args.join(' ')).toEqual(before)
      return err
    }
    expect(await refused(...record(dir))).toBe(closed)
    expect(await refused('publish', AGENT_RELAY, file, '--dir', dir)).toBe(closed)
    const keep = ['record', 'keep', '--as', 'jane-keys', '--relay', AGENT_RELAY, '--once', '--dir', dir]
    expect(await refused(...keep)).toBe(closed)
    const accept = ['record', 'accept-from', 'jane-keys', '--root', '*', '--max-bytes', '9', '--ttl', '60']
    expect((await cli(io, ...accept, '--dir', dir)).code).toBe(0)
    expect((await cli(io, 'logout', '--as', 'jane', '--dir', dir)).code).toBe(0)
    await login.ran
    expect((await cli(io, ...record(dir))).code).toBe(0)
    expect((await cli(io, 'publish', AGENT_RELAY, file, '--dir', dir)).code).toBe(0)
  })

  it('refuses while a listener holds the socket, for the address of the agent pointer only, and not with none', async () => {
    const { io, dir } = await janeHome()
    await cli(io, 'keygen', 'bob', '--dir', dir)
    const server = createServer((c) => c.on('error', () => undefined))
    await new Promise<void>((up) => server.listen(join(dir, 'agent.sock'), up))
    const code = async (name: string) => (await cli(io, ...record(dir, name))).err[0]
    const closed = 'bag: window-open: a login window holds jane: run ac logout first'
    try {
      expect(await code('jane-keys')).toBe(closed)
      expect(await code('bob')).toBeUndefined()
    } finally {
      await new Promise<void>((down) => server.close(() => down()))
    }
    expect(await code('jane-keys')).toBeUndefined()
  })

  it('writes --recovery into the pointer, lists it as a fifth field, and lists a pointer without one as four (S7 (a))', async () => {
    const { io, dir } = await janeHome()
    for (const [name, setting] of [
      ['r1', 'personal'],
      ['r2', 'none'],
    ] as const) {
      const args = ['--custody', 'agent', '--principal', 'jane-keys', '--recovery', setting]
      expect((await cli(io, 'keygen', name, ...args, '--dir', dir)).code).toBe(0)
      const pointer = JSON.parse(readFileSync(join(dir, 'agent', `${name}.json`), 'utf8'))
      expect(pointer).toMatchObject({ custody: 'agent', recovery: setting })
    }
    const listed = (await cli(io, 'keys', 'list', '--dir', dir)).out.map((l) => l.split(' '))
    expect(listed.map((f) => [f[0], f[2], f[4]])).toEqual([
      ['jane', 'agent', undefined],
      ['jane-keys', 'file', undefined],
      ['r1', 'agent', 'recovery=personal'],
      ['r2', 'agent', 'recovery=none'],
    ])
    expect(listed.map((f) => f.length)).toEqual([4, 4, 5, 5])
  })

  it('lists a pointer with a hand-written recovery value outside personal and none as four fields, forging no line', async () => {
    const { io, dir } = await janeHome()
    const file = join(dir, 'agent', 'jane.json')
    const pointer = JSON.parse(readFileSync(file, 'utf8'))
    for (const odd of ['personal\nx jane-keys ed25519:00 agent -', 'odd', 'none ']) {
      writeFileSync(file, JSON.stringify({ ...pointer, recovery: odd }), { mode: 0o600 })
      const listed = (await cli(io, 'keys', 'list', '--dir', dir)).out
      expect(
        listed.map((l) => l.split(' ').length),
        JSON.stringify(odd),
      ).toEqual([4, 4])
    }
    writeFileSync(file, JSON.stringify({ ...pointer, recovery: 'personal' }), { mode: 0o600 })
    expect((await cli(io, 'keys', 'list', '--dir', dir)).out.map((l) => l.split(' ').length)).toEqual([5, 4])
  })

  it('refuses --recovery without --custody agent, and a value other than personal or none, as usage with no pointer', async () => {
    const { io, dir } = await janeHome()
    const refuse = async (...args: string[]) => (await cli(io, 'keygen', 'x', ...args, '--dir', dir)).err[0]
    const agent = ['--custody', 'agent', '--principal', 'jane-keys']
    const both = 'bag: usage: --principal and --recovery go with --custody agent'
    expect(await refuse('--recovery', 'personal')).toBe(both)
    expect(await refuse('--custody', 'file', '--recovery', '')).toBe(both)
    expect(await refuse(...agent, '--recovery', 'sometimes')).toBe(
      'bag: usage: --recovery is personal or none, not "sometimes"',
    )
    expect(await refuse(...agent, '--recovery', '')).toBe(
      'bag: usage: --recovery is personal or none, not ""',
    )
    expect([existsSync(join(dir, 'agent', 'x.json')), existsSync(join(dir, 'keys', 'x.json'))]).toEqual([
      false,
      false,
    ])
  })

  it('checks the new name before it reads a keychain principal: a bad name raises no dialog', async () => {
    const fake = new FakeSecurity()
    const io = { ...testIo(new MemoryRelay()), security: fake.run }
    const dir = home()
    await cli(io, 'keygen', 'bob', '--custody', 'keychain', '--dir', dir)
    const calls = fake.calls.length
    const bad = await cli(io, 'keygen', '../x', '--custody', 'agent', '--principal', 'bob', '--dir', dir)
    expect([bad.code, bad.err[0]]).toEqual([1, expect.stringContaining('a key name is 1 to 64')])
    expect(fake.calls.length).toBe(calls)
    const made = await cli(io, 'keygen', 'ab', '--custody', 'agent', '--principal', 'bob', '--dir', dir)
    expect(made.code).toBe(0)
    expect(fake.calls.filter((c) => c.args[0] === 'find-generic-password')).toHaveLength(1)
  })
})

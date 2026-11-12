import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { SecurityResult, SecurityRunner } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { defaultCustody, NO_RECOVERY } from '../src/commands/keygen.ts'
import { tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'
import { FakeSecurity, occurrences } from './support/security.ts'

// keygen's default custody per platform, and identity custody's move both ways with the read-back before the move,
// on the fake /usr/bin/security (items in memory). Each home and HOME is a fresh directory under a short temp dir; no
// test reaches a real keychain.

const tmp = tempDir('idc')
afterAll(() => tmp.cleanup())
let n = 0
const STAMP = '20270115T080000Z' // T0 of the test clock
const bytes = (s: string): Uint8Array => new TextEncoder().encode(s)
const answer = (status: number, stdout = ''): SecurityResult => ({
  status,
  stdout: bytes(stdout),
  stderr: new Uint8Array(),
})

/** A fake security that also answers `default-keychain` (with `keychain`, or 50 for none) and can tamper reads. */
function world(o: { platform?: NodeJS.Platform; keychain?: string | null; tty?: boolean } = {}) {
  const base = join(tmp.dir, `w${n++}`)
  const home = join(base, 'home')
  const HOME = join(base, 'user')
  mkdirSync(join(HOME, '.Trash'), { recursive: true })
  const kcFile = join(base, 'login.keychain-db')
  writeFileSync(kcFile, '')
  const fake = new FakeSecurity()
  const hooks = { read: null as ((r: SecurityResult) => SecurityResult) | null, defaults: 0 }
  const run: SecurityRunner = (args, input) => {
    if (args[0] === 'default-keychain') {
      hooks.defaults++
      const kc = o.keychain === undefined ? kcFile : o.keychain
      return kc === null ? answer(50) : answer(0, `    "${kc}"\n`)
    }
    const r = fake.run(args, input)
    return args[0] === 'find-generic-password' && hooks.read !== null ? hooks.read(r) : r
  }
  const io = Object.assign(testIo(new MemoryRelay(), { HOME }), {
    security: run,
    ...(o.platform === undefined ? {} : { platform: o.platform }),
  })
  io.tty = o.tty ?? false
  return { base, home, HOME, fake, hooks, io, trash: join(HOME, '.Trash', `bag-custody-alice-${STAMP}`) }
}

describe('keygen: the default custody per platform', () => {
  it('darwin with a default keychain, a person at a terminal: a keychain item with the prompt access, one stderr line, the address only on stdout', async () => {
    const w = world({ platform: 'darwin', tty: true })
    const r = await cli(w.io, 'keygen', 'alice', '--dir', w.home)
    expect(r.code).toBe(0)
    expect(r.out).toHaveLength(1)
    expect(r.err).toEqual(['keygen: alice is kept in the macOS keychain (bag:alice)', NO_RECOVERY])
    expect(existsSync(join(w.home, 'keychain', 'alice.json'))).toBe(true)
    expect(existsSync(join(w.home, 'keys', 'alice.json'))).toBe(false)
    expect(w.fake.calls[0]?.input).toContain(' -T "" -X ')
    expect((await cli(w.io, 'keys', 'list', '--dir', w.home)).out[0]).toContain(' keychain ')
  })

  it('no terminal (a script, onboard, SSH, CI, rehearse), darwin with no default keychain, linux, the tests io: a key file, as before', async () => {
    const cases = [
      { platform: 'darwin', tty: false },
      { platform: 'darwin', keychain: null, tty: true },
      { platform: 'linux', tty: true },
      { tty: true },
    ] as const
    for (const o of cases) {
      const w = world(o)
      const r = await cli(w.io, 'keygen', 'alice', '--dir', w.home)
      expect([r.code, r.err]).toEqual([0, o.tty ? [NO_RECOVERY] : []])
      expect(existsSync(join(w.home, 'keys', 'alice.json'))).toBe(true)
      expect(existsSync(join(w.home, 'keychain'))).toBe(false)
      expect(w.hooks.defaults).toBe('platform' in o && o.platform === 'darwin' && o.tty ? 1 : 0)
    }
    expect(defaultCustody({ platform: 'darwin', isTty: true })).toBe('file') // no runner: no keychain
  })

  it('--custody file keeps a key file on darwin and never asks for the default keychain', async () => {
    const w = world({ platform: 'darwin', tty: true })
    expect((await cli(w.io, 'keygen', 'alice', '--custody', 'file', '--dir', w.home)).code).toBe(0)
    expect(existsSync(join(w.home, 'keys', 'alice.json'))).toBe(true)
    expect([w.hooks.defaults, w.fake.calls.length]).toEqual([0, 0])
  })

  it('a defaulted keychain that refuses (locked, no one at the dialog) names --custody file, and leaves no pointer', async () => {
    const w = world({ platform: 'darwin', tty: true })
    const run = w.io.security
    const io = Object.assign(w.io, {
      security: ((a, i) => (a[0] === '-i' ? answer(36) : run(a, i))) as SecurityRunner,
    })
    const r = await cli(io, 'keygen', 'alice', '--dir', w.home)
    expect(r.code).toBe(1)
    expect(r.err[0]).toMatch(
      /^bag: EACCES: keychain: .*; on a host no one watches, run keygen again with --custody file$/,
    )
    expect(existsSync(join(w.home, 'keychain', 'alice.json'))).toBe(false)
  })
})

describe('identity custody: the move both ways, verified before anything moves', () => {
  const made = async (w: ReturnType<typeof world>, custody: 'file' | 'keychain') => {
    const r = await cli(w.io, 'keygen', 'alice', '--custody', custody, '--dir', w.home)
    expect(r.code).toBe(0)
    w.io.tty = true
    return r.out[0] as string
  }

  it('--to keychain: the item written and read back, the key file into the dated Trash folder, created kept', async () => {
    const w = world()
    const address = await made(w, 'file')
    const keyFile = join(w.home, 'keys', 'alice.json')
    const text = readFileSync(keyFile, 'utf8')
    const created = statSync(keyFile).mtimeMs
    w.io.answers.push(true)
    const r = await cli(w.io, 'identity', 'custody', 'alice', '--to', 'keychain', '--dir', w.home)
    expect([r.code, r.err]).toEqual([0, []])
    expect(w.io.asked[0]).toContain('answer Allow; Always Allow would let any')
    expect(w.io.asked[0]).toContain(`then ${keyFile} moves into ${w.trash}; nothing is deleted`)
    expect(r.out).toEqual([
      `wrote bag:alice in the default keychain, ${join(w.home, 'keychain', 'alice.json')}`,
      `verified alice ${address}: the keychain copy reads back the same keys`,
      `moved ${keyFile} -> ${join(w.trash, 'alice.json')}`,
      `custody alice keychain ${address}`,
      expect.stringContaining(`${join(w.trash, 'alice.json')} still holds the private key of alice`),
    ])
    // the item was read back once, after the write, before the move
    expect(w.fake.calls.map((c) => c.args[0])).toEqual(['-i', 'find-generic-password'])
    expect(readFileSync(join(w.trash, 'alice.json'), 'utf8')).toBe(text)
    expect(existsSync(keyFile)).toBe(false)
    expect(statSync(join(w.home, 'keychain', 'alice.json')).mtimeMs).toBe(created)
    expect((await cli(w.io, 'address', 'alice', '--dir', w.home)).out).toEqual([address])
    const needles = JSON.parse(text) as { sign_seed: string; seal_priv: string }
    const printed = [...w.io.stdout, ...w.io.stderr, ...w.io.asked].join('\n')
    expect(occurrences(printed, [needles.sign_seed, needles.seal_priv])).toBe(0)
  })

  it('--to keychain: an item that reads back another sealing key is taken back (bad-key); the key file stays, nothing moves', async () => {
    const w = world()
    const address = await made(w, 'file')
    // the same signing key (so the custody's own address check passes) and another sealing key: only the compare sees it
    const held = JSON.parse(readFileSync(join(w.home, 'keys', 'alice.json'), 'utf8')) as { sign_seed: string }
    const other = JSON.stringify({ suite: 1, sign_seed: held.sign_seed, seal_priv: '00'.repeat(32) })
    w.hooks.read = (r) => (r.status === 0 ? answer(0, `${other}\n`) : r)
    w.io.answers.push(true)
    const r = await cli(w.io, 'identity', 'custody', 'alice', '--to', 'keychain', '--dir', w.home)
    expect(r.code).toBe(1)
    expect(r.err[0]).toMatch(
      /^bag: bad-key: the new copy of alice did not verify \(it reads back other keys\)/,
    )
    expect(r.err[0]).toContain(`the item stays: security delete-generic-password -s bag:alice -a ${address}`)
    expect(existsSync(join(w.home, 'keys', 'alice.json'))).toBe(true)
    expect(existsSync(join(w.home, 'keychain', 'alice.json'))).toBe(false)
    expect(existsSync(w.trash)).toBe(false)
    expect((await cli(w.io, 'address', 'alice', '--dir', w.home)).out).toEqual([address])
  })

  it('--to keychain: a Deny at the read-back dialog is EACCES; the key file stays, nothing moves', async () => {
    const w = world()
    await made(w, 'file')
    w.hooks.read = () => answer(128)
    w.io.answers.push(true)
    const r = await cli(w.io, 'identity', 'custody', 'alice', '--to', 'keychain', '--dir', w.home)
    expect(r.code).toBe(1)
    expect(r.err[0]).toMatch(
      /^bag: EACCES: the new copy of alice did not verify \(keychain: reading the item/,
    )
    expect(existsSync(join(w.home, 'keys', 'alice.json'))).toBe(true)
    expect(existsSync(join(w.home, 'keychain', 'alice.json'))).toBe(false)
  })

  it('--to file: a key file written and read back, the pointer into the Trash folder, the item named with its delete line', async () => {
    const w = world()
    const address = await made(w, 'keychain')
    const pointer = join(w.home, 'keychain', 'alice.json')
    const keyFile = join(w.home, 'keys', 'alice.json')
    const before = w.fake.seeds().map((s) => Buffer.from(s).toString('hex'))
    w.io.answers.push(true)
    const r = await cli(w.io, 'identity', 'custody', 'alice', '--to', 'file', '--dir', w.home)
    expect([r.code, r.err]).toEqual([0, []])
    expect(r.out).toEqual([
      `wrote ${keyFile}`,
      `verified alice ${address}: the file copy reads back the same keys`,
      `moved ${pointer} -> ${join(w.trash, 'alice.json')}`,
      `custody alice file ${address}`,
      `the keychain item of alice stays in the macOS keychain; to delete it: security delete-generic-password -s bag:alice -a ${address}`,
    ])
    const o = JSON.parse(readFileSync(keyFile, 'utf8')) as { sign_seed: string; seal_priv: string }
    expect([o.sign_seed, o.seal_priv]).toEqual(before)
    expect(statSync(keyFile).mode & 0o777).toBe(0o600)
    expect(w.fake.items.size).toBe(1) // never deleted
    expect((await cli(w.io, 'keys', 'list', '--dir', w.home)).out[0]).toContain(' file ')
  })

  it('a run again after a stop between write and move reads both, compares them and finishes; different keys are bad-key', async () => {
    const w = world()
    const address = await made(w, 'keychain')
    const keyFile = join(w.home, 'keys', 'alice.json')
    const [sign, seal] = w.fake.seeds().map((s) => Buffer.from(s).toString('hex'))
    mkdirSync(join(w.home, 'keys'), { mode: 0o700 })
    writeFileSync(keyFile, JSON.stringify({ suite: 1, sign_seed: sign, seal_priv: '11'.repeat(32) }), {
      mode: 0o600,
    })
    w.io.answers.push(true)
    const bad = await cli(w.io, 'identity', 'custody', 'alice', '--to', 'file', '--dir', w.home)
    expect([bad.code, bad.err[0]]).toEqual([
      1,
      expect.stringMatching(/^bag: bad-key: alice has a key file and a keychain item with different keys/),
    ])
    expect(w.io.asked).toEqual([]) // refused before the question
    writeFileSync(keyFile, JSON.stringify({ suite: 1, sign_seed: sign, seal_priv: seal }))
    w.io.answers.push(true)
    const r = await cli(w.io, 'identity', 'custody', 'alice', '--to', 'file', '--dir', w.home)
    expect(r.code).toBe(0)
    expect(w.io.asked[0]).toContain('is written already (an earlier run)')
    expect(r.out.at(-2)).toBe(`custody alice file ${address}`)
    expect(existsSync(join(w.home, 'keychain', 'alice.json'))).toBe(false)
  })

  it('an item an earlier --to file left: a later --to keychain is EEXIST with its delete line, nothing changed', async () => {
    const w = world()
    const address = await made(w, 'keychain')
    w.io.answers.push(true)
    expect((await cli(w.io, 'identity', 'custody', 'alice', '--to', 'file', '--dir', w.home)).code).toBe(0)
    const trash = join(w.HOME, '.Trash')
    const before = readdirSync(trash)
    w.io.answers.push(true)
    const r = await cli(w.io, 'identity', 'custody', 'alice', '--to', 'keychain', '--dir', w.home)
    expect(r.code).toBe(1)
    expect(r.err[0]).toBe(
      `bag: EEXIST: the keychain holds an item bag:alice already (an earlier --to file leaves it): nothing was changed; delete it with security delete-generic-password -s bag:alice -a ${address}, then run again`,
    )
    expect(existsSync(join(w.home, 'keys', 'alice.json'))).toBe(true)
    expect(existsSync(join(w.home, 'keychain', 'alice.json'))).toBe(false)
    expect(readdirSync(trash)).toEqual(before)
  })

  it('refuses: no terminal, a no, the custody it has, an agent identity, flags of the other direction', async () => {
    const w = world()
    await made(w, 'file')
    const go = (...a: string[]) => cli(w.io, 'identity', 'custody', ...a, '--dir', w.home)
    w.io.tty = false
    expect((await go('alice', '--to', 'keychain')).err[0]).toMatch(
      /^bag: no-tty: identity custody is a person's act/,
    )
    w.io.tty = true
    expect((await go('alice', '--to', 'keychain')).err[0]).toBe('bag: declined: nothing was changed')
    expect((await go('alice', '--to', 'file')).err[0]).toBe('bag: exists: alice is in file custody already')
    expect((await go('alice', '--to', 'vault')).err[0]).toBe(
      'bag: usage: --to is keychain or file, not "vault"',
    )
    expect((await go('alice', '--to', 'file', '--keychain', '/k')).err[0]).toBe(
      'bag: usage: --keychain and --keychain-access go with --to keychain',
    )
    expect(
      (await cli(w.io, 'keygen', 'ag', '--custody', 'agent', '--principal', 'alice', '--dir', w.home)).code,
    ).toBe(0)
    expect((await go('ag', '--to', 'keychain')).err[0]).toBe(
      'bag: not-authorized: ag is an agent identity: it holds no key to move',
    )
    expect(existsSync(join(w.home, 'keys', 'alice.json'))).toBe(true)
    expect(readdirSync(join(w.HOME, '.Trash'))).toEqual([])
  })
})

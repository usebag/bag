import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { rotateEpoch } from '../src/epochs.ts'
import { loadKeys } from '../src/home.ts'
import { addTrust, readTrust } from '../src/trust.ts'
import { T0, tempDir, testIo } from './support/io.ts'
import { makeLocalOnly, noRelay, recording, tripFetch } from './support/local-only.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// A local-only identity (relays [] in identities.json, bag 0.4.3) publishes nothing until bag identity relays gives it
// relays: keys rotate and record keep refuse with that step, before any key is read or relay asked; a keep job over
// the identities file passes it by with one line. init keeps --relay required in 0.4.3 (the spec's question 1).
// Every relay call, record read and fetch fails the test (packages/edge's tripwire, support/local-only.ts).

const tmp = tempDir('local-only')
afterAll(() => tmp.cleanup())
const R = 'http://127.0.0.1:1'
// The one refusal text, packages/home's refuseLocalOnly, for every command that would reach a relay as sam.
const PROMOTE =
  'bag: no-relays: sam is on this machine only: give it relays with bag identity relays sam --relay <url>, then run this again'
let n = 0

/** A home with sam on this machine only, and a relay network whose every call fails. */
async function localHome() {
  const net = noRelay()
  const io = testIo(net)
  const dir = join(tmp.dir, `h${n++}`)
  expect((await cli(io, 'keygen', 'sam', '--custody', 'file', '--dir', dir)).code).toBe(0)
  makeLocalOnly(dir, 'sam')
  return { net, io, dir }
}

describe('a local-only identity republishes nothing before its promotion', () => {
  it('keys rotate refuses with the promotion step, with or without --relay', async () => {
    const { net, io, dir } = await localHome()
    for (const relay of [['--relay', R], []]) {
      const ran = await cli(io, 'keys', 'rotate', 'sam', ...relay, '--dir', dir)
      expect(ran).toEqual({ code: 1, out: [], err: [PROMOTE] })
    }
    expect(existsSync(join(dir, 'key-records'))).toBe(false)
    expect(net.calls).toEqual([])
  })

  it('record keep --as refuses with the promotion step, the --plist job too', async () => {
    const { net, io, dir } = await localHome()
    for (const more of [['--once'], ['--plist'], []]) {
      const ran = await cli(io, 'record', 'keep', '--as', 'sam', '--relay', R, ...more, '--dir', dir)
      expect(ran).toEqual({ code: 1, out: [], err: [PROMOTE] })
    }
    expect(net.calls).toEqual([])
  })

  it('record keep --identities passes a local-only entry by with one line, no failure', async () => {
    const { net, io, dir } = await localHome()
    const ran = await cli(io, 'record', 'keep', '--identities', join(dir, 'identities.json'), '--once')
    expect(ran).toEqual({ code: 0, out: ['skipped sam: on this machine only'], err: [] })
    expect(net.calls).toEqual([])
  })

  it('record keep --identities over a mixed file (the keep job): the published one is kept, sam is never named', async () => {
    const relay = new MemoryRelay()
    const rec = recording(relay.client({}))
    const io = testIo({ client: () => rec.client })
    const base = join(tmp.dir, `mixed-${n++}`)
    const [here, there] = [join(base, 'sam'), join(base, 'ann')]
    const sam = (await cli(io, 'keygen', 'sam', '--local', '--custody', 'file', '--dir', here))
      .out[0] as string
    const ann = (await cli(io, 'keygen', 'ann', '--custody', 'file', '--dir', there)).out[0] as string
    expect((await cli(io, 'keys', 'rotate', 'ann', '--relay', R, '--dir', there)).code).toBe(0)
    const file = join(base, 'ids.json')
    const entries = [
      { label: 'sam', key: 'sam', home: here, relays: [] },
      { label: 'ann', key: 'ann', home: there, relays: [R] },
    ]
    writeFileSync(file, JSON.stringify({ version: 1, identities: entries }), { mode: 0o600 })
    io.time.now += 1
    const ran = await cli(io, 'record', 'keep', '--identities', file, '--once')
    expect(ran.code, ran.err.join(' ')).toBe(0)
    expect(ran.out[0]).toBe('skipped sam: on this machine only')
    expect(ran.out.some((l) => l.startsWith(`republished address ${ann}`))).toBe(true)
    expect(rec.calls.length).toBeGreaterThan(0)
    expect(rec.calls.filter((c) => c.includes(sam))).toEqual([])
    expect([...relay.records.keys()].filter((k) => k.startsWith(sam))).toEqual([])
  })

  it('an identity with relays keeps its usage: keys rotate still needs --relay', async () => {
    const io = testIo(noRelay())
    const dir = join(tmp.dir, `h${n++}`)
    expect((await cli(io, 'keygen', 'ann', '--custody', 'file', '--dir', dir)).code).toBe(0)
    const entry = { label: 'ann', key: 'ann', home: dir, relays: [R] }
    writeFileSync(join(dir, 'identities.json'), JSON.stringify({ version: 1, identities: [entry] }), {
      mode: 0o600,
    })
    expect((await cli(io, 'keys', 'rotate', 'ann', '--dir', dir)).err[0]).toBe(
      'bag: usage: --relay is required',
    )
  })

  it('init keeps --relay required in 0.4.3: no sheet, nothing written', async () => {
    const io = testIo(noRelay())
    io.tty = true
    const dir = join(tmp.dir, `h${n++}`)
    const ran = await cli(io, 'init', 'sam', '--dir', dir)
    expect(ran.code).toBe(1)
    expect(ran.err[0]).toBe('bag: usage: --relay is required')
    expect(existsSync(dir)).toBe(false)
  })
})

describe('keygen --local while an older bag service runs', () => {
  it('bag 0.4.2 alive in run/service.json: busy with the update step, nothing made, no relay asked', async () => {
    const net = noRelay()
    const io = testIo(net)
    const calls = tripFetch(io)
    const dir = join(tmp.dir, `h${n++}`)
    mkdirSync(join(dir, 'run'), { recursive: true })
    const service = { pid: process.pid, version: '0.4.2', contract: 1 }
    writeFileSync(join(dir, 'run', 'service.json'), JSON.stringify(service))
    const ran = await cli(io, 'keygen', 'sam', '--local', '--new', '--dir', dir)
    expect(ran.err[0], ran.err.join(' ')).toBe(
      `bag: busy: the running bag service (pid ${process.pid}) is bag 0.4.2, ` +
        'which refuses an identities file that holds an identity on this machine only: ' +
        'finish the update first (step P4 of the update page restarts it on the new version), then run this again',
    )
    expect(ran.code).toBe(1)
    expect(ran.out).toEqual([])
    expect(existsSync(join(dir, 'identities.json'))).toBe(false)
    expect(net.calls).toEqual([])
    expect(calls).toEqual([])
  })
})

describe('every command that reaches a relay as --as refuses a local-only identity first', () => {
  const ANY = `ed25519:${'ab'.repeat(32)}`
  const at = ['--relay', R]
  const table: [string, string[], string][] = [
    ['send', ['send', '--as', 'sam', ...at, '--to', ANY, '--body', 'hi'], 'run this again'],
    [
      'send to a handle',
      ['send', '--as', 'sam', ...at, '--to', 'ann@example.com', '--body', '{}'],
      'run this again',
    ],
    ['held list', ['held', 'list', '--as', 'sam', ...at], 'run this again'],
    ['resend', ['resend', '--as', 'sam', ...at], 'run this again'],
    ['inbox', ['inbox', '--as', 'sam', ...at, '--once'], 'run this again'],
    ['lookup', ['lookup', ANY, '--as', 'sam', ...at], 'run this again'],
    ['group create', ['group', 'create', 'sam', ...at, '--rotation-key', ANY], 'run this again'],
    ['group rotate', ['group', 'rotate', 'sam'], 'run this again'],
    ['peer invite', ['peer', 'invite', '--as', 'sam', ...at, '--name', 'bob'], 'run this again'],
    ['peer accept', ['peer', 'accept', 'x-code', '--as', 'sam', ...at, '--name', 'bob'], 'run this again'],
    ['pair', ['pair', '--as', 'sam', ...at, '--name', 'bob'], 'run this again'],
    ['login', ['login', '--as', 'sam', ...at], 'run this again'],
    ['onboard', ['onboard', 'sam', '--domain', 'example.com', ...at, '--accept', '*'], 'run this again'],
    ['keys rotate', ['keys', 'rotate', 'sam', ...at], 'rotate'],
    ['record keep', ['record', 'keep', '--as', 'sam', ...at, '--once'], 'rotate'],
  ]
  it.each(table)(
    '%s: no-relays with the promotion step, no relay asked, nothing fetched',
    async (_, argv) => {
      const { net, io, dir } = await localHome()
      io.tty = true
      const calls = tripFetch(io)
      const ran = await cli(io, ...argv.map((a) => (a === '.' ? dir : a)), '--dir', dir)
      expect(ran.err[0], ran.err.join(' ')).toBe(PROMOTE)
      expect(ran.code).toBe(1)
      expect(net.calls).toEqual([])
      expect(calls).toEqual([])
    },
  )
})

describe('rotateEpoch, the one path to KeyRecordAdmin.rotate, refuses a local-only identity for any caller', () => {
  it('no-relays with the promotion step, even with relays given; nothing signed, no relay asked', async () => {
    const { net, io, dir } = await localHome()
    const o = { home: dir, name: 'sam', keys: loadKeys(io, dir, 'sam'), relays: [R], held: null }
    await expect(rotateEpoch(io, o)).rejects.toMatchObject({ code: 'no-relays' })
    expect(existsSync(join(dir, 'records', 'sam.address.json'))).toBe(false)
    expect(net.calls).toEqual([])
  })
})

describe('unpair of a local-only identity: no --relay, no relay told', () => {
  const ROOT = `ed25519:${'cd'.repeat(32)}`

  it('takes no --relay: the root leaves trust.json, and no relay is asked', async () => {
    const { net, io, dir } = await localHome()
    io.tty = true
    io.answers.push(true)
    addTrust(dir, ROOT, T0)
    const calls = tripFetch(io)
    const ran = await cli(io, 'unpair', ROOT, '--as', 'sam', '--dir', dir)
    expect(ran.code, ran.err.join(' ')).toBe(0)
    expect(Object.keys(readTrust(dir))).not.toContain(ROOT)
    expect(net.calls).toEqual([])
    expect(calls).toEqual([])
  })

  it('with --relay is refused with the reason: trust.json unchanged, no relay asked', async () => {
    const { net, io, dir } = await localHome()
    io.tty = true
    addTrust(dir, ROOT, T0)
    const ran = await cli(io, 'unpair', ROOT, '--as', 'sam', '--relay', R, '--dir', dir)
    expect(ran.code).toBe(1)
    expect(ran.err[0]).toBe(
      'bag: usage: sam is on this machine only: no relay holds its records; run it without --relay',
    )
    expect(Object.keys(readTrust(dir))).toContain(ROOT)
    expect(net.calls).toEqual([])
  })

  it('an identity with relays still needs --relay', async () => {
    const io = testIo(noRelay())
    io.tty = true
    const dir = join(tmp.dir, `h${n++}`)
    expect((await cli(io, 'keygen', 'ann', '--custody', 'file', '--dir', dir)).code).toBe(0)
    const ran = await cli(io, 'unpair', ROOT, '--as', 'ann', '--dir', dir)
    expect(ran.err[0]).toBe('bag: usage: --relay is required')
  })
})

describe('the guard reads only identities.json, before any key', () => {
  it('group <verb> refuses before the key read: a local-only name with no key file is no-relays, not ENOENT', async () => {
    const io = testIo(noRelay())
    const dir = join(tmp.dir, `h${n++}`)
    expect((await cli(io, 'keygen', 'sam', '--custody', 'file', '--dir', dir)).code).toBe(0)
    makeLocalOnly(dir, 'ghost') // ghost: on this machine only, and no key in any custody
    for (const argv of [
      ['group', 'create', 'ghost', '--relay', R, '--rotation-key', `ed25519:${'ab'.repeat(32)}`],
      ['group', 'rotate', 'ghost'],
    ]) {
      const ran = await cli(io, ...argv, '--dir', dir)
      expect(ran.err[0]).toBe(PROMOTE.replaceAll('sam', 'ghost'))
    }
  })

  it('inbox --group refuses before the key read: a local-only name with no key file is no-relays, not ENOENT', async () => {
    const net = noRelay()
    const io = testIo(net)
    const dir = join(tmp.dir, `h${n++}`)
    expect((await cli(io, 'keygen', 'sam', '--custody', 'file', '--dir', dir)).code).toBe(0)
    makeLocalOnly(dir, 'ghost') // ghost: on this machine only, and no key in any custody
    const calls = tripFetch(io)
    const GROUP = `ed25519:${'ef'.repeat(32)}`
    const ran = await cli(
      io,
      'inbox',
      '--as',
      'ghost',
      '--relay',
      R,
      '--group',
      GROUP,
      '--once',
      '--dir',
      dir,
    )
    expect(ran.err[0], ran.err.join(' ')).toBe(PROMOTE.replaceAll('sam', 'ghost'))
    expect(ran.code).toBe(1)
    expect(net.calls).toEqual([])
    expect(calls).toEqual([])
  })

  it('an absent identities.json is not local-only: keys rotate goes past the guard to the relay', async () => {
    const net = noRelay()
    const io = testIo(net)
    const dir = join(tmp.dir, `h${n++}`)
    expect((await cli(io, 'keygen', 'sam', '--custody', 'file', '--dir', dir)).code).toBe(0)
    expect(existsSync(join(dir, 'identities.json'))).toBe(false)
    const ran = await cli(io, 'keys', 'rotate', 'sam', '--relay', R, '--dir', dir)
    expect(ran.code).toBe(1)
    expect(ran.err[0]).not.toContain('no-relays')
    expect(net.calls.length).toBeGreaterThan(0)
  })
})

describe('onboard refuses a local-only org key before anything is written or any relay asked', () => {
  // sam has relays (it is not in identities.json); only the org key is on this machine only.
  // A label has no dot, so the default org key's entry carries its own label, which the promotion step names.
  const cases: [string, string, string[], boolean][] = [
    ['org-example.com', 'org', [], true], // the default org key, with a key file
    ['acme', 'acme', ['--org-key', 'acme'], false], // a named org key with no key in any custody
  ]
  it.each(cases)(
    '%s: no-relays, no record and no served file, the tripwires saw nothing',
    async (org, label, more, keyed) => {
      const net = noRelay()
      const io = testIo(net)
      const dir = join(tmp.dir, `h${n++}`)
      expect((await cli(io, 'keygen', 'sam', '--custody', 'file', '--dir', dir)).code).toBe(0)
      if (keyed)
        expect((await cli(io, 'keygen', org, '--new', '--custody', 'file', '--dir', dir)).code).toBe(0)
      const entry = { label, key: org, home: dir, relays: [] }
      writeFileSync(join(dir, 'identities.json'), JSON.stringify({ version: 1, identities: [entry] }), {
        mode: 0o600,
      })
      const calls = tripFetch(io)
      const argv = ['onboard', 'sam', '--domain', 'example.com', '--relay', R, '--accept', '*', ...more]
      const ran = await cli(io, ...argv, '--dir', dir)
      expect(ran.err[0], ran.err.join(' ')).toBe(
        `bag: no-relays: ${label} is on this machine only: give it relays with bag identity relays ${label} --relay <url>, then run this again`,
      )
      expect(ran.code).toBe(1)
      expect(ran.out).toEqual([])
      expect(existsSync(join(dir, 'serve'))).toBe(false) // no well-known address file, no handle record
      for (const who of ['sam', org])
        expect(existsSync(join(dir, 'records', `${who}.address.json`))).toBe(false)
      expect(existsSync(join(dir, 'keys', 'acme.json'))).toBe(false) // no org key made for it either
      expect(net.calls).toEqual([])
      expect(calls).toEqual([])
    },
  )
})

describe('host install of a local-only identity: wired with no relay, nothing republished', () => {
  const REFUSED =
    'bag: usage: sam is on this machine only: no relay holds its records; run it without --relay'

  /** sam on this machine only, a project folder, and the tripwires on the relay and the record source. */
  async function hostHome() {
    const h = await localHome()
    const project = join(h.dir, '..', `project-${n++}`)
    mkdirSync(project, { recursive: true })
    const fetched = tripFetch(h.io)
    return { ...h, project, fetched }
  }
  const serverArgs = (file: string): string[] =>
    (JSON.parse(readFileSync(file, 'utf8')) as { mcpServers: { bag: { args: string[] } } }).mcpServers.bag
      .args

  it('claude-code --project: wired with no --relay, the tripwires saw nothing', async () => {
    const { net, io, dir, project, fetched } = await hostHome()
    const ran = await cli(
      io,
      'host',
      'install',
      'claude-code',
      '--as',
      'sam',
      '--project',
      project,
      '--dir',
      dir,
    )
    expect(ran.code, ran.err.join(' ')).toBe(0)
    expect(ran.out).toContain('sam: on this machine only, nothing republished')
    const args = serverArgs(join(project, '.mcp.json'))
    expect(args).toContain('sam')
    expect(args).not.toContain('--relay')
    expect(net.calls).toEqual([])
    expect(fetched).toEqual([])
  })

  it('claude-code --identities: the entry it records keeps relays []', async () => {
    const { net, io, dir, project } = await hostHome()
    const file = join(dir, '..', `ids-${n++}.json`) // a host's own file: the home's still says relays []
    const ran = await cli(
      io,
      ...[
        'host',
        'install',
        'claude-code',
        '--as',
        'sam',
        '--project',
        project,
        '--identities',
        file,
        '--dir',
        dir,
      ],
    )
    expect(ran.code, ran.err.join(' ')).toBe(0)
    const doc = JSON.parse(readFileSync(file, 'utf8')) as {
      identities: { label: string; relays: string[] }[]
    }
    expect(doc.identities.filter((e) => e.label === 'sam').map((e) => e.relays)).toEqual([[]])
    expect(net.calls).toEqual([])
  })

  it('omp --project: wired with no --relay, the tripwires saw nothing', async () => {
    const { net, io, dir, project, fetched } = await hostHome()
    const ran = await cli(io, 'host', 'install', 'omp', '--as', 'sam', '--project', project, '--dir', dir)
    expect(ran.code, ran.err.join(' ')).toBe(0)
    expect(readFileSync(join(project, '.omp', 'mcp.json'), 'utf8')).not.toContain('--relay')
    expect(net.calls).toEqual([])
    expect(fetched).toEqual([])
  })

  it('a --relay for it is refused with its label, on both paths; nothing wired, no relay asked', async () => {
    const { net, io, dir, project } = await hostHome()
    for (const host of ['claude-code', 'omp']) {
      const ran = await cli(
        io,
        'host',
        'install',
        host,
        '--as',
        'sam',
        '--relay',
        R,
        '--project',
        project,
        '--dir',
        dir,
      )
      expect(ran.err[0]).toBe(REFUSED)
    }
    expect(existsSync(join(project, '.mcp.json'))).toBe(false)
    expect(existsSync(join(project, '.omp'))).toBe(false)
    expect(net.calls).toEqual([])
  })

  it('an identity with relays still needs --relay, on both paths', async () => {
    const io = testIo(noRelay())
    const dir = join(tmp.dir, `h${n++}`)
    expect((await cli(io, 'keygen', 'ann', '--custody', 'file', '--dir', dir)).code).toBe(0)
    for (const host of ['claude-code', 'omp']) {
      const ran = await cli(io, 'host', 'install', host, '--as', 'ann', '--project', dir, '--dir', dir)
      expect(ran.err[0]).toBe('bag: usage: --relay <url> is required, at least once')
    }
  })
})

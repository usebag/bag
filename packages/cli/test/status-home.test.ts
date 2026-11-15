import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type Server, type Socket } from 'node:net'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// status --home: one read of the whole home. Homes under a short /tmp path, so that a fake
// service's socket fits sun_path.

const base = mkdtempSync('/tmp/sh-')
afterAll(() => rmSync(base, { recursive: true, force: true }))
const [R9, R10] = ['http://127.0.0.1:9', 'http://127.0.0.1:10']
const TOKEN = 'ab'.repeat(32)
const SPOOLED = ['a', 'b'].map((c) => `${c.repeat(64)}.env`)
let n = 0

/**
 * A home with alice and bob (key files, both in identities.json), carol (a keychain pointer only), alice bound in
 * one live window (host pid 4242, this process as its shim), a local pair of alice and bob, two envelopes in bob's
 * spool, and the word as given. Its io counts any /usr/bin/security call.
 */
async function home(
  word: 'on' | 'off' | null,
): Promise<{ dir: string; io: ReturnType<typeof testIo>; security: { n: number } }> {
  const dir = join(base, `h${n++}`)
  const io = testIo(new MemoryRelay())
  const security = { n: 0 }
  Object.assign(io, {
    security: () => {
      security.n++
      throw new Error('status --home must not run /usr/bin/security')
    },
  })
  for (const name of ['alice', 'bob'])
    expect((await cli(io, 'keygen', '--new', name, '--dir', dir)).code).toBe(0)
  const entry = (label: string, relays: string[]) => ({ label, key: label, home: dir, relays })
  writeFileSync(
    join(dir, 'identities.json'),
    JSON.stringify({ version: 1, identities: [entry('bob', [R9, R10]), entry('alice', [R9])] }),
    { mode: 0o600 },
  )
  mkdirSync(join(dir, 'keychain'), { recursive: true, mode: 0o700 })
  writeFileSync(join(dir, 'keychain', 'carol.json'), '{"pointer":"test"}\n', { mode: 0o600 })
  mkdirSync(join(dir, 'run', 'shim'), { recursive: true, mode: 0o700 })
  writeFileSync(
    join(dir, 'run', 'shim', '4242.bound'),
    JSON.stringify({ v: 1, as: ['alice'], shim: process.pid }),
  )
  const pair = { a: 'bob', b: 'alice', a_addr: 'bob@x', b_addr: 'alice@x', added_at: 1 }
  writeFileSync(join(dir, 'run', 'local-peers.json'), JSON.stringify({ version: 1, pairs: [pair] }), {
    mode: 0o600,
  })
  if (word !== null)
    writeFileSync(join(dir, 'run', 'local.json'), JSON.stringify({ version: 1, local_delivery: word }), {
      mode: 0o600,
    })
  mkdirSync(join(dir, 'state', 'bob', 'local-spool'), { recursive: true })
  for (const f of [...SPOOLED, `${'c'.repeat(64)}.env.failed`])
    writeFileSync(join(dir, 'state', 'bob', 'local-spool', f), '')
  return { dir, io, security }
}

/** A fake bag service at <dir>/run/service.sock that answers a hello with a start time and records each method. */
async function service(dir: string): Promise<{ calls: string[]; close(): Promise<void> }> {
  writeFileSync(join(dir, 'run', 'service.token'), `${TOKEN}\n`, { mode: 0o600 })
  const calls: string[] = []
  const sockets: Socket[] = []
  const server: Server = createServer((s) => {
    sockets.push(s)
    let buf = ''
    s.on('data', (c) => {
      buf += c.toString()
      for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
        const m = JSON.parse(buf.slice(0, i)) as { id: unknown; method: string }
        buf = buf.slice(i + 1)
        calls.push(m.method)
        const service = { version: '0.4.1', pid: 5151, started_at: '2026-11-13T01:00:00Z' }
        s.write(
          `${JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { contract: 1, service, connection: 'c-1' } })}\n`,
        )
      }
    })
  })
  await new Promise<void>((done) => server.listen(join(dir, 'run', 'service.sock'), done))
  return {
    calls,
    close: () =>
      new Promise((done) => {
        for (const s of sockets) s.destroy()
        server.close(() => done())
      }),
  }
}

describe('status --home: the whole home, one fact per line, read-only', () => {
  it('prints the service, the word, every identity with its custody, the local pairs, the windows and the relays', async () => {
    const { dir, io, security } = await home('on')
    const ran = await cli(io, 'status', '--home', '--dir', dir)
    expect(ran.code).toBe(0)
    expect(ran.out).toEqual([
      `home ${dir}`,
      'identities_file ok',
      `no service at ${join(dir, 'run', 'service.sock')}`,
      'local_delivery on',
      'identity alice key alice custody file served yes hidden no open yes spooled 0',
      'identity bob key bob custody file served yes hidden no open no spooled 2',
      'identity carol key carol custody keychain served no hidden no open no spooled 0',
      'local_pair alice bob',
      `window 4242 session none as alice shim ${process.pid}`,
      `relay ${R10} for bob`,
      `relay ${R9} for alice,bob`,
    ])
    expect(security.n).toBe(0)
  })

  it('--json: the same read as one object, its shape pinned; the word off; the service from one hello and nothing more', async () => {
    const { dir, io } = await home('off')
    const svc = await service(dir)
    const ran = await cli(io, 'status', '--home', '--json', '--dir', dir)
    await svc.close()
    expect(ran.code).toBe(0)
    expect(ran.out).toHaveLength(1)
    const id = (
      label: string,
      custody: string,
      served: boolean,
      open: boolean,
      spooled: number,
      relays: string[],
    ) => ({
      label,
      key: label,
      custody,
      served,
      hidden: false,
      open,
      spooled,
      relays,
    })
    expect(JSON.parse(ran.out[0] as string)).toEqual({
      version: 1,
      home: dir,
      identities_file: 'ok',
      service: {
        state: 'up',
        socket: join(dir, 'run', 'service.sock'),
        version: '0.4.1',
        pid: 5151,
        contract: 1,
        since: '2026-11-13T01:00:00Z',
      },
      local_delivery: 'off',
      identities: [
        id('alice', 'file', true, true, 0, [R9]),
        id('bob', 'file', true, false, 2, [R9, R10]),
        id('carol', 'keychain', false, false, 0, []),
      ],
      local_pairs: [{ a: 'alice', b: 'bob' }],
      windows: [{ host: 4242, session: null, as: ['alice'], shim: process.pid }],
      relays: [
        { url: R10, identities: ['bob'] },
        { url: R9, identities: ['alice', 'bob'] },
      ],
    })
    expect(svc.calls).toEqual(['service/hello'])
    const text = await cli(io, 'status', '--home', '--dir', dir)
    expect(text.out).toContain('local_delivery off')
  })

  it('reads no key, skips a dead window, and refuses nothing: no word is on (the default), a broken identities.json is named', async () => {
    const { dir, io, security } = await home(null)
    for (const name of ['alice', 'bob']) chmodSync(join(dir, 'keys', `${name}.json`), 0o000)
    // A window whose shim is gone (a SIGKILL leaves the file): not listed, and alice is no longer open.
    writeFileSync(
      join(dir, 'run', 'shim', '4242.bound'),
      JSON.stringify({ v: 1, as: ['alice'], shim: 2 ** 22 + 7 }),
    )
    writeFileSync(join(dir, 'identities.json'), '{"version": 2}')
    const ran = await cli(io, 'status', '--home', '--dir', dir)
    for (const name of ['alice', 'bob']) chmodSync(join(dir, 'keys', `${name}.json`), 0o600)
    expect(ran.code).toBe(0)
    expect(ran.out).toEqual([
      `home ${dir}`,
      'identities_file invalid identities-invalid',
      `no service at ${join(dir, 'run', 'service.sock')}`,
      'local_delivery on',
      'identity alice key alice custody file served no hidden no open no spooled 0',
      'identity bob key bob custody file served no hidden no open no spooled 2',
      'identity carol key carol custody keychain served no hidden no open no spooled 0',
      'local_pair alice bob',
    ])
    expect(security.n).toBe(0)
  })

  it('marks an identity kept apart (the word version 2, hidden by label) as hidden, in the lines and in --json', async () => {
    const { dir, io } = await home('on')
    writeFileSync(
      join(dir, 'run', 'local.json'),
      JSON.stringify({ version: 2, local_delivery: 'on', hidden: ['bob'] }),
      { mode: 0o600 },
    )
    const text = await cli(io, 'status', '--home', '--dir', dir)
    expect(text.out).toContain('local_delivery on')
    expect(text.out.filter((l) => l.startsWith('identity '))).toEqual([
      'identity alice key alice custody file served yes hidden no open yes spooled 0',
      'identity bob key bob custody file served yes hidden yes open no spooled 2',
      'identity carol key carol custody keychain served no hidden no open no spooled 0',
    ])
    const json = await cli(io, 'status', '--home', '--json', '--dir', dir)
    const ids = (JSON.parse(json.out[0] as string) as { identities: { label: string; hidden: boolean }[] })
      .identities
    expect(ids.map((i) => [i.label, i.hidden])).toEqual([
      ['alice', false],
      ['bob', true],
      ['carol', false],
    ])
  })

  it('reads a Codex window keyed <host pid>-<session id>.bound beside a <host pid>.bound, and no other name', async () => {
    const { dir, io } = await home('on')
    const sid = '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0'
    const shim = (as: string[]) => JSON.stringify({ v: 1, as, shim: process.pid })
    writeFileSync(join(dir, 'run', 'shim', `4242-${sid}.bound`), shim(['bob']))
    writeFileSync(join(dir, 'run', 'shim', '4242-not-a-uuid.bound'), shim(['carol']))
    writeFileSync(join(dir, 'run', 'shim', 'x4242.bound'), shim(['carol']))
    const ran = await cli(io, 'status', '--home', '--dir', dir)
    expect(ran.out.filter((l) => l.startsWith('identity ') || l.startsWith('window '))).toEqual([
      'identity alice key alice custody file served yes hidden no open yes spooled 0',
      'identity bob key bob custody file served yes hidden no open yes spooled 2',
      'identity carol key carol custody keychain served no hidden no open no spooled 0',
      `window 4242 session none as alice shim ${process.pid}`,
      `window 4242 session ${sid} as bob shim ${process.pid}`,
    ])
    const json = JSON.parse((await cli(io, 'status', '--home', '--json', '--dir', dir)).out[0] as string)
    expect(json.windows).toEqual([
      { host: 4242, session: null, as: ['alice'], shim: process.pid },
      { host: 4242, session: sid, as: ['bob'], shim: process.pid },
    ])
  })

  it('status --as keeps its service line, from the same hello', async () => {
    const { dir, io } = await home('on')
    const svc = await service(dir)
    const ran = await cli(io, 'status', '--as', 'bob', '--dir', dir)
    await svc.close()
    expect(ran.out).toContain(`service bag 0.4.1 pid 5151 contract 1 ${join(dir, 'run', 'service.sock')}`)
  })
})

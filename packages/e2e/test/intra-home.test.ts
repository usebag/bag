import { type ChildProcess, spawn } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createConnection, type Socket } from 'node:net'
import { join } from 'node:path'
import { buildEnvelope, newThread, serializeRecord } from '@usebag/core'
import { FsKeyStore, keepAddressCopy, systemRng } from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  type Party,
  party,
  REPO,
  rawPublish,
  relayEvents,
  sleep,
  until,
  world,
} from './harness.ts'
import { exited, terminal } from './terminal.ts'

// Delivery between identities of one home (spec/SPEC.md 9.2, decision 98), the red team's proof (host-design-review
// intra-home-0-4-1, section 5) end to end: the real bag service process (packages/mcp/src/main.ts --service) over a
// home with two key-file identities, personal and research, on the real release relay; the home word written by the
// real CLI on a pseudo-terminal after a y; windows on the service socket as a host's shim speaks to it, the person's
// dialogs answered there. The relay's request log (its JSON lines on stderr, one `publish` line per envelope with its
// id) shows no request for any local envelope id. The negatives: word off, a mixed recipient set, delegate, an
// envelope of personal's key over the relay to research, a local send after unpair. A Keychain recipient's spool is
// proved in packages/mcp/test/service-local.test.ts with a key reader stand-in (no Keychain from tests).

type Json = Record<string, unknown>

const MAIN = join(REPO, 'packages', 'mcp', 'src', 'main.ts')
const DIALOG_META = 'bag.dev/dialog'

/** A short home under /tmp, so the service socket fits sun_path; removed at the end. */
function shortHome(): string {
  const home = mkdtempSync('/tmp/bih-')
  onTestFinished(() => rmSync(home, { recursive: true, force: true }))
  return home
}

/** The bag service of `home` as a process, through the scrubbed launch's flags; stopped (SIGTERM) at the end. */
async function service(home: string, identities: string): Promise<ChildProcess> {
  mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
  const child = spawn(
    process.execPath,
    ['--disable-sigusr1', MAIN, '--service', '--dir', home, '--identities', identities],
    {
      cwd: join(home, 'run'),
      env: { HOME: home, PATH: '/usr/bin:/bin:/usr/sbin:/sbin', DO_NOT_TRACK: '1' },
      stdio: ['ignore', 'ignore', 'pipe'],
    },
  )
  let err = ''
  child.stderr?.on('data', (b: Buffer) => {
    err += b.toString()
  })
  const exit = new Promise<void>((r) => child.once('exit', () => r()))
  onTestFinished(async () => {
    child.kill('SIGTERM')
    await exit
  })
  await until('the service token', () => existsSync(join(home, 'run', 'service.token'))).catch((e) => {
    throw new Error(`${String(e)}; the service's stderr: ${err}`)
  })
  return child
}

interface Window {
  call(tool: string, args?: Json): Promise<Json>
  close(): Promise<void>
  readonly rings: Json[]
  readonly dialogs: string[]
}

/** A host window on the service socket, bound to `label` by the person's typed word; every dialog answered `yes`. */
async function window(home: string, label: string, yes = true): Promise<Window> {
  const socket: Socket = createConnection(join(home, 'run', 'service.sock'))
  onTestFinished(() => void socket.destroy())
  await new Promise<void>((r) => socket.once('connect', () => r()))
  const waiters = new Map<number, (m: Json) => void>()
  const rings: Json[] = []
  const dialogs: string[] = []
  const send = (m: Json): boolean => socket.write(`${JSON.stringify(m)}\n`)
  let buf = ''
  socket.on('data', (b: Buffer) => {
    buf += b.toString()
    for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
      const m = JSON.parse(buf.slice(0, i)) as Json
      buf = buf.slice(i + 1)
      if (m.method === 'service/ring') rings.push(m.params as Json)
      else if (m.method === 'elicitation/create') {
        const params = m.params as Json
        dialogs.push(String(params.message))
        const handle = (params._meta as Json)[DIALOG_META]
        const result = yes ? { action: 'accept', content: { confirm: true } } : { action: 'decline' }
        send({ jsonrpc: '2.0', id: m.id, result: { ...result, _meta: { [DIALOG_META]: handle } } })
      } else if (typeof m.id === 'number') waiters.get(m.id)?.(m)
    }
  })
  let id = 0
  const request = (method: string, params: Json): Promise<Json> => {
    const n = ++id
    const answer = new Promise<Json>((r) => waiters.set(n, r))
    send({ jsonrpc: '2.0', id: n, method, params })
    return answer
  }
  const token = readFileSync(join(home, 'run', 'service.token'), 'utf8')
  const hello = { contract: 1, token, host: 'claude-code', cwd: `/w/${label}`, input_hook: true }
  const said = await request('service/hello', {
    ...hello,
    client_capabilities: { elicitation: { form: {} } },
  })
  expect(said.result, JSON.stringify(said)).toBeDefined()
  expect((await request('service/use', { label, via: 'typed' })).result).toMatchObject({ bound: true })
  return {
    rings,
    dialogs,
    close: () =>
      new Promise<void>((r) => {
        socket.once('close', () => r())
        socket.destroy()
      }),
    async call(tool, args = {}) {
      const r = (await request('tools/call', { name: tool, arguments: args })).result as {
        content?: { text: string }[]
      }
      return JSON.parse(r.content?.[0]?.text ?? '{}') as Json
    },
  }
}

describe('e2e intra-home: delivery between identities of one home', () => {
  it('(intra-home) the word by the CLI, the first touch asked once, local mail both ways, every negative', async () => {
    const w = await world('intra-home')
    const home = shortHome()
    // Labels are the key names, as the CLI writes an identities file: the CLI lends an identity by that name.
    const [alice, carol] = [party('personal'), party('research')]
    const keys = new FsKeyStore(join(home, 'keys'))
    for (const p of [alice, carol]) {
      keys.save(p.name, { signing: p.signing, sealing: p.sealing })
      keepAddressCopy(home, p.name, addressRecord(p, { relays: [w.url] }))
    }
    // research's accept-from at the relay admits every root: the relay takes a wire envelope, so the refusal below is
    // research's own edge, by trust.json alone (which a local pair never writes: M1).
    expect((await rawPublish(w.url, serializeRecord(acceptFrom(carol, ['*'])))).status).toBe(200)
    const file = join(home, 'identities.json')
    const entry = (p: Party) => ({ label: p.name, key: p.name, home, relays: [w.url], allow_delegate: true })
    const doc = { version: 1, identities: [entry(alice), entry(carol)] }
    writeFileSync(file, JSON.stringify(doc), { mode: 0o600 })
    await service(home, file)
    const a = await window(home, 'personal')
    const own = { error: 'to-own-identity' }

    // Word off (the brake; with no file it is on, decision 104): every guard as today.
    writeFileSync(join(home, 'run', 'local.json'), '{"version":2,"local_delivery":"off","hidden":[]}', {
      mode: 0o600,
    })
    expect(await a.call('send', { to: [carol.address], type: 'chat.v1', body: 'x' })).toMatchObject(own)
    expect(await a.call('pair_invite', { for: carol.address })).toMatchObject(own)
    expect(await a.call('status')).toMatchObject({ local_delivery: 'off' })

    // The word: the real CLI on a terminal, after the person's y.
    const seen: string[] = []
    const t = terminal(['local-delivery', 'on', '--dir', home], seen)
    await until('the question', () => t.err().includes('and any identity you add later'))
    t.type('y')
    expect(await exited(t, 'local-delivery on')).toBe(0)
    expect(JSON.parse(readFileSync(join(home, 'run', 'local.json'), 'utf8'))).toEqual({
      version: 2,
      local_delivery: 'on',
      hidden: [],
    })

    // Two research windows: the later bind speaks, the first gets the quiet ring.
    const b1 = await window(home, 'research')
    const b2 = await window(home, 'research')
    const ids: string[] = []
    // The first touch (decision 104): the message is held, and only research's speaking window asks, once, in the
    // words of the two labels; its Yes allows both ways and delivers it. Nothing else is written.
    const one = await a.call('send', { to: [carol.address], type: 'chat.v1', body: { text: 'one' } })
    expect(one).toMatchObject({ delivery: 'local', pairing: 'requested' })
    ids.push(one.id as string)
    await b1.call('status')
    expect(b1.dialogs).toEqual([])
    await b2.call('status')
    expect(b2.dialogs).toEqual([
      'personal on this machine wants to message research. Allow both ways? Their messages stay on this machine, ' +
        'never go to a relay, and reach each agent as mail from your own identity.',
    ])
    expect(a.dialogs).toEqual([])
    expect(existsSync(join(home, 'trust.json'))).toBe(false)
    // The mail waits unread in research's desk: the speaking window rings, the other gets the quiet notice.
    await until('the rings', () => b1.rings.length > 0 && b2.rings.length > 0)
    expect(b2.rings[0]).toMatchObject({ as: 'research', speaking: true })
    expect(b1.rings[0]).toMatchObject({ as: 'research', speaking: false })
    const got = (await b2.call('wait', { timeout_s: 5 })).message as Json
    expect(got).toMatchObject({ id: one.id, from: alice.address, via: 'local', body: { text: 'one' } })
    // The reply, by its reply field, back to personal.
    const reply = got.reply as { to: string[]; thread: Json }
    const back = await b2.call('send', { to: reply.to, type: 'chat.v1', body: 'two', thread: reply.thread })
    expect(back).toMatchObject({ delivery: 'local' })
    ids.push(back.id as string)
    expect(((await a.call('wait', { timeout_s: 5 })).message as Json).id).toBe(back.id)
    // One unseal of each at its recipient.
    const audit = (name: string): string => readFileSync(join(home, 'state', name, 'audit.jsonl'), 'utf8')
    for (const [id, name] of [
      [one.id, 'research'],
      [back.id, 'personal'],
    ] as const) {
      const unseals = audit(name)
        .split('\n')
        .filter((l) => l.includes('"unseal"') && l.includes(String(id)))
      expect(unseals).toHaveLength(1)
    }

    // The negatives with the word on and the pair in place.
    const bob = party('bob')
    expect(
      await a.call('send', { to: [carol.address, bob.address], type: 'chat.v1', body: 'x' }),
    ).toMatchObject(own)
    expect(
      await a.call('delegate', { to: carol.address, caveats: ['type=chat.*'], exp: '+60' }),
    ).toMatchObject(own)
    // An envelope of personal's key published at the relay to research: the relay takes it, research refuses it.
    const wire = buildEnvelope({
      from: alice.signing,
      to: [{ address: carol.address, sealingKey: carol.sealing.publicKey }],
      auth: [],
      type: 'chat.v1',
      thread: newThread((n) => systemRng.bytes(n)),
      body: 'over the wire',
      ts: Math.floor(Date.now() / 1000),
      rng: (n) => systemRng.bytes(n),
    })
    expect((await rawPublish(w.url, wire.bytes)).status).toBe(200)
    await until('the wire refusal', () =>
      audit('research')
        .split('\n')
        .some((l) => l.includes(wire.envelope.id) && l.includes('"untrusted-root"')),
    )

    // After unpair (the CLI on a terminal; it borrows research from the service, so its windows close first), a local
    // send is refused again.
    await b1.close()
    await b2.close()
    const u = terminal(['unpair', alice.address, '--as', 'research', '--relay', w.url, '--dir', home], seen)
    await until('the unpair question', () => u.err().includes('on this machine'))
    u.type('y')
    expect(await exited(u, 'unpair')).toBe(0)
    expect(u.out()).toEqual([`unpaired locally ${alice.address}`])
    // The next touch asks again: held, not delivered.
    expect(await a.call('send', { to: [carol.address], type: 'chat.v1', body: 'x' })).toMatchObject({
      pairing: 'requested',
    })

    // The relay's request log: no request for any local envelope id; the one wire envelope is there.
    await sleep(200)
    const published = relayEvents(w.relay)
      .filter((e) => e.event === 'publish')
      .map((e) => e.id)
    for (const id of ids) {
      expect(published).not.toContain(id)
      expect(w.relay.stderr()).not.toContain(id)
    }
    expect(published).toContain(wire.envelope.id)
    expect(readdirSync(join(home, 'run'))).toContain('local-peers.json')
  }, 60_000)
})

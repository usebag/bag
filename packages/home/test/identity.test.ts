import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { dirname, join } from 'node:path'
import { parseRecord } from '@usebag/core'
import {
  acceptCopy,
  addressCopy,
  type EdgeKeys,
  generateEdgeKeys,
  HomeCustody,
  KeychainCustody,
  KeyEpochStore,
  keepAcceptCopy,
  keepAliveChoice,
  type RelayClient,
  systemRng,
} from '@usebag/edge'
import { recordingRelay, relayTripwire } from '@usebag/edge/test-support'
import { describe, expect, it } from 'vitest'
import {
  addToServiceHome,
  addTrust,
  identityKeepAlive,
  identityRelays,
  identityRemove,
  keepFirstRecordsLocal,
  NameBook,
  peersPath,
  type RemoveInput,
  readIdentities,
  readRemoved,
  readTrust,
  saveIdentities,
  writeWhole,
} from '../src/index.ts'
import {
  type Answer,
  acceptFrom,
  client,
  FakeRelay,
  FakeSecurity,
  fakeIo,
  folder,
  homeWith,
  publishAt,
  signer,
} from './support.ts'

// identity remove, relays and keep-alive: the acts on one identity of a home.

const R1 = 'https://r1.example'
const R2 = 'https://r2.example'
const bob = generateEdgeKeys(systemRng).signing.address

const entry = (label: string, home: string, key = label) => ({ label, key, home, relays: [R1] })

describe('identityKeepAlive', () => {
  it("writes the person's word under the service's label, found by label or key name; ENOENT for none", () => {
    const { home } = homeWith('jane')
    const io = fakeIo()
    expect(identityKeepAlive(io, home, 'jane', true)).toBe('jane')
    saveIdentities(join(home, 'identities.json'), { version: 1, identities: [entry('lab', home, 'jane')] })
    expect(identityKeepAlive(io, home, 'jane', false)).toBe('lab')
    expect(identityKeepAlive(io, home, 'lab', null)).toBe('lab')
    expect(io.said).toEqual(['keep-alive jane on', 'keep-alive lab off', 'keep-alive lab default'])
    expect(keepAliveChoice(home, 'jane').keep).toBe(true)
    expect(keepAliveChoice(home, 'lab').keep).toBeNull()
    expect(() => identityKeepAlive(io, home, 'kim', true)).toThrow('ENOENT: no identity kim')
  })
})

describe('identityRelays', () => {
  const done = (name: string, relays: string[]) => [
    `relays ${name} ${relays.join(' ')}`,
    `publish its records at each: bag record keep --once --as ${name} ${relays.map((r) => `--relay ${r}`).join(' ')}`,
  ]

  it('adds a name the file lacks after the yes; ENOENT for an identity the home lacks', async () => {
    const { home } = homeWith('jane')
    const file = join(home, 'identities.json')
    await expect(identityRelays(fakeIo(), home, 'kim', [R1])).rejects.toThrow('ENOENT')
    const io = fakeIo()
    await identityRelays(io, home, 'jane', [R1, R2])
    expect(io.asked).toEqual([`add jane to ${file} with the relays ${R1} ${R2}?`])
    expect(io.said).toEqual(done('jane', [R1, R2]))
    expect(readIdentities(file, true).identities[0]?.relays).toEqual([R1, R2])
  })

  it('changes nothing for the same relays, and sets new ones after the yes', async () => {
    const { home } = homeWith('jane')
    const file = join(home, 'identities.json')
    saveIdentities(file, { version: 1, identities: [entry('jane', home)] })
    const same = fakeIo()
    await identityRelays(same, home, 'jane', [R1])
    expect([same.asked, same.said]).toEqual([[], [`relays jane ${R1} (unchanged)`]])
    const io = fakeIo()
    await identityRelays(io, home, 'jane', [R2])
    expect(io.asked).toEqual([`set the relays of jane in ${file}: ${R1} -> ${R2}?`])
    expect(io.said).toEqual(done('jane', [R2]))
    expect(readIdentities(file, true).identities[0]?.relays).toEqual([R2])
  })

  it('a no, a failed dialog, or the file changed while asked writes nothing', async () => {
    for (const [answer, err] of [
      [false, 'declined: nothing was changed'],
      ['throw', 'the dialog failed'],
    ] as const) {
      const { home } = homeWith('jane')
      await expect(identityRelays(fakeIo({ answer }), home, 'jane', [R1])).rejects.toThrow(err)
      expect(existsSync(join(home, 'identities.json'))).toBe(false)
    }
    const { home } = homeWith('jane')
    const file = join(home, 'identities.json')
    saveIdentities(file, { version: 1, identities: [entry('jane', home)] })
    const before = readFileSync(file, 'utf8')
    const io = fakeIo({
      answer: () => {
        saveIdentities(file, { version: 1, identities: [entry('jane', home)] })
        return true
      },
    })
    await expect(identityRelays(io, home, 'jane', [R2])).rejects.toThrow(
      'busy: it changed while you were asked: identities.json; nothing was changed, ask again',
    )
    expect(readFileSync(file, 'utf8')).toBe(before)
  })

  it('no relays for an entry that has some is usage, nothing written', async () => {
    const { home } = homeWith('jane')
    const file = join(home, 'identities.json')
    saveIdentities(file, { version: 1, identities: [entry('jane', home)] })
    await expect(identityRelays(fakeIo(), home, 'jane', [])).rejects.toThrow(
      'usage: give jane at least one relay',
    )
    expect(readIdentities(file, true).identities[0]?.relays).toEqual([R1])
  })

  it('on an identity on this machine only is the promotion: epoch 1 and an address record naming the relays', async () => {
    const { home, keys } = homeWith('jane')
    const address = signer(keys, 'jane').address
    const file = join(home, 'identities.json')
    const net = new FakeRelay()
    // Before the promotion every relay call trips the wire; at the yes a recording stub over the network takes over.
    const tripwire = relayTripwire()
    const recorder = recordingRelay(client(net))
    let relay: RelayClient = tripwire
    const local = Object.assign(fakeIo(), { relay: () => relay })
    addToServiceHome(home, 'jane', [], undefined, true)
    keepFirstRecordsLocal(local, home, 'jane')
    await identityRelays(local, home, 'jane', [])
    expect(local.said).toEqual(['relays jane  (unchanged)'])
    const epoch1 = new KeyEpochStore(join(home, 'key-records')).epoch(address, 1)
    // A local pairing since: the accept-from copy names a root more, which the promotion keeps.
    local.now += 5
    keepAcceptCopy(home, 'jane', acceptFrom(signer(keys, 'jane'), [address, bob], local.now))
    const yes = () => {
      relay = recorder
      return true
    }
    const io = Object.assign(fakeIo({ answer: yes, now: local.now + 5 }), { relay: () => relay })
    await identityRelays(io, home, 'jane', [R1, R2])
    expect(tripwire.calls).toEqual([])
    // The order: key record, then the address record naming the new relays, then the accept-from; nothing before.
    expect(recorder.calls.every((c) => c.method === 'publish')).toBe(true)
    expect(recorder.published.map((p) => [p.kind, p.url, p.address, p.relays])).toEqual([
      ['key', R1, address, null],
      ['key', R2, address, null],
      ['address', R1, address, [R1, R2]],
      ['address', R2, address, [R1, R2]],
      ['accept-from', R1, address, null],
      ['accept-from', R2, address, null],
    ])
    expect(io.asked).toEqual([
      `publish jane at ${R1} ${R2}: set its relays in ${file} and publish its key, address and accept-from records?`,
    ])
    expect(io.said).toEqual([
      `relays jane ${R1} ${R2}`,
      ...['key', 'address', 'accept-from'].flatMap((k) =>
        [R1, R2].map((u) => `published ${k} ${address} ${u}`),
      ),
    ])
    expect(readIdentities(file, true).identities[0]?.relays).toEqual([R1, R2])
    const at = (url: string, kind: string) => {
      const bytes = net.records.get(`${url} ${address} ${kind}`)
      return bytes === undefined ? null : (parseRecord(bytes) as unknown as Record<string, unknown>)
    }
    for (const url of [R1, R2]) {
      // Epoch 1 itself, re-dated: no new epoch was minted.
      expect(at(url, 'key')).toMatchObject({ iat: io.now })
      expect(at(url, 'key')?.sealing_key).toBe(Buffer.from(epoch1.key.publicKey).toString('hex'))
      expect(at(url, 'address')).toMatchObject({ sealing_key: null, relays: [R1, R2], iat: io.now })
      expect(at(url, 'accept-from')?.roots).toEqual([address, bob])
    }
    const store = new KeyEpochStore(join(home, 'key-records'))
    expect(store.epochs(address)).toEqual([1])
    expect(store.epoch(address, 1).published).toBe(true)
    expect(addressCopy(home, 'jane', address)?.relays).toEqual([R1, R2])
    expect(acceptCopy(home, 'jane', address)?.iat).toBe(io.now)
  })

  it('a promotion no relay takes says the relays stay written and epoch 1 stays kept, to be offered again', async () => {
    const { home, keys } = homeWith('jane')
    const address = signer(keys, 'jane').address
    const net = new FakeRelay()
    net.down.add(R1)
    addToServiceHome(home, 'jane', [], undefined, true)
    keepFirstRecordsLocal(fakeIo(), home, 'jane')
    const io = fakeIo({ relay: net, now: 1_800_000_010 })
    await expect(identityRelays(io, home, 'jane', [R1])).rejects.toThrow(
      'unreachable: jane is made, but no relay took its key and address record (unreachable): nothing after it was ' +
        'published; its relays stay written and its epoch 1 stays kept, unpublished: will be offered again at the next rotation',
    )
    expect(readIdentities(join(home, 'identities.json'), true).identities[0]?.relays).toEqual([R1])
    expect(new KeyEpochStore(join(home, 'key-records')).epoch(address, 1).published).toBe(false)
  })

  it('a chmod to the same mode with its mtime put back, while asked, is busy too', async () => {
    const { home } = homeWith('jane')
    const file = join(home, 'identities.json')
    saveIdentities(file, { version: 1, identities: [entry('jane', home)] })
    const { atime, mtime } = statSync(file)
    const io = fakeIo({
      answer: async () => {
        await new Promise((done) => setTimeout(done, 20))
        chmodSync(file, 0o600)
        utimesSync(file, atime, mtime)
        return true
      },
    })
    await expect(identityRelays(io, home, 'jane', [R2])).rejects.toThrow(
      'busy: it changed while you were asked: identities.json;',
    )
    expect(readIdentities(file, true).identities[0]?.relays).toEqual([R1])
  })
})

/** A home with jane, kim and amy, and what removing jane takes. */
function removal(answer: Answer = true, more: Partial<RemoveInput> = {}) {
  const { home, keys } = homeWith('jane', 'kim')
  const jane = keys.jane?.signing.address as string
  const net = new FakeRelay()
  const io = fakeIo({ answer, relay: net })
  const input: RemoveInput = {
    home,
    name: 'jane',
    relays: [R1],
    lent: async () => false,
    ...more,
  }
  return { home, keys, jane, net, io, input, run: () => identityRemove(io, input) }
}

describe('identityRemove', () => {
  it('with nothing to re-sign: moves its files into one folder beside the home, the key last', async () => {
    const w = removal()
    await w.run()
    const left = readdirSync(dirname(w.home)).find((d) => d.startsWith('bag-left-jane-')) as string
    const to = join(dirname(w.home), left)
    expect(w.io.asked).toHaveLength(1)
    expect(w.io.asked[0]).toContain(`remove jane (${w.jane}) from ${w.home}:`)
    expect(w.io.said).toEqual([
      `no accept-from of ${w.jane} at ${R1}: nothing to re-sign`,
      `moved ${join(w.home, 'keys', 'jane.json')} -> ${join(to, 'home', 'keys', 'jane.json')}`,
      `removed jane ${w.jane}: ${to}`,
      expect.stringContaining(`${to} holds the private key of jane`),
    ])
    expect(existsSync(join(w.home, 'keys', 'jane.json'))).toBe(false)
    expect(existsSync(join(w.home, 'keys', 'kim.json'))).toBe(true)
  })

  it('with no relays (on this machine only): no relay is told, and no line names an empty relay list', async () => {
    const w = removal(true, { relays: [] })
    const tripwire = relayTripwire()
    const io = Object.assign(w.io, { relay: () => tripwire })
    await identityRemove(io, w.input)
    expect(io.asked[0]).toContain(`  no accept-from of ${w.jane}: nothing to re-sign`)
    expect(io.said[0]).toBe(`no accept-from of ${w.jane}: nothing to re-sign`)
    expect([...io.asked, ...io.said].some((l) => / at (:|$)/m.test(l))).toBe(false)
    expect(tripwire.calls).toEqual([])
    expect(existsSync(join(w.home, 'keys', 'jane.json'))).toBe(false)
  })

  it('re-signs its accept-from to name only itself, drops its trust roots and names, and its service entry', async () => {
    const w = removal(true, { relays: [R1, R2] })
    await publishAt(w.net, acceptFrom(signer(w.keys, 'jane'), [bob], 100), R1, R2)
    addTrust(w.home, bob, 1)
    const book = NameBook.load(w.home)
    book.add('me', w.jane, 1)
    book.save()
    const file = join(w.home, 'identities.json')
    saveIdentities(file, {
      version: 1,
      default: 'jane',
      identities: [entry('jane', w.home), entry('kim', w.home)],
    })
    await w.run()
    expect(w.io.said.slice(0, 5)).toEqual([
      `published accept-from ${w.jane} ${R1}`,
      `published accept-from ${w.jane} ${R2}`,
      `untrusted ${bob}`,
      `forgot me ${w.jane}`,
      `took jane out of ${file}`,
    ])
    expect(w.net.rootsAt(R1, w.jane)).toEqual([w.jane])
    expect(readTrust(w.home)).toEqual({})
    expect(NameBook.load(w.home).list()).toEqual([])
    expect(readIdentities(file, true)).toEqual({ version: 1, identities: [entry('kim', w.home)] })
  })

  it("keeps a root another identity still names, and says how to end that one's pairing with it", async () => {
    const w = removal()
    await publishAt(w.net, acceptFrom(signer(w.keys, 'jane'), [bob], 100), R1)
    addTrust(w.home, bob, 1)
    keepAcceptCopy(w.home, 'kim', acceptFrom(signer(w.keys, 'kim'), [bob, w.jane], 100))
    await w.run()
    expect(w.io.asked[0]).toContain(`trust.json keeps ${bob} for kim`)
    expect(w.io.said).toContain(`kept trust ${bob}: the accept-from of kim still names it`)
    expect(w.io.said).toContain(
      `kim accepts ${w.jane}: to end that, run on a terminal: bag unpair ${w.jane} --as kim --relay ${R1}`,
    )
  })

  it("takes its project wiring out, the omp host's with it, and names a Codex table it leaves", async () => {
    const env = { HOME: folder() }
    const project = folder()
    const w = removal(true, { project })
    const io = fakeIo({ relay: w.net, env })
    const args = ['--as', 'jane', '--dir', w.home]
    mkdirSync(join(project, '.omp'))
    writeFileSync(join(project, '.omp', 'mcp.json'), JSON.stringify({ mcpServers: { bag: { args } } }))
    writeFileSync(join(project, '.mcp.json'), JSON.stringify({ mcpServers: { bag: { args }, other: {} } }))
    mkdirSync(join(project, '.claude'))
    const hook = (c: string) => ({ hooks: [{ command: c }] })
    const settings = {
      hooks: {
        SessionStart: [hook(`bag wake-hook --as jane --dir ${w.home}`), hook('other')],
        Stop: [hook(`bag wake-hook --as jane --dir ${w.home}`)],
      },
    }
    writeFileSync(join(project, '.claude', 'settings.json'), JSON.stringify(settings))
    mkdirSync(join(env.HOME, '.codex'))
    writeFileSync(join(env.HOME, '.codex', 'config.toml'), 'args = ["--principal", "jane"]\n')
    await identityRemove(io, w.input)
    expect(JSON.parse(readFileSync(join(project, '.omp', 'mcp.json'), 'utf8'))).toEqual({ mcpServers: {} })
    expect(io.said).toContain(`wrote ${join(project, '.omp', 'mcp.json')} (mcpServers.bag removed)`)
    expect(JSON.parse(readFileSync(join(project, '.mcp.json'), 'utf8'))).toEqual({
      mcpServers: { other: {} },
    })
    expect(JSON.parse(readFileSync(join(project, '.claude', 'settings.json'), 'utf8'))).toEqual({
      hooks: { SessionStart: [hook('other')] },
    })
    expect(io.said).toContain(`wrote ${join(project, '.mcp.json')} (mcpServers.bag removed)`)
    expect(io.said.some((l) => l.includes('runs bag for jane ([mcp_servers.bag], --principal jane)'))).toBe(
      true,
    )
  })

  it('names wiring that is not its own and leaves it; a project folder that is not there is ENOENT', async () => {
    const project = folder()
    const w = removal(true, { project })
    writeFileSync(
      join(project, '.mcp.json'),
      JSON.stringify({ mcpServers: { bag: { args: ['--identities', 'f'] } } }),
    )
    mkdirSync(join(project, '.omp'))
    writeFileSync(
      join(project, '.omp', 'mcp.json'),
      JSON.stringify({ mcpServers: { bag: { args: ['--as', 'kim'] } } }),
    )
    await w.run()
    expect(w.io.asked[0]).toContain('its bag server reads an identities file: left as it is')
    expect(w.io.asked[0]).toContain("its bag server is not jane's: left as it is")
    expect(JSON.parse(readFileSync(join(project, '.omp', 'mcp.json'), 'utf8'))).toEqual({
      mcpServers: { bag: { args: ['--as', 'kim'] } },
    })
    const none = removal(true, { project: join(folder(), 'gone') })
    await expect(none.run()).rejects.toThrow('ENOENT: no project directory')
    const bad = folder()
    writeFileSync(join(bad, '.mcp.json'), '[1]')
    await expect(removal(true, { project: bad }).run()).rejects.toThrow('host-file-invalid')
  })

  it('refuses, changing nothing: a relay that does not answer, a full folder to move into, a keep job', async () => {
    const down = removal()
    down.net.down.add(R1)
    await expect(down.run()).rejects.toThrow(`unreachable: ${R1} did not answer: nothing was changed`)
    const to = folder()
    writeFileSync(join(to, 'x'), '')
    await expect(removal(true, { to }).run()).rejects.toThrow(`exists: ${to} is not empty: name another --to`)
    const HOME = folder()
    mkdirSync(join(HOME, 'Library', 'LaunchAgents'), { recursive: true })
    writeFileSync(join(HOME, 'Library', 'LaunchAgents', 'bag.keep.jane.plist'), '')
    const kept = removal()
    await expect(identityRemove(fakeIo({ env: { HOME } }), kept.input)).rejects.toThrow(
      'held: the keep job of jane is set up',
    )
    expect(existsSync(join(kept.home, 'keys', 'jane.json'))).toBe(true)
  })

  it('a no, a failed dialog, a file changed or a record published while asked writes nothing', async () => {
    for (const [answer, err] of [
      [false, 'declined: nothing was changed'],
      ['throw', 'the dialog failed'],
    ] as const) {
      const w = removal(answer)
      await expect(w.run()).rejects.toThrow(err)
      expect(existsSync(join(w.home, 'keys', 'jane.json'))).toBe(true)
    }
    let home = ''
    const changed = removal(() => {
      addTrust(home, bob, 9)
      return true
    })
    home = changed.home
    await expect(changed.run()).rejects.toMatchObject({ code: 'busy' })
    expect(existsSync(join(home, 'keys', 'jane.json'))).toBe(true)
    let w: ReturnType<typeof removal> | null = null
    w = removal(async () => {
      const own = w as ReturnType<typeof removal>
      await publishAt(own.net, acceptFrom(signer(own.keys, 'jane'), [bob], 300), R1)
      return true
    })
    await expect(w.run()).rejects.toThrow('stale-record: the accept-from of')
    expect(existsSync(join(w.home, 'keys', 'jane.json'))).toBe(true)
  })

  it('a relay that refuses the re-sign is said and thrown before anything local changes', async () => {
    const w = removal(true, { relays: [R1, R2] })
    await publishAt(w.net, acceptFrom(signer(w.keys, 'jane'), [bob], 100), R1, R2)
    w.net.refuse.set(R2, 'bad-record')
    await expect(w.run()).rejects.toThrow(`bad-record: ${R2} did not take the accept-from`)
    expect(w.io.said).toEqual([
      `published accept-from ${w.jane} ${R1}`,
      `failed accept-from ${w.jane} ${R2} bad-record`,
    ])
    expect(existsSync(join(w.home, 'keys', 'jane.json'))).toBe(true)
  })

  it('drops its local pairs; with a service that lent it, the held mail stays for the service', async () => {
    const w = removal()
    const kim = w.keys.kim?.signing.address as string
    writeWhole(w.home, peersPath(w.home), {
      version: 1,
      pairs: [{ a: 'jane', b: 'kim', a_addr: w.jane, b_addr: kim, added_at: 1 }],
    })
    await w.run()
    expect(w.io.asked[0]).toContain('run/local-peers.json: its local pairs leave')
    expect(w.io.said).toContain('dropped the local pairs of jane')
    const id = 'c'.repeat(64)
    const s = removal(true, { lent: async () => true })
    const k2 = s.keys.kim?.signing.address as string
    writeWhole(s.home, peersPath(s.home), {
      version: 1,
      pairs: [{ a: 'kim', b: 'jane', a_addr: k2, b_addr: s.jane, added_at: 1, held: [id] }],
    })
    const held = join(s.home, 'state', 'jane', 'local-spool', 'held')
    mkdirSync(held, { recursive: true })
    writeFileSync(join(held, `${id}.env`), 'x')
    await s.run()
    expect(s.io.asked[0]).toContain(
      'the bag service fails it to the senders when this command gives jane back',
    )
    expect(s.io.said).toContain(
      'the bag service tells the senders of its held mail when this command gives jane back to it',
    )
    expect(existsSync(join(s.home, 'state', 'kim', 'local-spool', 'held', `${id}.env`))).toBe(true)
    expect(JSON.parse(readFileSync(peersPath(s.home), 'utf8')).pairs).toHaveLength(1)
  })

  it('asked to, reads the service again after the yes: one that changed its answer is busy, nothing written', async () => {
    const id = 'e'.repeat(64)
    let asks = 0
    const flips = async (): Promise<boolean> => asks++ > 0
    const w = removal(true, { lent: flips, lentAgain: true })
    const kim = w.keys.kim?.signing.address as string
    writeWhole(w.home, peersPath(w.home), {
      version: 1,
      pairs: [{ a: 'kim', b: 'jane', a_addr: kim, b_addr: w.jane, added_at: 1, held: [id] }],
    })
    const held = join(w.home, 'state', 'kim', 'local-spool', 'held')
    mkdirSync(held, { recursive: true })
    writeFileSync(join(held, `${id}.env`), 'x')
    await expect(w.run()).rejects.toThrow(
      'busy: it changed while you were asked: service; nothing was changed, ask again',
    )
    expect(asks).toBe(2)
    expect(w.io.said).toEqual([])
    expect(existsSync(join(held, `${id}.env`))).toBe(true)
    expect(existsSync(join(w.home, 'keys', 'jane.json'))).toBe(true)
    let once = 0
    const v = removal(true, {
      lent: async () => {
        once++
        return false
      },
    })
    await v.run()
    expect(once).toBe(1)
  })

  it('served, records the remove in run/removed.json before anything moves: a refused re-sign leaves it', async () => {
    const w = removal(true, { relays: [R1, R2], lent: async () => true })
    await publishAt(w.net, acceptFrom(signer(w.keys, 'jane'), [bob], 100), R1, R2)
    w.net.refuse.set(R2, 'bad-record')
    await expect(w.run()).rejects.toThrow(`bad-record: ${R2} did not take the accept-from`)
    expect(readRemoved(w.home)).toEqual([{ label: 'jane', key: 'jane', address: w.jane, at: w.io.now }])
    expect(existsSync(join(w.home, 'keys', 'jane.json'))).toBe(true)
    // Not served: no record (the command fails its held mail itself).
    const plain = removal()
    await plain.run()
    expect(readRemoved(plain.home)).toEqual([])
  })

  it("passes a lock the service's own quiet accounts for, before the question and after; any other refuses held", async () => {
    const lockOf = (home: string): void => {
      mkdirSync(join(home, 'state', 'jane'), { recursive: true })
      writeFileSync(join(home, 'state', 'jane', 'mcp.lock'), JSON.stringify({ pid: process.pid }))
    }
    const asked: string[] = []
    const own = removal(true, {
      lent: async () => true,
      heldByOwnQuiet: (n) => {
        asked.push(n)
        return n === 'jane'
      },
    })
    lockOf(own.home)
    await own.run()
    expect(own.io.said.some((l) => l.startsWith(`removed jane ${own.jane}: `))).toBe(true)
    // Asked by name: before the question, in the check before and after it, and in the re-check under the quiet.
    expect(asked.length).toBeGreaterThanOrEqual(4)
    expect(new Set(asked)).toEqual(new Set(['jane']))
    const other = removal(true, { lent: async () => true, heldByOwnQuiet: () => false })
    lockOf(other.home)
    await expect(other.run()).rejects.toThrow('held: the identity jane is held by a running bag MCP server')
    expect(other.io.asked).toEqual([])
    // A lock the quiet accounted for before the question but not after it (a window took it meanwhile): held, nothing moved.
    let n = 0
    const late = removal(true, { lent: async () => true, heldByOwnQuiet: () => n++ < 2 })
    lockOf(late.home)
    await expect(late.run()).rejects.toThrow(/^(busy|held): /)
    expect(existsSync(join(late.home, 'keys', 'jane.json'))).toBe(true)
  })

  it('with no service, drops held mail that has no sender in the home', async () => {
    const id = 'd'.repeat(64)
    const w = removal()
    const kim = w.keys.kim?.signing.address as string
    writeWhole(w.home, peersPath(w.home), {
      version: 1,
      pairs: [{ a: 'kim', b: 'jane', a_addr: kim, b_addr: w.jane, added_at: 1, held: [id] }],
    })
    const held = join(w.home, 'state', 'kim', 'local-spool', 'held')
    mkdirSync(held, { recursive: true })
    writeFileSync(join(held, `${id}.env`), 'x')
    await w.run()
    expect(w.io.asked[0]).toContain(
      'its held local mail (1): failed to the senders, in their audit logs, and deleted',
    )
    expect(w.io.said).toContain(`dropped held mail ${id}`)
    expect(existsSync(join(held, `${id}.env`))).toBe(false)
  })

  it('takes the identities file with it when it is the last entry, and finishes a move a run left partial', async () => {
    const w = removal()
    const file = join(w.home, 'identities.json')
    saveIdentities(file, { version: 1, identities: [entry('jane', w.home)] })
    const partial = join(dirname(w.home), 'bag-left-jane-20000101T000000Z')
    mkdirSync(join(partial, 'home', 'state'), { recursive: true })
    await w.run()
    expect(w.io.asked[0]).toContain('identities.json: jane leaves')
    expect(w.io.said).toContain(`moved ${file} -> ${join(partial, 'home', 'identities.json')}`)
    expect(w.io.said).toContain(`removed jane ${w.jane}: ${partial}`)
    expect(existsSync(join(partial, 'home', 'keys', 'jane.json'))).toBe(true)
  })

  it('refuses an identity whose address another of the home holds too (exists)', async () => {
    const w = removal()
    const security = new FakeSecurity()
    new KeychainCustody({ dir: join(w.home, 'keychain'), run: security.run }).create(
      'kim',
      w.keys.jane as EdgeKeys,
    )
    await expect(identityRemove(fakeIo({ relay: w.net, security: security.run }), w.input)).rejects.toThrow(
      `exists: kim of ${w.home} is ${w.jane} too (keychain): take it out first`,
    )
  })

  it('a keychain identity: its pointer moves, and the line that deletes its item is said', async () => {
    const parent = folder()
    const home = join(parent, 'home')
    mkdirSync(home, { mode: 0o700 })
    const security = new FakeSecurity()
    const keys = generateEdgeKeys(systemRng)
    new HomeCustody(home, { run: security.run }).create('jane', keys, {
      custody: 'keychain',
      access: 'security',
    })
    const io = fakeIo({ security: security.run })
    await identityRemove(io, {
      home,
      name: 'jane',
      relays: [R1],
      lent: async () => false,
    })
    const address = keys.signing.address
    expect(io.said).toContain(
      `the keychain item of jane stays in the macOS keychain; to delete it: security delete-generic-password -s bag:jane -a ${address}`,
    )
    expect(io.said.at(-1)).toMatch(new RegExp(`^removed jane ${address}: `))
    expect(existsSync(join(home, 'keychain', 'jane.json'))).toBe(false)
  })
})

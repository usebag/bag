import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, statSync, utimesSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { codingEvaluator, parseEnvelope, utf8 } from '@usebag/core'
import { type Frame, RelayError, SqliteStore, type Subscription } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { honored, ObservedSubscription, trustedRoot } from '../src/commands/inbox.ts'
import { rootHint, unpairedNote } from '../src/commands/send.ts'
import { type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

const tmp = tempDir('send-inbox')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
let n = 0

/** Polls `test` every 10 ms for up to 5 s (a hang detector, not a bound on the work); fails naming `what`. */
async function until(what: string, test: () => boolean): Promise<void> {
  for (const end = Date.now() + 5000; !test(); await new Promise((r) => setTimeout(r, 10))) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`)
  }
}

interface World {
  readonly relay: MemoryRelay
  readonly io: TestIo
  readonly dir: string
  readonly alice: string
  readonly bob: string
  readonly carol: string
}

/** Three identities in one home; bob's address record, with his sealing key, published at the relay. */
async function world(): Promise<World> {
  const relay = new MemoryRelay()
  const io = testIo(relay)
  const dir = join(tmp.dir, `home-${n++}`)
  const [alice, bob, carol] = await Promise.all(
    ['alice', 'bob', 'carol'].map(
      async (who) => (await cli(io, 'keygen', who, '--dir', dir)).out[0] as string,
    ),
  )
  const file = join(dir, 'bob.address.json')
  await cli(io, 'record', 'address', 'bob', '--relay', RELAY, '--sealing-key', '--out', file, '--dir', dir)
  await cli(io, 'publish', RELAY, file)
  return { relay, io, dir, alice: alice as string, bob: bob as string, carol: carol as string }
}

const send = (w: World, as: string, type: string, body: string, ...more: string[]) =>
  cli(
    w.io,
    'send',
    '--as',
    as,
    '--to',
    w.bob,
    '--relay',
    RELAY,
    '--type',
    type,
    '--body',
    body,
    '--dir',
    w.dir,
    ...more,
  )

const inboxOnce = (w: World, ...more: string[]) =>
  cli(w.io, 'inbox', '--as', 'bob', '--relay', RELAY, '--once', '--dir', w.dir, ...more)

/** What a finished pairing leaves in this home for `address`: a name in the book and a root in the trust file. */
async function paired(w: World, name: string, address: string): Promise<void> {
  await cli(w.io, 'name', 'add', name, address, '--dir', w.dir)
  const roots = { [address]: { added_at: 1 } }
  writeFileSync(join(w.dir, 'trust.json'), JSON.stringify({ version: 1, roots }), { mode: 0o600 })
}

describe('send: a refusal from a peer that unpaired this identity', () => {
  const refused = async (w: World, ...more: string[]): Promise<string> => {
    w.relay.failPublish = new RelayError('root-not-accepted', 403, null, 'refused')
    const r = await send(w, 'alice', 'chat.v1', '{}', ...more)
    expect(r.code).toBe(1)
    return r.err[0] as string
  }

  it('names the peer and the two ways on, for the one recipient a finished pairing left here', async () => {
    const w = await world()
    await paired(w, 'bobby', w.bob)
    expect(await refused(w)).toContain(`; ${unpairedNote('bobby', w.bob, 'alice', RELAY)}`)
    expect(unpairedNote('bobby', w.bob, 'alice', RELAY)).toBe(
      `bobby no longer accepts mail from you (it unpaired you): ask them to pair again, or run unpair ${w.bob} --as alice --relay ${RELAY} to stop keeping their root (this is not a relay ban)`,
    )
  })

  it('keeps the accept-from hint for a name with no trust entry, a trust entry with no name, and a stranger', async () => {
    const named = await world()
    await cli(named.io, 'name', 'add', 'bobby', named.bob, '--dir', named.dir)
    expect(await refused(named)).toContain(rootHint(named.alice))
    const trusted = await world()
    const roots = { [trusted.bob]: { added_at: 1 } }
    writeFileSync(join(trusted.dir, 'trust.json'), JSON.stringify({ version: 1, roots }))
    expect(await refused(trusted)).toContain(rootHint(trusted.alice))
    const stranger = await world()
    expect(await refused(stranger)).toContain(rootHint(stranger.alice))
  })

  it('keeps the accept-from hint for a former address, for several recipients and for a file that does not read', async () => {
    const moved = await world()
    await paired(moved, 'bobby', moved.bob)
    await cli(moved.io, 'name', 'add', 'bobby', moved.carol, '--replace', '--dir', moved.dir)
    expect(await refused(moved)).toContain(rootHint(moved.alice))

    const two = await world()
    await paired(two, 'bobby', two.bob)
    const file = join(two.dir, 'carol.address.json')
    const record = ['address', 'carol', '--relay', RELAY, '--sealing-key', '--out', file, '--dir', two.dir]
    await cli(two.io, 'record', ...record)
    await cli(two.io, 'publish', RELAY, file)
    expect(await refused(two, '--to', two.carol)).toContain(rootHint(two.alice))

    const broken = await world()
    await paired(broken, 'bobby', broken.bob)
    writeFileSync(join(broken.dir, 'trust.json'), 'not json')
    expect(await refused(broken)).toContain(rootHint(broken.alice))
  })

  it('keeps the accept-from hint under a chain: a pairing says nothing of its root', async () => {
    const w = await world()
    await paired(w, 'bobby', w.bob)
    const chain = join(w.dir, 'chain.json')
    const hop = ['--from', 'carol', '--to', w.alice, '--exp', '+3600', '--out', chain, '--dir', w.dir]
    await cli(w.io, 'delegate', ...hop)
    expect(await refused(w, '--auth', chain)).toContain(rootHint(w.carol))
  })
})

describe('send: one envelope through the edge Sender, its id and each target printed', () => {
  it('seals to the recipient its record names, publishes it, and prints the id and the published target', async () => {
    const w = await world()
    const sent = await send(w, 'alice', 'chat.v1', '{"text":"hi","n":1}')
    expect(sent.code).toBe(0)
    expect(sent.out).toHaveLength(2)
    expect(sent.out[0]).toMatch(/^[0-9a-f]{64}$/)
    expect(sent.out[1]).toBe(`published ${RELAY} tries=1`)
    expect([...w.relay.envelopes.keys()]).toEqual([sent.out[0]])
    expect(w.relay.box(w.bob)).toHaveLength(1)
  })

  it('fails with the relay code of a refused target, with unreachable and a next try for a relay that gave no answer, and with publish-failed for an answer without a code', async () => {
    const w = await world()
    w.relay.failPublish = new RelayError('root-not-accepted', 403, null, `${RELAY}/v0/publish answered 403`)
    const refused = await send(w, 'alice', 'chat.v1', '{}')
    expect(refused.code).toBe(1)
    expect(refused.out[1]).toBe(`failed ${RELAY} tries=1 reason=root-not-accepted`)
    expect(refused.err).toEqual([
      `bag: root-not-accepted: ${RELAY} failed; the bytes stay in the outbox, and resend --id ${refused.out[0]} sends them; ${rootHint(w.alice)}`,
    ])
    expect(rootHint(w.alice)).toBe(
      `the recipient does not accept this identity's root yet: ask them to add ${w.alice} (or your org's domain root) to their accept-from record, or send under a chain from a root they accept (send --auth / delegate)`,
    )
    // No answer at all (L4 d): unreachable, the retry still scheduled by the outbox.
    w.relay.failPublish = new RelayError(null, 0, null, 'fetch failed')
    const lost = await send(w, 'alice', 'chat.v1', '{}')
    expect(lost.code).toBe(1)
    expect(lost.out[1]).toBe(`retry ${RELAY} tries=1 reason=unreachable next_at=${w.io.time.now + 1}`)
    expect(lost.err).toEqual([
      `bag: unreachable: ${RELAY} retry; the bytes stay in the outbox, and resend --id ${lost.out[0]} sends them`,
    ])
    w.relay.failPublish = new RelayError(null, 502, null, `${RELAY}/v0/publish answered 502`)
    const proxied = await send(w, 'alice', 'chat.v1', '{}')
    expect(proxied.out[1]).toBe(`retry ${RELAY} tries=1 reason=publish-failed next_at=${w.io.time.now + 1}`)
    expect(proxied.err).toEqual([
      `bag: publish-failed: ${RELAY} retry; the bytes stay in the outbox, and resend --id ${proxied.out[0]} sends them`,
    ])
    console.log(`MEASURE L4(d): send prints "${lost.out[1]}" and "${lost.err[0]}"`)
  })

  it('refuses a body that is not JSON, a recipient that is not an address, --prev without --thread, and an unknown recipient', async () => {
    const w = await world()
    expect((await send(w, 'alice', 'chat.v1', '{bad')).err[0]).toBe('bag: usage: --body is not JSON')
    const bad = await cli(
      w.io,
      'send',
      '--as',
      'alice',
      '--to',
      'bob',
      '--relay',
      RELAY,
      '--type',
      't',
      '--body',
      '1',
    )
    expect(bad.err[0]).toBe('bag: usage: no home directory: pass --dir, or set AC_HOME or HOME')
    const name = await send(w, 'alice', 'chat.v1', '{}', '--to', 'dave')
    expect(name.err[0]).toBe(
      `bag: name-unknown: no name "dave" in ${join(w.dir, 'names.json')}; the book is empty`,
    )
    const neither = await send(w, 'alice', 'chat.v1', '{}', '--to', 'Dave!')
    expect(neither.err[0]).toBe('bag: bad-address: "Dave!" is neither an address nor a name')
    expect(w.relay.envelopes.size).toBe(0)
    const prev = await send(w, 'alice', 'chat.v1', '{}', '--prev', 'ab'.repeat(32))
    expect(prev.err[0]).toBe('bag: usage: --prev needs --thread')
    const thread = await send(w, 'alice', 'chat.v1', '{}', '--thread', 'xyz')
    expect(thread.err[0]).toBe('bag: bad-thread: thread.id is 32 bytes of lowercase hex')
    const unknown = await cli(
      w.io,
      'send',
      '--as',
      'bob',
      '--to',
      w.carol,
      '--relay',
      RELAY,
      '--type',
      't',
      '--body',
      '1',
      '--dir',
      w.dir,
    )
    expect(unknown.err[0]).toBe(`bag: resolve-failed: address:${w.carol} from relay; tried ${RELAY} (none)`)
    expect((await cli(w.io, 'send', '--as', 'alice')).err[0]).toBe('bag: usage: --to is required')
  })
})

describe('inbox: every relay named, each its own subscription', () => {
  const OTHER = 'http://127.0.0.1:10'
  const both = ['--trust-root', 'x', '--relay', OTHER, '--allow-private-relays']

  it('reads every relay named, and a message that reaches two prints once', async () => {
    const w = await world()
    const asked: string[] = []
    const subscribe = w.relay.subscribe.bind(w.relay)
    w.relay.subscribe = (url, ...rest) => {
      asked.push(url)
      return subscribe(url, ...rest)
    }
    const id = (await send(w, 'alice', 'chat.v1', '{"text":"hello"}')).out[0] as string
    const got = await inboxOnce(w, ...both.with(1, w.alice))
    expect(asked).toEqual([RELAY, OTHER])
    expect(got.out).toEqual([`accept ${id} ${w.alice} ${w.alice} chat.v1 {"text":"hello"}`])
  })

  it('a relay that ends costs the others nothing, and is named', async () => {
    const w = await world()
    const subscribe = w.relay.subscribe.bind(w.relay)
    w.relay.subscribe = (url, ...rest) => {
      if (url === OTHER) throw new RelayError(null, 0, null, 'down')
      return subscribe(url, ...rest)
    }
    await send(w, 'alice', 'chat.v1', '{"text":"hello"}')
    const got = await inboxOnce(w, ...both.with(1, w.alice))
    expect([got.code, got.out.length]).toEqual([0, 1])
    expect(got.err).toEqual([expect.stringMatching(/^bag: a relay ended: /)])
  })
})

describe('inbox: the edge Receiver at one relay, one line per handled message', () => {
  it('--once prints the accepted message with its id, from, root, type and body, acks it, and then prints nothing new', async () => {
    const w = await world()
    const sent = await send(w, 'alice', 'chat.v1', '{"text":"hello","list":[1,2.5,true,null]}')
    const id = sent.out[0] as string
    const got = await inboxOnce(w, '--trust-root', w.alice)
    expect(got).toEqual({
      code: 0,
      out: [`accept ${id} ${w.alice} ${w.alice} chat.v1 {"text":"hello","list":[1,2.5,true,null]}`],
      err: [],
    })
    expect(w.relay.acks.get(w.bob)).toBe(1)
    expect(w.relay.options.at(-1)).toEqual({ maxReconnects: 0 })
    expect(await inboxOnce(w, '--trust-root', w.alice)).toEqual({ code: 0, out: [], err: [] })
    const store = new SqliteStore(join(w.dir, 'state', 'bob', 'edge.sqlite'))
    try {
      expect(store.inboxList().map((r) => [r.cursor, r.state, r.session])).toEqual([[1, 'acked', 'cli']])
    } finally {
      store.close()
    }
    expect((await cli(w.io, 'audit', 'verify', join(w.dir, 'state', 'bob', 'audit.jsonl'))).out[0]).toMatch(
      /^ok \d+ lines$/,
    )
  })

  it('prints rejections with their code: an untrusted root, a type not accepted', async () => {
    const w = await world()
    const fromCarol = (await send(w, 'carol', 'chat.v1', '{}')).out[0] as string
    const otherType = (await send(w, 'alice', 'other.v1', '{}')).out[0] as string
    const ok = (await send(w, 'alice', 'chat.v1', '{"ok":true}')).out[0] as string
    const got = await inboxOnce(w, '--trust-root', w.alice, '--accept-type', 'chat.v1')
    expect(got.out).toEqual([
      `reject ${fromCarol} untrusted-root`,
      `reject ${otherType} type-not-accepted`,
      `accept ${ok} ${w.alice} ${w.alice} chat.v1 {"ok":true}`,
    ])
  })

  it('trusts a root by domain through its well-known record, and refuses a root that is neither address nor domain', async () => {
    const w = await world()
    const file = join(w.dir, 'alice.address.json')
    await cli(w.io, 'record', 'address', 'alice', '--relay', RELAY, '--out', file, '--dir', w.dir)
    w.io.wellKnown.set('acme.test', utf8(readFileSync(file, 'utf8').trim()))
    const id = (await send(w, 'alice', 'chat.v1', '{}')).out[0] as string
    expect((await inboxOnce(w, '--trust-root', 'acme.test')).out).toEqual([
      `accept ${id} ${w.alice} ${w.alice} chat.v1 {}`,
    ])
    // A domain root in the trust file is trusted as --trust-root <host> is, with no flag.
    writeFileSync(
      join(w.dir, 'trust.json'),
      JSON.stringify({ version: 1, roots: { 'domain:acme.test': { added_at: 1 } } }),
    )
    const id2 = (await send(w, 'alice', 'chat.v1', '{}')).out[0] as string
    expect((await inboxOnce(w)).out).toEqual([`accept ${id2} ${w.alice} ${w.alice} chat.v1 {}`])
    expect(trustedRoot('acme.test:8443')).toEqual({ domain: 'acme.test:8443' })
    expect((await inboxOnce(w, '--trust-root', '*')).err[0]).toBe(
      'bag: usage: --trust-root "*" is neither an address nor a domain',
    )
  })

  it('replies in a thread with --thread and --prev, and the reply reaches the thread the CLI bound', async () => {
    const w = await world()
    const first = (await send(w, 'alice', 'chat.v1', '{"q":1}')).out[0] as string
    await inboxOnce(w, '--trust-root', w.alice)
    const store = new SqliteStore(join(w.dir, 'state', 'bob', 'edge.sqlite'))
    const thread = (JSON.parse(store.inboxList()[0]?.content as string) as { thread: { id: string } }).thread
      .id
    store.close()
    const reply = await send(w, 'alice', 'chat.v1', '{"q":2}', '--thread', thread, '--prev', first)
    const id = reply.out[0] as string
    expect((await inboxOnce(w, '--trust-root', w.alice)).out).toEqual([
      `accept ${id} ${w.alice} ${w.alice} chat.v1 {"q":2}`,
    ])
    const after = new SqliteStore(join(w.dir, 'state', 'bob', 'edge.sqlite'))
    try {
      const row = after.inboxList()[1]
      expect(JSON.parse(row?.content as string)).toMatchObject({ thread: { id: thread, prev: [first] } })
      expect([row?.state, row?.session]).toEqual(['acked', 'cli'])
    } finally {
      after.close()
    }
  })

  it('prints a row a crash left unfinished, and does not print again a frame the relay sends after its ack', async () => {
    const w = await world()
    const one = (await send(w, 'alice', 'chat.v1', '{"n":1}')).out[0] as string
    await inboxOnce(w, '--trust-root', w.alice)
    const two = (await send(w, 'alice', 'chat.v1', '{"n":2}')).out[0] as string
    const store = new SqliteStore(join(w.dir, 'state', 'bob', 'edge.sqlite'))
    store.inboxAdd('http://elsewhere', w.bob, 7, w.relay.envelopes.get(two) as Uint8Array, w.io.time.now)
    store.close()
    w.relay.replay = true
    const got = await inboxOnce(w, '--trust-root', w.alice)
    expect(got.out).toEqual([
      `accept ${two} ${w.alice} ${w.alice} chat.v1 {"n":2}`,
      `reject ${two} duplicate`,
    ])
    expect(got.out.join('\n')).not.toContain(one)
  })

  it('prints a frame that is not an envelope as a rejection without an id', async () => {
    const w = await world()
    w.relay.box(w.bob).push({ cursor: 1, bytes: utf8('not an envelope') })
    expect((await inboxOnce(w, '--trust-root', w.alice)).out).toEqual(['reject - bad-json'])
  })

  it('rings the doorbell for each accepted message, never for a refusal; --doorbell-path prints it first', async () => {
    const w = await world()
    const path = join(w.dir, 'state', 'bob', 'doorbell')
    const OLD = new Date('2020-01-01T00:00:00Z')
    // carol's root is not trusted: her message is refused and touches nothing; the path is printed first, with --once.
    const refused = (await send(w, 'carol', 'chat.v1', '{}')).out[0] as string
    expect(await inboxOnce(w, '--trust-root', w.alice, '--doorbell-path')).toEqual({
      code: 0,
      out: [`doorbell ${path}`, `reject ${refused} untrusted-root`],
      err: [],
    })
    expect(existsSync(path)).toBe(false)
    const one = (await send(w, 'alice', 'chat.v1', '{"n":1}')).out[0] as string
    expect((await inboxOnce(w, '--trust-root', w.alice)).out).toEqual([
      `accept ${one} ${w.alice} ${w.alice} chat.v1 {"n":1}`,
    ])
    const mode = (p: string): number => statSync(p).mode & 0o777
    expect([mode(path), statSync(path).size, mode(join(w.dir, 'state', 'bob'))]).toEqual([0o600, 0, 0o700])
    utimesSync(path, OLD, OLD)
    // A refusal after it leaves the mtime where it was; a second accepted message moves it, and writes nothing.
    await send(w, 'carol', 'chat.v1', '{}')
    expect((await inboxOnce(w, '--trust-root', w.alice)).out).toHaveLength(1)
    expect(statSync(path).mtimeMs).toBe(OLD.getTime())
    await send(w, 'alice', 'chat.v1', '{"n":2}')
    expect((await inboxOnce(w, '--trust-root', w.alice)).out).toHaveLength(1)
    expect([statSync(path).mtimeMs > OLD.getTime(), statSync(path).size]).toEqual([true, 0])
    // The name and the identity are checked before a path is printed.
    const bell = (as: string) =>
      cli(w.io, 'inbox', '--as', as, '--relay', RELAY, '--doorbell-path', '--dir', w.dir)
    const bad = await bell('../keys')
    expect([bad.out, bad.err[0]]).toEqual([[], expect.stringContaining('a key name is 1 to 64')])
    const nobody = await bell('nobody')
    expect([nobody.out, nobody.err[0]]).toEqual([
      [],
      expect.stringMatching(/^bag: ENOENT: no identity nobody/),
    ])
  })

  it('writes one stderr line for a doorbell it cannot touch, and still prints and acks the message', async () => {
    const w = await world()
    // A directory where the file belongs: opening it to write fails with EISDIR.
    mkdirSync(join(w.dir, 'state', 'bob', 'doorbell'), { recursive: true, mode: 0o700 })
    const id = (await send(w, 'alice', 'chat.v1', '{}')).out[0] as string
    expect(await inboxOnce(w, '--trust-root', w.alice)).toEqual({
      code: 0,
      out: [`accept ${id} ${w.alice} ${w.alice} chat.v1 {}`],
      err: [expect.stringMatching(/^bag: doorbell EISDIR: /)],
    })
    expect(w.relay.acks.get(w.bob)).toBe(1)
    const store = new SqliteStore(join(w.dir, 'state', 'bob', 'edge.sqlite'))
    try {
      expect(store.inboxList().map((r) => r.state)).toEqual(['acked'])
    } finally {
      store.close()
    }
  })

  it('writes one stderr line for a FIFO at the doorbell path, never blocks on it, and still prints and acks the message', async () => {
    const w = await world()
    // A FIFO with no reader: a blocking open for writing would wait for one, inside the delivery path.
    mkdirSync(join(w.dir, 'state', 'bob'), { recursive: true, mode: 0o700 })
    execFileSync('mkfifo', ['-m', '0600', join(w.dir, 'state', 'bob', 'doorbell')])
    const id = (await send(w, 'alice', 'chat.v1', '{}')).out[0] as string
    expect(await inboxOnce(w, '--trust-root', w.alice)).toEqual({
      code: 0,
      out: [`accept ${id} ${w.alice} ${w.alice} chat.v1 {}`],
      err: [expect.stringMatching(/^bag: doorbell ENXIO: /)],
    })
    expect(w.relay.acks.get(w.bob)).toBe(1)
  })

  it('refuses to open an edge whose audit log ends in a line that does not parse, and closes its store', async () => {
    const w = await world()
    await inboxOnce(w, '--trust-root', w.alice)
    const log = join(w.dir, 'state', 'bob', 'audit.jsonl')
    writeFileSync(log, 'not a line\n', { flag: 'a' })
    const got = await inboxOnce(w, '--trust-root', w.alice)
    expect(got.code).toBe(1)
    expect(got.err[0]).toMatch(/^bag: error: /)
    const store = new SqliteStore(join(w.dir, 'state', 'bob', 'edge.sqlite'))
    store.close()
  })

  it('without --once runs until the stop signal, and fails with the code of a refused subscription', async () => {
    const w = await world()
    const id = (await send(w, 'alice', 'chat.v1', '{}')).out[0] as string
    const running = cli(
      w.io,
      'inbox',
      '--as',
      'bob',
      '--relay',
      RELAY,
      '--trust-root',
      w.alice,
      '--dir',
      w.dir,
    )
    await until('the accept line', () => w.io.stdout.at(-1)?.startsWith('accept') === true)
    expect(w.io.stdout.at(-1)).toBe(`accept ${id} ${w.alice} ${w.alice} chat.v1 {}`)
    expect([w.io.stopAsked, w.relay.options.at(-1)]).toEqual([1, {}])
    w.io.stop.abort()
    expect((await running).code).toBe(0)
    w.relay.failSubscribe = new RelayError('bad-auth', 0, null, 'the relay refused the subscription')
    expect((await inboxOnce(w)).err).toEqual(['bag: bad-auth: the relay refused the subscription'])
  })
})

describe('names: send --to a name from the book, inbox labels the addresses the book knows', () => {
  const name = (w: World, ...args: string[]) => cli(w.io, 'name', ...args, '--dir', w.dir)

  it('sends to a name as to its address, and inbox prints a known from and root as "<name> (<short>)"', async () => {
    const w = await world()
    await name(w, 'add', 'bob', w.bob)
    await name(w, 'add', 'alice', w.alice)
    const sent = await cli(
      w.io,
      'send',
      '--as',
      'alice',
      '--to',
      'bob',
      '--relay',
      RELAY,
      '--type',
      'chat.v1',
      '--body',
      '{"n":1}',
      '--dir',
      w.dir,
    )
    expect(sent.code).toBe(0)
    expect(w.relay.box(w.bob)).toHaveLength(1)
    const id = sent.out[0] as string
    const label = `alice (${w.alice.slice(0, 16)}…)`
    expect((await inboxOnce(w, '--trust-root', w.alice)).out).toEqual([
      `accept ${id} ${label} ${label} chat.v1 {"n":1}`,
    ])
    const unknown = await cli(
      w.io,
      'send',
      '--as',
      'alice',
      '--to',
      'bobby',
      '--relay',
      RELAY,
      '--type',
      't',
      '--body',
      '1',
      '--dir',
      w.dir,
    )
    expect(unknown.err).toEqual([
      `bag: name-unknown: no name "bobby" in ${join(w.dir, 'names.json')}; the known names are alice, bob`,
    ])
  })

  it("prints a message from a name's former address with the warning, and an address the book lacks in full", async () => {
    const w = await world()
    await name(w, 'add', 'alice', w.alice)
    w.io.time.now += 60
    await name(w, 'add', 'alice', w.carol, '--replace')
    const old = (await send(w, 'alice', 'chat.v1', '{}')).out[0] as string
    const now = (await send(w, 'carol', 'chat.v1', '{}')).out[0] as string
    const stranger = `ed25519:${'d4'.repeat(32)}`
    const got = await inboxOnce(w, '--trust-root', w.alice, '--trust-root', w.carol, '--trust-root', stranger)
    const former = `alice? (${w.alice.slice(0, 16)}…) WARNING: former address of alice, replaced 2027-01-15T08:01:00Z`
    const current = `alice (${w.carol.slice(0, 16)}…)`
    expect(got.out).toEqual([
      `accept ${old} ${former} ${former} chat.v1 {}`,
      `accept ${now} ${current} ${current} chat.v1 {}`,
    ])
    await name(w, 'forget', 'alice')
    const again = (await send(w, 'alice', 'chat.v1', '{}')).out[0] as string
    expect((await inboxOnce(w, '--trust-root', w.alice)).out).toEqual([
      `accept ${again} ${w.alice} ${w.alice} chat.v1 {}`,
    ])
  })

  it('refuses to start inbox on a name book that is not one', async () => {
    const w = await world()
    writeFileSync(join(w.dir, 'names.json'), '[]')
    expect((await inboxOnce(w, '--trust-root', w.alice)).err).toEqual([
      `bag: names-invalid: ${join(w.dir, 'names.json')}: version is not 1`,
    ])
  })
})

describe("send --auth and inbox --honor: a session that signs under its principal's chain", () => {
  /** alice-session's keys in the same home, a chain from alice to it under `caveats`, and alice's address record. */
  async function delegated(w: World, caveats: readonly string[], record = true) {
    const session = (await cli(w.io, 'keygen', 'alice-session', '--dir', w.dir)).out[0] as string
    const chain = join(w.dir, 'session.chain.json')
    const flags = caveats.flatMap((c) => ['--caveat', c])
    const args = [
      '--from',
      'alice',
      '--to',
      session,
      ...flags,
      '--exp',
      '+600',
      '--out',
      chain,
      '--dir',
      w.dir,
    ]
    expect((await cli(w.io, 'delegate', ...args)).code).toBe(0)
    if (record) {
      const file = join(w.dir, 'alice.address.json')
      await cli(w.io, 'record', 'address', 'alice', '--relay', RELAY, '--out', file, '--dir', w.dir)
      await cli(w.io, 'publish', RELAY, file)
    }
    return { session, chain }
  }

  it('sends as the session with the chain in auth; bob, trusting alice and honoring coding, accepts it with root alice', async () => {
    const w = await world()
    const { session, chain } = await delegated(w, ['type=chat.v1'])
    const sent = await send(w, 'alice-session', 'chat.v1', '{"text":"from the session"}', '--auth', chain)
    expect([sent.code, sent.out[1]]).toEqual([0, `published ${RELAY} tries=1`])
    const id = sent.out[0] as string
    const env = parseEnvelope(w.relay.envelopes.get(id) as Uint8Array)
    expect([env.from, env.auth]).toEqual([session, JSON.parse(readFileSync(chain, 'utf8'))])
    expect((await inboxOnce(w, '--trust-root', w.alice, '--honor', 'coding')).out).toEqual([
      `accept ${id} ${session} ${w.alice} chat.v1 {"text":"from the session"}`,
    ])
  })

  it('names the chain root, not the session key, when a session is refused root-not-accepted', async () => {
    const w = await world()
    const { session, chain } = await delegated(w, ['type=chat.v1'])
    w.relay.failPublish = new RelayError('root-not-accepted', 403, null, `${RELAY}/v0/publish answered 403`)
    const refused = await send(w, 'alice-session', 'chat.v1', '{}', '--auth', chain)
    expect(refused.code).toBe(1)
    expect(refused.err[0]).toContain(`ask them to add ${w.alice} (or your org's domain root)`)
    expect(refused.err[0]).not.toContain(session)
  })

  it("fails closed: unknown-caveat without --honor, caveat-failed for a caveat that does not hold, resolve-failed without the root's record", async () => {
    const w = await world()
    const { chain } = await delegated(w, ['type=other.v1'], false)
    const early = (await send(w, 'alice-session', 'chat.v1', '{}', '--auth', chain)).out[0] as string
    expect((await inboxOnce(w, '--trust-root', w.alice, '--honor', 'coding')).out).toEqual([
      `reject ${early} resolve-failed`,
    ])
    const file = join(w.dir, 'alice.address.json')
    await cli(w.io, 'record', 'address', 'alice', '--relay', RELAY, '--out', file, '--dir', w.dir)
    await cli(w.io, 'publish', RELAY, file)
    const unhonored = (await send(w, 'alice-session', 'chat.v1', '{}', '--auth', chain)).out[0] as string
    expect((await inboxOnce(w, '--trust-root', w.alice)).out).toEqual([`reject ${unhonored} unknown-caveat`])
    const failing = (await send(w, 'alice-session', 'chat.v1', '{}', '--auth', chain)).out[0] as string
    expect(
      (await inboxOnce(w, '--trust-root', w.alice, '--honor', 'coding', '--honor', 'coding')).out,
    ).toEqual([`reject ${failing} caveat-failed`])
  })

  it('refuses a chain whose last hop is not to the sender, and one it cannot read, before anything is published', async () => {
    const w = await world()
    const { session, chain } = await delegated(w, ['type=chat.v1'])
    const notMine = await send(w, 'alice', 'chat.v1', '{}', '--auth', chain)
    expect([notMine.code, notMine.out, notMine.err]).toEqual([
      1,
      [],
      [`bag: chain-not-to-sender: the chain's last hop is to ${session}, not to alice`],
    ])
    const missing = await send(w, 'alice-session', 'chat.v1', '{}', '--auth', join(w.dir, 'missing.json'))
    expect(missing.err[0]).toMatch(/^bag: ENOENT: /)
    expect(w.relay.envelopes.size).toBe(0)
    const self = join(w.dir, 'self.chain.json')
    writeFileSync(self, '[]\n')
    const rooted = await send(w, 'alice', 'chat.v1', '{}', '--auth', self)
    expect([rooted.code, rooted.out[1]]).toEqual([0, `published ${RELAY} tries=1`])
  })

  it('follows an org root by domain through a countersigned rotation once its cached record expires, and refuses one without a countersignature', async () => {
    const w = await world()
    const publish = async (name: string, ...more: string[]) => {
      const file = join(w.dir, `${name}.address.json`)
      const args = ['--relay', RELAY, '--ttl', '60', '--out', file, '--dir', w.dir, ...more]
      expect((await cli(w.io, 'record', 'address', name, ...args)).code).toBe(0)
      w.io.wellKnown.set('acme.test', utf8(readFileSync(file, 'utf8').trim()))
    }
    const chainFrom = async (org: string) => {
      const file = join(w.dir, `${org}.chain.json`)
      const args = [
        '--to',
        w.alice,
        '--caveat',
        'type=chat.*',
        '--exp',
        '+3600',
        '--out',
        file,
        '--dir',
        w.dir,
      ]
      expect((await cli(w.io, 'delegate', '--from', org, ...args)).code).toBe(0)
      return file
    }
    const [k1, k2] = await Promise.all(
      ['org-acme', 'org-acme-2', 'org-acme-3'].map(
        async (k) => (await cli(w.io, 'keygen', k, '--dir', w.dir)).out[0] as string,
      ),
    )
    const trust = ['--trust-root', 'acme.test', '--honor', 'coding']
    await publish('org-acme')
    const first = (await send(w, 'alice', 'chat.v1', '{"n":1}', '--auth', await chainFrom('org-acme'))).out[0]
    expect((await inboxOnce(w, ...trust)).out).toEqual([`accept ${first} ${w.alice} ${k1} chat.v1 {"n":1}`])
    // A chain from the next key, before the cached record of org-acme expires: the root is not the domain's key yet.
    const second = await chainFrom('org-acme-2')
    const early = (await send(w, 'alice', 'chat.v1', '{"n":2}', '--auth', second)).out[0]
    expect((await inboxOnce(w, ...trust)).out).toEqual([`reject ${early} untrusted-root`])
    w.io.time.now += 61
    await publish('org-acme-2', '--rotated-from', 'org-acme')
    const rotated = (await send(w, 'alice', 'chat.v1', '{"n":3}', '--auth', second)).out[0]
    expect((await inboxOnce(w, ...trust)).out).toEqual([`accept ${rotated} ${w.alice} ${k2} chat.v1 {"n":3}`])
    w.io.time.now += 61
    await publish('org-acme-3')
    const bare = (await send(w, 'alice', 'chat.v1', '{"n":4}', '--auth', second)).out[0]
    expect((await inboxOnce(w, ...trust)).out).toEqual([`reject ${bare} pin-mismatch`])
    const lines = readFileSync(join(w.dir, 'state', 'bob', 'audit.jsonl'), 'utf8')
      .trim()
      .split('\n')
    const rotations = lines.map((l) => JSON.parse(l) as { event: string; decision: string })
    expect(rotations.filter((l) => l.event === 'rotate').map((l) => l.decision)).toEqual(['accept', 'reject'])
  })

  it('honors only the profiles it knows', async () => {
    expect(honored([])).toEqual([])
    expect(honored(['coding', 'coding'])).toEqual([codingEvaluator])
    const w = await world()
    expect((await inboxOnce(w, '--honor', 'payments')).err[0]).toBe(
      'bag: usage: --honor "payments" is not a profile; the profiles are coding',
    )
  })
})

describe('ObservedSubscription: reports acks, and ends a quiet stream when it has an idle limit', () => {
  function fake(frames: Frame[]): Subscription & { acked: number[]; closed: boolean } {
    const s = {
      acked: [] as number[],
      closed: false,
      async *[Symbol.asyncIterator](): AsyncGenerator<Frame> {
        yield* frames
        await new Promise(() => {})
      },
      ack(cursor: number) {
        s.acked.push(cursor)
      },
      close() {
        s.closed = true
      },
    }
    return s
  }

  it('passes frames through, forwards acks and close, and ends after the idle limit', async () => {
    const frames = [1, 2].map((cursor) => ({ cursor, envelopeBytes: utf8('{}') }))
    const inner = fake(frames)
    const seen: number[] = []
    const sub = new ObservedSubscription(inner, 20, (c) => seen.push(c))
    const got: number[] = []
    for await (const f of sub) {
      got.push(f.cursor)
      sub.ack(f.cursor)
    }
    sub.close()
    expect([got, inner.acked, seen, inner.closed]).toEqual([[1, 2], [1, 2], [1, 2], true])
  })

  it('without an idle limit ends only when the inner stream ends', async () => {
    const inner = {
      async *[Symbol.asyncIterator](): AsyncGenerator<Frame> {
        yield { cursor: 5, envelopeBytes: utf8('{}') }
      },
      ack() {},
      close() {},
    }
    const got: number[] = []
    for await (const f of new ObservedSubscription(inner, null, () => {})) got.push(f.cursor)
    expect(got).toEqual([5])
  })
})

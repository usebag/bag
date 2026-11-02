import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type AcceptFromRecord, type AddressRecord, type KeyRecord, parseRecord } from '@usebag/core'
import { addressCopy, inviteText as invited, pairingCode, RelayError, WORDS } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { NameBook } from '../src/names.ts'
import { addTrust, readTrust } from '../src/trust.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { Network } from './support/network.ts'
import { cli, type Ran } from './support/run.ts'

// Lines L1 to L4 for `peer invite` and `peer accept`: homes on in-process relays by URL (support/network.ts,
// which refuses as spec/SPEC.md §8.2 does: 409 stale-record, 403 root-not-accepted), the terminal's answers and the
// clock injected through the test io. L5 (no MCP surface) is packages/mcp/test/trust.test.ts.
// Forward secrecy (since 2026-10-29): each side pairs with its current key record
// (cli/src/epochs.ts currentKey), publishing a new epoch first when one is due, so a side's first line is rotateEpoch's
// `published key <address> <relay>` (and `published address ...` when the held record was re-signed or none was held);
// its address record keeps no sealing key, and the other side's relay holds its key record after the pairing.

const tmp = tempDir('peer')
afterAll(() => tmp.cleanup())
const [R1, R2, R3] = ['http://127.0.0.1:1', 'http://127.0.0.1:2', 'http://127.0.0.1:3']
const END = T0 + 601
let n = 0

interface Party {
  readonly io: TestIo
  readonly dir: string
  readonly address: string
  readonly name: string
  readonly relay: string
}

/** The six digits an acceptor's person last read out: what an inviter's person types. */
let readOut = ''

/** `digits` with the first changed: seeded wrong digits, the same shape as the right ones. */
const wrong = (digits: string): string => digits.replace(/^\d/, (d) => String((Number(d) + 1) % 10))

/**
 * An identity in a home of its own, on a terminal (tty), whose relay is `relay`; nothing published. `answers` are its
 * person's: an acceptor's a y or an n, an inviter's the digits read out or, for false, the end of input.
 */
async function party(net: Network, name: string, relay: string, ...answers: boolean[]): Promise<Party> {
  const io = testIo(net)
  io.tty = true
  io.answers.push(...answers)
  const { out } = io
  io.out = (line) => {
    out(line)
    if (line.startsWith('check digits ')) readOut = line.slice('check digits '.length)
  }
  io.readLine = async () => (io.answers.shift() === true ? readOut : null)
  const dir = join(tmp.dir, `${name}-${n++}`)
  const address = (await cli(io, 'keygen', name, '--dir', dir)).out[0] as string
  return { io, dir, address, name, relay }
}

const invite = (p: Party, as: string, ...more: string[]): Promise<Ran> =>
  cli(p.io, 'peer', 'invite', '--as', p.name, '--relay', p.relay, '--name', as, '--dir', p.dir, ...more)
/** peer accept, its relays on loopback addresses allowed (the guard itself: the word code describe). */
const accept = (p: Party, as: string, text: string, ...more: string[]): Promise<Ran> =>
  guarded(p, as, text, '--allow-private-relays', ...more)
const guarded = (p: Party, as: string, text: string, ...more: string[]): Promise<Ran> =>
  cli(p.io, 'peer', 'accept', '--as', p.name, '--relay', p.relay, '--name', as, '--dir', p.dir, text, ...more)

async function until(what: string, test: () => boolean, ms = 5000): Promise<void> {
  const end = Date.now() + ms
  while (!test()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`)
    await new Promise((r) => setTimeout(r, 5))
  }
}

/** The lines a first command of `p` prints for its epoch 1: no address record was held, so key and address records. */
const rotated = (p: Party): string[] => [
  `published key ${p.address} ${p.relay}`,
  `published address ${p.address} ${p.relay}`,
]

/** The record of `kind` that `p` has at `url`, parsed. */
const rec = <T>(net: Network, url: string, p: Party, kind: string): T =>
  parseRecord(net.record(url, p.address, kind) as string) as T

/** The invite string the inviter printed, once it has. */
async function printed(p: Party): Promise<string> {
  await until('the invite', () => p.io.stdout.some((l) => l.startsWith('invite ')))
  return (p.io.stdout.find((l) => l.startsWith('invite ')) as string).slice('invite '.length)
}

/** An invite string of four fields, and the code of a request under one. */
const inviteText = (inviter: string, i: string, relay: string, secret: string): string =>
  invited({ inviter, i, relay, secret })
const code = (inviter: string, i: string, requester: string, sealing: string, secret: string): string =>
  pairingCode({ inviter, i, relay: R1, secret }, requester, sealing)

/** The four fields of an invite string: inviter, I, relay, S. */
function fields(text: string): [string, string, string, string] {
  const list = JSON.parse(Buffer.from(text.slice('ac-peer1:'.length), 'base64url').toString()) as string[]
  return list.slice(1) as [string, string, string, string]
}

/** names.json and trust.json of a home, as bytes or null. */
const files = (p: Party): (string | null)[] =>
  ['names.json', 'trust.json'].map((f) =>
    existsSync(join(p.dir, f)) ? readFileSync(join(p.dir, f), 'utf8') : null,
  )
const roots = (net: Network, url: string, p: Party | string): readonly string[] | null => {
  const text = net.record(url, typeof p === 'string' ? p : p.address, 'accept-from')
  return text === null ? null : (parseRecord(text) as AcceptFromRecord).roots
}
const envelopes = (net: Network, url: string): number => net.at(url).envelopes.size

describe('a listed relay that does not take a record (spec/SPEC.md Appendix B 110)', () => {
  it('pairs past it and prints the relay, on the side that lists it', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1, true)
    const bob = await party(net, 'bob', R1, true)
    await cli(alice.io, 'keys', 'rotate', 'alice', '--relay', R1, '--relay', R3, '--dir', alice.dir)
    net.at(R3).failRecordPublish.set(R3, new RelayError(null, 0, null, 'no answer'))
    const inviting = invite(alice, 'bob')
    const text = await printed(alice)
    const [a, b] = await Promise.all([inviting, accept(bob, 'alice', text)])
    expect([a.code, b.code, a.err, b.err]).toEqual([0, 0, [], []])
    expect(a.out).toContain(`failed accept-from ${alice.address} ${R3} unreachable`)
    expect(a.out.at(-1)).toBe(`paired bob ${bob.address}`)
    expect(b.out.join('\n')).not.toContain('failed')
    expect(roots(net, R1, alice)).toContain(bob.address)
  })
})

describe('L1: one command a side, a y and the typed digits pair two homes on two relays', () => {
  it('names, trusts and admits each side, leaves the invitation to lapse, and lets each send to the other by name', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1, true)
    const bob = await party(net, 'bob', R2, true)
    const started = Date.now()
    const inviting = invite(alice, 'bob')
    const text = await printed(alice)
    const [a, b] = await Promise.all([inviting, accept(bob, 'alice', text)])
    const wall = Date.now() - started
    expect([a.code, b.code, a.err, b.err]).toEqual([0, 0, [], []])
    const [inviter, i, relay, s] = fields(text)
    expect([inviter, relay, s]).toEqual([alice.address, R1, expect.stringMatching(/^[0-9a-f]{32}$/)])
    // The code is over bob's key record's sealing key; bob's address record names none.
    const sealing = rec<KeyRecord>(net, R2, bob, 'key').sealing_key
    const six = code(alice.address, i, bob.address, sealing, s)
    expect(a.out).toEqual([
      ...rotated(alice),
      `invite ${text}`,
      'one request until 2027-01-15T08:10:00Z; the other side reads you six digits, and you type them here',
      `request ${bob.address}`,
      'to pair with it as bob, type the six digits the other side reads you',
      `paired bob ${bob.address}`,
    ])
    expect(b.out).toEqual([
      ...rotated(bob),
      `inviter ${alice.address} at ${R1}`,
      `check digits ${six}`,
      'read them out now, not where the code was sent, before you answer: that is the security check',
      "requested; waiting until 2027-01-15T08:10:00Z for the inviter's answer",
      `paired alice ${alice.address}`,
    ])
    expect([alice.io.asked, bob.io.asked]).toEqual([[], ['pair with it as alice?']])
    // The records: the test published none. Each side's epoch 1 first (key, then address), then I's, then the inviter
    // shares bob's address and key record at R1 and admits him, bob shares alice's two at R2 and admits her; each
    // side's accept-from names the other, I's is left to lapse.
    expect(net.log).toEqual([
      `${R1} key ${alice.address}`,
      `${R1} address ${alice.address}`,
      `${R1} address ${i}`,
      `${R1} accept-from ${i}`,
      `${R2} key ${bob.address}`,
      `${R2} address ${bob.address}`,
      `${R1} address ${bob.address}`,
      `${R1} key ${bob.address}`,
      `${R1} accept-from ${alice.address}`,
      `${R2} address ${alice.address}`,
      `${R2} key ${alice.address}`,
      `${R2} accept-from ${bob.address}`,
    ])
    // No address record of either side names a sealing key, wherever it is held; I's keeps its own; each side's
    // key record is served at the other side's relay, the very bytes its owner published.
    for (const [url, p] of [
      [R1, alice],
      [R2, bob],
      [R1, bob],
      [R2, alice],
    ] as const) {
      expect(rec<AddressRecord>(net, url, p, 'address').sealing_key, `${url} ${p.name}`).toBeNull()
    }
    expect((parseRecord(net.record(R1, i, 'address') as string) as AddressRecord).sealing_key).toMatch(
      /^[0-9a-f]{64}$/,
    )
    expect(net.record(R1, bob.address, 'key')).toBe(net.record(R2, bob.address, 'key'))
    expect(net.record(R2, alice.address, 'key')).toBe(net.record(R1, alice.address, 'key'))
    expect([roots(net, R1, alice), roots(net, R2, bob), roots(net, R1, i)]).toEqual([
      [bob.address],
      [alice.address],
      ['*'],
    ])
    expect((parseRecord(net.record(R1, i, 'address') as string) as AddressRecord).ttl).toBe(600)
    // The files: the name book and the trust file, 0600.
    expect(NameBook.load(alice.dir).resolve('bob')).toBe(bob.address)
    expect(NameBook.load(bob.dir).resolve('alice')).toBe(alice.address)
    expect(Object.keys(readTrust(alice.dir))).toEqual([bob.address])
    expect(readTrust(bob.dir)).toEqual({ [alice.address]: { added_at: T0 } })
    expect(statSync(join(alice.dir, 'trust.json')).mode & 0o777).toBe(0o600)
    // Each sends to the other by name, and the other's inbox accepts it with no --trust-root.
    for (const [from, to, as] of [
      [alice, bob, 'bob'],
      [bob, alice, 'alice'],
    ] as const) {
      const ok = await cli(
        from.io,
        'send',
        ...['--as', from.name, '--to', as, '--relay', from.relay, '--type', 'chat.v1', '--body', '{"hi":1}'],
        ...['--allow-private-relays', '--dir', from.dir],
      )
      expect(ok.code).toBe(0)
      const got = await cli(to.io, 'inbox', '--as', to.name, '--relay', to.relay, '--once', '--dir', to.dir)
      expect(got.out).toEqual([
        expect.stringMatching(
          new RegExp(`^accept [0-9a-f]{64} ${from.name} \\(.*\\) ${from.name} \\(.*\\) chat.v1`),
        ),
      ])
    }
    expect(wall).toBeLessThan(60_000)
  })
})

/** The inviter and the acceptor of one invite, and the invite running. */
async function opened(...answers: [boolean[], boolean[]]) {
  const net = new Network()
  const alice = await party(net, 'alice', R1, ...answers[0])
  const bob = await party(net, 'bob', R2, ...answers[1])
  const inviting = invite(alice, 'bob')
  return { net, alice, bob, inviting, text: await printed(alice) }
}

describe('the word code: a short code when the relay offers pair', () => {
  it('peer invite prints the code, and peer accept pairs on it as typed in any case, claimed at its --relay', async () => {
    const net = new Network()
    net.pair = true
    const alice = await party(net, 'alice', R1, true)
    const bob = await party(net, 'bob', R1, true)
    const inviting = invite(alice, 'bob')
    await until('the code', () => alice.io.stdout.some((l) => l.startsWith('pairing code ')))
    const text = (alice.io.stdout.find((l) => l.startsWith('pairing code ')) as string).slice(
      'pairing code '.length,
    )
    expect(text).toMatch(/^472(-[^-\s]+){3}$/)
    const [a, b] = await Promise.all([inviting, accept(bob, 'alice', text.toUpperCase())])
    expect([a.code, b.code, a.err, b.err]).toEqual([0, 0, [], []])
    expect(a.out.at(-1)).toBe(`paired bob ${bob.address}`)
    expect(b.out).toContain(`inviter ${alice.address} at ${R1}`)
    expect(b.out.at(-1)).toBe(`paired alice ${alice.address}`)
    const six = b.out.find((l) => /^check digits \d{3} \d{3}$/.test(l))?.slice(-7) as string
    expect(a.out.join('\n')).not.toContain(six)
  })

  it('pairs two relays through a shared --rendezvous: the nameplate and the request to I both there', async () => {
    const net = new Network()
    net.pair = true
    const alice = await party(net, 'alice', R1, true)
    const bob = await party(net, 'bob', R2, true)
    const inviting = invite(alice, 'bob', '--rendezvous', R3)
    await until('the code', () => alice.io.stdout.some((l) => l.startsWith('pairing code ')))
    const text = (alice.io.stdout.find((l) => l.startsWith('pairing code ')) as string).slice(13)
    expect([...net.plates.keys()]).toEqual([`${R3} 472`])
    const [a, b] = await Promise.all([inviting, accept(bob, 'alice', text, '--rendezvous', R3)])
    expect([a.code, b.code, a.err, b.err]).toEqual([0, 0, [], []])
    expect(b.out).toContain(`inviter ${alice.address} at ${R3}`)
    expect([a.out.at(-1), b.out.at(-1)]).toEqual([
      `paired bob ${bob.address}`,
      `paired alice ${alice.address}`,
    ])
  })

  it('peer accept refuses a code@host on a private address it was not given (resolve-failed), unless --allow-private-relays', async () => {
    const net = new Network()
    net.pair = true
    const bob = await party(net, 'bob', R1)
    const code = `472-${WORDS[0]}-${WORDS[1]}-${WORDS[2]}@10.0.0.1`
    expect((await guarded(bob, 'alice', code)).err[0]).toMatch(/^bag: resolve-failed: /)
    expect((await accept(bob, 'alice', code)).err[0]).toMatch(
      /^bag: invite-expired: https:\/\/10\.0\.0\.1 holds no open invitation 472$/,
    )
  })

  it('peer accept refuses an invite string whose relay is a private address it was not given (resolve-failed), before any request', async () => {
    const net = new Network()
    const bob = await party(net, 'bob', R2)
    const text = inviteText(bob.address, bob.address, R1, '0'.repeat(32))
    expect((await guarded(bob, 'alice', text)).err[0]).toMatch(/^bag: resolve-failed: /)
    expect(net.relays.has(R1)).toBe(false)
  })

  it('peer accept refuses a code that --relay holds no invitation for (invite-expired)', async () => {
    const net = new Network()
    net.pair = true
    const bob = await party(net, 'bob', R1)
    const code = `472-${WORDS[0]}-${WORDS[1]}-${WORDS[2]}`
    expect((await accept(bob, 'alice', code)).err[0]).toMatch(/^bag: invite-expired: /)
  })
})

describe('L2: an invite lives 600 s and takes one request', () => {
  it('(a) an accept after iat + ttl + skew refuses invite-expired and sends nothing', async () => {
    const { net, alice, bob, inviting, text } = await opened([], [true])
    bob.io.time.now = T0 + 600 + 301
    const late = await accept(bob, 'alice', text)
    expect([late.code, late.err[0], bob.io.asked]).toEqual([
      1,
      expect.stringMatching(/^bag: invite-expired: /),
      [],
    ])
    alice.io.time.now = END
    const ended = await inviting
    expect([ended.code, ended.err]).toEqual([
      1,
      ['bag: invite-expired: no request came before the invitation ended'],
    ])
    expect(envelopes(net, R1)).toBe(0)
    expect([...files(alice), ...files(bob)]).toEqual([null, null, null, null])
  })

  it('(b) a request after the invite ended goes unconsumed: its sender ends no-answer', async () => {
    const { net, alice, bob, inviting, text } = await opened([], [true])
    alice.io.time.now = END
    expect((await inviting).code).toBe(1)
    const [, i] = fields(text)
    expect(roots(net, R1, i)).toEqual(['*'])
    bob.io.time.now = T0 + 600
    const late = await accept(bob, 'alice', text)
    expect([late.code, late.err[0]]).toEqual([1, expect.stringMatching(/^bag: no-answer: /)])
    expect([...files(alice), ...files(bob)]).toEqual([null, null, null, null])
  })

  it('(c) after one pairing, a second request with the same string goes the same way', async () => {
    const { net, bob, inviting, text } = await opened([true], [true])
    expect((await Promise.all([inviting, accept(bob, 'alice', text)])).map((r) => r.code)).toEqual([0, 0])
    const carol = await party(net, 'carol', R2, true)
    carol.io.time.now = T0 + 600
    const again = await accept(carol, 'alice', text)
    expect([again.code, again.err[0]]).toEqual([1, expect.stringMatching(/^bag: no-answer: /)])
    expect(files(carol)).toEqual([null, null])
  })

  it('(d) --ttl above 600 is a usage error; --ttl below it is the record ttl; 600 is the default (L1)', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1)
    for (const ttl of ['601', '0', 'x']) {
      expect((await invite(alice, 'bob', '--ttl', ttl)).err[0]).toMatch(/^bag: usage: --ttl /)
    }
    const short = invite(alice, 'bob', '--ttl', '30')
    const [, i] = fields(await printed(alice))
    expect((parseRecord(net.record(R1, i, 'address') as string) as AddressRecord).ttl).toBe(30)
    alice.io.time.now = T0 + 30
    expect((await short).err).toEqual(['bag: invite-expired: no request came before the invitation ended'])
    expect(net.log).toEqual([
      `${R1} key ${alice.address}`,
      `${R1} address ${alice.address}`,
      `${R1} address ${i}`,
      `${R1} accept-from ${i}`,
    ])
  })
})

describe('L3: every failure ends the invite and writes nothing', () => {
  it('(a) a wrong secret is told refused <requester> bad-mac, with no prompt, and ends nothing', async () => {
    const { net, alice, bob, inviting, text } = await opened([], [true])
    const [inviter, i, relay] = fields(text)
    const wrong = inviteText(inviter, i, relay, '0'.repeat(32))
    const accepting = accept(bob, 'alice', wrong)
    await until('the refusal', () => alice.io.stdout.includes(`refused ${bob.address} bad-mac`))
    alice.io.time.now = END
    const a = await inviting
    expect([a.code, a.out.at(-1), alice.io.asked]).toEqual([1, `refused ${bob.address} bad-mac`, []])
    bob.io.time.now = END
    expect((await accepting).err).toEqual([
      `bag: no-answer: ${alice.address} did not admit this identity before the invitation ended`,
    ])
    expect([...files(alice), ...files(bob), roots(net, R1, alice), roots(net, R1, i)]).toEqual([
      null,
      null,
      null,
      null,
      null,
      ['*'],
    ])
  })

  it('(b) the inviter stops typing (end of input): declined, nothing written, the acceptor gets no answer', async () => {
    const { net, alice, bob, inviting, text } = await opened([false], [true])
    const accepting = accept(bob, 'alice', text)
    const a = await inviting
    expect([a.code, a.err]).toEqual([1, ['bag: declined: nothing was written']])
    bob.io.time.now = END
    expect((await accepting).code).toBe(1)
    expect([...files(alice), ...files(bob), roots(net, R1, alice), roots(net, R2, bob)]).toEqual([
      null,
      null,
      null,
      null,
      null,
      null,
    ])
  })

  it('(b) three wrong tries, a wrong digit, a wrong length and nothing: digits-mismatch, the digits never shown', async () => {
    const { net, alice, bob, inviting, text } = await opened([], [true])
    const tries = [() => wrong(readOut), () => readOut.slice(0, 5), () => '']
    alice.io.readLine = async () => (tries.shift() as () => string)()
    const accepting = accept(bob, 'alice', text)
    const a = await inviting
    expect([a.code, a.err]).toEqual([
      1,
      ['bag: digits-mismatch: the typed digits did not match; nothing was written'],
    ])
    expect(a.out.slice(-3)).toEqual([
      'to pair with it as bob, type the six digits the other side reads you',
      'no match; tries left: 2; ask the other side to repeat them',
      'no match; tries left: 1; ask the other side to repeat them',
    ])
    expect(a.out.join('\n')).not.toContain(readOut)
    // No oracle: the acceptor's end is the plain no-answer of an inviter who never answered.
    bob.io.time.now = END
    expect((await accepting).err).toEqual([
      `bag: no-answer: ${alice.address} did not admit this identity before the invitation ended`,
    ])
    expect([...files(alice), ...files(bob), roots(net, R1, alice), roots(net, R2, bob)]).toEqual([
      null,
      null,
      null,
      null,
      null,
      null,
    ])
  })

  it('(b) a wrong try leaves the invitation open: the next, typed with a hyphen and a line end, pairs', async () => {
    const { alice, bob, inviting, text } = await opened([], [true])
    const tries = [() => wrong(readOut), () => `${readOut.replace(' ', '-')}\r`]
    alice.io.readLine = async () => (tries.shift() as () => string)()
    const [a, b] = await Promise.all([inviting, accept(bob, 'alice', text)])
    expect([a.code, b.code, a.err, b.err]).toEqual([0, 0, [], []])
  })

  it('(c) the acceptor answers N: no request is sent', async () => {
    const { net, alice, bob, inviting, text } = await opened([true], [false])
    const b = await accept(bob, 'alice', text)
    expect([b.code, b.err]).toEqual([1, ['bag: declined: no request was sent; nothing was written']])
    expect(envelopes(net, R1)).toBe(0)
    alice.io.time.now = END
    expect((await inviting).code).toBe(1)
    expect([...files(alice), ...files(bob)]).toEqual([null, null, null, null])
  })

  it('(d) an edited string shows another code, and the inviter refuses it bad-mac; an edited I has no record', async () => {
    const { net, alice, bob, inviting, text } = await opened([], [true, false])
    const [, i, relay, s] = fields(text)
    const carol = await party(net, 'carol', R2)
    const edited = inviteText(carol.address, i, relay, s)
    const accepting = accept(bob, 'carol', edited)
    await until('the refusal', () => alice.io.stdout.includes(`refused ${bob.address} bad-mac`))
    alice.io.time.now = END
    const a = await inviting
    const b = await (async () => {
      bob.io.time.now = END
      return accepting
    })()
    const shown = b.out.find((l) => l.startsWith('check digits ')) as string
    const sealing = rec<KeyRecord>(net, R2, bob, 'key').sealing_key
    expect(shown).not.toBe(`check digits ${code(alice.address, i, bob.address, sealing, s)}`)
    expect([a.out.at(-1), alice.io.asked]).toEqual([`refused ${bob.address} bad-mac`, []])
    const noI = await accept(bob, 'alice', inviteText(alice.address, carol.address, relay, s))
    expect(noI.err[0]).toMatch(/^bag: invite-expired: /)
    const declined = await accept(bob, 'alice', text)
    expect(declined.err[0]).toMatch(/^bag: declined: /)
    expect([...files(alice), ...files(bob), roots(net, R1, alice)]).toEqual([null, null, null, null, null])
  })
})

describe('L4: the string alone pairs with no one', () => {
  it('(a) both commands refuse no-tty before any network call', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1)
    alice.io.tty = false
    const i = await invite(alice, 'bob')
    const a = await accept(alice, 'bob', inviteText(alice.address, alice.address, R1, '0'.repeat(32)))
    for (const r of [i, a]) expect(r.err[0]).toMatch(/^bag: no-tty: peer (invite|accept) is a person's act/)
    expect([net.log, net.relays.size]).toEqual([[], 0])
  })

  it('(b) a racer first: its code differs from bob’s, and bob’s request too ends the invite as leaked', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1)
    const bob = await party(net, 'bob', R2, true)
    const mallory = await party(net, 'mallory', R3, true)
    let bobs: Promise<Ran> | null = null
    alice.io.readLine = async () => {
      const mallorys = readOut
      bobs = accept(bob, 'alice', text)
      await until("bob's request", () => net.at(R1).envelopes.size === 2)
      await new Promise((r) => setTimeout(r, 30))
      return mallorys
    }
    const inviting = invite(alice, 'bob')
    const text = await printed(alice)
    const racing = accept(mallory, 'alice', text)
    const a = await inviting
    expect(a.out).toContain(`request ${mallory.address}`)
    expect(a.out).toContain(`second request ${bob.address}: the invite string leaked`)
    expect([a.code, a.err]).toEqual([1, ['bag: leaked: a second request reached this invitation']])
    for (const p of [bob, mallory]) p.io.time.now = END
    const b = await (bobs as unknown as Promise<Ran>)
    const m = await racing
    expect(m.code).toBe(1)
    const [bob6, mallory6] = [b, m].map((r) =>
      (r.out.find((l) => l.startsWith('check digits ')) as string).slice('check digits '.length),
    )
    expect([bob6, mallory6]).toEqual([
      expect.stringMatching(/^\d{3} \d{3}$/),
      expect.stringMatching(/^\d{3} \d{3}$/),
    ])
    expect(bob6).not.toBe(mallory6)
    expect([...files(alice), ...files(bob), ...files(mallory)]).toEqual([null, null, null, null, null, null])
    expect([roots(net, R1, alice), roots(net, R2, bob), roots(net, R3, mallory)]).toEqual([null, null, null])
  })

  it('(c) with --for bob, the racer is refused not-for with no prompt, and bob then pairs', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1, true)
    const bob = await party(net, 'bob', R2, true)
    const mallory = await party(net, 'mallory', R3, true)
    const inviting = invite(alice, 'bob', '--for', bob.address)
    const text = await printed(alice)
    const racing = accept(mallory, 'alice', text)
    await until('the refusal', () => alice.io.stdout.includes(`refused ${mallory.address} not-for`))
    expect(alice.io.asked).toEqual([])
    const [a, b] = await Promise.all([inviting, accept(bob, 'alice', text)])
    expect([a.code, b.code, a.out.at(-1)]).toEqual([0, 0, `paired bob ${bob.address}`])
    expect(a.out.filter((l) => l.startsWith('request '))).toEqual([`request ${bob.address}`])
    mallory.io.time.now = END
    expect((await racing).code).toBe(1)
    expect(files(mallory)).toEqual([null, null])
    expect(roots(net, R1, alice)).toEqual([bob.address])
  })

  it('(d) the racer alone, and the inviter stops typing: nothing is written', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1, false)
    const mallory = await party(net, 'mallory', R3, true)
    const inviting = invite(alice, 'bob')
    const racing = accept(mallory, 'alice', await printed(alice))
    expect((await inviting).err).toEqual(['bag: declined: nothing was written'])
    mallory.io.time.now = END
    expect((await racing).code).toBe(1)
    expect([...files(alice), ...files(mallory), roots(net, R1, alice), roots(net, R3, mallory)]).toEqual([
      null,
      null,
      null,
      null,
      null,
      null,
    ])
  })
})

describe('a name the book holds: the rule of the MCP tools', () => {
  /** Writes the name book of `p`: `name` is `address`. */
  const holds = (p: Party, name: string, address: string): void => {
    const names = { [name]: { address, added_at: 1 } }
    writeFileSync(join(p.dir, 'names.json'), JSON.stringify({ version: 1, names }))
  }
  const refused = (name: string, address: string): string =>
    `bag: name-exists: ${name} is ${address}: pair under another name, pass that address as --for to pair the same peer again, or change it with ac name`

  it('stops both commands at their first step, naming the entry: no code, no claim, no question, no network', async () => {
    const net = new Network()
    net.pair = true
    let claims = 0
    const claim = net.pairClaim.bind(net)
    net.pairClaim = (url, nameplate) => {
      claims++
      return claim(url, nameplate)
    }
    const alice = await party(net, 'alice', R1)
    const bob = await party(net, 'bob', R2)
    const carol = await party(net, 'carol', R3)
    holds(alice, 'bob', carol.address)
    const book = files(alice)
    const code = `472-${WORDS[0]}-${WORDS[1]}-${WORDS[2]}`
    // --for with another address is no way round the book.
    for (const more of [[], ['--for', bob.address]]) {
      const a = await invite(alice, 'bob', ...more)
      const b = await accept(alice, 'bob', code, ...more)
      for (const r of [a, b]) {
        expect([r.code, r.out, r.err]).toEqual([1, [], [refused('bob', carol.address)]])
      }
    }
    expect([net.log, net.relays.size, net.plates.size, claims, alice.io.asked, files(alice)]).toEqual([
      [],
      0,
      0,
      0,
      [],
      book,
    ])
  })

  it('--for says it is the same peer: a re-pair under the held names pairs both ways and changes no entry', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1, true)
    const bob = await party(net, 'bob', R2, true)
    holds(alice, 'bob', bob.address)
    holds(bob, 'alice', alice.address)
    const inviting = invite(alice, 'bob', '--for', bob.address)
    const text = await printed(alice)
    const [a, b] = await Promise.all([inviting, accept(bob, 'alice', text, '--for', alice.address)])
    expect([a.code, b.code, a.err, b.err]).toEqual([0, 0, [], []])
    expect([a.out.at(-1), b.out.at(-1)]).toEqual([
      `paired bob ${bob.address}`,
      `paired alice ${alice.address}`,
    ])
    expect(NameBook.load(alice.dir).list()).toEqual([['bob', { address: bob.address, added_at: 1 }]])
    expect(NameBook.load(bob.dir).list()).toEqual([['alice', { address: alice.address, added_at: 1 }]])
    expect(Object.keys(readTrust(alice.dir))).toEqual([bob.address])
    expect(Object.keys(readTrust(bob.dir))).toEqual([alice.address])
  })

  it("peer accept's --for is the only inviter: another's invitation is not-for, before any request", async () => {
    const { net, alice, bob, inviting, text } = await opened([], [])
    const carol = await party(net, 'carol', R3)
    const b = await accept(bob, 'alice', text, '--for', carol.address)
    expect([b.code, b.err]).toEqual([
      1,
      [`bag: not-for: that invitation is from ${alice.address}, not ${carol.address}: nothing was sent`],
    ])
    expect([bob.io.asked, envelopes(net, R1), ...files(bob)]).toEqual([[], 0, null, null])
    alice.io.time.now = END
    expect((await inviting).code).toBe(1)
  })

  it('a name taken while the inviter waits is refused at the request: no digits asked, nothing written over it', async () => {
    const { net, alice, bob, inviting, text } = await opened([], [true])
    const carol = await party(net, 'carol', R3)
    holds(alice, 'bob', carol.address)
    const accepting = accept(bob, 'alice', text)
    const a = await inviting
    expect([a.code, a.err]).toEqual([1, [refused('bob', carol.address)]])
    expect(a.out.filter((l) => l.startsWith('request '))).toEqual([])
    expect(NameBook.load(alice.dir).resolve('bob')).toBe(carol.address)
    bob.io.time.now = END
    expect((await accepting).code).toBe(1)
  })

  it('a name taken under the claim of a code is refused before the question', async () => {
    const net = new Network()
    net.pair = true
    const alice = await party(net, 'alice', R1)
    const bob = await party(net, 'bob', R1)
    const carol = await party(net, 'carol', R3)
    const inviting = invite(alice, 'bob')
    await until('the code', () => alice.io.stdout.some((l) => l.startsWith('pairing code ')))
    const text = (alice.io.stdout.find((l) => l.startsWith('pairing code ')) as string).slice(13)
    const claim = net.pairClaim.bind(net)
    net.pairClaim = (url, nameplate) => {
      holds(bob, 'alice', carol.address)
      return claim(url, nameplate)
    }
    const b = await accept(bob, 'alice', text)
    expect([b.code, b.err, bob.io.asked]).toEqual([1, [refused('alice', carol.address)], []])
    alice.io.time.now = END
    expect((await inviting).code).toBe(1)
  })

  it('a name taken under the digits stays: the inviter ends name-exists and writes no trust', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1)
    const bob = await party(net, 'bob', R2, true)
    const carol = await party(net, 'carol', R3)
    alice.io.readLine = async () => {
      holds(alice, 'bob', carol.address)
      return readOut
    }
    const inviting = invite(alice, 'bob')
    const [a, b] = await Promise.all([inviting, accept(bob, 'alice', await printed(alice))])
    expect([a.code, a.err, b.code]).toEqual([1, [refused('bob', carol.address)], 0])
    expect(NameBook.load(alice.dir).resolve('bob')).toBe(carol.address)
    expect(readTrust(alice.dir)).toEqual({})
  })

  it('a pairing keeps a name another command wrote while it ran', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1)
    const bob = await party(net, 'bob', R2, true)
    const carol = await party(net, 'carol', R3)
    alice.io.readLine = async () => {
      holds(alice, 'carol', carol.address)
      return readOut
    }
    const inviting = invite(alice, 'bob')
    const [a, b] = await Promise.all([inviting, accept(bob, 'alice', await printed(alice))])
    expect([a.code, b.code, a.err, b.err]).toEqual([0, 0, [], []])
    expect(
      NameBook.load(alice.dir)
        .list()
        .map(([n]) => n),
    ).toEqual(['bob', 'carol'])
  })
})

describe('the trust file: <home>/trust.json, read by inbox beside --trust-root', () => {
  it('is empty when missing, and trust-invalid when it is not one (inbox exits 1 on it)', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1)
    expect(readTrust(alice.dir)).toEqual({})
    const bad = (text: string | null): string => {
      const path = join(alice.dir, 'trust.json')
      if (text === null) mkdirSync(path)
      else writeFileSync(path, text)
      try {
        readTrust(alice.dir)
        return 'read'
      } catch (e) {
        return (e as Error).message.replace(path, '<file>')
      } finally {
        rmSync(path, { recursive: true })
      }
    }
    expect(bad('{')).toMatch(/^trust-invalid: <file> cannot be read as JSON: /)
    expect(bad(null)).toMatch(/^trust-invalid: <file> cannot be read as JSON: EISDIR/)
    for (const text of [
      'null',
      '{"version":2,"roots":{}}',
      '{"version":1,"roots":[]}',
      '{"version":1,"roots":null}',
      '{"version":1,"roots":{"bob":{"added_at":1}}}',
      `{"version":1,"roots":{"${alice.address}":{"added_at":1.5}}}`,
      `{"version":1,"roots":{"${alice.address}":null}}`,
    ]) {
      expect(bad(text)).toBe('trust-invalid: <file> is not a trust file of version 1')
    }
    writeFileSync(join(alice.dir, 'trust.json'), '[]')
    const inbox = await cli(alice.io, 'inbox', '--as', 'alice', '--relay', R1, '--once', '--dir', alice.dir)
    expect([inbox.code, inbox.err[0]]).toEqual([1, expect.stringMatching(/^bag: trust-invalid: /)])
  })
})

describe("the trust file holds domain roots in SPEC.md §7.2's grammar, with no port", () => {
  it('keeps domain:<host> beside addresses, and refuses a ported, uppercase, IP or one-label root on write and read', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1)
    addTrust(alice.dir, 'domain:acme.example', T0)
    addTrust(alice.dir, alice.address, T0 + 1)
    expect(readTrust(alice.dir)).toEqual({
      [alice.address]: { added_at: T0 + 1 },
      'domain:acme.example': { added_at: T0 },
    })
    for (const root of [
      'domain:acme.example:8443',
      'domain:ACME.example',
      'domain:10.0.0.1',
      'domain:acme',
      'acme.example',
    ]) {
      expect(() => addTrust(alice.dir, root, T0)).toThrow(
        /^trust-invalid: .* is not a root a trust file holds$/,
      )
      writeFileSync(
        join(alice.dir, 'trust.json'),
        JSON.stringify({ version: 1, roots: { [root]: { added_at: 1 } } }),
      )
      expect(() => readTrust(alice.dir)).toThrow(/is not a trust file of version 1$/)
    }
  })

  it('peer --trust-domain names the domain in the question and writes domain:<host> at the end, not the address', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1, true)
    const bob = await party(net, 'bob', R2, true)
    const inviting = invite(alice, 'bob', '--trust-domain', 'bob.example')
    const text = await printed(alice)
    const [a, b] = await Promise.all([
      inviting,
      accept(bob, 'alice', text, '--trust-domain', 'alice.example'),
    ])
    expect([a.code, b.code, a.err, b.err]).toEqual([0, 0, [], []])
    expect(a.out).toContain(
      'to pair with it as bob, trusting every agent of bob.example, type the six digits the other side reads you',
    )
    expect([alice.io.asked, bob.io.asked]).toEqual([
      [],
      ['pair with it as alice, trusting every agent of alice.example?'],
    ])
    expect(Object.keys(readTrust(alice.dir))).toEqual(['domain:bob.example'])
    expect(Object.keys(readTrust(bob.dir))).toEqual(['domain:alice.example'])
  })

  it('refuses a --trust-domain that is not a host, before any network', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1)
    for (const host of ['acme.example:8443', 'Acme.example', 'acme', 'domain:acme.example']) {
      expect((await invite(alice, 'bob', '--trust-domain', host)).err[0]).toBe(
        `bag: usage: --trust-domain ${JSON.stringify(host)} is not a host (a DNS name, no port)`,
      )
    }
    expect(net.relays.size).toBe(0)
  })
})

describe('peer: its arguments, its records and its refusals', () => {
  it('refuses a missing verb, a bad --name, --for or invite string as usage, before any network', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1)
    expect((await cli(alice.io, 'peer')).err[0]).toBe(
      'bag: usage: peer invite ... | peer accept ... <code or invite>',
    )
    expect((await cli(alice.io, 'peer', 'pair')).code).toBe(1)
    expect((await invite(alice, 'Bob')).err[0]).toMatch(/^bag: usage: --name "Bob" is not a name/)
    expect((await invite(alice, 'bob', '--for', 'bob')).err[0]).toBe('bag: usage: --for takes an address')
    const good = inviteText(alice.address, alice.address, R1, '0'.repeat(32))
    expect((await accept(alice, 'bob', good, '--for', 'bob')).err[0]).toBe(
      'bag: usage: --for takes an address',
    )
    const list = (...l: unknown[]) => `ac-peer1:${Buffer.from(JSON.stringify(l)).toString('base64url')}`
    for (const text of ['nonsense', good.replace('ac-peer1:', 'ac-peer2:')]) {
      expect((await accept(alice, 'bob', text)).err[0]).toBe(
        'bag: bad-code: neither a code nor an invite string',
      )
    }
    for (const text of [
      'ac-peer1:nonsense',
      list('ac/peer-invite/2', alice.address, alice.address, R1, '0'.repeat(32)),
      list('ac/peer-invite/1', 'alice', alice.address, R1, '0'.repeat(32)),
      list('ac/peer-invite/1', alice.address, 'i', R1, '0'.repeat(32)),
      list('ac/peer-invite/1', alice.address, alice.address, R1, '0'.repeat(31)),
      list('ac/peer-invite/1', alice.address, alice.address, 'ftp://x', '0'.repeat(32)),
    ]) {
      expect((await accept(alice, 'bob', text)).err[0]).toBe(
        'bag: bad-invite: not a string that peer invite printed',
      )
    }
    expect(net.relays.size).toBe(0)
  })

  it('keeps a current null-sealing address record, an accept-from of ["*"] and a held name; a relay holding a newer record keeps it', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1, true)
    const bob = await party(net, 'bob', R2, true)
    const out = join(alice.dir, 'a.json')
    await cli(alice.io, 'record', 'address', 'alice', '--relay', R1, '--out', out, '--dir', alice.dir)
    await cli(alice.io, 'publish', R1, out)
    const wild = join(bob.dir, 'f.json')
    await cli(
      bob.io,
      'record',
      'accept-from',
      'bob',
      '--root',
      '*',
      '--max-bytes',
      '9000',
      '--ttl',
      '60',
      '--out',
      wild,
      '--dir',
      bob.dir,
    )
    await cli(bob.io, 'publish', R2, wild)
    // R1 already holds a record of bob's newer than the one bob will publish at R2: R1 keeps it (stale-record).
    const later = testIo(net)
    later.time.now = T0 + 100
    const newer = join(bob.dir, 'b.json')
    await cli(
      later,
      'record',
      'address',
      'bob',
      '--relay',
      R2,
      '--sealing-key',
      '--out',
      newer,
      '--dir',
      bob.dir,
    )
    await cli(later, 'publish', R1, newer)
    await cli(bob.io, 'name', 'add', 'alice', alice.address, '--dir', bob.dir)
    const before = net.log.length
    const inviting = invite(alice, 'bob')
    const [a, b] = await Promise.all([
      inviting,
      accept(bob, 'alice', await printed(alice), '--for', alice.address),
    ])
    expect([a.code, b.code]).toEqual([0, 0])
    // alice's held record names no sealing key, so it is not re-signed: her epoch is only a key record at R1, and bob
    // shares her address record and her key record at R2.
    expect(net.log.slice(before).filter((l) => l.endsWith(alice.address))).toEqual([
      `${R1} key ${alice.address}`,
      `${R1} accept-from ${alice.address}`,
      `${R2} address ${alice.address}`,
      `${R2} key ${alice.address}`,
    ])
    expect(roots(net, R2, bob)).toEqual(['*'])
    const kept = parseRecord(net.record(R2, bob.address, 'accept-from') as string) as AcceptFromRecord
    expect([kept.max_bytes, kept.ttl]).toEqual([9000, 60])
    expect((parseRecord(net.record(R1, bob.address, 'address') as string) as AddressRecord).iat).toBe(
      T0 + 100,
    )
  })

  it('reads the newest record across relays, and only the signer and kind it asked for', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1, true)
    const bob = await party(net, 'bob', R2, true, true, true)
    const file = (io: TestIo, f: string, ...args: string[]) =>
      cli(io, 'record', ...args, '--out', join(alice.dir, f), '--dir', alice.dir)
    // alice lives at R1 and R3; R3 holds an older accept-from than R1.
    await file(alice.io, 'a.json', 'address', 'alice', '--relay', R1, '--relay', R3)
    await cli(alice.io, 'publish', R1, join(alice.dir, 'a.json'))
    await file(
      alice.io,
      'old.json',
      'accept-from',
      'alice',
      '--root',
      bob.address,
      '--max-bytes',
      '100',
      '--ttl',
      '1',
    )
    await cli(alice.io, 'publish', R3, join(alice.dir, 'old.json'))
    const later = testIo(net)
    later.time.now = T0 + 5
    await file(
      later,
      'new.json',
      'accept-from',
      'alice',
      '--root',
      alice.address,
      '--max-bytes',
      '200',
      '--ttl',
      '2',
    )
    await cli(later, 'publish', R1, join(alice.dir, 'new.json'))
    const inviting = invite(alice, 'bob')
    const text = await printed(alice)
    // A relay that answers another key's record, or another kind, for I's address record: no invitation.
    const [, i] = fields(text)
    const held = net.at(R1).records
    const own = held.get(`${i} address`) as Uint8Array
    for (const other of [`${alice.address} address`, `${i} accept-from`]) {
      held.set(`${i} address`, held.get(other) as Uint8Array)
      expect((await accept(bob, 'alice', text)).err[0]).toMatch(/^bag: invite-expired: /)
    }
    held.set(`${i} address`, own)
    const [a, b] = await Promise.all([inviting, accept(bob, 'alice', text)])
    expect([a.code, b.code]).toEqual([0, 0])
    for (const url of [R1, R3]) {
      const r = parseRecord(net.record(url, alice.address, 'accept-from') as string) as AcceptFromRecord
      expect([r.roots, r.max_bytes, r.ttl]).toEqual([[alice.address, bob.address], 200, 2])
    }
  })

  it('drops a request that is not one, or not an envelope at all, unsaid: only the clock ends it', async () => {
    for (const bad of ['type', 'garbage'] as const) {
      const net = new Network()
      const alice = await party(net, 'alice', R1)
      const bob = await party(net, 'bob', R2)
      const inviting = invite(alice, 'bob')
      const [, i] = fields(await printed(alice))
      const relay = net.at(R1)
      if (bad === 'type') {
        const out = join(bob.dir, 'b.json')
        await cli(
          bob.io,
          'record',
          'address',
          'bob',
          '--relay',
          R2,
          '--sealing-key',
          '--out',
          out,
          '--dir',
          bob.dir,
        )
        const body = JSON.stringify({ record: readFileSync(out, 'utf8').trim(), mac: '00' })
        const send = ['--to', i, '--relay', R1, '--type', 'chat.v1', '--body', body, '--allow-private-relays']
        expect((await cli(bob.io, 'send', '--as', 'bob', ...send, '--dir', bob.dir)).code).toBe(0)
      } else {
        relay.box(i).push({ cursor: 1, bytes: new TextEncoder().encode('{}') })
        for (const s of relay.subs) s.wake()
      }
      await new Promise((r) => setTimeout(r, 30))
      alice.io.time.now = END
      const a = await inviting
      expect([a.code, a.out.filter((l) => l.startsWith('refused '))]).toEqual([1, []])
      expect(alice.io.asked).toEqual([])
    }
  })

  it("pairs when the inviter's relay has lost its address record: the acceptor shares none", async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1)
    const bob = await party(net, 'bob', R2, true)
    alice.io.readLine = async () => {
      net.at(R1).records.delete(`${alice.address} address`)
      return readOut
    }
    const inviting = invite(alice, 'bob')
    const [a, b] = await Promise.all([inviting, accept(bob, 'alice', await printed(alice))])
    expect([a.code, b.code]).toEqual([0, 0])
    expect(net.record(R2, alice.address, 'address')).toBeNull()
    // Her key record is still at R1, and the acceptor shares it.
    expect(net.record(R2, alice.address, 'key')).not.toBeNull()
  })

  it('ends the invite with the subscription error, and leaves I to lapse', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1)
    const inviting = invite(alice, 'bob')
    const [, i] = fields(await printed(alice))
    net.at(R1).failSubscribe = new RelayError('not-authorized', 401, null, 'refused')
    for (const s of net.at(R1).subs) s.wake()
    expect((await inviting).err[0]).toMatch(/^bag: not-authorized: /)
    expect(roots(net, R1, i)).toEqual(['*'])
  })

  it('takes its root out of its accept-from again when the acceptor never admits it (no-answer)', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1)
    const bob = await party(net, 'bob', R2, true)
    alice.io.readLine = async () => {
      net.at(R2).failRecordPublish.set(R2, new RelayError('body-too-large', 413, null, 'no'))
      return readOut
    }
    const inviting = invite(alice, 'bob')
    const b = await accept(bob, 'alice', await printed(alice))
    expect([b.code, b.err[0]]).toEqual([1, expect.stringMatching(/^bag: body-too-large: /)])
    net.at(R2).failRecordFetch.set(R2, new RelayError(null, 0, null, 'unreachable'))
    alice.io.time.now = END
    const a = await inviting
    expect([a.code, a.err]).toEqual([
      1,
      [`bag: no-answer: ${bob.address} did not admit this identity before the invitation ended`],
    ])
    expect([...files(alice), ...files(bob)]).toEqual([null, null, null, null])
    expect(roots(net, R1, alice)).toEqual([alice.address])
  })

  it('ends the invite when a relay refuses the shared record or the epoch, and re-signs an expired address record as null', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1)
    const bob = await party(net, 'bob', R2, true)
    const out = join(alice.dir, 'a.json')
    const early = testIo(net)
    early.time.now = T0 - 90_000
    await cli(
      early,
      'record',
      'address',
      'alice',
      '--relay',
      R1,
      '--revoke',
      bob.address,
      '--out',
      out,
      '--dir',
      alice.dir,
    )
    await cli(early, 'publish', R1, out)
    net.at(R1).failRecordPublish.set(R1, new RelayError('body-too-large', 413, null, 'no'))
    expect((await invite(alice, 'bob')).err[0]).toMatch(/^bag: body-too-large: /)
    net.at(R1).failRecordPublish.clear()
    alice.io.readLine = async () => {
      net.at(R1).failRecordPublish.set(R1, new RelayError('body-too-large', 413, null, 'no'))
      return readOut
    }
    const inviting = invite(alice, 'bob')
    const accepting = accept(bob, 'alice', await printed(alice))
    expect((await inviting).err[0]).toMatch(/^bag: body-too-large: /)
    bob.io.time.now = END
    expect((await accepting).code).toBe(1)
    const held = parseRecord(net.record(R1, alice.address, 'address') as string) as AddressRecord
    // The expired record named no sealing key: it is re-signed with none, its revocations kept.
    expect([held.iat, held.revoked, held.sealing_key]).toEqual([T0, [bob.address], null])
    expect([...files(alice), roots(net, R1, alice)]).toEqual([null, null, null])
  })
})

describe('forward secrecy: the key record a pairing carries (currentKey)', () => {
  /** A pairing of `inviter` and `acceptor`, whose inviter has not invited before in this test. */
  async function pairing(inviter: Party, acceptor: Party, as: string, called: string) {
    const inviting = invite(inviter, as)
    return Promise.all([inviting, accept(acceptor, called, await printed(inviter))])
  }
  /** The four fields of the invite string a run printed. */
  const printedFields = (ran: Ran) =>
    fields((ran.out.find((l) => l.startsWith('invite ')) as string).slice('invite '.length))
  const at = (seconds: number, ...ps: Party[]): void => {
    for (const p of ps) p.io.time.now = T0 + seconds
  }

  it('re-signs the live epoch it holds: no new epoch is published, and the key record is the very bytes published', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1, true)
    const bob = await party(net, 'bob', R2, true, true)
    const carol = await party(net, 'carol', R3, true)
    const [a1, b1] = await pairing(alice, bob, 'bob', 'alice')
    expect([a1.code, b1.code]).toEqual([0, 0])
    expect(b1.out.slice(0, 2)).toEqual(rotated(bob))
    const epoch = net.record(R2, bob.address, 'key') as string
    // Three hours later bob's newest epoch is not 12 hours old: bob accepts carol's invite with that epoch's key record.
    at(3 * 3600, bob, carol)
    const before = net.log.length
    const [c2, b2] = await pairing(carol, bob, 'bob', 'carol')
    expect([c2.code, b2.code, c2.err, b2.err]).toEqual([0, 0, [], []])
    expect(b2.out.filter((l) => l.startsWith('published '))).toEqual([])
    expect(b2.out[0]).toBe(`inviter ${carol.address} at ${R3}`)
    expect(c2.out.slice(0, 2)).toEqual(rotated(carol))
    expect(net.record(R2, bob.address, 'key')).toBe(epoch)
    expect(net.record(R3, bob.address, 'key')).toBe(epoch)
    expect(net.log.slice(before).filter((l) => l.endsWith(bob.address) && l.startsWith(R2))).toEqual([
      `${R2} accept-from ${bob.address}`,
    ])
    // The code carol types is over that epoch's sealing key.
    const [inviter, i, , s] = printedFields(c2)
    const six = (b2.out.find((l) => l.startsWith('check digits ')) as string).slice('check digits '.length)
    expect(six).toBe(code(inviter, i, bob.address, rec<KeyRecord>(net, R2, bob, 'key').sealing_key, s))
  })

  it('continues the copy in the home when the relay lost the address record, and moves the copy on', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1, true)
    const bob = await party(net, 'bob', R2, true, true)
    const carol = await party(net, 'carol', R3, true)
    await pairing(alice, bob, 'bob', 'alice')
    at(3 * 3600, bob, carol)
    net.at(R2).records.delete(`${bob.address} address`)
    const [c2, b2] = await pairing(carol, bob, 'bob', 'carol')
    expect([c2.code, b2.code, c2.err, b2.err]).toEqual([0, 0, [], []])
    const held = rec<AddressRecord>(net, R2, bob, 'address')
    expect(held.iat).toBe(T0 + 3 * 3600)
    expect(addressCopy(bob.dir, 'bob', bob.address)?.iat).toBe(held.iat)
  })

  it('rotates when the newest epoch is 12 hours old: a new key record first, and the held null address record is kept', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1, true)
    const bob = await party(net, 'bob', R2, true, true)
    const carol = await party(net, 'carol', R3, true)
    await pairing(alice, bob, 'bob', 'alice')
    const old = parseRecord(net.record(R2, bob.address, 'key') as string) as KeyRecord
    const address = net.record(R2, bob.address, 'address')
    at(12 * 3600, bob, carol)
    const before = net.log.length
    const [c2, b2] = await pairing(carol, bob, 'bob', 'carol')
    expect([c2.code, b2.code, c2.err, b2.err]).toEqual([0, 0, [], []])
    // Only the key record is published: the held address record has no sealing key, so it is not re-signed.
    expect(b2.out.slice(0, 2)).toEqual([
      `published key ${bob.address} ${R2}`,
      `inviter ${carol.address} at ${R3}`,
    ])
    const fresh = parseRecord(net.record(R2, bob.address, 'key') as string) as KeyRecord
    expect([fresh.iat, fresh.sealing_key === old.sealing_key]).toEqual([T0 + 12 * 3600, false])
    expect(net.record(R3, bob.address, 'key')).toBe(net.record(R2, bob.address, 'key'))
    expect(net.record(R2, bob.address, 'address')).toBe(address)
    expect(net.log.slice(before).filter((l) => l.endsWith(bob.address) && l.startsWith(R2))).toEqual([
      `${R2} key ${bob.address}`,
      `${R2} accept-from ${bob.address}`,
    ])
    const [inviter, i, , s] = printedFields(c2)
    const six = (b2.out.find((l) => l.startsWith('check digits ')) as string).slice('check digits '.length)
    expect(six).toBe(code(inviter, i, bob.address, fresh.sealing_key, s))
    expect(six).not.toBe(code(inviter, i, bob.address, old.sealing_key, s))
  })

  it('publishes the key record and re-signs a held address record that names a sealing key, keeping its revocations', async () => {
    const net = new Network()
    const alice = await party(net, 'alice', R1, true)
    const bob = await party(net, 'bob', R2, true)
    const early = testIo(net)
    early.time.now = T0 - 10
    const out = join(alice.dir, 'a.json')
    const own = ['--relay', R1, '--sealing-key', '--revoke', bob.address, '--out', out, '--dir', alice.dir]
    expect((await cli(early, 'record', 'address', 'alice', ...own)).code).toBe(0)
    expect((await cli(early, 'publish', R1, out)).code).toBe(0)
    const [a, b] = await pairing(alice, bob, 'bob', 'alice')
    expect([a.code, b.code, a.err, b.err]).toEqual([0, 0, [], []])
    expect(a.out.slice(0, 2)).toEqual(rotated(alice))
    const held = rec<AddressRecord>(net, R1, alice, 'address')
    expect([held.sealing_key, held.iat, held.revoked, held.relays]).toEqual([null, T0, [bob.address], [R1]])
  })
})

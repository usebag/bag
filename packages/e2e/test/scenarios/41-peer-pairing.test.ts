import { spawn } from 'node:child_process'
import { readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  type AcceptFromRecord,
  type AcRecord,
  type AddressRecord,
  type KeyRecord,
  parseRecord,
  verifyRecord,
} from '@usebag/core'
import { createRelayClient, inviteOf, pairingCode, systemClock, systemRng } from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  CLI_MAIN,
  type CliRun,
  cliProcess,
  extraRelay,
  homeSecrets,
  now,
  REPO,
  type RelayHandle,
  relayEvents,
  until,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// e2e scenario 41 (end to end): the peer pairing ceremony through the CLI in child processes against two
// release relays and a third, R0, the shared rendezvous both sides name with --rendezvous.
// alice (home 1, R1) runs `peer invite`, which opens a nameplate at R0
// and prints the pairing code; bob (home 2, R2) runs `peer accept` with the code, claimed at R0; I is at R0 too, the one
// relay a pairing cannot go without (spec/SPEC.md Appendix B 110); the test reads the six digits from bob's stdout,
// answers y on his terminal, and types them on alice's, which never prints them. The CLI
// refuses `no-tty` when stdin is a pipe (io.isTty is process.stdin.isTTY), so each child's stdin is a pseudo-terminal:
// Python's pty module (the gate already needs Python 3.13) opens one, gives its slave end to the child as fd 0 and
// copies the test's lines into its master end; the child's stdout and stderr stay the pipes the test reads. No CLI
// source and no environment variable is involved: the CLI sees a real terminal on stdin. L1's "both exit 0" is read
// as each child ending by itself within 5 s of its `paired` line; one that does not is recorded, given a Ctrl-D (EOF)
// so that every other clause is still measured, and fails the test at its end, after the MEASURE line.
//
// Forward secrecy (pairing ruling of 2026-10-29): each side pairs with its current key record, so
// its first line is rotateEpoch's. The setup publishes address records that still name a sealing key (a record made
// with --sealing-key), so each side's epoch 1 is a key record and the address record re-signed with none; the code is
// over the key record's sealing key; after the pairing neither address record names a sealing key, and each side's
// key record is served at the other side's relay.

const outputs: string[] = []
const cli = (...args: string[]): Promise<CliRun> => cliProcess(args, outputs)
const lines = (text: string): string[] => text.split('\n').filter((l) => l !== '')

/**
 * Runs argv[1:] with its stdin on a new pseudo-terminal: this process's stdin is copied to the master end, whatever
 * the terminal echoes is drained and dropped, stdout and stderr are inherited. SIGTERM ends the child; the exit code is
 * the child's (128 + n for a signal n).
 */
const PTY = `
import os, pty, select, signal, subprocess, sys
master, slave = pty.openpty()
child = subprocess.Popen(sys.argv[1:], stdin=slave)
os.close(slave)
signal.signal(signal.SIGTERM, lambda *_: child.terminate())
fds = [0, master]
while child.poll() is None:
    for fd in select.select(fds, [], [], 0.05)[0]:
        try:
            data = os.read(fd, 4096)
        except OSError:
            data = b''
        if fd == 0 and data:
            os.write(master, data)
        elif not data:
            fds.remove(fd)
code = child.returncode
sys.exit(code if code >= 0 else 128 - code)
`

/** A CLI process whose stdin is a terminal: its stdout lines, its raw stderr, a line typed at it, its exit. */
interface Terminal {
  out(): string[]
  err(): string
  type(line: string): void
  /** Ctrl-D at the terminal: EOF on the child's stdin. */
  eof(): void
  /** When a stdout line starting with `paired ` was first read (ms since the epoch), or null. */
  pairedAt(): number | null
  readonly exit: Promise<number>
}

function terminal(args: readonly string[]): Terminal {
  const env: NodeJS.ProcessEnv = { ...process.env }
  delete env.AC_HOME
  // The CLI keeps one telemetry store per machine, in HOME/.bag: off here, so no scenario counts into it or marks it.
  env.DO_NOT_TRACK = '1'
  const child = spawn('python3', ['-I', '-c', PTY, process.execPath, CLI_MAIN, ...args], { cwd: REPO, env })
  let out = ''
  let err = ''
  let paired: number | null = null
  child.stdout.on('data', (d: Buffer) => {
    out += d.toString()
    if (paired === null && lines(out).some((l) => l.startsWith('paired '))) paired = Date.now()
  })
  child.stderr.on('data', (d: Buffer) => {
    err += d.toString()
  })
  child.stdin.on('error', () => {})
  const exit = new Promise<number>((resolve) => {
    child.on('close', (code, signal) => {
      outputs.push(out, err)
      resolve(code ?? (signal === null ? -1 : 128))
    })
  })
  onTestFinished(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM')
  })
  return {
    out: () => lines(out),
    err: () => err,
    type: (line) => child.stdin.write(`${line}\n`),
    eof: () => child.stdin.write('\x04'),
    pairedAt: () => paired,
    exit,
  }
}

/** The first stdout line of `t` that starts with `prefix`, once it is there. */
async function line(t: Terminal, prefix: string): Promise<string> {
  await until(`a line "${prefix}..."`, () => t.out().some((l) => l.startsWith(prefix)), 30_000)
  return t.out().find((l) => l.startsWith(prefix)) as string
}

/** Whether `t` exits within `ms`. */
async function exitsWithin(t: Terminal, ms: number): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined
  const late = new Promise<false>((resolve) => {
    timer = setTimeout(() => resolve(false), ms)
  })
  try {
    return await Promise.race([t.exit.then(() => true), late])
  } finally {
    clearTimeout(timer)
  }
}

/** The exit code of `t`; fails after 30 s naming what it printed (addresses and digits; the code, whose words make S, as `pairing code <S>`). */
async function exited(t: Terminal, what: string): Promise<number> {
  let timer: NodeJS.Timeout | undefined
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(
        new Error(
          `${what} did not exit within 30 s; stdout ${JSON.stringify(t.out().map((l) => (l.startsWith('pairing code ') ? 'pairing code <S>' : l)))}, stderr ${JSON.stringify(t.err())}`,
        ),
      )
    }, 30_000)
  })
  try {
    return await Promise.race([t.exit, late])
  } finally {
    clearTimeout(timer)
  }
}

/** The record of `kind` the relay serves for `address`, verified; null for a 404. */
async function served(url: string, address: string, kind: string): Promise<AcRecord | null> {
  const res = await fetch(`${url}/v0/fetch/record/${address}/${kind}`)
  if (res.status === 404) {
    await res.arrayBuffer()
    return null
  }
  expect(res.status, `${kind} of ${address}`).toBe(200)
  return verifyRecord(parseRecord(new Uint8Array(await res.arrayBuffer())), now())
}
const roots = async (url: string, address: string): Promise<readonly string[] | undefined> =>
  ((await served(url, address, 'accept-from')) as AcceptFromRecord | null)?.roots

/** The records a relay logged as published, `<kind> <signer>`, in order. */
const published = (relay: RelayHandle): string[] =>
  relayEvents(relay)
    .filter((e) => e.event === 'publish-record')
    .map((e) => `${e.kind} ${e.signer}`)

/** A home's names.json or trust.json, parsed. */
const json = (home: string, file: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(home, file), 'utf8')) as Record<string, unknown>

describe('e2e scenario 41: the peer pairing ceremony end to end', () => {
  it("(41) the peer pairing through the CLI in child processes on two release relays and a shared rendezvous: peer invite prints a pairing code, peer accept takes it, and each answers y once on a terminal, and both print paired with equal six-digit codes; each relay serves its side's accept-from naming the other with a newer iat; names.json and trust.json name the other in each home; send --to <name> is accepted by the other's inbox with no --trust-root both ways; the test publishes no record; 2 prompts; no key material in any output", async () => {
    // It reads its relays' stderr (the setup publishes logged), so it spawns its relays even under AC_RELAY_URL.
    const w = await withSpawnedRelays(() => world('s41'))
    const [r2, r0] = [await extraRelay(w, 'r2', []), await extraRelay(w, 'r0', [])]
    const [R1, R2, R0] = [w.url, r2.url, r0.url]
    const [home1, home2, home3] = ['home-1', 'home-2', 'home-3'].map((h) => join(w.dir, h)) as [
      string,
      string,
      string,
    ]
    const made = await Promise.all([
      cli('keygen', 'alice', '--dir', home1),
      cli('keygen', 'bob', '--dir', home2),
      cli('keygen', 'carol', '--dir', home3),
    ])
    for (const m of made) expect([m.code, m.err]).toEqual([0, []])
    const [alice, bob, carol] = made.map((m) => m.out[0] as string) as [string, string, string]

    // Each identity's once-only steps (an address record and an accept-from, published at its own
    // relay), so that the accept-from each side re-signs has a "before": carol, a contact each already accepts.
    for (const [name, home, relay] of [
      ['alice', home1, R1],
      ['bob', home2, R2],
    ] as const) {
      const address = join(home, `${name}.address.json`)
      const own = ['--relay', relay, '--sealing-key', '--ttl', '3600', '--dir', home, '--out', address]
      expect(await cli('record', 'address', name, ...own)).toEqual({ code: 0, out: [], err: [] })
      const acc = await cli(
        'record',
        'accept-from',
        name,
        '--root',
        carol,
        ...['--max-bytes', '65536', '--ttl', '86400', '--dir', home],
      )
      expect([acc.code, acc.err]).toEqual([0, []])
      const accept = join(home, `${name}.accept.json`)
      writeFileSync(accept, `${acc.out[0]}\n`)
      expect((await cli('publish', relay, address)).code).toBe(0)
      expect((await cli('publish', relay, accept)).code).toBe(0)
    }
    const before = {
      alice: (await served(R1, alice, 'accept-from')) as AcceptFromRecord,
      bob: (await served(R2, bob, 'accept-from')) as AcceptFromRecord,
    }
    expect([before.alice.roots, before.bob.roots]).toEqual([[carol], [carol]])
    await until(
      'the setup publishes logged',
      () => published(w.relay).length === 2 && published(r2).length === 2,
    )
    const setup = [published(w.relay).length, published(r2).length]
    // The epoch each side publishes at the start of its command re-signs the address record, whose iat is the second it
    // was made in: a relay refuses a record not newer (409), so the ceremony starts a clock second after the setup.
    await new Promise((resolve) => setTimeout(resolve, 1_100))

    // The control: with stdin a pipe, peer invite refuses no-tty before any network call.
    const piped = await cli('peer', 'invite', '--as', 'alice', '--relay', R1, '--name', 'bob', '--dir', home1)
    expect(piped).toEqual({
      code: 1,
      out: [],
      err: ["bag: no-tty: peer invite is a person's act, confirmed on a terminal; stdin is not one"],
    })

    // The ceremony: one command a side, bob's y, and alice typing the digits bob read out.
    const started = Date.now()
    const inviter = terminal([
      ...['peer', 'invite', '--as', 'alice', '--relay', R1, '--rendezvous', R0],
      ...['--name', 'bob', '--dir', home1],
    ])
    const text = (await line(inviter, 'pairing code ')).slice('pairing code '.length)
    expect(text).toMatch(/^[1-9][0-9]{2,8}(-[a-z]+){3}$/)
    // The invitation the code names, as bob's edge reads it: claimed at R0, S from the words.
    const ports = { client: createRelayClient(), clock: systemClock, rng: systemRng, pollMs: 50 }
    const invite = await inviteOf(ports, R0, text)
    expect([invite.inviter, invite.relay]).toEqual([alice, R0])
    const acceptor = terminal([
      ...['peer', 'accept', '--as', 'bob', '--relay', R2, '--rendezvous', R0, '--allow-private-relays'],
      ...['--name', 'alice', '--dir', home2, text],
    ])
    const bobCode = (await line(acceptor, 'check digits ')).slice('check digits '.length)
    await until("bob's question", () => acceptor.err().includes('pair with it as alice? [y/N] '), 30_000)
    acceptor.type('y')
    expect(await line(inviter, 'request ')).toBe(`request ${bob}`)
    expect(bobCode).toMatch(/^\d{3} \d{3}$/)
    await line(inviter, 'to pair with it as bob, ')
    inviter.type(bobCode)
    await until('both paired', () => inviter.pairedAt() !== null && acceptor.pairedAt() !== null, 30_000)
    const wall = Math.max(inviter.pairedAt() as number, acceptor.pairedAt() as number) - started
    // L1: both exit once paired. A child still running 5 s after its `paired` line is recorded and asserted at the
    // end; it is then given a Ctrl-D, so that every other clause of L1 is still measured.
    const ownExit = await Promise.all([inviter, acceptor].map((t) => exitsWithin(t, 5_000)))
    for (const [k, t] of [inviter, acceptor].entries()) if (!ownExit[k]) t.eof()
    const [a, b] = await Promise.all([exited(inviter, 'peer invite'), exited(acceptor, 'peer accept')])

    expect([a, b]).toEqual([0, 0])
    expect(inviter.out()).toEqual([
      `published key ${alice} ${R1}`,
      `published address ${alice} ${R1}`,
      `pairing code ${text}`,
      expect.stringMatching(
        /^one request until \S+; the other side reads you six digits, and you type them here$/,
      ),
      `request ${bob}`,
      'to pair with it as bob, type the six digits the other side reads you',
      `paired bob ${bob}`,
    ])
    expect(acceptor.out()).toEqual([
      `published key ${bob} ${R2}`,
      `published address ${bob} ${R2}`,
      `inviter ${alice} at ${R0}`,
      `check digits ${bobCode}`,
      'read them out now, not where the code was sent, before you answer: that is the security check',
      expect.stringMatching(/^requested; waiting until \S+ for the inviter's answer$/),
      `paired alice ${alice}`,
    ])
    // The prompts: bob's one question, on stderr (io.confirm writes it there), none on stdout; alice is asked no y.
    const prompts = [inviter, acceptor].map((t) => t.err().split('[y/N] ').length - 1) as [number, number]
    expect(prompts).toEqual([0, 1])
    expect([...inviter.out(), ...acceptor.out()].some((l) => l.includes('[y/N]'))).toBe(false)
    expect(wall).toBeLessThan(60_000)

    // The code is the one the pairing defines, over bob's sealing key as his key record at R2 names it.
    const keyOf = {
      alice: (await served(R1, alice, 'key')) as KeyRecord,
      bob: (await served(R2, bob, 'key')) as KeyRecord,
    }
    expect([keyOf.alice.key, keyOf.bob.key]).toEqual([alice, bob])
    expect(pairingCode(invite, bob, keyOf.bob.sealing_key)).toBe(bobCode)

    // The relays: each side's accept-from names the other beside carol, newer than before; I's is left to lapse.
    const after = {
      alice: (await served(R1, alice, 'accept-from')) as AcceptFromRecord,
      bob: (await served(R2, bob, 'accept-from')) as AcceptFromRecord,
    }
    expect([...after.alice.roots].sort()).toEqual([carol, bob].sort())
    expect([...after.bob.roots].sort()).toEqual([carol, alice].sort())
    expect([after.alice.iat > before.alice.iat, after.bob.iat > before.bob.iat]).toEqual([true, true])
    expect(await roots(R0, invite.i)).toEqual(['*'])
    expect(((await served(R0, invite.i, 'address')) as AddressRecord).ttl).toBe(600)
    // Each side's address record is served at the other's relay, as signed by its owner.
    expect(((await served(R1, bob, 'address')) as AddressRecord).relays).toEqual([R2])
    expect(((await served(R2, alice, 'address')) as AddressRecord).relays).toEqual([R1])
    // After the pairing neither address record names a sealing key, wherever it is served; each side's key record is
    // served at the other side's relay, the record its owner published at its own.
    for (const [url, who] of [
      [R1, alice],
      [R2, bob],
      [R1, bob],
      [R2, alice],
    ] as const) {
      expect(((await served(url, who, 'address')) as AddressRecord).sealing_key, `${url} ${who}`).toBeNull()
    }
    expect(await served(R2, alice, 'key')).toEqual(keyOf.alice)
    expect(await served(R1, bob, 'key')).toEqual(keyOf.bob)

    // The records the ceremony published, from the relays' logs: every one by alice, bob or I (the children); none by
    // the test, which only fetched. R0, which neither side lists, holds I's and what an acceptor reads of the inviter.
    await until(
      'the ceremony publishes logged',
      () =>
        published(w.relay).length >= (setup[0] as number) + 5 &&
        published(r2).length >= (setup[1] as number) + 5 &&
        published(r0).length >= 5,
    )
    const atR1 = published(w.relay).slice(setup[0])
    const atR2 = published(r2).slice(setup[1])
    const atR0 = published(r0)
    expect(atR1).toEqual([
      `key ${alice}`,
      `address ${alice}`,
      `address ${bob}`,
      `key ${bob}`,
      `accept-from ${alice}`,
    ])
    expect(atR2).toEqual([
      `key ${bob}`,
      `address ${bob}`,
      `address ${alice}`,
      `key ${alice}`,
      `accept-from ${bob}`,
    ])
    expect(atR0).toEqual([
      `address ${invite.i}`,
      `accept-from ${invite.i}`,
      `address ${alice}`,
      `key ${alice}`,
      `accept-from ${alice}`,
    ])
    const signers = new Set([invite.i, alice, bob])
    const others = [...atR1, ...atR2, ...atR0].filter((r) => !signers.has(r.split(' ')[1] as string)).length

    // The homes: the name book and the trust file name the other, 0600.
    const named = (home: string) =>
      json(home, 'names.json') as { version: number; names: Record<string, unknown> }
    expect(named(home1)).toEqual({ version: 1, names: { bob: expect.objectContaining({ address: bob }) } })
    expect(named(home2)).toEqual({
      version: 1,
      names: { alice: expect.objectContaining({ address: alice }) },
    })
    expect(json(home1, 'trust.json')).toEqual({
      version: 1,
      roots: { [bob]: { added_at: expect.any(Number) } },
    })
    expect(json(home2, 'trust.json')).toEqual({
      version: 1,
      roots: { [alice]: { added_at: expect.any(Number) } },
    })
    for (const home of [home1, home2]) {
      for (const f of ['names.json', 'trust.json']) expect(statSync(join(home, f)).mode & 0o777).toBe(0o600)
    }

    // Each sends to the other by name through its own relay, which serves the other's record since the pairing; the
    // other's inbox accepts it with no --trust-root. --allow-private-relays: the other's relay is another loopback
    // port, which the edge's private-address guard refuses otherwise.
    const delivered: string[] = []
    for (const [from, home, relay, to, toHome, toRelay, toName] of [
      ['alice', home1, R1, 'bob', home2, R2, 'bob'],
      ['bob', home2, R2, 'alice', home1, R1, 'alice'],
    ] as const) {
      const body = `{"text":"hello ${toName}"}`
      const sent = await cli(
        ...['send', '--as', from, '--to', toName, '--relay', relay, '--type', 'chat.v1', '--body', body],
        ...['--allow-private-relays', '--dir', home],
      )
      expect([sent.code, sent.out.length, sent.out[1], sent.err]).toEqual([
        0,
        2,
        `published ${toRelay} tries=1`,
        [],
      ])
      const got = await cli('inbox', '--as', to, '--relay', toRelay, '--once', '--dir', toHome)
      expect([got.code, got.err]).toEqual([0, []])
      expect(got.out).toEqual([
        expect.stringMatching(
          new RegExp(`^accept ${sent.out[0]} ${from} \\(\\S+\\) ${from} \\(\\S+\\) chat\\.v1 ${body}$`),
        ),
      ])
      delivered.push(`${from}->${to}`)
    }
    expect(delivered).toEqual(['alice->bob', 'bob->alice'])
    // The sends and the inboxes published no record.
    expect([published(w.relay).length, published(r2).length, published(r0).length]).toEqual([
      (setup[0] as number) + atR1.length,
      (setup[1] as number) + atR2.length,
      atR0.length,
    ])

    // No key material in any output: every child's stdout and stderr, the two files, the relays' logs.
    const seeds = [
      ...homeSecrets(home1, ['alice']),
      ...homeSecrets(home2, ['bob']),
      ...homeSecrets(home3, ['carol']),
    ]
    const printed = [
      ...outputs,
      ...[home1, home2].flatMap((h) =>
        ['names.json', 'trust.json'].map((f) => readFileSync(join(h, f), 'utf8')),
      ),
      w.relay.stderr(),
      r2.stderr(),
      r0.stderr(),
    ].join('\n')
    const leaked = seeds.filter((s) => printed.includes(s)).length
    expect([seeds.length, seeds.every((s) => s.length === 64), leaked]).toEqual([6, true, 0])

    console.log(
      `MEASURE L1 41: exited on their own after paired: invite ${ownExit[0]}, accept ${ownExit[1]} (exit codes ${a} and ${b}${ownExit.every(Boolean) ? '' : ' after a Ctrl-D'}); prompts ${prompts[0] + prompts[1]} (alice ${prompts[0]}, bob ${prompts[1]}); digits shown to the inviter ${inviter.out().join(' ').includes(bobCode)}; record publishes in the ceremony R1 ${atR1.length} (${atR1.map((r) => r.split(' ')[0]).join(', ')}) and R2 ${atR2.length}, by any key but I, alice and bob ${others}, the test process publishing nothing (setup before the invite: R1 ${setup[0]}, R2 ${setup[1]}); invite to the second paired ${wall} ms; sends accepted with no --trust-root ${delivered.length} of 2; key material in output ${leaked} of ${seeds.length} private keys`,
    )
    expect(ownExit, 'peer invite and peer accept exit by themselves once paired').toEqual([true, true])
  }, 120_000)
})

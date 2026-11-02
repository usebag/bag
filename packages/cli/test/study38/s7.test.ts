import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type GroupKeyBody, SealingKey, SigningKey, sealGroupKey, signMembership } from '@usebag/core'
import { GroupKeyStore } from '@usebag/edge'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { agentHome, CAVEAT, loggedIn, publishRecord, sessionAddress } from '../support/agent.ts'
import { T0, tempDir, testIo } from '../support/io.ts'
import { MemoryRelay } from '../support/relay.ts'
import { cli } from '../support/run.ts'

// S7, recovery is a format field. Three halves run:
// (a) the custody pointer written with a recovery setting (`personal`, and `none`) as key metadata, which `keys list`
// and the pointer must round-trip; (b) no recovery wrap file or message written by any command; (c) an `agent`
// identity holding group memberships refused with `agent-groups` at `keygen --custody agent` and at `ac login`. The
// fourth half, a `recovery-key.v1` opening to the statement's `sealing_key` and refused by `checkGroupKeyBody`, is
// the wrap's: not run by design. The tests assert the pre-registered bounds; an arm whose feature the code does not have
// at this commit fails and says so in its MEASURE line.

const tmp = tempDir('study38-s7')
afterAll(() => tmp.cleanup())
afterEach(() => {
  process.emit('SIGHUP')
})
let n = 0
const home = (): string => {
  const dir = join(tmp.dir, `h${n++}`)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  return dir
}

/** One MEASURE line, as the run records it. */
function measure(line: string, arm: string, text: string): void {
  console.log(`MEASURE ${line}(${arm}): ${text}`)
}

/** Every regular file under `dir` (a socket is not one), relative to it. */
function filesUnder(dir: string): string[] {
  return readdirSync(dir, { recursive: true })
    .map(String)
    .filter((rel) => lstatSync(join(dir, rel)).isFile())
}

describe('S7 (a): the recovery setting is a field of the custody pointer, round-tripped by keys list', () => {
  // Deferred to the recovery work, which builds
  // `keygen --recovery` and keys list's fifth field: this was `it.fails` until then, and is a plain `it` in that head.
  it('keygen --custody agent with a recovery setting of personal and of none: the pointer holds it and keys list shows it', async () => {
    const dir = home()
    const io = testIo(new MemoryRelay())
    expect((await cli(io, 'keygen', 'jane-keys', '--dir', dir)).code).toBe(0)
    const out: string[] = []
    let roundTrips = 0
    for (const setting of ['personal', 'none']) {
      const name = `rec-${setting}`
      const made = await cli(
        io,
        'keygen',
        name,
        '--custody',
        'agent',
        '--principal',
        'jane-keys',
        '--recovery',
        setting,
        '--dir',
        dir,
      )
      const file = join(dir, 'agent', `${name}.json`)
      const pointer = existsSync(file)
        ? (JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>)
        : {}
      const field = Object.entries(pointer).find(([k]) => /recover/i.test(k))
      const listed = (await cli(io, 'keys', 'list', '--dir', dir)).out.find((l) => l.startsWith(`${name} `))
      const held = field !== undefined && String(field[1]).includes(setting)
      const shown = listed?.includes(setting) === true
      if (made.code === 0 && held && shown) roundTrips++
      out.push(
        `${setting}: keygen exit ${made.code}${made.err[0] === undefined ? '' : ` (${made.err[0]})`}, pointer holds the field ${held}, keys list shows it ${shown}`,
      )
    }
    // The same question of a pointer written by hand with the field: does keys list carry it?
    const hand = home()
    const handIo = testIo(new MemoryRelay())
    await cli(handIo, 'keygen', 'jane-keys', '--dir', hand)
    await cli(handIo, 'keygen', 'jane', '--custody', 'agent', '--principal', 'jane-keys', '--dir', hand)
    const file = join(hand, 'agent', 'jane.json')
    writeFileSync(file, JSON.stringify({ ...JSON.parse(readFileSync(file, 'utf8')), recovery: 'personal' }), {
      mode: 0o600,
    })
    const handList = (await cli(handIo, 'keys', 'list', '--dir', hand)).out.find((l) => l.startsWith('jane '))
    measure(
      'S7',
      'a',
      `${roundTrips} of 2 settings round-trip. ${out.join('; ')}. A pointer written by hand with recovery "personal": keys list prints "${handList}"`,
    )
    expect(roundTrips, 'the recovery setting is a field of the pointer that keys list round-trips').toBe(2)
  })
})

describe('S7 (b): no recovery wrap file or message is written by any command', () => {
  it('keygen, login, grant, logout leave 0 files named or holding a recovery wrap, and print none', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(home())
    publishRecord(relay, h)
    const login = await loggedIn(relay, h)
    login.io.lines.push('y')
    const io = testIo(relay)
    const grant = await cli(
      io,
      'grant',
      '--as',
      'jane',
      '--session',
      sessionAddress(),
      '--caveat',
      CAVEAT,
      '--exp',
      '+600',
      '--dir',
      h.dir,
    )
    const out = await cli(io, 'logout', '--as', 'jane', '--dir', h.dir)
    const ran = await login.ran
    const files = filesUnder(h.dir)
    const wrapFiles = files.filter(
      (f) =>
        /recover|wrap/i.test(f) ||
        /recovery-key|group-key\.v1|recovery-read/i.test(readFileSync(join(h.dir, f), 'latin1')),
    )
    const said = [
      ...login.io.stdout,
      ...login.io.stderr,
      ...grant.out,
      ...grant.err,
      ...out.out,
      ...out.err,
      ...ran.out,
      ...ran.err,
    ]
    const printed = said.filter((l) => /recover|wrap/i.test(l))
    measure(
      'S7',
      'b',
      `${files.length} files in the home after keygen, login, grant, logout (exit ${grant.code}, ${out.code}, ${ran.code}): recovery wrap files ${wrapFiles.length}, lines printed naming a recovery or a wrap ${printed.length}`,
    )
    expect(wrapFiles).toEqual([])
    expect(printed).toEqual([])
    expect(files.length).toBeGreaterThan(0)
  })
})

describe('S7 (c): an agent identity that holds group memberships is refused with agent-groups', () => {
  /** A membership body of a group for `holder`, written to the identity's group store (<home>/groups/<name>). */
  function hold(
    dir: string,
    name: string,
    holder: { address: string; sealing: SealingKey },
    ofs: number,
  ): void {
    const group = new SigningKey(new Uint8Array(32).fill(0x31 + ofs))
    const body: GroupKeyBody = sealGroupKey({
      group,
      generation: 1,
      key: new SealingKey(new Uint8Array(32).fill(0x41 + ofs)),
      holder: { address: holder.address, sealingKey: holder.sealing.publicKey },
      hop: signMembership(group, holder.address, T0 + 86_400),
      iat: T0,
      rng: () => new Uint8Array(32).fill(0x51 + ofs),
    })
    new GroupKeyStore(join(dir, 'groups', name)).put(body)
  }

  // RETIRED at this head: S7 (c) asserts the agent-groups
  // hold, the agent's group support lifts it, and the line is retired by a dated note, never edited. The
  // The test is `it.fails`, with the plain sibling below asserting the new behaviour as measured, so
  // that this `it.fails` cannot pass for another reason. Its assertions are unchanged and now fail, as registered.
  it.fails('keygen --custody agent and ac login for an identity with memberships: refused, with agent-groups', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(home())
    publishRecord(relay, h)
    // The memberships are held under the agent identity's name and under its principal's: both stores the commands read.
    hold(h.dir, 'jane', { address: h.address, sealing: h.keys.sealing }, 0)
    hold(h.dir, 'jane-keys', { address: h.address, sealing: h.keys.sealing }, 1)

    const keygen = await cli(
      testIo(relay),
      'keygen',
      'again',
      '--custody',
      'agent',
      '--principal',
      'jane-keys',
      '--dir',
      h.dir,
    )
    const keygenRefused = keygen.code !== 0 && keygen.err.some((l) => l.includes('agent-groups'))

    const login = await loggedIn(relay, h)
    const opened = login.io.stdout.some((l) => l.startsWith('login '))
    if (opened) {
      await cli(testIo(relay), 'logout', '--as', 'jane', '--dir', h.dir)
    }
    const ran = await login.ran
    const loginRefused = !opened && ran.code !== 0 && login.io.stderr.some((l) => l.includes('agent-groups'))
    measure(
      'S7',
      'c',
      `keygen --custody agent for a principal holding memberships: exit ${keygen.code}, ${keygen.err[0] ?? 'no error'}, agent-groups ${keygenRefused}, pointer made ${existsSync(join(h.dir, 'agent', 'again.json'))}; ac login for an agent identity holding memberships: ${opened ? 'the window OPENED, so a group generation could reach a session' : 'no window'}, exit ${ran.code}, ${login.io.stderr[0] ?? 'no error'}, agent-groups ${loginRefused}`,
    )
    expect(
      keygenRefused,
      'keygen --custody agent refuses an identity that holds memberships with agent-groups',
    ).toBe(true)
    expect(loginRefused, 'ac login refuses an agent identity that holds memberships with agent-groups').toBe(
      true,
    )
  })

  // The plain sibling of the `it.fails` above: the same setup and the behaviour the agent's group support lifts the
  // hold to. keygen --custody agent for a principal holding memberships exits 0 and makes the pointer, and ac login for
  // such an identity opens its window, with no agent-groups on either.
  it('keygen --custody agent and ac login for an identity with memberships: admitted, the pointer made and the window opened', async () => {
    const relay = new MemoryRelay()
    const h = agentHome(home())
    publishRecord(relay, h)
    hold(h.dir, 'jane', { address: h.address, sealing: h.keys.sealing }, 0)
    hold(h.dir, 'jane-keys', { address: h.address, sealing: h.keys.sealing }, 1)

    const keygen = await cli(
      testIo(relay),
      'keygen',
      'again',
      '--custody',
      'agent',
      '--principal',
      'jane-keys',
      '--dir',
      h.dir,
    )
    const pointer = existsSync(join(h.dir, 'agent', 'again.json'))

    const login = await loggedIn(relay, h)
    const opened = login.io.stdout.some((l) => l.startsWith('login '))
    if (opened) {
      await cli(testIo(relay), 'logout', '--as', 'jane', '--dir', h.dir)
    }
    const ran = await login.ran
    const said = [...keygen.err, ...login.io.stderr].some((l) => l.includes('agent-groups'))
    measure(
      'S7',
      'c2',
      `keygen --custody agent for a principal holding memberships: exit ${keygen.code}, pointer made ${pointer}; ac login for an agent identity holding memberships: ${opened ? 'the window opened' : 'no window'}, exit ${ran.code}, agent-groups named ${said}`,
    )
    expect(keygen.code, 'keygen --custody agent for a principal holding memberships exits 0').toBe(0)
    expect(pointer, 'keygen makes the custody pointer').toBe(true)
    expect(opened, 'ac login for an identity holding memberships opens its window').toBe(true)
    expect(said, 'no command names agent-groups').toBe(false)
  })
})

describe('S7 (d): the wrap half', () => {
  it('records the wrap half as not run', () => {
    measure(
      'S7',
      'd',
      "not run: a recovery-key.v1 opening to the statement's sealing_key and refused by checkGroupKeyBody is the B2 wrap, which the cut holds back",
    )
  })
})

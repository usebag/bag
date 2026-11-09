import { chmodSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { PeerRequest } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import type { Fetch } from '../src/instance.ts'
import {
  endLinks,
  newPairs,
  PAIRINGS_PATH,
  type PairingCommand,
  type PairingPorts,
  pairedPeers,
  pairingCommands,
  pairingsPath,
  readPairings,
  runPairing,
} from '../src/pairings.ts'
import { signedRoots } from '../src/records.ts'
import { enterpriseDir, type Session, writeJson } from '../src/session.ts'
import { T0, tempDir } from './support/fixtures.ts'

// The console's pairings, client side (decision 38b): a faked instance holds the commands and takes the events, a
// faked ceremony stands for the edge's invitePeer. The digits the console's person typed are checked here, three times;
// a revoke or a term's end takes the peer out; the accept-from signs the paired peers beside the accept list.

const tmp = tempDir('pairings')
afterAll(() => tmp.cleanup())
let n = 0
const ORIGIN = 'https://bag.acme.example'
const ROOT = `ed25519:${'a'.repeat(64)}`
const PEER = `ed25519:${'b'.repeat(64)}`
const ID = '3f2c9a1e-0b7d-4e55-9a61-2c4d8e0f1a2b'
const ID2 = '7d1e0c2b-4a5f-4b6e-8c7d-9e0f1a2b3c4d'
const session = {
  state: 'live',
  domain: 'acme.example',
  instance: ORIGIN,
  access_token: 'pairings-test-bearer',
  org: { domain: 'acme.example', root: ROOT, relays: [] },
} as unknown as Session
const pair = (more: Partial<PairingCommand> = {}): PairingCommand => ({
  id: ID,
  action: 'pair',
  termDays: 7,
  outsideAddress: PEER,
  name: 'sam',
  expiresAt: T0 + 600,
  spoken: null,
  ...more,
})

function profile(): string {
  const p = join(tmp.dir, `profile-${n++}`)
  mkdirSync(enterpriseDir(p), { recursive: true, mode: 0o700 })
  return p
}

/** The instance: its commands (each GET answers them, then `after` runs), the events posted, a status per POST. */
function instance(commands: PairingCommand[], after: (c: PairingCommand[]) => void = () => {}) {
  const events: { id: string; body: Record<string, unknown> }[] = []
  let gets = 0
  const fetch: Fetch = async (url, init) => {
    if (url === `${ORIGIN}${PAIRINGS_PATH}` && init.method === 'GET') {
      gets++
      const res = new Response(
        JSON.stringify({ pairings: commands.map((c) => ({ ...c })), etag: `p${gets}` }),
      )
      after(commands)
      return res
    }
    const id = url.slice(`${ORIGIN}${PAIRINGS_PATH}/`.length)
    events.push({ id, body: JSON.parse(String(init.body)) })
    return new Response(null, { status: 204 })
  }
  return { fetch, events, gets: () => gets }
}

/** The machine: a ceremony that opens, then asks with `code` from PEER (or throws `end`), and the writes it saw. */
function machine(o: { code?: string; end?: string; written?: boolean } = {}) {
  const written: [string, string][] = []
  const removed: string[] = []
  const relays: (string | undefined)[] = []
  let now = T0
  const ports: PairingPorts = {
    invite: async (i) => {
      relays.push(i.relay)
      i.opened('472-tulip-orbit-cedar', T0 + i.ttl)
      if (o.end !== undefined) throw Object.assign(new Error(o.end), { code: o.end })
      const yes = await i.ask({ from: PEER, code: o.code ?? '123456' } as PeerRequest)
      if (!yes) throw Object.assign(new Error('declined'), { code: 'declined' })
      return PEER
    },
    write: (peer, name) => {
      if (o.written === false) throw new Error('name-exists')
      written.push([peer, name])
    },
    remove: async (peer) => void removed.push(peer),
    now: () => now,
    sleep: async (ms) => {
      now += ms / 1000
    },
  }
  return {
    ports,
    written,
    removed,
    relays,
    at: (t: number) => {
      now = t
    },
  }
}

const events = (x: { events: { body: Record<string, unknown> }[] }) => x.events.map((e) => e.body)

describe('runPairing', () => {
  it('posts the code, then the request, checks the typed digits, writes the peer, keeps the link with its term, posts paired', async () => {
    const p = profile()
    const commands = [pair()]
    const at = instance(commands, (c) => {
      if (at.gets() === 2) c[0] = { ...(c[0] as PairingCommand), spoken: '123 456' }
    })
    const m = machine()
    await runPairing(session, at.fetch, p, pair(), m.ports)
    expect(events(at)).toEqual([
      { event: 'code_shown', code: '472-tulip-orbit-cedar', until: T0 + 600 },
      { event: 'request', from: PEER },
      { event: 'paired', peerAddress: PEER },
    ])
    expect(m.written).toEqual([[PEER, 'sam']])
    const link = readPairings(p).links[0]
    expect(link).toMatchObject({
      id: ID,
      peer: PEER,
      name: 'sam',
      until: (link?.paired_at as number) + 7 * 86_400,
    })
    expect(pairedPeers(p)).toEqual([PEER])
    expect(newPairs(p, [pair(), pair({ id: ID2 })]).map((c) => c.id)).toEqual([ID2])
    expect(signedRoots(session, pairedPeers(p))).toEqual([ROOT, PEER])
  })

  it('posts confirm_retry with the tries left on a miss, and failed confirm_mismatch after three, writing nothing', async () => {
    const p = profile()
    const commands = [pair({ spoken: '000000' })]
    const at = instance(commands)
    const m = machine()
    await runPairing(session, at.fetch, p, pair(), m.ports)
    expect(events(at).slice(1)).toEqual([
      { event: 'request', from: PEER },
      { event: 'confirm_retry', triesLeft: 2 },
      { event: 'confirm_retry', triesLeft: 1 },
      { event: 'failed', reason: 'confirm_mismatch' },
    ])
    expect([m.written, readPairings(p).links, readPairings(p).done]).toEqual([[], [], [ID]])
  })

  it('ends unanswered when the console revokes it while waiting, or no digits come before the invitation ends', async () => {
    const gone = instance([])
    await runPairing(session, gone.fetch, profile(), pair(), machine().ports)
    expect(events(gone).at(-1)).toEqual({ event: 'failed', reason: 'refused' })
    const silent = instance([pair()])
    const m = machine()
    await runPairing(
      session,
      silent.fetch,
      profile(),
      pair({ termDays: null, outsideAddress: null }),
      m.ports,
    )
    expect(events(silent).at(-1)).toEqual({ event: 'failed', reason: 'expired' })
    expect(silent.gets()).toBeGreaterThan(100)
  })

  it('posts failed expired for an invitation no one answered, error for any other end or a write refused', async () => {
    const ends: [string, string][] = [
      ['invite-expired', 'expired'],
      ['no-answer', 'expired'],
      ['leaked', 'error'],
    ]
    for (const [end, reason] of ends) {
      const at = instance([])
      await runPairing(session, at.fetch, profile(), pair(), machine({ end }).ports)
      expect(events(at).at(-1)).toEqual({ event: 'failed', reason })
    }
    const at = instance([pair({ spoken: '123456' })])
    const p = profile()
    await runPairing(session, at.fetch, p, pair(), machine({ written: false }).ports)
    expect([events(at).at(-1), readPairings(p).links]).toEqual([{ event: 'failed', reason: 'error' }, []])
  })
})

describe('runPairing: where the invitation opens', () => {
  it("hands the ceremony the session's first organisation relay, and none for a session with no relays", async () => {
    const org = { ...session.org, relays: ['https://relay1.acme.example', 'https://relay2.acme.example'] }
    const m = machine({ end: 'invite-expired' })
    await runPairing({ ...session, org }, instance([]).fetch, profile(), pair(), m.ports)
    await runPairing(session, instance([]).fetch, profile(), pair(), m.ports)
    expect(m.relays).toEqual(['https://relay1.acme.example', undefined])
  })
})

describe('endLinks', () => {
  it('ends a link the console revoked and one whose term passed, posting unpaired; others stay', async () => {
    const p = profile()
    const link = (id: string, peer: string, until: number | null) => ({
      id,
      peer,
      name: 'x',
      paired_at: T0,
      until,
    })
    const C = `ed25519:${'c'.repeat(64)}`
    const D = `ed25519:${'d'.repeat(64)}`
    const kept = {
      v: 1,
      links: [
        link(ID, PEER, null),
        link(ID2, C, T0 + 10),
        link('11111111-2222-4333-8444-555555555555', D, null),
      ],
      done: [],
    }
    writeJson(pairingsPath(p), kept)
    const at = instance([])
    const m = machine()
    m.at(T0 + 10)
    const ended = await endLinks(session, at.fetch, p, [pair({ action: 'unpair' })], m.ports)
    expect([ended, m.removed]).toEqual([
      [ID, ID2],
      [PEER, C],
    ])
    expect(at.events).toEqual([
      { id: ID, body: { event: 'unpaired' } },
      { id: ID2, body: { event: 'unpaired' } },
    ])
    expect(pairedPeers(p)).toEqual([D])
  })
})

describe('the pull and the kept file', () => {
  it('reads the commands that are well formed, and null for a refusal or no answer', async () => {
    const answer =
      (status: number, body: unknown): Fetch =>
      async () =>
        new Response(JSON.stringify(body), { status })
    const good = pair()
    const all = [
      good,
      { ...good, id: 'x' },
      { ...good, action: 'run' },
      { ...good, outsideAddress: 'sam@okok.example' },
      null,
    ]
    expect(await pairingCommands(session, answer(200, { pairings: all }))).toEqual([good])
    expect(await pairingCommands(session, answer(404, {}))).toBeNull()
    expect(await pairingCommands(session, answer(200, { pairings: 'none' }))).toBeNull()
    expect(await pairingCommands(session, async () => Promise.reject(new Error('down')))).toBeNull()
  })

  it("takes no kept file that is not this user's 0600 file, nor entries that are not links", () => {
    const p = profile()
    expect(readPairings(p)).toEqual({ v: 1, links: [], done: [] })
    const bad = { id: 'nope', peer: PEER, name: 'x', paired_at: T0, until: null }
    writeFileSync(pairingsPath(p), JSON.stringify({ v: 1, links: [bad], done: [ID, 7] }), { mode: 0o600 })
    expect(readPairings(p)).toEqual({ v: 1, links: [], done: [ID] })
    chmodSync(pairingsPath(p), 0o644)
    expect(readPairings(p).done).toEqual([])
    writeFileSync(pairingsPath(p), '{', { mode: 0o600 })
    chmodSync(pairingsPath(p), 0o600)
    expect(readPairings(p).done).toEqual([])
    writeFileSync(pairingsPath(p), JSON.stringify({ v: 2, links: [], done: [ID] }))
    expect(readPairings(p).done).toEqual([])
  })
})

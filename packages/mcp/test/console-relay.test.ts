import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { type Fetch, PAIRINGS_PATH, writeJson } from '@usebag/enterprise-client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CONSOLE_POLL_MS } from '../src/console.ts'
import {
  FakeClock,
  ManualTimers,
  P,
  publishAddress,
  RELAY,
  saveKeys,
  T0,
  tempDir,
  testServer,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// Where a console pairing opens in the MCP server (Pairings.consoleInvite): at the organisation's first relay, where
// the enterprise agent's records and mailbox are, as the CLI's bag pairings opens it, even when the server's --relay
// names another; that relay joins the guard's own relays. The edge's invitePeer is replaced here to read its options.

const seen: { relay: string; rendezvous: string | undefined; own: boolean }[] = []
vi.mock('@usebag/edge', async (original) => {
  const edge = await original<typeof import('@usebag/edge')>()
  return {
    ...edge,
    invitePeer: async (
      ports: { guard: { allows: (url: string) => boolean } },
      o: { relay: string; rendezvous?: string; opened: (t: string, e: number) => void },
    ) => {
      seen.push({
        relay: o.relay,
        rendezvous: o.rendezvous,
        own: ports.guard.allows(o.relay),
      })
      o.opened('472-tulip-orbit-cedar', T0 + 600)
      throw Object.assign(new Error('no request came'), { code: 'invite-expired' })
    },
  }
})

const DOMAIN = 'acme.example'
const ORIGIN = 'https://bag.acme.example'
const ORG_RELAY = 'https://relay1.acme.example'
const ID = '3f2c9a1e-0b7d-4e55-9a61-2c4d8e0f1a2b'
let tmp: ReturnType<typeof tempDir>

beforeEach(() => {
  tmp = tempDir('console-relay')
  seen.length = 0
})
afterEach(() => {
  vi.useRealTimers()
  tmp.cleanup()
})

describe('consoleInvite: the organisation relay', () => {
  it("opens the invitation at the session's first organisation relay, not the server's --relay", async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    const h = join(tmp.dir, 'home')
    const dir = join(h, 'orgs', DOMAIN, 'enterprise')
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const org = { domain: DOMAIN, root: P.org.address, relays: [ORG_RELAY] }
    const session = {
      v: 1,
      domain: DOMAIN,
      instance: ORIGIN,
      name: 'alice',
      access_token: 't',
      state: 'live',
      org,
    }
    writeJson(join(dir, 'session.json'), session)
    const relay = new MemoryRelay()
    saveKeys(h, P.alice)
    await publishAddress(relay, P.alice)
    const events: unknown[] = []
    const command = {
      id: ID,
      action: 'pair',
      termDays: null,
      outsideAddress: null,
      name: 'bob',
      expiresAt: T0 + 600,
      spoken: null,
    }
    const fetch: Fetch = async (url, init) => {
      if (url === `${ORIGIN}${PAIRINGS_PATH}`) return Response.json({ pairings: [command], etag: 'p1' })
      events.push(JSON.parse(String(init.body)))
      return new Response(null, { status: 204 })
    }
    const timers = new ManualTimers()
    const server = await testServer({
      home: h,
      name: 'alice',
      relay,
      clock: new FakeClock(),
      timers,
      enterprise: { fetch },
    })
    try {
      await vi.advanceTimersByTimeAsync(CONSOLE_POLL_MS)
      await vi.waitFor(() => expect(events).toHaveLength(2))
      expect(RELAY).not.toBe(ORG_RELAY)
      expect(seen).toEqual([{ relay: ORG_RELAY, rendezvous: ORG_RELAY, own: true }])
      expect(events).toEqual([
        { event: 'code_shown', code: '472-tulip-orbit-cedar', until: T0 + 600 },
        { event: 'failed', reason: 'expired' },
      ])
    } finally {
      await server.close()
    }
  })
})

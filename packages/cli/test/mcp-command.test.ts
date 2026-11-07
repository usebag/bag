import { join } from 'node:path'
import { connectCodeOf } from '@usebag/enterprise-client'
import { FakeInstance } from '@usebag/enterprise-client/testing'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { USAGE } from '../src/cli.ts'
import { tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// bag mcp through run(): the server of @usebag/enterprise-client on a transport the test holds (the host's end written
// by hand, JSON-RPC frames in and out), against the recorded fake instance. Exactly the three tools; a bad or used code
// answers its reason with the code scrubbed; the command returns 0 only once the host closed the transport, and the
// CLI wrote nothing to stdout (the transport's) or stderr the whole time.

const tmp = tempDir('mcp-command')
afterAll(() => tmp.cleanup())
const DOMAIN = 'acme.example'
const SECRET = 'cli-test-secret-only-for-these-tests-000000'

interface Frame {
  readonly jsonrpc: '2.0'
  readonly id?: number
  readonly method?: string
  readonly params?: unknown
  readonly result?: { tools?: { name: string }[]; content?: { text: string }[]; isError?: boolean }
}

/** The host's end of the server's transport: the server sets onmessage and onclose; send is the server's answer. */
function host() {
  const answers = new Map<number, (f: Frame) => void>()
  const t = {
    onmessage: undefined as ((f: Frame) => void) | undefined,
    onclose: undefined as (() => void) | undefined,
    start: async () => {},
    close: async () => t.onclose?.(),
    send: async (f: Frame) => {
      if (f.id !== undefined) answers.get(f.id)?.(f)
    },
  }
  let id = 0
  const request = (method: string, params: unknown = {}) =>
    new Promise<Frame>((done) => {
      answers.set(++id, done)
      t.onmessage?.({ jsonrpc: '2.0', id, method, params })
    })
  return { t, request }
}

describe('bag mcp', () => {
  it('is in the usage text', () => {
    expect(USAGE).toContain('  mcp [--dir <home>]\n')
    expect(USAGE).toContain('claude mcp add bag -- npx -y @usebag/bag@<version> mcp')
  })

  it('serves exactly connect, sign_in and status; refuses a bad and a used code, scrubbed; returns at the close', async () => {
    const io = testIo(new MemoryRelay())
    io.tty = true
    const fake = new FakeInstance({ domain: DOMAIN, now: () => io.time.now })
    const code = connectCodeOf({ instance: fake.origin, domain: DOMAIN }, SECRET)
    const h = host()
    Object.assign(io, {
      fetch: fake.fetch,
      enterpriseNet: {
        txt: async () => [],
        get: async () => ({ status: 404, body: null }),
        guard: { connectTo: async () => '192.0.2.10' },
      },
      mcpTransport: h.t,
    })
    let ended = false
    const ran = cli(io, 'mcp', '--dir', join(tmp.dir, 'home')).finally(() => {
      ended = true
    })
    await vi.waitFor(() => expect(h.t.onmessage).toBeDefined())
    const clientInfo = { name: 'test', version: '0' }
    const init = await h.request('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo,
    })
    expect(init.result).toBeDefined()
    h.t.onmessage?.({ jsonrpc: '2.0', method: 'notifications/initialized' })
    const listed = await h.request('tools/list')
    expect(listed.result?.tools?.map((t) => t.name)).toEqual(['connect', 'sign_in', 'status'])
    const call = async (args: Record<string, unknown>) => {
      const r = (await h.request('tools/call', { name: 'connect', arguments: args })).result
      return { text: (r?.content ?? []).map((c) => c.text).join('\n'), isError: r?.isError === true }
    }
    const bad = await call({ code: code.slice(0, -1) })
    expect(bad).toEqual({
      text: 'usage: this is not a connect code from the console: it is cut short or changed',
      isError: true,
    })
    const used = await call({ code })
    expect(used.isError).toBe(true)
    expect(used.text.split('\n')).toEqual([
      `Connecting to ${DOMAIN} at ${fake.origin}`,
      expect.stringMatching(/^invalid_grant: /),
    ])
    for (const text of [bad.text, used.text]) {
      expect(text).not.toContain(SECRET)
      expect(text).not.toContain(code.slice(0, -1))
    }
    expect(ended).toBe(false)
    await h.t.close()
    expect(await ran).toEqual({ code: 0, out: [], err: [] })
    expect([io.stdout, io.stderr]).toEqual([[], []])
  })
})

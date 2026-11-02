import { once } from 'node:events'
import { writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:net'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { checkNoWindow } from '../src/home.ts'
import { agentHome, CAVEAT } from './support/agent.ts'
import { T0, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// The edges of the agent's socket that a real agent does not produce: a stale socket file (checkNoWindow finds no
// window), and a fake agent that answers a grant with a hop of a bad signature, or a logout with a bare refusal.

const tmp = tempDir('window')
afterAll(() => tmp.cleanup())
let n = 0
const dir = (): string => join(tmp.dir, `h${n++}`)
const servers: Server[] = []
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((resolve) => s.close(resolve))))
})
const S = `ed25519:${'ef'.repeat(32)}`

/** A fake agent on <home>/agent.sock: the nonce line, then `reply(frame)` for each frame. */
async function fake(home: string, reply: (frame: { op?: string }) => unknown): Promise<void> {
  const server = createServer((s) => {
    s.write(`${JSON.stringify({ nonce: '00'.repeat(32) })}\n`)
    const lines = createInterface({ input: s })
    lines.on('line', (line) => s.write(`${JSON.stringify(reply(JSON.parse(line)))}\n`))
  })
  servers.push(server)
  server.listen(join(home, 'agent.sock'))
  await once(server, 'listening')
}

describe('the agent socket at its edges', () => {
  it('finds no window behind a socket file nothing listens on', async () => {
    const h = agentHome(dir())
    writeFileSync(join(h.dir, 'agent.sock'), '')
    await expect(checkNoWindow(testIo(new MemoryRelay()), h.dir, h.address)).resolves.toBeUndefined()
  })

  it('refuses a grant whose hop is the one asked but not signed by the principal', async () => {
    const h = agentHome(dir())
    const exp = T0 + 60
    const hop = { iss: h.address, sub: S, caveats: [CAVEAT], exp, sig: '00'.repeat(64) }
    await fake(h.dir, () => ({ ok: true, hop }))
    const args = ['--as', 'jane', '--session', S, '--caveat', CAVEAT, `--exp=${exp}`, '--dir', h.dir]
    const r = await cli(testIo(new MemoryRelay()), 'grant', ...args)
    expect(r.err.at(-1)).toBe(`bag: bad-sig: the grant is not signed by ${h.address}`)
  })

  it('reports a logout refusal that carries no detail', async () => {
    const h = agentHome(dir())
    await fake(h.dir, () => ({ ok: false, code: 'bad-shape' }))
    const r = await cli(testIo(new MemoryRelay()), 'logout', '--as', 'jane', '--dir', h.dir)
    expect(r.err).toEqual(['bag: bad-shape: the agent refused the logout'])
  })
})

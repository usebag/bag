import { type ChildProcess, spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { SUITE, toHex } from '@usebag/core'
import { FsKeyStore, generateEdgeKeys, type Rng } from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import { tempDir } from './support/fixtures.ts'
import { StreamClientTransport } from './support/streams.ts'

// The server as a child process (`node packages/mcp/src/main.ts`) through a scripted
// session (tools/list, every tool, status, tool errors and a schema error), on a scratch home whose
// keys come from a seeded rng. Its stdout, its stderr, every tool result and every file under the home are searched
// for both identities' secrets (hex, upper hex, base64, base64url, the decimal byte list) and the key file's JSON
// text; binary files also for the raw 32 bytes. A count is asserted, never a string, so a failure prints no secret.

const MAIN = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'main.ts')
// Port 1 on loopback refuses every connection: each tool that needs the relay fails, and the server stays up.
const DOWN = 'http://127.0.0.1:1'

function seededRng(label: string): Rng {
  let counter = 0
  return {
    bytes(length: number): Uint8Array {
      const out = new Uint8Array(length)
      for (let off = 0; off < length; off += 32) {
        const block = createHash('sha256').update(`${label}:${counter++}`).digest()
        out.set(block.subarray(0, Math.min(32, length - off)), off)
      }
      return out
    },
  }
}

function forms(secret: Uint8Array): string[] {
  const b = Buffer.from(secret)
  return [
    b.toString('hex'),
    b.toString('hex').toUpperCase(),
    b.toString('base64'),
    b.toString('base64url'),
    [...b].join(', '),
    [...b].join(','),
  ]
}

function identity(label: string) {
  const keys = generateEdgeKeys(seededRng(`adversarial-mcp:${label}`))
  const sign = keys.signing.exportSeed()
  const seal = keys.sealing.exportSeed()
  const keyFile = JSON.stringify({ suite: SUITE, sign_seed: toHex(sign), seal_priv: toHex(seal) })
  return {
    keys,
    address: keys.signing.address,
    raw: [Buffer.from(sign), Buffer.from(seal)],
    needles: [...forms(sign), ...forms(seal), keyFile],
  }
}

type Identity = ReturnType<typeof identity>

function count(text: string, ids: readonly Identity[]): number {
  let n = 0
  for (const id of ids) {
    for (const needle of id.needles) {
      for (let i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + 1)) n++
    }
  }
  return n
}

function countInFile(file: string, ids: readonly Identity[]): number {
  const bytes = readFileSync(file)
  let n = count(bytes.toString('latin1'), ids)
  for (const id of ids)
    for (const r of id.raw) for (let i = bytes.indexOf(r); i >= 0; i = bytes.indexOf(r, i + 1)) n++
  return n
}

interface Child {
  readonly child: ChildProcess
  readonly out: Buffer[]
  readonly err: Buffer[]
  readonly exit: Promise<number | null>
}

function start(args: readonly string[], home: string): Child {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: dirname(home) }
  delete env.AC_HOME
  const child = spawn(process.execPath, [MAIN, ...args], { stdio: ['pipe', 'pipe', 'pipe'], env })
  const out: Buffer[] = []
  const err: Buffer[] = []
  child.stdout?.on('data', (c: Buffer) => out.push(c))
  child.stderr?.on('data', (c: Buffer) => err.push(c))
  // 'close', not 'exit': Node may emit 'exit' before the last stderr data has arrived.
  const exit = new Promise<number | null>((r) => child.once('close', (code) => r(code)))
  return { child, out, err, exit }
}

describe('a scripted child session prints no secret', () => {
  it('tools/list, every tool, status and the tool errors: 0 occurrences in stdout, stderr, results and state files', async () => {
    const tmp = tempDir('adversarial')
    onTestFinished(() => tmp.cleanup())
    const home = join(tmp.dir, 'home')
    const alice = identity('alice')
    const bob = identity('bob')
    new FsKeyStore(join(home, 'keys')).save('alice', alice.keys)
    const c = start(
      ['--as', 'alice', '--dir', home, '--relay', DOWN, '--trust-root', bob.address, '--allow-delegate'],
      home,
    )
    const client = new Client({ name: 'adversarial-secrets', version: '0.0.0' })
    await client.connect(new StreamClientTransport(c.child.stdin as never, c.child.stdout as never))
    const calls: [string, Record<string, unknown>][] = [
      ['status', {}],
      ['inbox', {}],
      ['wait', { timeout_s: 0.05 }],
      ['delegate', { to: bob.address, caveats: ['type=chat.*'], exp: '+60' }],
      ['send', { to: [bob.address], type: 'chat.v1', body: { text: 'hi' } }],
      ['ask', { to: bob.address, body: 'q', timeout_s: 1 }],
      ['handoff', { to: bob.address, threads: ['a'.repeat(64)] }],
      ['lookup', { address: bob.address }],
      ['send', { to: [bob.address] }],
      ['delegate', { to: 'nobody', caveats: [], exp: '+1' }],
      ['connect', { code: 'bagcode_not-a-code.not-a-secret' }],
      ['enterprise_status', {}],
      ['status', {}],
      ['facts', {}],
    ]
    const tools = await client.listTools()
    expect(tools.tools.map((t) => t.name).sort()).toEqual(
      [
        'ask',
        'connect',
        'delegate',
        'enterprise_status',
        'facts',
        'handoff',
        'inbox',
        'lookup',
        'pair_accept',
        'pair_cancel',
        'pair_invite',
        'receipts',
        'send',
        'sign_in',
        'status',
        'wait',
      ].sort(),
    )
    const results: string[] = [JSON.stringify(tools)]
    let errors = 0
    for (const [name, args] of calls) {
      const r = await client.callTool({ name, arguments: args })
      if (r.isError === true) errors++
      results.push(JSON.stringify(r))
    }
    // The status result names alice's address: the public form is there, the secrets are not.
    expect(results.some((r) => r.includes(alice.address))).toBe(true)
    expect(errors).toBeGreaterThanOrEqual(2)
    c.child.stdin?.end()
    expect(await c.exit).toBe(0)
    const ids = [alice, bob]
    const stdout = Buffer.concat(c.out).toString('utf8')
    const stderr = Buffer.concat(c.err).toString('utf8')
    const inResults = results.map((r) => count(r, ids))
    const files = readdirSync(home, { recursive: true, withFileTypes: true })
      .filter((e) => e.isFile())
      .map((e) => join(e.parentPath, e.name))
    const keyFile = join(home, 'keys', 'alice.json')
    const inFiles = files
      .filter((f) => f !== keyFile)
      .map((f) => [relative(home, f), countInFile(f, ids)] as const)
    const total = count(stdout, ids) + count(stderr, ids) + inResults.reduce((a, b) => a + b, 0)
    const fileTotal = inFiles.reduce((a, [, n]) => a + n, 0)
    console.log(
      `MEASURE L3 (MCP): ${total} occurrences in stdout, stderr and ${results.length} results (${errors} tool errors); ` +
        `${fileTotal} in ${inFiles.length} state files other than the key file`,
    )
    expect(count(stdout, ids)).toBe(0)
    expect(count(stderr, ids)).toBe(0)
    expect(inResults.filter((n) => n !== 0)).toEqual([])
    expect(inFiles.filter(([, n]) => n !== 0)).toEqual([])
    // The positive control of the search: the key file itself holds alice's seeds.
    expect(countInFile(keyFile, [alice])).toBeGreaterThan(0)
  })
})

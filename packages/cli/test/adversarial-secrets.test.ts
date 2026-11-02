import { execFile } from 'node:child_process'
import { Console } from 'node:console'
import { createHash, randomBytes } from 'node:crypto'
import {
  chmodSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve } from 'node:path'
import { Writable } from 'node:stream'
import { fileURLToPath } from 'node:url'
import { format, inspect } from 'node:util'
import { parseEnvelope, parseRecord, recordSigner, SUITE, toHex } from '@usebag/core'
import {
  Audit,
  type EdgeKeys,
  FsAuditSink,
  FsKeyStore,
  generateEdgeKeys,
  type Rng,
  readAuditLines,
} from '@usebag/edge'
import { afterAll, beforeAll, describe, expect, it, onTestFinished } from 'vitest'

// Lines L3 and L4 for the CLI, and the CLI halves of L1 and L2, on S-LOCAL: the CLI as child processes
// (`node packages/cli/src/main.ts`) on scratch homes, against a fake relay on 127.0.0.1 (node:http answering as the
// relay does: publish, record fetch, health, and the subscribe WebSocket), or http://127.0.0.1:1 for the unreachable
// path. Every stdout and stderr, and every file under the scratch root, is searched for each identity's two secrets
// (as hex, upper hex, base64, base64url and the decimal byte list) and for its key file's JSON text; binary files
// also for the raw 32 bytes. A count is asserted, never a string, so a failure prints no secret.

const MAIN = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'main.ts')
const DOWN = 'http://127.0.0.1:1'
// Node 24.4.1 warns once per process that node:sqlite is experimental; that is not output.
const NODE_WARNING = /ExperimentalWarning: SQLite is an experimental feature|node --trace-warnings/

// --- scratch, search and child processes ------------------------------------------------------------------------

function scratchDir(prefix: string): string {
  return mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), `bag-adv-cli-${prefix}-`))
}

function remove(dir: string): void {
  if (process.env.AC_KEEP_TMP !== '1') rmSync(dir, { recursive: true, force: true })
}

/** A scratch directory removed when the current test finishes. */
function scratch(prefix: string): string {
  const dir = scratchDir(prefix)
  onTestFinished(() => remove(dir))
  return dir
}

/** The text forms a 32-byte secret could take in output. */
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

/** One identity's secrets: the two raw seeds, their text forms, and its key file's JSON text. */
interface Secrets {
  readonly name: string
  readonly raw: readonly Buffer[]
  readonly needles: readonly string[]
}

function secretsOf(name: string, sign: Uint8Array, seal: Uint8Array, keyFile: string): Secrets {
  return {
    name,
    raw: [Buffer.from(sign), Buffer.from(seal)],
    needles: [...forms(sign), ...forms(seal), keyFile],
  }
}

/** The secrets in a home's key file `keys/<name>.json`, read back from the file the CLI wrote. */
function homeSecrets(home: string, name: string): Secrets {
  const text = readFileSync(join(home, 'keys', `${name}.json`), 'utf8')
  const f = JSON.parse(text) as { sign_seed: string; seal_priv: string }
  return secretsOf(name, Buffer.from(f.sign_seed, 'hex'), Buffer.from(f.seal_priv, 'hex'), text)
}

function count(text: string, needles: readonly string[]): number {
  let n = 0
  for (const needle of needles) {
    for (let i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + 1)) n++
  }
  return n
}

/** Occurrences of the secrets in a text (count of every form). */
function inText(text: string, all: readonly Secrets[]): number {
  return all.reduce((n, s) => n + count(text, s.needles), 0)
}

/** Occurrences of the secrets in a file: its text forms, and the raw bytes. */
function inFile(file: string, all: readonly Secrets[]): number {
  const bytes = readFileSync(file)
  let n = inText(bytes.toString('latin1'), all)
  for (const s of all)
    for (const r of s.raw) for (let i = bytes.indexOf(r); i >= 0; i = bytes.indexOf(r, i + 1)) n++
  return n
}

function filesUnder(dir: string): string[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => join(e.parentPath, e.name))
}

interface Ran {
  readonly args: readonly string[]
  readonly code: number
  readonly stdout: string
  readonly stderr: string
  readonly out: string[]
  readonly err: string[]
}

const lines = (text: string): string[] => text.split('\n').filter((l) => l !== '')

/** One CLI process, with no AC_HOME and HOME pointed at the scratch root, so nothing reaches the real home. */
function cli(home: string, args: readonly string[]): Promise<Ran> {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: dirname(home) }
  delete env.AC_HOME
  return new Promise((done) => {
    execFile(process.execPath, [MAIN, ...args], { env, timeout: 30_000 }, (error, stdout, stderr) => {
      const code = error === null ? 0 : typeof error.code === 'number' ? error.code : -1
      done({
        args,
        code,
        stdout,
        stderr,
        out: lines(stdout),
        err: lines(stderr).filter((l) => !NODE_WARNING.test(l)),
      })
    })
  })
}

/** A run's stderr for an assertion message, with every 64-hex and 43-character base64 run cut, so no seed can show. */
const redacted = (r: Ran): string =>
  r.err
    .join('\n')
    .replace(/[0-9a-fA-F]{64}/g, '<hex64>')
    .replace(/[A-Za-z0-9+/_-]{43,}=?/g, '<b64>')

const mode = (path: string): string => (lstatSync(path).mode & 0o777).toString(8).padStart(4, '0')

/** An edge Rng from a label: sha256 of the label and a counter (test keys only, never a real key). */
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

function seededKeys(label: string): { readonly keys: EdgeKeys; readonly secrets: Secrets } {
  const keys = generateEdgeKeys(seededRng(`adversarial-cli:${label}`))
  const sign = keys.signing.exportSeed()
  const seal = keys.sealing.exportSeed()
  const file = JSON.stringify({ suite: SUITE, sign_seed: toHex(sign), seal_priv: toHex(seal) })
  return { keys, secrets: secretsOf(label, sign, seal, file) }
}

// --- the fake relay ---------------------------------------------------------------------------------------------

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

function wsFrame(text: string): Buffer {
  const payload = Buffer.from(text, 'utf8')
  const n = payload.length
  const head =
    n < 126
      ? Buffer.from([0x81, n])
      : n < 65_536
        ? Buffer.from([0x81, 126, n >> 8, n & 0xff])
        : Buffer.concat([Buffer.from([0x81, 127]), Buffer.alloc(8)])
  if (n >= 65_536) head.writeBigUInt64BE(BigInt(n), 2)
  return Buffer.concat([head, payload])
}

/** The text frames of a client's masked stream; returns what is left over. */
function wsRead(buffer: Buffer, onText: (text: string) => void, onClose: () => void): Buffer {
  let b = buffer
  for (;;) {
    if (b.length < 2) return b
    const opcode = (b[0] as number) & 0x0f
    let length = (b[1] as number) & 0x7f
    let offset = 2
    if (length === 126) {
      length = b.readUInt16BE(2)
      offset = 4
    } else if (length === 127) {
      length = Number(b.readBigUInt64BE(2))
      offset = 10
    }
    const mask = b.subarray(offset, offset + 4)
    offset += 4
    if (b.length < offset + length) return b
    const payload = Buffer.from(b.subarray(offset, offset + length))
    for (let i = 0; i < payload.length; i++) payload[i] = (payload[i] as number) ^ (mask[i % 4] as number)
    b = b.subarray(offset + length)
    if (opcode === 0x1) onText(payload.toString('utf8'))
    if (opcode === 0x8) onClose()
  }
}

interface FakeRelay {
  readonly url: string
  readonly records: Map<string, Buffer>
  readonly boxes: Map<string, Buffer[]>
  close(): Promise<void>
}

/** A relay in a node:http server: POST /v0/publish, GET /v0/fetch/record/{address}/{kind}, GET /v0/health, subscribe. */
async function fakeRelay(): Promise<FakeRelay> {
  const records = new Map<string, Buffer>()
  const envelopes = new Set<string>()
  const boxes = new Map<string, Buffer[]>()
  const box = (address: string): Buffer[] => {
    const rows = boxes.get(address) ?? []
    boxes.set(address, rows)
    return rows
  }
  const send = (res: ServerResponse, status: number, body: unknown): void => {
    res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body))
  }
  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      const body = Buffer.concat(chunks)
      const url = req.url ?? ''
      try {
        if (req.method === 'GET' && url === '/v0/health') return send(res, 200, { ok: true })
        const rec = /^\/v0\/fetch\/record\/([^/]+)\/([a-z-]+)$/.exec(url)
        if (req.method === 'GET' && rec !== null) {
          const bytes = records.get(`${rec[1]} ${rec[2]}`)
          if (bytes === undefined) return send(res, 404, { error: 'not-found' })
          res.writeHead(200, { 'content-type': 'application/json' }).end(bytes)
          return
        }
        if (req.method === 'POST' && url === '/v0/publish') {
          const v = JSON.parse(body.toString('utf8')) as { kind?: unknown }
          if (v.kind !== undefined) {
            const r = parseRecord(body)
            records.set(`${recordSigner(r)} ${r.kind}`, body)
            return send(res, 200, { ok: true })
          }
          const env = parseEnvelope(body)
          const duplicate = envelopes.has(env.id)
          if (!duplicate) {
            envelopes.add(env.id)
            for (const to of env.to) box(to).push(body)
          }
          return send(res, 200, { ok: true, id: env.id, duplicate, delivered: duplicate ? 0 : env.to.length })
        }
        send(res, 404, { error: 'not-found' })
      } catch {
        send(res, 400, { error: 'bad-shape' })
      }
    })
  })
  const sockets = new Set<import('node:stream').Duplex>()
  server.on('upgrade', (req: IncomingMessage, socket: import('node:stream').Duplex) => {
    sockets.add(socket)
    socket.on('error', () => {})
    socket.on('close', () => sockets.delete(socket))
    const accept = createHash('sha1').update(`${req.headers['sec-websocket-key']}${GUID}`).digest('base64')
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
    )
    socket.write(wsFrame(JSON.stringify({ t: 'challenge', nonce: randomBytes(32).toString('hex') })))
    let pending: Buffer = Buffer.alloc(0)
    socket.on('data', (chunk: Buffer) => {
      pending = wsRead(
        Buffer.concat([pending, chunk]),
        (text) => {
          const f = JSON.parse(text) as { t?: string; mailbox?: string; cursor?: number | null }
          if (f.t !== 'auth') return
          const after = f.cursor ?? 0
          socket.write(wsFrame(JSON.stringify({ t: 'ok', cursor: after })))
          box(f.mailbox ?? '').forEach((bytes, i) => {
            // The envelope as a string.
            const envelope = JSON.stringify(bytes.toString('utf8'))
            if (i + 1 > after) socket.write(wsFrame(`{"t":"env","cursor":${i + 1},"envelope":${envelope}}`))
          })
        },
        () => socket.end(Buffer.from([0x88, 0x02, 0x03, 0xe8])),
      )
    })
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const { port } = server.address() as AddressInfo
  return {
    url: `http://127.0.0.1:${port}`,
    records,
    boxes,
    close: () =>
      new Promise<void>((r) => {
        for (const s of sockets) s.destroy()
        server.closeAllConnections()
        server.close(() => r())
      }),
  }
}

// --- L3 and L4: one CLI session on a scratch home ---------------------------------------------------------------

interface Session {
  readonly root: string
  readonly home: string
  readonly runs: Ran[]
  readonly secrets: Secrets[]
}

describe('L3 and L4 (CLI): one session of every command on a scratch home', () => {
  let session: Session
  let relay: FakeRelay

  beforeAll(async () => {
    relay = await fakeRelay()
    const root = scratchDir('session')
    const home = join(root, 'home')
    const runs: Ran[] = []
    const run = async (...args: string[]): Promise<Ran> => {
      const r = await cli(home, args)
      runs.push(r)
      return r
    }
    const R = relay.url
    const keygen = async (name: string): Promise<string> => {
      const r = await run('keygen', name, '--dir', home)
      expect(r.code, redacted(r)).toBe(0)
      return r.out[0] as string
    }
    const alice = await keygen('alice')
    const bob = await keygen('bob')
    const carol = await keygen('carol')
    await keygen('dave')
    expect((await run('address', 'alice', '--dir', home)).out).toEqual([alice])
    const file = (n: string): string => join(root, n)
    for (const who of ['alice', 'bob']) {
      const out = file(`${who}.address.json`)
      expect(
        (await run('record', 'address', who, '--relay', R, '--sealing-key', '--out', out, '--dir', home))
          .code,
      ).toBe(0)
      expect((await run('publish', R, out)).code).toBe(0)
    }
    const accept = file('bob.accept.json')
    const recordAccept = await run(
      'record',
      'accept-from',
      'bob',
      '--root',
      '*',
      '--max-bytes',
      '65536',
      '--ttl',
      '86400',
      '--out',
      accept,
      '--dir',
      home,
    )
    expect(recordAccept.code).toBe(0)
    expect((await run('publish', R, accept)).code).toBe(0)
    const chain = file('chain.json')
    const delegated = await run(
      'delegate',
      '--from',
      'alice',
      '--to',
      carol,
      '--caveat',
      'type=chat.*',
      '--exp',
      '+3600',
      '--out',
      chain,
      '--dir',
      home,
    )
    expect(delegated.code, redacted(delegated)).toBe(0)
    const sendArgs = (as: string, relayUrl: string, body: string): string[] => [
      'send',
      '--as',
      as,
      '--to',
      bob,
      '--relay',
      relayUrl,
      '--type',
      'chat.v1',
      '--body',
      body,
      '--dir',
      home,
    ]
    const sent = await run(...sendArgs('alice', R, '{"text":"hi from alice"}'))
    expect(sent.code, redacted(sent)).toBe(0)
    const sentUnder = await run(...sendArgs('carol', R, '{"text":"hi from carol"}'), '--auth', chain)
    expect(sentUnder.code, redacted(sentUnder)).toBe(0)
    const inbox = await run(
      'inbox',
      '--as',
      'bob',
      '--relay',
      R,
      '--once',
      '--trust-root',
      alice,
      '--honor',
      'coding',
      '--dir',
      home,
    )
    expect(inbox.code, redacted(inbox)).toBe(0)
    expect(inbox.out.filter((l) => l.startsWith('accept '))).toHaveLength(2)
    expect((await run('audit', 'verify', join(home, 'state', 'bob', 'audit.jsonl'))).out[0]).toMatch(
      /^ok \d+ lines$/,
    )
    expect((await run('audit', 'verify', join(home, 'state', 'alice', 'audit.jsonl'))).out[0]).toMatch(
      /^ok \d+ lines$/,
    )
    expect((await run('health', R)).out).toEqual(['ok'])
    expect((await run('help')).code).toBe(0)
    // The five error paths.
    const failing: Ran[] = []
    const fail = async (...args: string[]): Promise<void> => {
      const r = await run(...args)
      failing.push(r)
    }
    // An unreachable relay.
    // (send at it still succeeds: the recipient's record is cached from the first send and names the fake relay.)
    await run(...sendArgs('alice', DOWN, '{"text":"lost"}'))
    await fail('health', DOWN)
    await fail('publish', DOWN, file('alice.address.json'))
    await fail('inbox', '--as', 'bob', '--relay', DOWN, '--once', '--dir', home)
    // A missing key name: none given, and a name with no key file.
    await fail('address', '--dir', home)
    await fail('address', 'ghost', '--dir', home)
    // A corrupt key file: dave's, cut short so it still holds both his seeds.
    const daveFile = join(home, 'keys', 'dave.json')
    const daveText = readFileSync(daveFile, 'utf8')
    const dave = homeSecrets(home, 'dave')
    chmodSync(daveFile, 0o600)
    writeFileSync(daveFile, daveText.slice(0, -2))
    await fail('address', 'dave', '--dir', home)
    await fail(...sendArgs('dave', R, '{"text":"x"}'))
    // A wrong --as: a name with no key, and a name that would leave the key directory.
    await fail(...sendArgs('zed', R, '{"text":"x"}'))
    await fail(...sendArgs('../keys/alice', R, '{"text":"x"}'))
    // A malformed --body.
    await fail(...sendArgs('alice', R, '{"text":'))
    for (const r of failing) expect(r.code, r.args.join(' ')).not.toBe(0)
    const secrets = [
      homeSecrets(home, 'alice'),
      homeSecrets(home, 'bob'),
      homeSecrets(home, 'carol'),
      // dave's key file is cut, so his secrets come from the text read before the cut.
      secretsOf('dave', dave.raw[0] as Buffer, dave.raw[1] as Buffer, daveText),
    ]
    session = { root, home, runs, secrets }
  }, 120_000)

  afterAll(async () => {
    await relay?.close()
    if (session !== undefined) remove(session.root)
  })

  describe('L3 (CLI): no command and no error path prints a secret', () => {
    it('every command and the five error paths: 0 occurrences in every stdout and stderr', () => {
      const { runs, secrets } = session
      const commands = new Set(runs.map((r) => (r.args[0] === 'record' ? `record ${r.args[1]}` : r.args[0])))
      expect([...commands].sort()).toEqual(
        [
          'address',
          'audit',
          'delegate',
          'health',
          'help',
          'inbox',
          'keygen',
          'publish',
          'record accept-from',
          'record address',
          'send',
        ].sort(),
      )
      const perRun = runs.map((r) => inText(`${r.stdout}\n${r.stderr}`, secrets))
      const total = perRun.reduce((a, b) => a + b, 0)
      console.log(
        `MEASURE L3 (CLI): ${total} occurrences of ${secrets.length} identities' secrets (${secrets[0]?.needles.length} ` +
          `forms each) in the stdout and stderr of ${runs.length} CLI processes`,
      )
      expect(
        perRun.map((n, i) => [runs[i]?.args.slice(0, 2).join(' '), n]).filter(([, n]) => n !== 0),
      ).toEqual([])
      expect(total).toBe(0)
    })

    it('each error path exits non-zero with one "bag: <code>: <detail>" line', () => {
      const errors = session.runs.filter((r) => r.code !== 0)
      expect(errors.length).toBeGreaterThanOrEqual(9)
      for (const r of errors) {
        expect(r.err[0], r.args.join(' ')).toMatch(/^bag: [a-z0-9-]+: /i)
      }
    })
  })

  describe('L4 (CLI): key material lands only in its own key file', () => {
    it('every file under the scratch root: the seeds only in keys/<name>.json, none in SQLite, audit or records', () => {
      const { root, secrets } = session
      const hits: [string, number][] = []
      let ownCopies = 0
      const files = filesUnder(root)
      for (const f of files) {
        const rel = relative(root, f)
        for (const s of secrets) {
          const n = inFile(f, [s])
          if (rel === join('home', 'keys', `${s.name}.json`)) ownCopies += n > 0 ? 1 : 0
          else if (n > 0) hits.push([rel, n])
        }
      }
      const kinds = files.map((f) => relative(root, f))
      expect(kinds.some((f) => f.endsWith('edge.sqlite'))).toBe(true)
      expect(kinds.some((f) => f.endsWith('audit.jsonl'))).toBe(true)
      console.log(
        `MEASURE L4 (CLI): ${files.length} files under the scratch root; seeds outside their own key file: ${hits.length} ` +
          `files; own key files holding their seeds: ${ownCopies} of ${secrets.length}`,
      )
      expect(hits).toEqual([])
      expect(ownCopies).toBe(secrets.length)
    })

    it('MEASURE L2 modes: the home, the key directory and files, the state directory, the SQLite file and the audit log', () => {
      const { home } = session
      const state = join(home, 'state', 'bob')
      const paths: Record<string, string> = {
        home,
        keys: join(home, 'keys'),
        'keys/alice.json': join(home, 'keys', 'alice.json'),
        state: join(home, 'state'),
        'state/bob': state,
        'state/bob/edge.sqlite': join(state, 'edge.sqlite'),
        'state/bob/audit.jsonl': join(state, 'audit.jsonl'),
      }
      for (const extra of readdirSync(state)) {
        if (extra.startsWith('edge.sqlite-')) paths[`state/bob/${extra}`] = join(state, extra)
      }
      const modes = Object.fromEntries(Object.entries(paths).map(([k, p]) => [k, mode(p)]))
      console.log(
        `MEASURE L2 (modes after a CLI run, umask ${process.umask().toString(8).padStart(4, '0')}): ${JSON.stringify(modes)}`,
      )
      expect(modes.keys).toBe('0700')
      expect(modes['keys/alice.json']).toBe('0600')
      expect(modes['state/bob']).toBe('0700')
      expect(modes['state/bob/audit.jsonl']).toBe('0600')
    })
  })
})

// --- L3: the key objects in process -----------------------------------------------------------------------------

describe('L3 (in process): SigningKey and SealingKey print the address or public key only', () => {
  it('console.log, JSON.stringify, String(), util.inspect, util.format and a thrown error hold no secret', () => {
    const { keys, secrets } = seededKeys('objects')
    const printed: string[] = []
    const sink = new Writable({
      write(chunk, _enc, next) {
        printed.push(String(chunk))
        next()
      },
    })
    const logger = new Console({ stdout: sink, stderr: sink })
    const thrown = (v: unknown): string[] => {
      try {
        throw new Error(`refused ${String(v)} ${JSON.stringify(v)}`, { cause: v })
      } catch (e) {
        const err = e as Error
        return [err.message, String(err.stack), inspect(err, { depth: 5 })]
      }
    }
    for (const v of [keys.signing, keys.sealing, keys]) {
      logger.log(v)
      logger.error('%o %O %s %j', v, v, v, v)
      printed.push(
        JSON.stringify(v),
        String(v),
        `${v}`,
        inspect(v),
        inspect(v, { showHidden: true, depth: Number.POSITIVE_INFINITY }),
        inspect(v, { customInspect: false, showHidden: true, depth: Number.POSITIVE_INFINITY }),
        format('%o %O %s %j', v, v, v, v),
        JSON.stringify({ ...v }),
        inspect(structuredClone({ ...v })),
        ...thrown(v),
      )
    }
    const all = printed.join('\n')
    // The public forms are there: the address and the sealing public key.
    expect(all).toContain(keys.signing.address)
    expect(all).toContain(toHex(keys.sealing.publicKey))
    const n = inText(all, [secrets])
    console.log(
      `MEASURE L3 (in process): ${n} occurrences in ${printed.length} printed forms of the two key objects`,
    )
    expect(n).toBe(0)
  })
})

// --- L1 (CLI half): audit verify on (a) and (d) -----------------------------------------------------------------

describe('L1 (CLI half): `audit verify` on a tampered 20-line log', () => {
  /** A 20-line audit log written by the edge's Audit to a file, line 10 a reject with reason bad-sig. */
  function log(dir: string): string[] {
    const path = join(dir, 'source.jsonl')
    let t = 1_800_000_000
    const audit = new Audit(new FsAuditSink(path), { now: () => t++ })
    for (let i = 1; i <= 20; i++) {
      audit.record(
        i === 10
          ? { event: 'verify', decision: 'reject', reason: 'bad-sig', id: 'a'.repeat(64) }
          : { event: 'verify', decision: 'accept', id: i.toString(16).padStart(64, '0') },
      )
    }
    return readAuditLines(path)
  }

  it('the untampered log is ok 20 lines; (a) one byte of line 10 reason changed: bad line 10, exit 1', async () => {
    const dir = scratch('audit-a')
    const lines20 = log(dir)
    const good = join(dir, 'good.jsonl')
    writeFileSync(good, `${lines20.join('\n')}\n`)
    const ok = await cli(join(dir, 'home'), ['audit', 'verify', good])
    expect([ok.code, ok.out]).toEqual([0, ['ok 20 lines']])
    const tampered = [...lines20]
    tampered[9] = (lines20[9] as string).replace('"reason":"bad-sig"', '"reason":"bad-sih"')
    expect(tampered[9]).not.toBe(lines20[9])
    const bad = join(dir, 'a.jsonl')
    writeFileSync(bad, `${tampered.join('\n')}\n`)
    const r = await cli(join(dir, 'home'), ['audit', 'verify', bad])
    expect([r.code, r.out]).toEqual([1, ['bad line 10: not an audit line']])
  })

  it('(d) the last three lines removed: measured', async () => {
    const dir = scratch('audit-d')
    const cut = join(dir, 'd.jsonl')
    writeFileSync(cut, `${log(dir).slice(0, 17).join('\n')}\n`)
    const r = await cli(join(dir, 'home'), ['audit', 'verify', cut])
    console.log(
      `MEASURE L1(d) (CLI): audit verify on the log less its last 3 lines -> exit ${r.code}, "${r.out.join(' | ')}"`,
    )
    // What is observed: the truncated log verifies.
    expect([r.code, r.out]).toEqual([0, ['ok 17 lines']])
  })
})

// --- L2 (CLI half): `address <name>` on each bad key file -------------------------------------------------------

describe('L2 (CLI half): `address <name>` refuses each bad key file, exits non-zero, quotes nothing', () => {
  /** A home whose key directory (0700) holds `k.json` (0600) of seeded keys; `address k` prints its address. */
  async function home(label: string) {
    const root = scratch(`l2-${label}`)
    const dir = join(root, 'home')
    const { keys, secrets } = seededKeys(`l2:${label}`)
    new FsKeyStore(join(dir, 'keys')).save('k', keys)
    const ok = await cli(dir, ['address', 'k', '--dir', dir])
    expect([ok.code, ok.out]).toEqual([0, [keys.signing.address]])
    return { dir, keysDir: join(dir, 'keys'), file: join(dir, 'keys', 'k.json'), secrets }
  }

  async function refused(dir: string, name: string, expected: string, secrets: Secrets): Promise<void> {
    const r = await cli(dir, ['address', name, '--dir', dir])
    expect(r.code).toBe(1)
    expect(r.out).toEqual([])
    expect(r.err).toEqual([expected])
    expect(inText(`${r.stdout}\n${r.stderr}`, [secrets])).toBe(0)
  }

  for (const m of [0o644, 0o640, 0o620]) {
    const octal = m.toString(8).padStart(4, '0')
    it(`a key file at ${octal}`, async () => {
      const h = await home(`file-${octal}`)
      chmodSync(h.file, m)
      await refused(
        h.dir,
        'k',
        `bag: error: fs-keys: ${h.file} has mode ${octal}; it must be 0600`,
        h.secrets,
      )
    })
  }

  for (const m of [0o750, 0o707]) {
    const octal = m.toString(8).padStart(4, '0')
    it(`the key directory at ${octal}`, async () => {
      const h = await home(`dir-${octal}`)
      chmodSync(h.keysDir, m)
      await refused(
        h.dir,
        'k',
        `bag: error: fs-keys: ${h.keysDir} has mode ${octal}; it must be 0700`,
        h.secrets,
      )
    })
  }

  it('a symlink to a 0600 key file', async () => {
    const h = await home('symlink')
    const link = join(h.keysDir, 'link.json')
    symlinkSync(h.file, link)
    await refused(h.dir, 'link', `bag: error: fs-keys: ${link} is not a regular file`, h.secrets)
  })

  it('a FIFO in place of a key file (refused before any open)', async () => {
    const h = await home('fifo')
    const fifo = join(h.keysDir, 'pipe.json')
    await new Promise<void>((done, fail) =>
      execFile('mkfifo', ['-m', '0600', fifo], (e) => (e === null ? done() : fail(e))),
    )
    await refused(h.dir, 'pipe', `bag: error: fs-keys: ${fifo} is not a regular file`, h.secrets)
  })

  it('a key file that is not JSON (cut short, still holding both seeds)', async () => {
    const h = await home('notjson')
    const file = join(h.keysDir, 'cut.json')
    writeFileSync(file, readFileSync(h.file, 'utf8').slice(0, -2), { mode: 0o600 })
    await refused(h.dir, 'cut', `bag: error: fs-keys: ${file} is not JSON`, h.secrets)
  })

  it('a key file of the right shape with a 31-byte seed', async () => {
    const h = await home('short')
    const f = JSON.parse(readFileSync(h.file, 'utf8')) as { sign_seed: string; seal_priv: string }
    const file = join(h.keysDir, 'short.json')
    writeFileSync(
      file,
      JSON.stringify({ suite: 1, sign_seed: f.sign_seed.slice(0, 62), seal_priv: f.seal_priv }),
      {
        mode: 0o600,
      },
    )
    await refused(h.dir, 'short', `bag: error: fs-keys: ${file} is not a suite 1 key file`, h.secrets)
  })
})

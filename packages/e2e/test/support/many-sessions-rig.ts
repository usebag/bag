import { chmodSync, existsSync, mkdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { codingEvaluator, serializeRecord } from '@usebag/core'
import {
  FsAuditSink,
  FsKeyStore,
  HomeCustody,
  parseAuditLine,
  readAuditLines,
  systemClock,
  systemRng,
} from '@usebag/edge'
import {
  Agent,
  AgentAudit,
  AgentServer,
  type AgentServerOptions,
  resolveSessionName,
} from '@usebag/edge/agent'
import { onTestFinished } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  type Party,
  party,
  REPO,
  rawPublish,
  sleep,
  until,
  type World,
  world,
} from '../harness.ts'

// The rig of scenario 47 (many Claude Code sessions on one principal): a real relay, a real agent of the home `jane`
// in this process (its terminal types what the test types), one self-rooted peer `bob` as an MCP server process, and
// sessions as MCP server processes, each under its own stand-in `claude` parent (many-sessions-anchor.ts).

export const MAIN = join(REPO, 'packages', 'mcp', 'src', 'main.ts')
export const ANCHOR = join(REPO, 'packages', 'e2e', 'test', 'support', 'many-sessions-anchor.ts')
/** The caveat of every session's grant (a chat-only session); bob honors it as the coding profile does. */
export const CAVEAT = 'type=chat.*'
/** Poll interval of the helpers below, in ms (the harness's `until` polls every 20 ms). */
export const POLL_MS = 50
/**
 * The longest a root takes from bob's send to its answer at bob with both servers up: scenario 18 asserts a median
 * ask round trip under 2,000 ms; fifteen times that is the bound for a loaded machine (a failure, not a wait).
 */
export const ANSWER_DEADLINE_MS = 30_000
/** The longest a server takes to start and open its identity once its grant is typed. */
export const READY_DEADLINE_MS = 30_000
/** Tolerance on a time measured through a tool call and a poll, added to a constant of the code (ms). */
export const POLL_SLACK_MS = 1000
/**
 * A session asks the agent again every GRANT_RETRY_MS (10 s, packages/mcp/src/session.ts, not exported); the re-login
 * case allows that long, and one more, for a session to notice that its grant is gone and ask again.
 */
export const REASK_DEADLINE_MS = 2 * 10_000

export type Json = Record<string, unknown>

export interface Msg {
  readonly id: string
  readonly from: string
  readonly type: string
  readonly body: unknown
  readonly thread: { readonly id: string; readonly prev: readonly string[] }
  readonly reply: Json
}

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

/** An MCP server child process driven by the SDK's client; for a session, behind its stand-in `claude`. */
export class McpProc {
  readonly stderr: string[] = []
  readonly #client: Client
  readonly pid: number
  #closed = false

  readonly label: string

  private constructor(label: string, client: Client, transport: StdioClientTransport) {
    this.label = label
    this.#client = client
    this.pid = transport.pid as number
  }

  static async start(label: string, args: readonly string[]): Promise<McpProc> {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [...args],
      cwd: REPO,
      stderr: 'pipe',
    })
    const lines: string[] = []
    transport.stderr?.on('data', (c: Buffer) => lines.push(c.toString('utf8')))
    const client = new Client({ name: `e2e-${label}`, version: '0.0.0' })
    try {
      await client.connect(transport)
    } catch (e) {
      throw new Error(`${label} did not start: ${(e as Error).message}\nits stderr:\n${lines.join('')}`)
    }
    const p = new McpProc(label, client, transport)
    p.stderr.push(...lines)
    transport.stderr?.on('data', (c: Buffer) => p.stderr.push(c.toString('utf8')))
    return p
  }

  /** The anchor's pid a stand-in `claude` reported on stderr, or null (bob has none). */
  get anchorPid(): number | null {
    const m = /AC_ANCHOR_PID=(\d+)/.exec(this.stderr.join(''))
    return m === null ? null : Number(m[1])
  }

  get running(): boolean {
    return !this.#closed && alive(this.pid)
  }

  async call(tool: string, args: Json = {}): Promise<{ readonly isError: boolean; readonly value: Json }> {
    const r = await this.#client.callTool({ name: tool, arguments: args }, undefined, { timeout: 60_000 })
    const text = (r.content as { text: string }[])[0]?.text ?? ''
    return { isError: r.isError === true, value: JSON.parse(text) as Json }
  }

  /** Ends the process as a host does at the end of a session: stdin closes, the server stops and releases its locks. */
  async close(): Promise<void> {
    if (!this.#closed) {
      this.#closed = true
      await this.#client.close().catch(() => {})
    }
    await until(`${this.label} (pid ${this.pid}) to exit`, () => !alive(this.pid), 20_000)
  }
}

/** A session once its grant is in: its process, its name and key address, and the request code it was asked with. */
export interface Session {
  readonly proc: McpProc
  readonly name: string
  readonly address: string
  readonly anchor: number
  readonly code: string
}

/** The agent of the home `jane`, in this process, with a terminal a test types into. */
export class Terminal {
  readonly printed: string[] = []
  /** How many prompts the agent asked a person to answer, and how many `y` it was given. */
  asked = 0
  yes = 0
  readonly #typed: string[] = []
  #answer: ((line: string) => void) | null = null

  readonly print = (line: string): void => void this.printed.push(line)

  readonly ask = (): Promise<string> => {
    this.asked++
    return new Promise<string>((resolve) => {
      const next = this.#typed.shift()
      if (next === undefined) this.#answer = resolve
      else resolve(next)
    })
  }

  type(line: string): void {
    if (line === 'y') this.yes++
    const a = this.#answer
    this.#answer = null
    if (a === null) this.#typed.push(line)
    else a(line)
  }

  /** The request codes printed so far, in order. */
  codes(): string[] {
    return this.printed.filter((l) => l.startsWith('request ')).map((l) => l.slice('request '.length))
  }
}

export interface Rig {
  readonly w: World
  readonly jane: Party
  readonly bobParty: Party
  readonly janeHome: string
  readonly terminal: Terminal
  readonly bob: McpProc
  readonly sessions: McpProc[]
  /** The agent's server now (a new one after `relogin`). */
  agent(): AgentServer
  /**
   * `ac logout` then `ac login`: the agent process ends, its window and grants with it; its logout record, which
   * revokes the sessions' keys, is published; and a new one opens, holding that record.
   */
  relogin(): Promise<void>
}

function privateDir(dir: string): string {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)
  return dir
}

/**
 * A world for one case: the relay, jane's home with the agent identity and its agent logged in (the window of
 * `login`'s default), bob's home and server, both mailboxes' records published. Everything is closed at the case's end.
 * Home directories are short names: a unix socket path is limited to about a hundred bytes.
 */
export async function rig(name: string): Promise<Rig> {
  const w = await world(name)
  const jane = party('jane')
  const bobParty = party('bob')
  const janeHome = privateDir(join(w.dir, 'j'))
  const bobHome = privateDir(join(w.dir, 'b'))
  new HomeCustody(janeHome).agent.create('jane', jane.keys)
  new FsKeyStore(join(bobHome, 'keys')).save('bob', bobParty.keys)
  for (const [p, roots] of [
    [jane, [bobParty.address]],
    [bobParty, [jane.address]],
  ] as const) {
    for (const record of [addressRecord(p, { relays: [w.url] }), acceptFrom(p, roots)]) {
      const r = await rawPublish(w.url, serializeRecord(record))
      if (r.status !== 200) throw new Error(`publishing a ${record.kind} record: ${r.status}`)
    }
  }
  const terminal = new Terminal()
  let server: AgentServer | null = null
  // The held records: a logout re-signs the address record into this map, and the next login keeps it, as ac login does.
  const records: AgentServerOptions['records'] = new Map()
  records.set('address', addressRecord(jane, { relays: [w.url] }))
  const open = async (): Promise<AgentServer> => {
    const core = new Agent({
      principal: jane.address,
      clock: systemClock,
      rng: systemRng,
      audit: new AgentAudit(new FsAuditSink(join(janeHome, 'agent-audit.jsonl')), systemClock),
      evaluators: [codingEvaluator],
    })
    const s = new AgentServer({
      agent: core,
      clock: systemClock,
      home: janeHome,
      terminal,
      records,
      ended: () => {},
      // The process's signals are the test runner's: the agent here listens for none.
      signals: { on: () => 0, off: () => 0 },
    })
    await s.listen()
    s.login(jane.keys)
    return s
  }
  server = await open()
  const bob = await McpProc.start('bob', [
    MAIN,
    '--as',
    'bob',
    '--dir',
    bobHome,
    '--relay',
    w.url,
    '--trust-root',
    jane.address,
    '--honor',
    'coding',
  ])
  const sessions: McpProc[] = []
  const r: Rig = {
    w,
    jane,
    bobParty,
    janeHome,
    terminal,
    bob,
    sessions,
    agent: () => server as AgentServer,
    async relogin() {
      const old = server as AgentServer
      // The logout record revokes the sessions' keys on the wire (SPEC 13.3); each session re-grants under a fresh key
      // (§13.5), so its sends and the replies on its old threads go on.
      const record = old.logout()
      await old.close()
      if (record !== null) {
        const published = await rawPublish(w.url, serializeRecord(record))
        if (published.status !== 200) throw new Error(`publishing the logout record: ${published.status}`)
      }
      server = await open()
    },
  }
  // Registered after the world's own cleanup, so it runs before it: processes first, then the relay and the directory.
  onTestFinished(async () => {
    for (const s of [...sessions].reverse()) await s.close().catch(() => {})
    await bob.close().catch(() => {})
    await (server as AgentServer).close().catch(() => {})
  })
  return r
}

/** One tool call of a session that must not be an error (a session whose grant is in). */
export async function statusOf(p: McpProc): Promise<Json> {
  const r = await p.call('status')
  if (r.isError) throw new Error(`${p.label}: status answered ${JSON.stringify(r.value)}`)
  return r.value
}

/** Polls an async test every POLL_MS until it holds; throws naming `what` after `ms`. */
export async function eventually(what: string, test: () => Promise<boolean>, ms: number): Promise<void> {
  const end = Date.now() + ms
  while (!(await test())) {
    if (Date.now() > end) throw new Error(`timed out after ${ms} ms waiting for ${what}`)
    await sleep(POLL_MS)
  }
}

/** True when the session's tools run (its grant is in and its identity open). */
export const isReady = async (p: McpProc): Promise<boolean> => !(await p.call('status')).isError

/** Starts a session server behind its own stand-in `claude`; its tools answer the waiting line until the `y`. */
export async function startSession(r: Rig): Promise<McpProc> {
  const p = await McpProc.start(`session ${r.sessions.length + 1}`, [
    ANCHOR,
    MAIN,
    '--session',
    'auto',
    '--principal',
    'jane',
    '--grant-caveat',
    CAVEAT,
    '--dir',
    r.janeHome,
    '--relay',
    r.w.url,
    '--trust-root',
    r.bobParty.address,
  ])
  r.sessions.push(p)
  return p
}

/** The request code a waiting session shows in its error line "<name>: waiting for y at the agent, request <code>". */
export async function waitingCode(p: McpProc): Promise<{ readonly name: string; readonly code: string }> {
  let found: { name: string; code: string } | null = null
  await eventually(
    `${p.label} to show the code of its request`,
    async () => {
      const s = await p.call('status')
      const m = s.isError
        ? /^(s-[0-9a-f]{16}): waiting for y at the agent, request ([0-9a-f]+)$/.exec(String(s.value.detail))
        : null
      if (m !== null) found = { name: m[1] as string, code: m[2] as string }
      return found !== null
    },
    READY_DEADLINE_MS,
  )
  return found as unknown as { name: string; code: string }
}

/** A new session whose first grant is typed `y` at the agent; returns once its tools run. */
export async function grantedSession(r: Rig): Promise<Session> {
  const proc = await startSession(r)
  const { name, code } = await waitingCode(proc)
  r.terminal.type('y')
  await eventually(`${proc.label} to open`, () => isReady(proc), READY_DEADLINE_MS)
  const st = await statusOf(proc)
  const anchor = proc.anchorPid
  if (anchor === null) throw new Error(`${proc.label}: its stand-in claude reported no pid`)
  return { proc, name, address: st.address as string, anchor, code }
}

/** The session with the key address its status shows now: a re-grant takes a fresh key (spec/SPEC.md §13.5). */
export async function current(s: Session): Promise<Session> {
  return { ...s, address: (await statusOf(s.proc)).address as string }
}

/** The name the shared resolver gives the session whose stand-in `claude` is `anchor`, computed here from `ps`. */
export const expectedName = (r: Rig, anchor: number): string =>
  resolveSessionName(r.jane.address, { pid: anchor }).name

export async function inboxOf(p: McpProc): Promise<Msg[]> {
  const r = await p.call('inbox')
  return r.isError ? [] : (r.value.messages as Msg[])
}

/** Bob sends a root to jane; returns its envelope id. */
export async function rootFromBob(r: Rig, body: string): Promise<string> {
  const sent = await r.bob.call('send', { to: [r.jane.address], type: 'chat.v1', body })
  if (sent.isError) throw new Error(`bob's send: ${JSON.stringify(sent.value)}`)
  return sent.value.id as string
}

/** The messages at bob that answer `root` (their thread's prev holds it), with the key address that sent each. */
export async function answersTo(r: Rig, root: string): Promise<Msg[]> {
  return (await inboxOf(r.bob)).filter((m) => m.thread.prev.includes(root))
}

/** Every root a session's inbox holds is answered once by it, at the next poll: a model that answers what it reads. */
export class Responder {
  readonly answered = new Set<string>()
  #stop = false
  readonly #done: Promise<void>

  readonly proc: McpProc

  constructor(proc: McpProc) {
    this.proc = proc
    this.#done = this.#loop()
  }

  async #loop(): Promise<void> {
    while (!this.#stop) {
      try {
        for (const m of await inboxOf(this.proc)) {
          if (m.thread.prev.length > 0 || this.answered.has(m.id)) continue
          this.answered.add(m.id)
          await this.proc.call('send', { ...m.reply, type: 'chat.v1', body: `answer of ${this.proc.label}` })
        }
      } catch {
        return // the process ended
      }
      await sleep(POLL_MS)
    }
  }

  async stop(): Promise<void> {
    this.#stop = true
    await this.#done
  }
}

/** Polls until every root has at least one answer at bob; returns the answers per root, in the order given. */
export async function untilAnswered(r: Rig, roots: readonly string[]): Promise<Msg[][]> {
  await eventually(
    `${roots.length} roots to be answered`,
    async () => (await Promise.all(roots.map((id) => answersTo(r, id)))).every((a) => a.length > 0),
    ANSWER_DEADLINE_MS,
  )
  return await Promise.all(roots.map((id) => answersTo(r, id)))
}

/** The ids <home>/state/jane/desk-handled holds, in order (none: the file is not there); a line is `<id> <ts>`. */
export function ledger(r: Rig): string[] {
  const path = join(r.janeHome, 'state', 'jane', 'desk-handled')
  return existsSync(path)
    ? readFileSync(path, 'utf8')
        .split('\n')
        .filter((l) => l !== '')
        .map((l) => l.split(' ')[0] as string)
    : []
}

/** The audit lines of a session's edge that name an envelope: `event decision reason`, in order. */
export function auditOf(r: Rig, name: string, id: string): string[] {
  return readAuditLines(join(r.janeHome, 'state', name, 'audit.jsonl'))
    .map(parseAuditLine)
    .filter((l) => l.id === id)
    .map((l) => `${l.event} ${l.decision} ${l.reason ?? ''}`.trim())
}

/** How many opens the agent itself refused `not-in-grant` (its own audit): only the agent raises that code. */
export function agentRefusals(r: Rig): number {
  return readAuditLines(join(r.janeHome, 'agent-audit.jsonl'))
    .map(parseAuditLine)
    .filter((l) => l.event === 'open' && l.reason === 'not-in-grant').length
}

export const modeOf = (path: string): number => statSync(path).mode & 0o777

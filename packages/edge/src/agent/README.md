# The agent's protocol core (`packages/edge/src/agent/`)

The session half of the agent as pure logic and in-memory state: no socket, no file, no
terminal, no keychain. A server wraps it: the Unix socket at `<home>/agent.sock`, the client custody, `resign`
and the Receiver's awaited opener are built on this surface and are not here; keep-alive (packages/mcp and
packages/cli) calls `AgentClient.resign` and is the next piece. Import from `./agent/index.ts`.

## What the server supplies

| it supplies | where it goes |
|---|---|
| the peer uid check: refuse any peer whose uid is not the agent's with `not-authorized`, before calling in | before `handle`, `prepareGrant` |
| the clock (`Clock`, Unix seconds) and the rng (`Rng`, a CSPRNG) | `AgentOptions` |
| the principal's address, and its keys at login (`PrincipalKeys`: a `SignerLike` and an `OpenerLike`) | `new Agent`, `login` |
| the agent's own audit sink (`AuditSink`), wrapped in `AgentAudit` | `AgentOptions.audit` |
| the caveat evaluators of the read rule's limb (b) (`codingEvaluator`, a `group=` one) | `AgentOptions.evaluators` |
| one `connect()` per socket, its `nonce` sent to the session first, `disconnect()` when it closes | `connect`, `disconnect` |
| the request framing: one JSON object per request (`buildRequest` writes it) | `handle(conn, bytes)` |
| the terminal: print `PendingGrant.lines`, read one line, pass it as `answer` | `prepareGrant`, `confirmGrant` |
| one printed line when a `sign` reply has `renewal: true` | after `handle` |
| `ac logout` and SIGINT/SIGHUP: call `logout()`, re-sign the address record with the subjects it returns added to `revoked`, zero the keys | `logout` |

## The request on the wire

```
{"seq": 0, "session": "ed25519:<64 hex>", "op": "sign" | "open" | "register", "args": [...], "sig": "<128 hex>",
 "chain": [hops]            // optional; required on a connection's first request, may replace the authority later
 "envelope": "<JSON text>"} // open only: the envelope's exact JSON text
```

`args` is `[sub, caveats, exp]` (sign), `[mailbox, id]` (open) or `[thread]` (register). `sig` is the session key's
signature over `["ac/agent/1", nonce, seq, session, op, sha256hex(canonical(args))]`, where `nonce` is the
connection's: it is not sent back, the agent fills it in, so a request replayed on another connection is `bad-sig`.

## The exported surface

```ts
// agent.ts
interface PrincipalKeys { readonly signing: SignerLike; readonly sealing: OpenerLike }
interface AgentOptions { principal: string; clock: Clock; rng: Rng; audit: AgentAudit; evaluators: readonly CaveatEvaluator[] }
type Connection = { readonly nonce: string }
type AgentRefusal = { readonly ok: false; readonly code: AgentCode }
type AgentReply = AgentRefusal
  | { ok: true; op: 'sign'; hop: Hop; renewal: boolean }
  | { ok: true; op: 'open'; content: SealedContent }
  | { ok: true; op: 'register' }
interface PendingGrant { readonly ok: true; readonly hop: UnsignedHop; readonly lines: readonly string[] }
type GrantReply = AgentRefusal | { ok: false; code: 'declined' } | { ok: true; hop: Hop }
class Agent {
  readonly principal: string
  constructor(options: AgentOptions)
  windowEnd(): number | null                               // null: no window, every request is agent-locked
  login(keys: PrincipalKeys, seconds?: number): number      // the window's end; throws on a second window, keys not the principal's, bad seconds
  logout(): readonly string[]                               // the live grants' subjects, sorted, for logout's revoked
  connect(): Connection
  disconnect(conn: Connection): void
  handle(conn: Connection, input: Uint8Array | string): AgentReply   // never throws a verdict; a fault propagates
  prepareGrant(req: GrantRequest): PendingGrant | AgentRefusal
  confirmGrant(pending: PendingGrant, answer: string): GrantReply    // exactly "y" (trimmed) signs
}

// audit.ts
type AgentAuditEvent = 'sign' | 'open'
interface AgentAuditEntry { event; decision: 'accept' | 'reject'; reason: AgentCode | 'ok'; id; from; root; detail }
function signEntry(reason: AgentCode | 'ok', hop: UnsignedHop, from: string | null): AgentAuditEntry
function openEntry(reason: AgentCode | 'ok', req: Pick<OpenRequest, 'id' | 'session' | 'mailbox'>, root: string,
  rule: ReadRule | null): AgentAuditEntry
class AgentAudit { constructor(sink: AuditSink, clock: Clock); record(e: AgentAuditEntry): string }

// model.ts
const AGENT_TAG = 'ac/agent/1'
const WINDOW_MAX = 28_800, MIN_CAVEATS = 1, OPENS_PER_MINUTE = 600, SIGNS_PER_MINUTE = 60,
  THREADS_PER_SESSION = 4_096, SEQ_MAX = 1_000_000, NONCE_BYTES = 32         // the agent's caps; implementation defaults
const AGENT_CODES = ['agent-locked', 'not-in-grant'] as const
type AgentLocalCode = 'agent-locked' | 'not-in-grant'
type AgentCode = AcErrorCode | AgentLocalCode
class AgentError extends Error { readonly code: AgentCode; constructor(code: AgentCode, detail: string) }
function codeOf(error: unknown): AgentCode                 // rethrows anything that is not a code
type AgentOp = 'sign' | 'open' | 'register'
interface SignRequest { op: 'sign'; seq; session; sig; argsHash; chain: readonly Hop[] | null; sub; caveats; exp }
interface OpenRequest { op: 'open'; ...; mailbox; id; envelope: string }
interface RegisterRequest { op: 'register'; ...; thread }
type AgentRequest = SignRequest | OpenRequest | RegisterRequest
function parseRequest(input: Uint8Array | string): AgentRequest
function argsHash(args: CanonicalValue): string
function requestPreimage(nonce: string, r: Pick<AgentRequest, 'seq' | 'session' | 'op' | 'argsHash'>): CanonicalValue
function buildRequest(session: SignerLike, nonce: string, seq: number, op: AgentOp, args: readonly CanonicalValue[],
  extras?: { chain?: readonly Hop[]; envelope?: string }): string   // the session client's side

// rules.ts (pure)
type UnsignedHop = Omit<Hop, 'sig'>
interface GrantRequest { readonly session: string; readonly caveats: readonly string[]; readonly exp: number }
function hopDigest(h: UnsignedHop): string
function hasCaveatPrefix(caveats: readonly string[], prefix: readonly string[]): boolean
function deriveHop(principal: string, effective: readonly string[], req: Pick<Hop, 'sub' | 'caveats' | 'exp'>,
  limit: number): UnsignedHop
function checkGrant(principal: string, req: GrantRequest, limit: number): UnsignedHop
function grantLimit(now: number, end: number): number
type ReadRule = 'thread' | 'root'
type ReadDecision = { release: true; rule: ReadRule }
  | { release: false; rule: ReadRule; reason: 'not-in-grant' | 'caveat-failed' | 'unknown-caveat' }
function decideRead(content: SealedContent, threads: ReadonlySet<string>, caveats: readonly string[],
  evaluators: readonly CaveatEvaluator[], ctx: Omit<CaveatContext, 'sealed'>): ReadDecision
function grantLines(hop: UnsignedHop): readonly string[]
```

## Order of checks and codes

`handle`: parse (`bad-shape`, a malformed chain's own codes) → window (`agent-locked`) → `seq` (`rate-limited` from
SEQ_MAX, `bad-shape` unless one above the last) → request signature (`bad-sig`; a refused signature spends no `seq`) →
authority (the chain judged at the agent's clock with §6.2's codes, `not-authorized` for a root that is not the
principal or a session that is not the chain's last sub, `hop-expired` at every request, `not-in-grant` when the
principal hop is not in this window's grant-set) → the per-minute caps (`rate-limited`) → the op. `sign`: `bad-hop`,
`too-many-caveats`, `caveat-too-long`, `not-in-grant`, `exp-not-monotone`. `open`: `not-authorized` (not the
principal's mailbox), `envelope-too-large`, `bad-json` and the envelope shape codes, `bad-shape` (the envelope is not
the one named), `bad-id`, `bad-sig`, `not-recipient`, `open-failed`, `bad-content`, then the read rule, whose every
refusal is `not-in-grant`. `register`: `rate-limited` past 4,096 threads.

Every `sign` and `open` refusal is audited only after the request's signature verifies (a request refused
while the agent is locked, or for its `seq` or signature, writes no line). A grant prompt refused at the
terminal (any answer but `y`, or none) writes one `declined` line: event and reason `declined`, decision
`reject`, id and from null, the `sign` line's detail. A withheld read is audited with its precise
reason (`caveat-failed`, `unknown-caveat`, `not-in-grant` for an unregistered reply) and the limb; `register`
is not audited. The agent's audit is its own log, in the edge's line format: the edge's `parseAuditLine` and
`verifyAuditLog` read it (the events `sign`, `open` and `declined`; the codes `agent-locked` and
`not-in-grant` on the agent's events only, and `declined` on the `declined` event only), and an `AgentAudit`
continues a chain the edge's `Audit` began, or the other way round. `Audit.record` writes the edge's own
events only; the agent writes its lines itself through `AgentAudit`.

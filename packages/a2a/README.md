# @usebag/a2a

The A2A binding of bag: an unmodified A2A client completes a task with a bag agent through the
caller's own local bridge, and every relay between them carries ciphertext only. Pre-release.

**The A2A version implemented is 1.0.0**: the specification at <https://a2a-protocol.org/v1.0.0/specification/>, and its
normative proto, `specification/a2a.proto` at tag `v1.0.0` of `github.com/a2aproject/A2A`, commit
`173695755607e884aa9acf8ce4feed90e32727a1`. The objects are the proto's ProtoJSON form: camelCase members, enums by
name (`TASK_STATE_COMPLETED`, `ROLE_USER`), no `kind` member (removed in 1.0, Appendix A.2.1). The repository holds no
JSON schema file: at v1.0.0 A2A publishes none in git (`specification/json/README.md` says it is a build artifact of
the proto), so this package is written against the proto and the specification's text, both read on 2026-10-28.

## How it works

```
A2A client --HTTP JSON-RPC--> A2aBridge (127.0.0.1:7741) --sealed envelope--> relay --> agent edge --> A2aServer
           <-----------------               <------------- sealed reply in the same thread -------------
```

- **The message type.** One A2A JSON-RPC call is one envelope of the sealed type `a2a.jsonrpc.v1`, named as the
  repository's other profile types are (`group-key.v1`, `peer.request.v1`). Its body is
  `{"a2a": "1.0", "request": <the JSON-RPC 2.0 request, as the client sent it>}`; the answer is a reply in the same
  thread, of the same type, `{"a2a": "1.0", "response": <the JSON-RPC 2.0 response>}`. `type`, `thread` and `body` are
  the sealed content of `spec/SPEC.md` §5.2, so the method, the params and the result never reach a relay, which sees
  the nine outer members of §5.1. §5.2 already allows any `type` and any JSON `body`: packages/core, the edge and the
  MCP server are unchanged.
- **The bridge** (`A2aBridge`, `src/bridge.ts`), on the caller's machine, over the caller's edge: an HTTP server on
  the loopback only (127.0.0.1 by default; `host` may name another 127.0.0.0/8 address, `::1` or `localhost`, and any
  network address such as `0.0.0.0` or a LAN IP is refused before the bridge listens), port 7741 by default, that answers `POST /a2a/<address>` with `content-type: application/json` and
  `A2A-Version: 1.0`. It seals each request to `<address>` on a new thread bound to its session, waits for the reply in
  that thread from that address (30 s by default), and returns the response as it came. It answers itself: 403 for a
  Host header that is not `127.0.0.1`, `localhost` or `[::1]` at its port and for any request with an Origin (DNS
  rebinding and cross-site requests from a browser), 404 for another path or an address outside `agents`, 405, 415,
  413 over 24,576 bytes (set when an envelope was at most 64 KiB, the sealed content travelling as hex; the cap is
  196,608 since the release after v0.3.0, and this bound has not moved), Parse error, Invalid
  Request, VersionNotSupportedError (-32009) for any version but 1.0, an empty or absent header being 0.3 (section
  3.6.2), Internal error when the agent cannot be reached or does not answer in time, and InvalidAgentResponseError
  (-32006) for a reply that is not a response to the request. A client that goes away mid-body is dropped.
- **The agent** (`A2aServer` and `a2aSessionHandler`, `src/server.ts`): `edge.setDefault(a2aSessionHandler(edge,
  server))` answers each `a2a.jsonrpc.v1` envelope with the server's response, sealed back in its thread. Delivery
  returns at once and the answer is made in the background, so a long turn never holds the edge's frame loop; a fault
  in making or sending the answer goes to `onError`. The agent's code is one handler,
  `(turn) => ({state?, parts?, artifacts?})`, called once per message; its outcome is read as JSON (a function or a
  BigInt in it makes it invalid), and a handler that throws, an invalid outcome or a fault after the handler answered
  fails the task with a fixed text (its error is not shown).
- **Bounds of the server.** Tasks are in memory, each owned by the principal that opened it: another principal's
  GetTask or CancelTask is TaskNotFoundError, as for an unknown id. At most 1,000 tasks and 100 per principal; past a
  bound the oldest finished task is forgotten, a live one (working or interrupted) never, and with every slot live the
  request is refused with -32000 (JSON-RPC 2.0's implementation-defined server error: A2A 1.0 names no error for an
  agent at its limit). At most 16 turns run at once, -32000 past that. A blocking SendMessage waits at most 20 s,
  under the bridge's 30 s, then answers the working task, which the client reads again with GetTask.
- **Size.** An answer whose task cannot fit a sealed reply even without its history and artifacts fails its task at the
  turn's end (`the answer is over 24576 bytes, dropped`), so every stored task stays readable; a response that does not
  fit whole is sent without the task's history (section 3.2.4 leaves the default history to the implementation), then
  without its artifacts too.

## Agent cards: no public agent-card.json

Built now, and easy to reverse (one generator and one Worker path):

- **No public `/.well-known/agent-card.json` is served at all.** A2A 1.0.0 section 14.3 says the resource at that path
  MUST be an AgentCard; an AgentCard requires `supportedInterfaces` (section 4.4.1; a2a.proto marks
  `supported_interfaces` REQUIRED) and each interface must declare its URL accurately (section 8.3.1); and the only URL
  that reaches the agent is the caller's own bridge on loopback. A card without it would be invalid, and a card with it
  would name a port on every reader's machine, so the path is the Worker's 404.
- **The public extension** at the org's `/.well-known/bag/a2a.json`, beside its address record, written by
  `deploy/make-a2a-extension.sh <label>` from that record and served by the well-known Worker as a fourth fixed path:
  the bag extension alone, an A2A AgentExtension object (section 4.4.4) with `uri` `urn:bag:a2a:v1`,
  `required: true`, and `params` `address`, `addressRecord` (the record's URL) and `envelopeType`. It names no loopback
  URL, and its description says it is not an AgentCard and where the card is.
- **The full AgentCard** at the bridge's loopback path, `GET /a2a/<address>/.well-known/agent-card.json`, built from
  the address record the bridge's edge fetched from the relays and verified (`Edge.resolver.address`): one interface,
  `JSONRPC` 1.0 at `http://127.0.0.1:<port>/a2a/<address>`; no streaming, no push notifications, no extended card;
  the extension with the address, the record's relays and the envelope type (the bridge does not know the org's
  domain, so the card names no public URL); the skill `message`. 404 `no-record` when no record of that key is found,
  502 `resolve-failed` when the lookup fails.

## Methods

- `SendMessage`: a new task, or the next message of an interrupted one (`TASK_STATE_INPUT_REQUIRED`,
  `TASK_STATE_AUTH_REQUIRED`) by its `taskId`. Blocking by default (at most 20 s); `configuration.returnImmediately`
  answers the working task at once; `configuration.historyLength` cuts the history. The result is always
  `{"task": ...}`. A push notification config (`taskPushNotificationConfig`, or 0.3's `pushNotificationConfig`) is
  PushNotificationNotSupportedError (-32003).
- `GetTask`: the task, `historyLength` honoured.
- `CancelTask`: `TASK_STATE_CANCELED` for a task not in a terminal state, whose late answer is dropped;
  TaskNotCancelableError (-32002) otherwise.
- `SendStreamingMessage` and `SubscribeToTask`: UnsupportedOperationError (-32004), no streaming. `ListTasks`: the same.
- The four push notification config methods: PushNotificationNotSupportedError (-32003).
- `GetExtendedAgentCard`: ExtendedAgentCardNotConfiguredError (-32007). Any other method: Method not found (-32601).
- ProtoJSON leniency: a role by its enum number (1, 2) and `historyLength` as a quoted decimal are read as ProtoJSON
  reads them.

Left out of 1.0, on purpose for now: streaming (SSE) and push notifications; ListTasks; the gRPC and HTTP+JSON
bindings; A2A 0.3 (its method names `message/send` and `tasks/get` are Method not found, and the `kind` member is not
written); security schemes on the card (the bridge is local and the envelope is signed and sealed); `tenant` (ignored);
tasks that outlive the agent's process; a direct Message result in place of a Task; IPv6 listening addresses.

## Use

The bridge as a process, composed on a home as the CLI and the MCP server compose theirs (the key from the home's
custody, the store and the audit log at `<home>/state/<name>/`):

```sh
node packages/a2a/src/main.ts --as <key name> --relay <url> --agent <address> [--port 7741] [--dir <home>]
```

It prints `a2a-bridge http://127.0.0.1:7741 as <address>` and runs until SIGINT or SIGTERM; `--help` lists the flags.
There is no `bin` entry in package.json, as for the CLI and the MCP server (`packages/cli/src/main.ts` says why: a bin
changes the npm lock). As a library:

```ts
// The caller's side: its edge trusts the agent's root and accepts the type, then the bridge listens.
const bridge = await A2aBridge.start({ edge: callerEdge, agents: [agentAddress] })
// An A2A client reads bridge.endpoint(agentAddress) + '/.well-known/agent-card.json' and calls the card's url.

// The agent's side: its edge trusts the caller's root and accepts the type, then answers.
const server = new A2aServer({ handler: (turn) => ({ parts: [{ text: `got: ${textOf(turn.message)}` }] }) })
agentEdge.setDefault(a2aSessionHandler(agentEdge, server))
```

Both edges need `a2a.jsonrpc.v1` among their policy's types (or `*`), the other side's root among their trusted roots,
and the other side in their accept-from record, as for any type. The bridge signs as its edge's identity for every
local caller, and it has no caller authentication: any process on this machine that can open a loopback connection
can send as the identity, the same trust as the command line on the same home. That is why it listens on the
loopback only (`host` is refused unless it is a 127.0.0.0/8 address, `::1` or `localhost`; the process exits 2 with
"the bridge listens on loopback only; it has no caller authentication"), refuses foreign Host headers and any Origin
(which stop browsers, not local programs), and `agents` limits whom it calls. A caller token, for a bridge that other
machines may reach, is a later option and is not built.

`deploy/make-a2a-extension.sh acme` writes `deploy/well-known/public/acme/.well-known/bag/a2a.json` from
acme's record; `--domain`, `--record` and `--out` change the rest (the script's header). The committed samples, acme's
and globex's, regenerate byte for byte (a unit test).

## Tests

`npm test -w packages/a2a`: the unit tests in `test/`, with the 90 floors of the other packages (statements, branches,
functions, lines over `src/**/*.ts`; the target is 100 on all four). The bridge's tests run real HTTP on 127.0.0.1
over an edge in memory, among them `refuses DNS rebinding: a foreign Host header or any Origin gets 403` and the
replay of the specification's own JSON-RPC requests (sections 9.4.1 with 6.1, and 9.4.3) byte for byte. No test binds
a fixed port: the default, 7741, is checked on a watched listen call that is given port 0. e2e scenario 48
(`packages/e2e/test/scenarios/48-a2a-sealed-task.test.ts`) runs the whole path through the release relay and reads
the relay's SQLite files for the plaintext. The package has no npm dependency beyond the workspace's edge.

# @usebag/shim: bag-shim

The thin stdio MCP server a host session starts (Claude Code, Codex, omp). It forwards every MCP message to the one
bag service of the home over `<home>/run/service.sock`, as the wire contract says (`docs/bag-service.md`, contract 1),
and holds no key, no store and no token on disk (`docs/bag-service.md`, "What runs").

```
bag-shim [--dir <home>] [--input-hook]     the proxy, on stdio
bag-shim hook [--dir <home>]               the typed-word hook (Claude Code's UserPromptSubmit)
```

The binary is `dist/bag-shim.js` of the published package (packages/bag/src/build.ts); in the repository,
`node packages/shim/src/main.ts`.

The home is `--dir`, else `AC_HOME`, else `$HOME/.bag`.

## What it does

- **Hello, then initialize.** It waits for the host's `initialize` (the client capabilities are in it), connects, reads
  the launch token from `<home>/run/service.token`, sends `service/hello` (`contract`, `token`, `host`, `cwd`,
  `client_capabilities`, `input_hook`, `shim`), then forwards the host's `initialize` and relays the service's answer.
  The host kind is found in this order: `OMPCODE=1` is omp, else `CLAUDECODE=1` is Claude Code, else the
  host's `clientInfo.name` (Codex says `codex`), else `other`.
- **Everything else passes unchanged**: tool calls, progress, cancellation, list-changed notices.
- **A Codex sub-agent's mark.** At the first tool call whose `_meta` has the window's `sessionId` with a `threadId` of
  its own, the shim marks its connection a sub-agent's, before it forwards that call. The mark lasts the connection's
  life (a later call without `_meta`, or with the window's own, keeps it; tool arguments are never read for it), and
  every tool call it forwards from then on carries `"_meta":{"bag.dev/subagent":true}` for the service.
- **Dialogs.** An `elicitation/create` from the service is shown to the host under an id of the shim's, with the
  `bag.dev/dialog` handle kept back; the host's answer goes back on the same connection with the handle echoed in
  `result._meta`. Neither hop has a timeout of the shim's (the SDK's 60 s default does not apply: the shim does not
  use the SDK). A cancellation from either side is passed on under the other side's id. Before a dialog is shown the
  shim checks that `<home>/run/service.json` names the pid that answered the hello and that it is alive; it never
  touches the service lock (a probe would make a starting service exit `busy`).
- **No service.** The shim starts one through the scrubbed launch (`/bin/sh -c 'ulimit -c 0; exec node
  --disable-sigusr1 ...'`, an allow-listed environment, detached) from `<home>/package/current`, and waits up to 5 s.
  If none answers, `initialize` is answered by the shim, `tools/list` holds one tool, `status`, and every tool call
  answers one readable error naming the start line (`bag service start --dir <home>`) and the login agent. The shim
  keeps looking; when the service comes up it says hello and tells the host the tools changed.
- **A restart mid-call.** Each call in flight fails with a readable error and is never sent again (a `send` must not
  go twice); each open dialog is cancelled at the host. The shim reconnects with backoff, reads the new token, says
  hello again, replays the host's `initialize` and `notifications/initialized`, and sends `tools/list_changed`. The
  session starts unbound, as the contract says.
- **A drain.** On `service/draining` new calls are held (never lost, never sent twice) and go out on the next
  connection, after `retry_after_ms`.
- **Resume tokens.** For a host with a short tool timeout (Codex, 60 s) a call still running at 50 s is answered
  with a token, and the shim's own tool `resume` (added to the service's tool list for that host) returns the result
  when it comes, or "still running" again after another 50 s. Tokens live in memory only.
- **Rings.** Each `service/ring` is written to the session's ring file, `<home>/run/shim/<host pid>.ring` (below), for
  every host kind; the shim never moves the identity's doorbell on a service connection, since that file is per
  identity and would wake every window bound to it. With `speaking: false` the shim also sends the host a quiet
  `notifications/message` when the service declared logging.
- **Lifecycle.** On stdin EOF, EPIPE on stdout, SIGTERM, SIGHUP or SIGINT (on a terminal stdin, which runs raw as the
  stdio server does for omp's pty: Ctrl-C or Ctrl-D) the shim closes its connection cleanly (the service then drops the
  binding and cancels the connection's pairings), removes its channel files and exits 0. On SIGUSR2 (Codex's
  SessionEnd hook, `wake-hook --session service --end`, sends it to the shim of the session that ended) it removes its
  session's files, ends its connection the same way and connects again unbound, and keeps serving the host.

## The typed-word channel (hook to shim)

The person binds a session by typing `use <name>`. The host's input hook catches the whole prompt (pattern
`^\s*use\s+([a-z0-9][a-z0-9._-]{0,63})\s*$`, "use" in any case) and posts it to its own shim, never to the service.
The shim sends `service/use` with `via: "typed"` on its connection; the service honours it only after a hello that
said `input_hook: true`. Every other interactive prompt is posted as `typed`, and the shim sends `service/typed`
(params `{}`), so the service knows the speaking window.

Paths and modes (the CLI's `host install` writes the matching sandbox entry; one entry for `<home>/run/` covers them):

| Path | Mode | What |
|---|---|---|
| `<home>/run/` | 0700, the user's, not a link | the service's run directory (the shim creates it 0700 if it is missing) |
| `<home>/run/shim/` | 0700, the user's, not a link | the channel directory; refused (channel off, `input_hook: false`) if it has a group or other bit, another owner, or is a link |
| `<home>/run/shim/<8 hex>.sock` | 0600 (umask 077 at listen) | one shim's channel socket, its name drawn at random |
| `<home>/run/shim/<host pid>.json` | 0600, renamed into place | the index: `{"v":1,"sock":"<8 hex>.sock","secret":"<64 hex>","shim":<pid>}` |
| `<home>/run/shim/<host pid>.bound` | 0600, renamed into place | the session's bound identities, for the wake hook and the omp extension (below) |
| `<home>/run/shim/<host pid>.ring` | 0600, renamed into place | the session's last ring, for the same waiters (below) |
| `<home>/run/shim/<host pid>-<session id>.bound`, `.ring` | as above | Codex: the same two files of one window. Codex runs one server process for all of its windows, so the shim keys them by the window's session id (`_meta.sessionId`, else `threadId`, of its tool calls; a uuid) once a tool call names it, and moves them when it changes; the Stop hook finds them by its input's `session_id` |

`--input-hook` is passed by the installer only where it also wrote the hook; without it the channel stays off and the
hello says `input_hook: false`. The host pid is the shim's parent, or past a launcher (sh, bash, zsh, env, npx, npm,
pnpm, yarn, bunx, uvx) that one's parent, up to four steps. A hook walks its own ancestors (up to eight) and uses the
first one with an index. Requests, one line each: `{"v":1,"kind":"use","name":"omp-3","secret":"<64 hex>"}`, answered
`{"bound":true,"as":"omp-3"}` or `{"bound":false,"code":"<bag code>"}`; `{"v":1,"kind":"typed","secret":"<64 hex>"}`,
answered `{"typed":true|false}`. Any other kind (0.4.1's `bridge` included) is `{"bound":false,"code":"usage"}`.
The secret is compared with `timingSafeEqual`; a wrong one is `bad-auth`.

`bag-shim hook` (Claude Code's UserPromptSubmit) reads the hook's JSON on stdin. For `use <name>` it posts the word
and prints `{"decision":"block","reason":"bag: this session now acts as <name>."}` (or why not), so the model never
acts on it. It prints nothing, and the prompt goes on to the model, for any other prompt, when no shim of this window
answers, and for `unknown-identity` (so "use pandas" still reaches the model).

**The honest limit.** Same-user is not a security boundary (`docs/bag-service.md`, "What it protects, and what it does
not"). Any process of the user that can read `<home>/run/shim/` can read an index and post a typed word for that window,
and get a binding with no dialog; a model's unsandboxed shell can. The secret stops other users (with the 0700
directories), every shim after it closes, and a process that cannot read or write `<home>/run/`: the case where the
host's sandbox denies the model's tools that path. On Claude Code that needs `sandbox.enabled` with
`denyRead`/`denyWrite` for `<home>/run` (the permission rules alone stop only the built-in tools). Codex has no
deny-read, and omp has no path sandbox: there the typed path is exactly as strong as same-user, which is none.

## The bound file, for the waiters

The wake hook (Claude Code, Codex) and omp's wake extension need to know which identities their session is bound to,
which only the shim and the service know. The shim writes `<home>/run/shim/<host pid>.bound`:

```json
{"v":1,"as":["omp","omp-3"],"shim":4242}
```

`as` is the connection's bound labels in bind order (from `service/bound` and each typed bind's answer), `shim` the
shim's pid. It is 0600, written beside and renamed over on every change, and removed when the list becomes empty (the
connection was lost: the service drops its bindings) and when the shim exits. The shim removes it only while it still
names its own pid. A reader finds it by its host pid, as a hook finds the index: Claude Code's and Codex's hooks walk
their ancestors, omp's extension uses its own `process.pid`. A reader ignores a file that does not parse, has another
`v`, or whose `shim` pid is not alive (a shim killed with SIGKILL leaves one behind), and then wakes on nothing. While
the file exists the waiter wakes from the ring file only (next section), never from a doorbell. The service has no
unbind notification yet, and the shim sends no `service/unbind`, so a label leaves the file only with the connection.

## The ring file, for the waiters

On every `service/ring` the shim writes `<home>/run/shim/<host pid>.ring`:

```json
{"v":1,"n":2,"as":"omp","unread":3,"speaking":true,"at":"2026-11-12T12:45:10Z","shim":4242}
```

`n` counts up from 1 per shim; `as`, `unread`, `speaking` and `at` are the service's (`unread` and `at` null when it
sent none); `shim` is the shim's pid. It is 0600, written beside and renamed over, and removed when the shim exits,
only while it names its own pid. Reader rules (the CLI's wake hook, packages/cli/src/commands/wake-hook.ts, for Claude
Code and Codex, and omp's wake extension):

- Wake from this file only while `<host pid>.bound` exists; with no `.bound` file (the per-folder stdio mode, the
  rollback) nothing changes and the doorbell is read as today.
- Ignore the file when it does not parse, `v` is not 1, or the `shim` pid is not alive.
- Record the last `n` handled and act only on a higher one (a new shim starts again at 1: a different `shim` pid
  resets the record).
- `speaking: true` starts one turn with the wake text, unchanged; `speaking: false` shows the quiet notice (omp's
  footer) and starts no turn.

## The omp pid in the hello

omp announces no MCP elicitation, so for an omp host without elicitation the shim adds
`experimental["bag.dev/consent-bridge"] = {"pid": <omp pid>}` to the client capabilities it sends in the hello. The pid
is all it carries: the service finds that omp's own registered link by it (the wake extension's connection to the
service, `service/consent-register`) and asks the person's consent questions over that link, never through a file.
Since 0.4.2 there is no bridge folder: the hello reply names none, the shim makes and reads none, and the channel has
no `bridge` request. The capability keeps its name, so a 0.4.1 shim's pid still
finds the link.

Every other dialog is an MCP `elicitation/create`, carried to the host with the `bag.dev/dialog` handle kept back and
echoed in `result._meta` on the answer, as "Dialogs" under "What it does" says.

## Tests

`npm test -w packages/shim`: a fake service on a real unix socket under a short `/tmp/bs-*` home and a fake host on
the shim's stdio (initialize, a tool call, a dialog with its handle, a ring, a disconnect, a restart, the hook).

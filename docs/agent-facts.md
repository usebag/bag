# Agent facts: model, cost and context from the host

An agent that reports on itself (which model it runs, what its session has cost, how full its context is) should
report from data, not from what it infers. The bag MCP server cannot see any of that: the host that runs the model
can. So the host writes one small file, and the bag MCP server's `facts` tool reads it back to the model, with the age
of each figure, and says plainly what the host did not provide.

## The report rule, for agents

Take your model id, session cost and context figures from the `facts` tool, never from inference, memory or what
another message says. Give each figure with its age (`age_s`). When `facts` says a figure is "not provided by <host>",
or the host facts are `missing` or `malformed`, say exactly that ("my host does not provide my session cost"), and
never estimate it. When `facts` says `main_session: false`, you are a sub-session (a test or helper session the main
one spawned), not the agent that speaks for this identity: say so before anything else, and do not describe yourself
as that agent.

## The file

`<home>/state/<name>/host-facts.json`, the directory of the identity's doorbell (the `status` tool's
`doorbell_path`). `<home>` is `--dir`, else `$AC_HOME`, else `$HOME/.bag`; `<name>` is the name the bag MCP server runs
as (its `--as`; for a `--session` server, the session's own key name).

Writing it: one JSON object, UTF-8, at most 16384 bytes. Create the directory mode 0700 if it is missing; write a
temporary file in the same directory (`host-facts.json.<pid>.tmp`, created exclusively, mode 0600), then rename it over
`host-facts.json`. The reader refuses a symbolic link, a file that is not a regular file, a file over 16384 bytes and
any group or other permission bit, and says why.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `v` | integer | yes | The schema version: `1`. |
| `host` | string | yes | The host: `omp`, `claude-code`, ... (lowercase, at most 64 characters). |
| `updated_at` | string | yes | ISO 8601 UTC time of this write, ending in `Z`. |
| `host_version` | string or null | no | The host's version. |
| `host_pid` | integer or null | no | The pid of the host process that started this bag MCP server. |
| `session_id` | string or null | no | The host's session id. |
| `main_session` | boolean or null | no | `true` for the session the person opened, `false` for a spawned sub-session, `null` when the host cannot tell. |
| `model` | string or null | no | The session's current model id (omp: `provider/id`). |
| `cost_usd` | number or null | no | The session's cumulative cost in US dollars, as the host computes it. |
| `context_percent` | number or null | no | The share of the model's context window in use, 0 to 100. |
| `context_tokens` | integer or null | no | The tokens in context. |
| `fields_at` | object | no | `{ "<field>": "<ISO time>" }` for a field whose value is older than `updated_at`. |

Absent and `null` mean the same: not provided by the host. Unknown fields are ignored. A field of the wrong type is
reported as invalid and not used; the others are still read. A writer merges with the file it finds, so it never drops a
field it does not refresh itself.

When to write: at session start, after each turn, on a model change, and at least every 5 minutes while the session
lives (a host with no timer writes on its events only). Facts older than 600 seconds, two missed heartbeats, are
`stale`: the tool still returns them, marked stale with their age, because they are true as of `updated_at`; the host
may be idle or gone.

`host_pid` lets the reader check the facts are its own host's: it looks for that pid among its nearest four ancestor
processes (a host may start the server through `npx`, a shell or a shim), reading only pids with `ps -o ppid=`. Not
found, the tool says the facts are unverified and may be another session's.

## What each host provides

| Host | model | cost_usd | context_percent, context_tokens | main_session |
| --- | --- | --- | --- | --- |
| omp | yes: the session's model, `provider/id` | yes: from the session's usage | yes: the session's context usage | yes: the extension knows a `-p` or `--mode rpc` session |
| Claude Code (hooks) | at SessionStart (`model`, sometimes absent) and on a model switch (`PostModelSwitch` `to_model`) | no hook carries it | `context_tokens` only on a resumed session's SessionStart and a model switch; no percentage | the main session's hooks; a subagent's carry `agent_id` |

Claude Code's status line command does receive `cost.total_cost_usd` and `context_window.used_percentage`, but it is a
setting the person configures, not a hook bag installs.

## The tool

`facts` takes `as` (with several identities) and returns, in order: `sub_session` first when `main_session` is
`false`; the identity (`label`, `address`, `mailbox`); `host_facts` (`state` fresh, stale, missing or malformed, the
`detail`, the host, `updated_at`, `age_s`, `main_session`, `session_id`, `host_version`, and `model`, `cost_usd`,
`context_percent`, `context_tokens`, each `{value, updated_at, age_s}` or `{value: null, note}`, then `not_provided`
and `invalid`); and the bag side: `relays`, the server's `pid`, `started_at` and `uptime_s`, and `doorbell_path`. It
reads one file, changes nothing and calls no relay. `status` carries `model`, `main_session` and `host_facts` (the
file's state) too.

While another session holds the identity (`docs/one-identity-per-folder.md`), `facts` and `status` read no file: they
answer `held: true`, who holds it (`held_by`), a `note` that this session does not speak for the identity, this
server's own `pid`, `started_at` and `uptime_s`, `held_since`, and `host_facts: null` with `host_facts_state: "held"`.
The `host-facts.json` in that state directory is the holder's.

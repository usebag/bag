# One identity per folder: the lock

A bag identity has one MCP server at a time. The server owns the identity's mailbox (its edge store, its cursor, its
acknowledgements), and two servers on one mailbox would read and acknowledge the same messages. A lock file keeps it to
one. This page says what the lock is, what a second session sees, what happens when a session ends, and what the
command line does beside a running server.

## The rule

- Give each folder you run an agent in its own identity: the folder's host configuration (for Claude Code and Codex,
  `bag host install`; for any other MCP host, its MCP configuration) names one `--as` name, and no other folder uses it.
- Two agents in two folders get two identities. Two sessions opened in one folder share one: the first to start runs
  bag, the second is told who holds it (below).
- Make a second identity with `c keygen second-agent` and point the other folder's configuration at it.

## The lock

The server takes `state/<name>/mcp.lock` in the home (`~/.bag` unless `--dir` or `AC_HOME` says otherwise) when it
starts, and removes it when it stops. The file is one line of JSON:

```json
{"pid":4242,"keep_alive":false,"started_at":"2026-11-11T12:28:41.666Z","cwd":"/home/you/work/agent-a","ppid":4100,"host":"omp"}
```

`pid` is the server's process. `started_at` and `cwd` say when and where it started, `ppid` is the process that
started it, and `host` is the kind of MCP client that connected: `claude-code`, `codex`, `omp` or `other` (it appears
once the client has introduced itself). A reader needs only `pid`; every other field may be absent.

## A second session in the folder: held by

A second server on a held identity does not exit. It stays up as a server whose tools all answer one error, so the host
shows a readable message instead of "Connection closed":

```
bag: the identity agent-a is held by another session (pid 4242, started 2026-11-11T12:28:41.666Z, omp) in /home/you/work/agent-a; close that session or run bag in its own folder
```

The `status` and `facts` tools of that server return `{"held": true, "held_by": {"pid", "started_at", "cwd", "host",
"path"}, "note", "message", "pid", "started_at", "uptime_s", "held_since", "held_from_start", "host_facts": null,
"host_facts_state": "held"}` instead: `path` is the lock, `note` says this session does not speak for the identity,
the bare `pid`, `started_at` and `uptime_s` are this server's own, and `held_since` is when it became held (null, with
`held_from_start` true, when it was held from its start). Neither reads the holder's `host-facts.json`. Every other tool returns the error `busy` with the same message. The server also writes one `held` line to its
log on stderr.

## When the holder ends: takeover

- **The holder's host closes normally.** The server sees its stdin end, stops, and removes the lock.
- **The holder's host dies without closing the pipe** (a process that inherited it keeps it open). The server checks
  every two seconds that the process that started it is still its parent (and, when that parent is a launcher such as a shell or `npx`,
  that the process above it is still there). When one has gone it writes one
  `orphaned` line, stops, and removes the lock, about two seconds after the host went.
- **The holder crashes or is killed.** The lock stays on disk, but its pid is gone, and the next server to start
  replaces it.
- **A held server takes over by itself.** It tries the lock again every three seconds; when the holder is gone it
  opens the identity, writes one `takeover` line, and its tools work from the next call. Killing a session and starting
  a new one in the same folder therefore needs no manual step.

If a process you do not recognise still holds the lock, `c status --as agent-a` prints its pid, start time, host and
folder on a `held_by` line. Close that session, or end that process yourself; the lock is never removed by hand.

## The command line beside a running server

`c inbox` is a receiver: it subscribes, acknowledges and advances the mailbox cursor, so it cannot run beside the
server that holds the identity, and bag does not read the server's store behind its back. Beside a running server it
stops with one line and exit status 1:

```
bag: held: the identity agent-a is held by a running bag MCP server (pid 4242, started 2026-11-11T12:28:41.666Z, omp, in /home/you/work/agent-a); that session reads this mailbox with its inbox tool, so inbox needs that session closed first
```

Read the mail through that session's `inbox` tool, or close the session and run `c inbox` yourself. `c status --as
agent-a` always works and adds the `held_by` line while a server holds the identity.

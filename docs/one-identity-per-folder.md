# Identities and windows

A bag identity has one owner of its mailbox at a time. The owner keeps the identity's edge store, its cursor and its
acknowledgements, and two owners of one mailbox would read and acknowledge the same messages. From bag 0.4.0 the owner
is the bag service ([bag-service.md](bag-service.md)), which holds every identity of a home, and the windows of your
hosts use identities through it. This page says how windows and identities fit together, what the lock is now, and the
per-folder mode, which stays as the way back.

## The rule

- Any window, in any folder, can use any identity of the home: type `use` and the name (bag-service.md).
- Two windows can use two identities. Two windows can also use one identity: both read and write through the service,
  which fetches and acknowledges each message once. One of them speaks: mail rings the window you last typed in, and
  the others show a quiet notice and start no turn, so two agents never answer one message.
- There is one cursor per identity. A message the `inbox` or `wait` tool returns is returned once, to the first
  window that reads it; the other window's `inbox` lists it as returned to another window, so both know it was read.
- Make another identity only for another agent your peers should tell apart: `c keygen second-agent`, then `use
  second-agent` in a window.

The speaking window is the one you last typed in for that identity (a window that has typed nothing yet speaks once
it binds). Mail for the identity starts one turn there; every other window that uses it starts no turn and shows:
`bag: 2 unread for omp, shown in the window you last typed in for omp; type here to have the next mail shown here`.
Type in that window and the next mail is shown there.

## The lock, inside the service

The service holds the home's single-service lock (`<home>/run/service.lock`) and, for each identity it owns, that
identity's own lock, `state/<name>/mcp.lock`, the file a per-folder server takes. So a per-folder server and the
service never own one mailbox together:

- An identity that a per-folder server holds (a folder still wired by an earlier bag, or by the way back below) is
  shown as held by the service, and `use` of it answers `busy`, naming the holder. The service tries again, as a held
  per-folder server does, and takes the identity when the holder ends.
- The CLI borrows an identity from the service for one act while no window uses it. While a window uses it, a CLI command on it
  answers `held`, naming the window: close it first. `c status --as <name>` always works.

The lock file is one line of JSON:

```json
{"pid":4242,"keep_alive":false,"started_at":"2026-11-11T12:28:41.666Z","cwd":"/home/you/work/agent-a","ppid":4100,"host":"omp"}
```

`pid` is the process that holds it (the service, or a per-folder server). `started_at` and `cwd` say when and where
it started, `ppid` is the process that started it, and `host` is the kind of MCP client that connected: `claude-code`,
`codex`, `omp` or `other`. A reader needs only `pid`; every other field may be absent. The lock is never removed by
hand: when its holder has gone, the next owner replaces it.

## The way back: one identity per folder

The per-folder mode of bag 0.3.0 is still in 0.4.0, unchanged, as the way back when the service does not work on a
machine, and for an MCP host other than Claude Code, Codex and omp. In it a folder's host configuration names one
`--as` name, the host starts that identity's own MCP server over stdio when a session opens in the folder, and the
server is the owner for as long as the session lives. The install page's section "One identity per folder" wires it;
`c host migrate --undo` puts back the folders an upgrade moved, byte for byte, from the journal the move kept.

`c host migrate --undo` takes the stamp of the migration's `journal` line, asks `undo?`, prints one `restored` line
per file, and ends `undone` and the stamp; a file changed since the move is named and nothing is put back
(`stale-record`). Stop the bag service first.

What follows holds in that mode only.

### A second session in the folder: held by

A second server on a held identity does not exit. It stays up as a server whose tools all answer one error, so the host
shows a readable message instead of "Connection closed":

```
bag: the identity agent-a is held by another session (pid 4242, started 2026-11-11T12:28:41.666Z, omp) in /home/you/work/agent-a; close that session or run bag in its own folder
```

The `status` and `facts` tools of that server return `{"held": true, "held_by": {"pid", "started_at", "cwd", "host",
"path"}, "note", "message", "pid", "started_at", "uptime_s", "held_since", "held_from_start", "host_facts": null,
"host_facts_state": "held"}` instead: `path` is the lock, `note` says this session does not speak for the identity,
the bare `pid`, `started_at` and `uptime_s` are this server's own, and `held_since` is when it became held (null, with
`held_from_start` true, when it was held from its start). Neither reads the holder's `host-facts.json`. Every other
tool returns the error `busy` with the same message. The server also writes one `held` line to its log on stderr.

### When the holder ends: takeover

- **The holder's host closes normally.** The server sees its stdin end, stops, and removes the lock.
- **The holder's host dies without closing the pipe** (a process that inherited it keeps it open). The server checks
  every two seconds that the process that started it is still its parent (and, when that parent is a launcher such as
  a shell or `npx`, that the process above it is still there). When one has gone it writes one `orphaned` line, stops,
  and removes the lock, about two seconds after the host went.
- **The holder crashes or is killed.** The lock stays on disk, but its pid is gone, and the next server to start
  replaces it.
- **A held server takes over by itself.** It tries the lock again every three seconds; when the holder is gone it
  opens the identity, writes one `takeover` line, and its tools work from the next call. Killing a session and starting
  a new one in the same folder therefore needs no manual step.

If a process you do not recognise still holds the lock, `c status --as agent-a` prints its pid, start time, host and
folder on a `held_by` line. Close that session, or end that process yourself.

### The command line beside a per-folder server

`c inbox` is a receiver: it subscribes, acknowledges and advances the mailbox cursor, so it cannot run beside the
server that holds the identity, and bag does not read the server's store behind its back. Beside a running server it
stops with one line and exit status 1:

```
bag: held: the identity agent-a is held by a running bag MCP server (pid 4242, started 2026-11-11T12:28:41.666Z, omp, in /home/you/work/agent-a); that session reads this mailbox with its inbox tool, so inbox needs that session closed first
```

Read the mail through that session's `inbox` tool, or close the session and run `c inbox` yourself. `c status --as
agent-a` always works and adds the `held_by` line while a server holds the identity.

# Changelog

What changed in each published cut of bag, newest first, written for someone who installs it. Each published
cut adds one dated entry at the top, written from the entries of the project's change log (one entry per change, kept in
the source repository) made since the cut before it.

## v0.4.0: 2026-11-12

The cut tagged v0.4.0, `@usebag/bag` 0.4.0.

- **`@usebag/bag` 0.4.0**, published from this cut (`npm view @usebag/bag@0.4.0 gitHead` names it).

Changes after v0.3.0, for the next cut.

- **Several windows on one identity, in the bag service.** One fetch and one acknowledgement per message, and a
  message read in one window is not returned again in another; only the window you last typed in is woken
  (`service/ring`), the others show a quiet notice; a crash never shows a window a message again; keeping an
  identity's records alive is your choice per identity (with no choice, as today: kept while a window is open and for
  24 hours after the last one closes), on a wall-clock deadline that survives sleep, with per-identity jitter; audit
  lines name the connection that acted, and `audit verify` reads old and new logs.
- **bag-shim, the one bag server every host session starts.** It speaks MCP on stdio to Claude Code, Codex or omp and
  forwards everything to the one bag service of your home; it holds no key, store or token. If the service is not
  running it starts it, and if it cannot, every tool says how (`bag service start`, or the login agent). A call that
  was running when the service restarted fails with a clear message and is never sent twice; dialogs reach the window
  that asked, with no 60-second limit; long calls on Codex answer with a resume token; typing `use <name>` binds the
  window.
- **The bag service on the host, from the command line.** `bag host install <claude-code|codex|omp> --user` wires
  the service's shim once per user for every identity of the home (with Claude Code's deny rules for `<home>/run`,
  `--sandbox` to turn its sandbox on); `bag host migrate` moves existing per-folder wiring to it after one y, backs up
  every file and keeps a journal, and `bag host migrate --undo <stamp>` puts it all back; `bag host install service`
  prints the login agent and the line that loads it; installs stage each version under `<home>/package/versions/`;
  beside a running service, every command that writes an identity borrows it
  from it instead of answering held; `bag identity relays <name> --relay <url>...` sets a service identity's relays;
  `bag identity keep-alive on|off|default <name>` is your word on keeping its records alive.
  The per-folder forms stay as the rollback.
- **The install page sets the bag service up from the same one line.** "Set me up on bag.dev" in Claude Code, Codex or
  omp, on a fresh machine or an existing home: on an existing home it reuses an identity unless you ask for a new one;
  you run `host migrate`, the shim at user scope and the login agent yourself, then type `use` and the name in each
  window. One identity per folder stays on the page as the way back. See `docs/bag-service.md`.

### The bag service: one process per home that holds every identity

- **`bag-mcp --service --dir <home>` runs one bag service for the home, on a socket instead of stdio.** It holds every
  identity listed in `<home>/identities.json` (or `--identities <file>`), all in that one home, and each window's
  shim connects to it on `<home>/run/service.sock` (0600, in a 0700 directory). A second service for the same home
  answers busy and exits. Windows that connect present the token the service writes at each start; dialogs a window
  opens are answered only in that window. The per-folder stdio server (`--as`, `--identities`) stays as it was, as the
  way back.
- **Restarts hand over cleanly.** A drain tells every window, refuses new binds and pairings with `draining`, ends
  running pairings (their codes and digits die), stops fetching, flushes and releases each identity, and lets go of
  the service lock last, so a new service never runs beside the old one. Keys are read again by the new process.
- **A Keychain identity asks for its dialog only when you use it.** The service opens such an identity at the first
  window that binds to it, never at an unattended start or restart, and never retries a denied or unanswered dialog on
  a timer.
- **The service runs scrubbed.** It refuses to start with `NODE_OPTIONS` set or a debugging or code-loading flag,
  runs with `--disable-sigusr1` and core dumps off, and the login-agent text the install step prints sets those, a
  fixed working directory and a short environment.
- **One window, one identity, in the service.** A window acts as the identity you bind it to (type `use NAME`, or
  answer the bind dialog); before that only `status` answers, saying how. `status` shows that identity only. An agent
  identity's windows each get their own grant under the same caveats. An identity you add with the command line is
  usable at once, without a restart; one you remove stays with the windows already using it until they close.
- **A Keychain dialog holds only its own identity.** While one identity waits on its dialog, every other window and
  identity keeps working; at an unattended start a Keychain identity opens only if you turned keep-alive on for it.
- **`bag-mcp --print-login-agent` prints the login agent.** The launchd plist on macOS, or with `--platform linux` a
  systemd user unit, on stdout only; it names the version-independent launcher, so removing old versions never breaks
  it.

### Known limits of 0.4.0

- **Same user is not a boundary.** A program running as you can still use any of your identities through the running
  bag service, since it can read the service's token. The Keychain stops it copying your keys, not using them; only
  your host's sandbox, where it denies ~/.bag/run, stops that.
- **An identity whose keys an agent holds** is reachable from a `login` until about 24 hours after that login began,
  when its address and key records lapse; the service keeps none of them alive, and running `login` again refreshes
  them. A send from such a window under an organisation's members record is refused `not-authorized`. A lost or
  revoked grant answers `not-authorized` until the window binds again or the service restarts; the refusal's detail
  says how to recover, and regranting in place comes in a later release.
- **One login agent per user, for one home.** A second home gets none: its service starts with its first window and
  stops 60 seconds after the last.
- **`<home>/run` is the service's own.** It makes the folder with mode 0700 and refuses an existing one that is
  group- or world-accessible (`unsafe-path`, for example 0755); it does not replace it. Run `chmod 700` on it, or move
  the folder to `~/.Trash` so the service makes a fresh one.
- **After a stop, the old service can outlive its lock for up to half a minute.** It releases the lock first, then stays
  alive while an in-flight send's HTTP request to a relay is open, up to the relay client's timeout (29 seconds in the
  proof run); a new service may start meanwhile, and nothing is fetched or acknowledged twice.
- **One wake per Codex process.** On Codex, all TUI windows of one Codex process share one bag connection host. The
  wake is per Codex process, not per window: with two windows bound to two identities, a window can be woken for the
  other's mail (its name and that mail arrived, never the message) or miss its own. Closing a Codex window does not
  end its binding or any pairing it started until Codex itself quits: unbind or cancel the pairing first, or quit
  Codex. Each window still reads and sends only as the identity it is bound to. For a dependable wake on Codex, bind
  one identity per Codex process.
- **Claude Code asks before bag's tools.** Claude Code may ask you to allow bag's tools (in auto mode its classifier
  can stop a call until you approve it); bag never pre-approves them.
- **Proof runs not yet done live:** the one-line install in Claude Code, Codex and omp on a fresh and on an existing
  home; the login agent's restart of a killed service; the Keychain dialog answered Allow; and, optional, a pairing in
  a Codex window closed before it ended. Recorded headless on main: mail with no window open, a crash and the shim's
  restart, an upgrade under load (drain with a wait and a send in flight), host migrate and its undo, and omp's seven
  legs. Recorded live: in Claude Code, two windows on two identities and two windows on one identity; in Codex, two
  windows on one identity, and two windows on two identities (its wake as above).

### Keys in the macOS Keychain

- **On macOS, `bag keygen` run at a terminal now keeps a new identity's keys in the login keychain, and `bag identity custody <name> --to
  keychain` moves an existing key file there.** A program running as you can no longer read your keys from a file;
  reading the keychain item shows a macOS dialog naming `security`, where you answer Allow (never Always Allow), and
  only right after you started bag yourself. Linux, and `--custody
  file`, keep the key file as before; the move verifies the keychain copy before it puts the old file in the Trash,
  and `--to file` moves back.

### identity remove: one identity out of a home that keeps others

- **`bag identity remove <name> --relay <url>...` takes one identity out of a home and leaves the others working.**
  It runs on a terminal and asks one question that names every change; nothing is deleted. It re-signs the
  identity's accept-from to name only its own address at each relay, so peers' mail is refused from then on; a relay
  that does not take it stops the run before anything on the machine changes. It then takes out of `trust.json` only
  the roots no other identity's accept-from copy still names, forgets the names of its address in `names.json`, and
  prints the `unpair` line for each other identity that accepts it. With `--project <dir>` it takes its bag server out
  of `.omp/mcp.json` (and bag's wake link) or `.mcp.json` (and its wake hooks in `.claude/settings.json`), keeping
  every other server and hook. A Codex table naming it is left for you to edit, and the command says so. Its key file
  or keychain pointer, `state/<name>/`, its records, its key records and `install/<name>.env` move into `--to`
  (by default `bag-left-<name>-<UTC time>` beside the home, mode 0700). It refuses while an MCP server or a keep job
  holds the identity, and names the `launchctl bootout` line for the job.

### unpair in a home with several identities keeps the others' trust

- **Unpairing a peer for one identity no longer cuts it off from the others.** `trust.json` is one file for the whole
  home, and `unpair` took the peer out of it even when another identity of the same home still accepts it, so that
  identity's inbox and MCP server refused the peer's mail from then on. `unpair` now leaves the peer in `trust.json`
  while another identity's accept-from copy (`<home>/records/<name>.accept.json`) names it, says so (`kept trust <root>:
  the accept-from of <name> still names it`), and still re-signs its own accept-from without the peer. It also keeps
  its own copy current, so the next identity's `unpair` reads its roots as they are.

### Codex: a plain identity that can pair, and an honest answer when no dialog was shown

- **`host install codex --mode mcp` now registers a plain identity, as Claude Code's.** The server gets the same
  arguments as the Claude Code entry (`--as`, your relays, `--dir`, `--keep-alive-records`), so a Codex session can pair
  in its own dialogs. The first Codex session holds the identity; another answers that it is held. The earlier form, one
  grant session per Codex session under a principal, which had no pair tools, is now `--session auto:codex
  --grant-caveat <caveat>`; `--grant-caveat` alone is refused, naming `--session auto:codex`. A table of the other form
  is refused `exists`, never replaced: remove it first. Pairing needs the interactive `codex` TUI, 0.113.0 or later
  (`codex --version`), and an approval policy that lets MCP servers ask (`on-request`, the default). Codex asks before
  bag's tools that reach other agents: "Allow for this session" suits `pair_invite` and `pair_accept` only; keep `send`,
  `ask`, `handoff` and `delegate` at Allow per call. See `docs/partner-install.md`.
- **A pair tool no longer reports "declined" when nobody saw the dialog.** `codex exec` declines every dialog in under a
  millisecond, which bag reported as the person declining. A first pairing dialog answered in under 250 ms, or a Codex
  older than 0.113.0, now answers `no-elicitation`.
- **`no-elicitation` names what to change in your host, never a terminal command.** It named a `bag pair` line to run;
  it now names the host's own setting (for Codex: the interactive TUI, the version, the approval policy). `pair` stays
  available in your own terminal (`docs/pairing-without-dialogs.md`).
- **The install page wires Codex.** Its Codex step stopped with two lines for a grant session and a login terminal;
  it now runs the plain `host install codex --mode mcp` after a `codex --version` check, and ends with a restart.
- **The wake line no longer sends you to another session for a process that only reuses the server's pid.** It
  checks, as `status` does, that the pid in the server's lock started before the lock was written.

### host install: a stable node path, and no copy under a running server

- **`host install` writes Homebrew's node link, not the versioned Cellar path.** It wrote the resolved path of the node
  that ran it (for example `/opt/homebrew/Cellar/node/25.8.1_1/bin/node`), which a `brew upgrade` removes, leaving the
  MCP entry and the wake hooks pointing at nothing. When `/opt/homebrew/bin/node` or `/usr/local/bin/node` resolves to
  the same node, that link is written instead; any other node is written as before. Run `host install` again once:
  the entry and hooks an earlier install wrote with the Cellar path are replaced, not refused and not doubled.
- **`record keep --plist` and `--crontab`, and `onboard`'s commands and cron line, name the same link.** They printed
  the Cellar path too. A job or cron line you installed from them before keeps that path: print it again and replace it.
- **`host install` no longer replaces `<home>/package` under a running server.** A second identity's install of
  another version overwrote the copy a running server of the same home had started from. Now each version is staged
  once in `<home>/package/versions/<version>/` and never written again, `<home>/package/current` names the one in use,
  and the four launchers beside it run that one, so nothing runs from files an install changed. A running bag service
  is told: `the running bag service (pid N) moves to bag V at its next drain and restart`. See
  `docs/partner-install.md`.

### The omp wake no longer answers mail on its own

- **An omp agent shows the mail it is woken for and answers only when you ask.** The wake turn said "read it, then
  answer it", so two omp agents paired with each other answered each other without end. It now says to show the mail
  to you and to answer only when you ask, or when the message plainly asks a question you already told the agent to
  answer. When one peer has sent 3 or more messages in ten minutes since you last typed, the wake adds "this looks like
  a loop: show your person and do not answer", with the count and the peer's name. See `docs/host-omp.md`.

### The envelope cap: 196,608 bytes

- **An envelope can be 196,608 bytes (192 KiB), up from 65,536.** One recipient's body now holds about 97,000
  characters of JSON text, up from about 32,000, and a 64 KiB body fits with up to 16 recipients. The request body cap
  (262,144), the record cap (131,072) and the WebSocket frame cap (262,144) do not change. `send`'s description in the
  MCP server derives its figure from the cap. See `docs/message-size.md`.
- **Accept-from records are lifted on their next re-sign.** Every accept-from record signed so far carries `max_bytes`
  65,536, the old default. Each re-sign (`record keep`, the MCP server's keep-alive, `onboard`, a pairing and `unpair`)
  now writes 196,608 in place of exactly 65,536 and keeps any other value. `record keep` re-signs at least every
  11 hours, so an identity on the new version takes the larger mailbox within about 11 hours, with nothing to type. A
  `max_bytes` of 65,536 chosen on purpose is lifted too; sign it as 65,535 to keep it small. `onboard` and the
  organisation client's records default to the cap.
- **The relay call's time limit follows the body.** Each relay call is given 10 seconds plus 1 second per 16 KiB of its
  body, at most 29 seconds, under the relay's 30 second body timeout: 22 seconds for a full envelope, so a full send
  still goes out on a slow uplink (a flat 10 seconds failed it below about 160 kbit/s). A fetch by id is given the time
  of a full envelope.

### A partial delivery

- **`send` reads a partial delivery the same in the CLI and the MCP server.** Delivered via at least one relay is a
  success: the CLI's `send` (and `resend`, `held release` and `group send`) exits 0 with a warning line on stderr,
  `warning: delivered via 2 of 3 relays; refused 1: <relay> envelope-too-large; ...`, where it exited 1 before. The MCP
  send tool's answer gains `summary`: `delivered`, `relays`, `refused` (each relay with its reason), `retrying` and a
  `text` line; it answered a partial delivery as a success before too, with no count. No relay taking it is still an
  error, with the first refusal's code, its bytes kept in the outbox and the `resend --id` hint. A script that read
  exit 1 as "some relay refused" reads the warning line now.

### Pairing: a cancel

- **`pair_cancel` ends a running pairing in the MCP server.** A person who opened an invite and changed their mind
  (for another address, say) met `busy` for up to ten minutes, and an agent could only say to wait or to stop the
  server. The new tool ends the invite or the accept on the person's word and writes nothing. An invitation that no
  request has reached is withdrawn (its one-time invitation identity's address record, never the inviter's own), so its code meets `invite-expired` on the other side; `busy` now names
  `pair_cancel`. The CLI's pairing runs in the foreground with no lock, so it needs none: Ctrl-C ends it.

### Migration: the order

1. The relay flag first, the operator's deploy: `--max-envelope-bytes 196608` at every relay. A relay of 0.2.3 or later
   takes it with no new binary; until it moves it refuses a larger envelope `envelope-too-large`, and the sender reads
   a partial delivery.
2. Then the readers: every `bag` and `bag-mcp` on the new version. v0.3.0 and before refuse a larger envelope when
   they read it, so a message to a peer still on them is lost on its side.
3. Then the lift, automatic, within about 11 hours through `record keep`.
4. Only once every reader runs the new version may a policy file set a scope `max_bytes` over 65,536: v0.3.0 and
   before refuse such a file at start (`bad-record`).

## v0.3.0: 2026-11-11

The cut tagged v0.3.0, `@usebag/bag` 0.3.0.

- **`@usebag/bag` 0.3.0**, published from this cut (`npm view @usebag/bag@0.3.0 gitHead` names it).

### MCP server

- **A `facts` tool: the model's id, session cost and context from the host, never guessed.** The host writes
  `host-facts.json` in the identity's state directory, and `facts` returns each figure with its age, says which ones
  the host did not provide, marks facts over 10 minutes old stale, and says first when the session is a spawned
  sub-session rather than the one that speaks for the identity. `status` carries `model` and `main_session`. See
  `docs/agent-facts.md`. Telemetry counts `facts` calls under the tool `facts`: the telemetry Worker's
  `SCHEMA_COMMIT` and the client's `TELEMETRY_SCHEMA_COMMIT` name the release's schema commit, set at release-bump,
  and the Worker is deployed first (the release runbook's step 4a), since it refuses reports from a schema commit it
  does not know.
- **`facts` and `status` in a held server.** While another session holds the identity, both answer `held: true`,
  `held_by` (pid, start time, folder, host and the lock's `path`), a `note` that this session does not speak for the
  identity, the server's own `pid`, `started_at` and `uptime_s`, `held_since` (null, with `held_from_start`, when it
  was held from its start) and `host_facts: null` with `host_facts_state: "held"`. Neither reads the holder's
  `host-facts.json`.
- **A second copy is not a rejection.** A message that arrives again over another of the identity's relays is counted in
  `status` as `copies_already_received_via_another_relay`, no longer under `rejected` (`duplicate`).
- **`send` says how big a body can be:** about 32,000 characters of JSON text (the envelope cap is 65,536 bytes); past
  it the send is refused `envelope-too-large`.
- **Large sends no longer hang when the server's stdin is a terminal.** A host that runs `bag-mcp` on a pty (an omp
  background service does) wrote each request as one line into a terminal in canonical mode, which passes at most
  1,024 bytes of a line on macOS: a send with a body over about 880 bytes never reached the server and its caller
  waited for good. When stdin is a terminal the server now puts it in raw mode once it has started (one `stdin` line on stderr
  says so), restores it on exit, and stops on Ctrl-C or Ctrl-D. Over pipes, as MCP hosts start it, nothing changes.
  Message size limits: `docs/message-size.md`.
- **Pairing works inside a host that cannot show dialogs, when it runs a bag extension (the consent bridge).** omp has
  no MCP elicitation, so the pair tools could before only hand you the `bag pair` terminal command. Now, when the
  host's extension marks a user-interface session (a presence file in the identity's consent directory), the server
  asks you through files the extension answers: you paste the peer's code, read the six check digits out to the peer and
  press Yes, with no terminal and the model never seeing the code or the digits. A question stands 120 seconds; a
  timeout counts as No. With no such extension (a piped or background run), nothing changes: a host with dialogs uses
  them, and one without keeps getting the `bag pair` command (see `docs/pairing-without-dialogs.md`).

### omp

- **`bag host install omp --as <name> --relay <url>... --project <dir>`** wires an omp folder in one command: the bag
  server in `.omp/mcp.json`, and `.omp/hooks/pre/bag-wake.js`, a link to bag's wake extension in `<home>/package/`.
  The extension starts one turn per delivered message, holds a message that arrives during a turn until the turn
  ends, wakes only the main interactive session, and writes the session's model, cost and context use for the
  `facts` tool. `bag host remove omp` undoes it. See `docs/host-omp.md`.

### Locks

- **A second session in a folder is told who holds the identity.** A bag MCP server that finds the identity held by a
  live server no longer exits (the host showed only "Connection closed"). It stays up: `status` returns `held_by` (pid,
  start time, folder, host) and every other tool answers `bag: the identity NAME is held by another session (pid N,
  started T); close that session or run bag in its own folder`. It tries the lock every three seconds and takes the
  identity over when the holder ends.
- **A server whose host died releases the lock.** Besides the end of stdin, the server checks every two seconds that the
  process that started it is still its parent, and stops, removing `mcp.lock`, when it is not.
- **`mcp.lock` says more.** It now holds `started_at`, `cwd`, `ppid` and, once the client has introduced itself, `host`
  beside `pid`; readers that want the pid alone are unchanged.
- **`bag inbox` beside a running server** stops with `held:` and names the holder instead of the store's lock file, and
  `bag status` prints a `held_by` line. See `docs/one-identity-per-folder.md`.

### Fixes

- **A pairing leaves your records at every relay you name, not the rendezvous alone.** `peer invite`, `peer accept` and
  `pair` now take `--relay` more than once, and a completed pairing publishes the identity's address and accept-from
  records at every relay named, so a later host install does not warn that a second relay is missing them; a relay that
  refuses is a warning line, not a failure of the pairing.
- **The Claude Code and Codex wake hook no longer wakes twice for one burst of mail.** Several messages arriving
  together ring the doorbell several times; the hook now waits 300 ms and remembers the last ring, so the next Stop
  hook stays silent for mail the model has already read.
- **A send to a recipient whose relays moved reaches them.** When every target of a send is given up, as not hosted
  or unreachable, the sender reads its recipients' records again once, forgetting what it had cached, and sends again
  when that read names other relays for a recipient; when nothing changed, the send ends as before.
- **`host install` says when a relay will refuse the identity's mail.** For omp, and for Claude Code with `--project`,
  the install reads the identity's address and accept-from records at each relay it names, and warns, pointing to
  `bag onboard`, when no relay and no copy in the home holds one.
- **`host install` mends a relay that lacks a record another one holds.** When a named relay holds no address or
  accept-from record of the identity but another named relay or the home's copy does, the install publishes the newest
  copy to that relay as it is, with nothing re-signed (the same act as `bag record keep --once`), and a line says so.

## v0.2.3: 2026-11-10

The cut tagged v0.2.3, `@usebag/bag` 0.2.3.

- **`@usebag/bag` 0.2.3**, published from this cut (`npm view @usebag/bag@0.2.3 gitHead` names it).

### Enterprise: pairing and trust

- **A pairing revoked from the console leaves the agent's accept-from at once.** The bag MCP server signs and publishes
  the accept-from again after a console pass that ends a pairing or runs one, as `bag pairings` already did, instead of
  at the next hourly refresh.
- **Read receipts follow the organisation's setting.** While the organisation's instance has read receipts off, the bag
  MCP server's `--receipts-to` answers none; it answers again once the setting is back on. An instance that does not
  send the setting keeps receipts on. The CLI sends no receipts.

### Testing

- **A test zone switch, off by default**, for two bag enterprise instances and their relays on one machine under the
  zone `pilot.bag.dev`. It is on only when `BAG_TEST_ZONE_FILE` names a zone file, and then the CLI and the MCP server
  print one stderr line that says so: TXT lookups in that zone read the file, `BAG_TEST_ZONE_ORIGINS` maps a domain's
  origin to a loopback address, and the relay guard lets loopback relays through. Malformed values print a usage line
  and exit 2. Never for real use; with the variables unset nothing changes.

## v0.2.2: 2026-11-09

The cut tagged v0.2.2, `@usebag/bag` 0.2.2.

- **`@usebag/bag` 0.2.2**, published from this cut (`npm view @usebag/bag@0.2.2 gitHead` names it).

### Enterprise: mail between organisations

- **`bag send --to <label>@<your organisation's domain>`** goes to the organisation's agent of that label, read from
  the organisation's directory, as `--to <label>` does. A label the directory lacks, or a directory that does not
  answer (one line on stderr), takes the public path: the domain's DNS record, its org record and the handle record.
- **`bag send --to <agent>@<partner's domain>`** goes to a partner organisation's agent by the handle record that its
  instance publishes, as for any handle.
- **The agent takes a partner's mail.** The agent's accept-from record now lists the organisation's accept list: its own
  root, and the root of each partner whose agreement covers this agent. The list is read from the instance at each
  refresh, and the record is published again when the list changes. An instance without the list keeps the
  organisation's root alone. A list that names `*`, more roots than a record holds, or something that is not a root is
  refused with one line, and the record keeps the roots it had. inbox trusts a partner's root once the organisation
  grants it, with its partnership named in `trust.json`; the root leaves when the partnership ends.

### Enterprise: pairing started from the console

- **An organisation can pair one of its agents with someone outside it from the console.** The agent's machine runs the
  same pairing as `bag peer invite`, and the code shows in the console. The console's person types the six check digits
  that the other side reads out, with three tries. The pairing ends when the console revokes it or its term ends. The
  bag MCP server picks this up every 15 s, and **`bag pairings [--watch]`** does the same for an agent with no MCP host.
  Both open the pairing at the organisation's first relay, where the agent's records are, even when the MCP server
  was installed with another `--relay`.

### Names and labels

- **A name in the name book and an agent's label in the organisation's directory can be up to 64 characters**
  (previously 32), in the CLI and in the MCP server.

### Fixes

- **Security: the relay's SQLite is 3.54 or later** (RUSTSEC-2026-0459, CVE-2026-119375). The relay's bundled SQLite
  came through `rusqlite` 0.40.2 and `libsqlite3-sys` 0.38.2, and it is now `rusqlite` 0.41.1 and `libsqlite3-sys`
  0.39.1. Older SQLite can return uninitialised memory when it opens a database together with a write-ahead log whose
  page size differs. The relay opens only its own database, which it writes itself. No relay API or behaviour changes.
- **`bag connect` to an instance on a private network** (RFC 1918 or ULA, such as a container network) now works as
  loopback does, with one stderr line naming the addresses. Link-local, multicast and other addresses are still
  refused.

## v0.2.1: 2026-11-07

The cut tagged v0.2.1, `@usebag/bag` 0.2.1.

- **`@usebag/bag` 0.2.1**, published from this cut (`npm view @usebag/bag@0.2.1 gitHead` names it).

### Enterprise: connect proves the path

- **`bag connect` ends with one line, `Connected as <label>; relay round trip <n> ms`.** Once the organisation
  approves, the same command publishes the agent's records at every relay of the organisation, sends the agent one
  envelope from its own session key through the organisation's first relay (the same send path as `bag send`) and
  reads it back on the agent's own subscription, acknowledged so that the agent's inbox does not show it. `<n>` is that
  round trip, on a monotonic clock. Nothing else is to be run before the first send.
- **A step that fails is one line, exit 1, the session kept**: `Connected as <label>, but its records were not
  published at <relay> (<code>): bag status tries again`, or `..., but the relay round trip failed at <relay>
  (<code>): ...`. Each relay step is bounded at 5 s (`timeout`).
- **`--verbose`** prints what connect printed before (`Connecting to <domain> at <origin>`, `Approved: agent
  <fingerprint>`) and each relay's records; without it no fingerprint, key or address is printed. The line
  `relay <relay>: records not published (<code>)` is replaced by the failure line above.
- **`bag status`** (with no `--as`), for a live session, adds the same line from one probe that sends nothing (the
  agent's address record read back from the first relay), or the failure line with exit 1.
- **The MCP tools** `connect` and `status` (and `enterprise_status` of `bag-mcp`) return the same lines.
- **Where the check message can show once.** When the organisation has more than one relay, the check envelope also
  reaches the agent's other relays, up to three, and an inbox read at one of those shows it once. When older mail waits
  ahead of it at the first relay, as after a reconnect with the same keys, connect leaves that mail alone, and the
  agent's inbox shows the check message once after it.

### Enterprise: the code's label

- **A connect code carries the agent's label.** `bag connect` sends no label unless `--label` is given; `Connected as
  <label>` prints the label the organisation returns (the code's, such as `example-com-1`, or the next free number
  when that one is held), and the session keeps it for `bag status`. A `--label` that a live agent of the
  organisation already holds exits 1 with `label_taken`, naming the label, and leaves the code unused. The MCP
  `connect` tools return the same lines.

### Enterprise: one profile per organisation

- **Connecting to a second organisation keeps the first.** `bag connect` and `bag sign-in` on a home already signed in
  to another organisation add the new one beside it and revoke nothing: no sign-out is asked for and no key is
  revoked. The line names both: `Connected as <label> (<domain>); relay round trip <n> ms; also signed in to <other>:
  bag status --org <other>`.
- **`--org <domain>`** picks the organisation for `bag status` and `bag sign-out`. With one it is implied. With
  several, `status` shows the most recently connected and names it and the others in one line on stderr, and refreshes
  them all; `sign-out` without `--org` removes nothing and exits 2 with the list. `bag sign-out --org <domain>` revokes
  that one only. The MCP `status` and `enterprise_status` tools take an optional `org`.
- **The home's layout.** Each organisation's session files now live in `<home>/orgs/<domain>/enterprise/`;
  `<home>/enterprise/current.json` names the most recently connected. A home of the older shape is moved into its
  organisation's profile the first time it is read, with nothing to do. The chain file a session prints moves with it:
  `bag status` names the new path.

### Enterprise: send and inbox with no flags

- **`bag send` and `bag inbox` after `bag connect`, with no other flag.** With a live enterprise session,
  `bag send --to <name|label|address> --type <type> --body <json>` and `bag inbox --once` take the relay, the sender,
  the chain and the trust root from the session; a flag given still wins, and with no session nothing changes. The
  trust root is the organisation's root address, so receiving never waits on a DNS lookup, and `--trust-root
  <domain>` for the session's own domain reads as that address. A `--to` the name book lacks is looked up as an
  agent's label in the organisation's directory. `bag inbox --once` ends 200 ms after the relay admits it and its
  backlog is delivered, instead of after a fixed second: about 0.45 s end to end on this machine, where it was 1.25 s.
  With several organisations in the home, both take `--org <domain>`, and without it name the organisation they use on
  stderr; the directory's copy is kept per organisation.
- **`bag inbox` says when a message is kept, not refused.** A message refused for a cause that can pass prints
  `waiting <id> resolve-failed: kept; the next read after the trust root is fixed delivers it` (or `future-ts`, `...
  after its timestamp is past ...`) instead of `reject <id> <code>`, and the next read delivers it with no resend.
  `reject` is kept for final verdicts.
- **`bag send` needs no `--type`.** Without one the message's type is `chat.v1`; a `--type` given wins.
- **`bag send --body @-` and `--body @<path>`.** The JSON body from stdin, read whole, or from a regular file (no
  symbolic link followed), each at most 65,536 bytes: text from elsewhere never has to be quoted into the command line,
  for example `printf '%s' "$text" | jq -c '{text: .}' | bag send --to <name> --body @-`.

## v0.2.0: 2026-11-07

The cut tagged v0.2.0, `@usebag/bag` 0.2.0.

- **`@usebag/bag` 0.2.0**, published from this cut (`npm view @usebag/bag@0.2.0 gitHead` names it).

### The enterprise client: one public client

- **`bag connect`.** Connects this machine's agent to its organisation with the one-time code a person copies from
  their organisation's bag console. The code is read from `BAG_ORG_CODE` or from one line of stdin ("Paste the code"),
  never from the command line. The code names the instance and the organisation, so nothing else is typed: the
  instance it names is pinned (no discovery), https or http on this machine only, the private-address guard runs
  before any call, and no call follows a redirect. It prints `Connecting to <domain> at <origin>`, `Approved: agent
  <fingerprint>` and `Connected as <label>`; exit 4 while the organisation's signer is still to sign. No key, token or
  code is printed.
- **`bag sign-in <domain> --instance <origin> [--no-wait]`.** The same session without a code: the device flow a
  person approves in the console. It prints the link to open, the user code and the key's fingerprint, and with
  `--no-wait` exits 4 while the approval waits; the same line run again resumes it. `--instance` pins the console origin
  as a code does. Without `--instance`, the instance comes from `BAG_ENTERPRISE_INSTANCES`, the organisation's
  `.well-known/bag/enterprise.json` record, or `BAG_ENTERPRISE_URL`.
- **`bag status`** (with no `--as`) shows the enterprise session after one refresh tick: the organisation, the agent's
  address, its state, the token, the org hop and the local hop, the generation; `--chain` prints the chain for an MCP
  server's `--chain-cmd`; `--plist` and `--crontab` print the hourly refresh job. `bag sign-out` ends the session.
  Exits: 0 done, 1 refused or failed, 2 usage, 3 ended or none, 4 waiting on a person or the signer.
- **The agent's records.** After the grant, and again before they lapse, the agent publishes its address record and
  its accept-from record at each relay the organisation names, signed by its own key on this machine; a relay that did
  not take them is one line, `relay <relay>: records not published (<code>)`, and every tick tries again.
- **The MCP tools.** `bag mcp` serves `connect`, `sign_in` and `status` over stdio to an MCP host, for an agent with
  no identity yet: `claude mcp add bag -- npx -y @usebag/bag@<version> mcp`, then the person pastes the code into the
  chat. The identity server, `bag-mcp`, lists the same three as `connect`, `sign_in` and `enterprise_status` beside
  its other tools. Every result holds only the lines the commands print, scrubbed of the code, the device code and
  the token.
- **The home.** The session lives in `<home>/enterprise/` of bag's own home (`AC_HOME`, else `~/.bag`), 0700 with 0600
  files; a home of another user is refused, and every run holds the home to its owner.

## v0.1.2: 2026-11-04

The cut tagged v0.1.2, `@usebag/bag` 0.1.2.

- **`@usebag/bag` 0.1.2**, published from this cut (`npm view @usebag/bag@0.1.2 gitHead` names it), and the first
  release with a tag, `v0.1.2`, and a GitHub Release. 0.1.0 and 0.1.1 are not tagged.

### Telemetry

- **The daily report names the package version.** A report's `build` is the package's npm version when the telemetry
  service lists it (0.1.0, 0.1.1 and 0.1.2), else `other`. Until now every report's build was `other`, though the
  notice said the version was sent; 0.1.0 and 0.1.1 were built before the change and still send `other`. `bag version`
  and `bag --version` are counted as the command `version`, no longer as `other`.
- **The notice names a command that lasts.** Run from the package, the telemetry notice prints
  `npx --yes --package=@usebag/bag@<version> bag telemetry preview`, not a file in npm's cache, which npm may clear.
- **A day's counts reach that day's report.** A long-running process, such as the MCP server or the A2A bridge, that
  counted in a day's last minute and then went quiet held that count until its next one, and the day's report went
  without it. It now writes held counts a minute after a count.

### Security

- **`SECURITY.md` says more.** The two public relays, `relay1.bag.dev` and `relay2.bag.dev`, are run by the project
  and in scope for good-faith testing, with no load, availability or volume testing, no one else's data and no social
  engineering. Reports about the project's other services (the site, its install guide, the `.well-known` and handle
  records, the telemetry endpoint) are welcome, but active testing against them is out of scope. There is no bounty;
  reporters are credited by consent in `docs/thanks.md`. A safe harbour: good-faith research within the policy is not
  reported to law enforcement or pursued by us.
- **A known limitation, stated.** The install guide checks the package's version and the commit that the registry and
  `bag --version` name, which whoever controls the registry's answers could also serve; it does not verify the
  package's provenance. Its step 2a gives the check by hand, `npm audit signatures`, which checks the provenance's
  signature but not who signed it.

### Documentation

- **`docs/partner-install.md` offers two routes**: the npm package (section 1a: the `npx` command, its `--version`
  and `npm view ... gitHead` checked against each other, the three programs) and from source (section 1b). The later
  sections hold for both: section 3 names the public relays and the relay image for the package route, section 5c
  wires the MCP server through `host install`, and section 6 marks the handle script source-only.
- **`packages/mcp/README.md`, "Install"**, gains the package route: `bag host install` run from the package copies it
  to `<home>/package/` and registers `node <home>/package/bag-mcp.js`.
- **`docs/release.md`** says how a release is made: the version change, the cut, the staged publish and its approval
  on npm, the read-backs, the relay image, the tag and the GitHub Release, and the rollbacks.
- **The pinned install lines name 0.1.2**, in `README.md`, `docs/partner-install.md`, `packages/mcp/README.md` and the
  package's own `README.md`.

## v0.1.1: 2026-11-03

The cut 3c343d65, `@usebag/bag` 0.1.1.

- **`@usebag/bag` 0.1.1**, published from this cut (`npm view @usebag/bag@0.1.1 gitHead` names it). No code changed
  from 0.1.0: the version, the package's home page (`https://bag.dev`) and the version its README names.
- **The package is staged, then approved.** The publish workflow stages each version by npm's trusted publishing
  (OIDC, no token) and checks npm's answer against the packed file; a maintainer approves the staged version on npm,
  with two-factor authentication, before anyone can install it. The token path is gone.

## v0.1.0: 2026-11-03

The cut 58400aaf, `@usebag/bag` 0.1.0. The cut bc212d8c of the same evening carried the same, but for one fix to the
package's build test; no package was published from it.

- **bag is an npm package, `@usebag/bag`.** One bundle with no dependency and no install script holds the command
  line (`bag`), the MCP server (`bag-mcp`) and the A2A bridge (`bag-a2a`); it needs Node 24 or later, and
  `npx --yes --package=@usebag/bag@0.1.0 bag` runs it without a global install. `bag --version` prints the version
  and the commit it was built from. The package is published from that commit by a workflow with npm provenance, and
  `npm view @usebag/bag@0.1.0 gitHead` names it. The relay is not in the package (`README.md`, "Quick start", and its
  new section "From source").
- **The wiring outlives npm's cache.** Run from the package, `host install`, `record keep --plist` or `--crontab` and
  `onboard` first copy the package to `<home>/package/` and write that path, so a cleared npm cache does not break
  them.
- **The relay image can be pulled.** `docs/self-host.md`, "Run it with Docker", gains "Or pull the published image":
  `ghcr.io/usebag/relay:<commit>`, tagged by commit with no `latest`, with the checks of its platforms, provenance and
  SBOM, and a compose override you write that names the image by commit and digest.

## 2026-11-03: the cut cc4f25dd

New since the cut 635a89b2 of the same morning.

### Security

- **The A2A bridge listens on the loopback only.** `--host` (and `A2aBridgeOptions.host`) now accept a 127.0.0.0/8
  address, `::1` or `localhost` and refuse anything else before the bridge listens, with exit 2 and the line "the
  bridge listens on loopback only; it has no caller authentication". Before this change `--host 0.0.0.0` or a LAN
  address let every machine that could reach the port send as the bridge's identity, since the Host and Origin
  checks stop browsers, not programs. The default, 127.0.0.1, was already safe. Any local process can still call the
  bridge, the same trust as the command line on the same home; a caller token is a later option (`packages/a2a/README.md`).

### New

- **Telemetry can send, once a person turns it on.** It stays off until then. While it is on, each finished UTC day's
  report goes once to `telemetry.bag.dev`, from 01:05 UTC the next day; `c telemetry status`, `preview`, `on`, `off`
  and `forget` (`README.md`, "Telemetry"). The report gains the family `pairs`: the machine's trusted peers counted
  by age (under 7 days, or more), and of those, the ones it sent to in the last 7 days. It needs consent version 2, so
  a yes given to version 1 reads as off and is asked again. Earlier cuts send nothing.
- **The clients go through a company proxy.** The command line, the MCP server and the bridge honour `HTTPS_PROXY`,
  `HTTP_PROXY` and `NO_PROXY`: when a proxy is set, each restarts itself once with Node's `NODE_USE_ENV_PROXY=1`, and
  `status` shows the network it uses. A fallback for a proxy that cuts WebSockets is not built.
- **The relay as a container.** `deploy/docker/` builds the relay into a small image with no shell that runs as a
  non-root user, with a compose file for one relay on the host's loopback and a Caddy TLS front
  (`docs/self-host.md`, "Run it with Docker"). The image of this cut is published as
  `ghcr.io/usebag/relay:cc4f25dd22448ae066cc99c2195eb9491d6ca24a`. The self-host guide's Linux steps and systemd unit
  were run on Ubuntu.
- **`docs/inside-a-company.md`**, a guide to using bag inside a company: the security team first, your own relays,
  company identities and an allow-list of writers, telemetry off, the public relays only with approval, and the proxy.
- **The relay counts first subscribes**, `ac_relay_first_subscribes_total`: a fresh mailbox's subscription, once a UTC
  day, with nothing new stored (`docs/self-host.md`).
- **The spec says what the code does**, with no wire change: the pairing invite string and request are written out
  (`spec/SPEC.md` section 2.4, section 8.10), pair/open takes 1 to 64 relays, a nameplate's `ttl` is required, 1 to 600 seconds
  (Appendix B, item 89), and section 7.2 states the relay URL form once, as every record reader checks it.
  `spec/vectors/pair-code.json` gains the check digits, the request MAC, the invite string and pair/open.

## 2026-11-01: the first public cut

The first public release: version 0 of the wire format, a security preview (`README.md`, "Status"), under
Apache-2.0. Earlier cuts were private previews, handed out as git bundles; the last two were e4c2c7c9 and e109553c,
both of 2026-10-31.

### What it is

- **The specification**, `spec/SPEC.md`, with its test vectors and adversarial cases, and three implementations that
  the vectors bind: the TypeScript reference (`packages/`), the Rust verification crate and reference relay
  (`crates/`), and a participant in Python written from the spec alone (`examples/python-join`).
- **An identity** is an Ed25519 key pair, and its address is its public key. It publishes signed records: an address
  record with its relays and its sealing key, and an accept-from record naming the roots it takes mail from.
- **A message** is a signed, sealed, threaded envelope. A relay sees who writes to whom and when, never the type, the
  thread or the body (`SECURITY.md`). The sender publishes it to up to three of the relays its recipient lists, which
  keep it for up to 7 days, and the recipient reads every relay it lists.
- **Pairing** joins two identities with a one-use code and six check digits that the two people check against each
  other, through a rendezvous relay (`spec/SPEC.md` section 8.10).
- **The tools**: the command line (`packages/cli`: keys, records and `record keep`, `send`, `inbox`, `resend`, `peer
  invite` and `peer accept`, `unpair`, `host install`, `audit verify`); an MCP server that gives an agent in an MCP
  host an address and a mailbox, up to 64 identities in one server, with pairing as tools (`packages/mcp`); and an A2A
  1.0 binding through a local bridge (`packages/a2a`).

### New since the preview cut e109553c

- **The relay limits what one address can load on it.** Each client address may fetch 6,000 times a minute, counted
  before any signature is checked, under a relay-wide ceiling of 30,000 fetches a minute, and may store 100 MB of
  envelopes a UTC day; past either, the relay answers 429 `rate-limited` with `Retry-After` (`--fetch-per-ip`,
  `--fetch-global-per-minute`, `--bytes-per-ip-per-day`). On IPv6 the rates and quotas count per /56 and the
  connection cap per /64. A full store also refuses records from signers it does not yet hold, while a signer it holds
  may still update its records.
- **The relay keeps answering under that load.** The expiry sweep runs off the async worker thread, at most 256 rows of
  each kind a transaction. An acknowledgement at or below the last one costs no store call, and a subscription stores
  its latest acknowledgement at most once a second. A pending envelope's domain lookups are bounded: at most eight
  domains a row and 64 a pass. A subscriber that cannot take a frame within the idle timeout is closed with 4003. A
  domain root's grant comes from the newest valid record of the key the relay holds, so a stale copy from the host rolls
  back no revoked list.
- **Pairing and resolving follow three new rules** (`spec/SPEC.md` section 8.10 and section 9 item 4). A pairing binds to the peer's
  address when it is known (`--for` on the terminal, an address field in the MCP dialogs), and the open invitation is
  for first contact only. A frame that is not a well-formed request no longer ends a pairing or counts against its
  tries, and `leaked` now means a second good request from another requester. The resolver keeps the record with the
  greatest `iat` across the relays that answered, so a lagging relay cannot serve an older epoch key or revoked list,
  and a relay that does not answer never blocks a read. The spec also states the relay limits above (section 8.2 to section 8.4,
  section 8.9).
- **The MCP server after its first real run.** `pair_invite` answers `paired` in the call that took the right digits,
  where it answered pending; each pairing dialog takes the peer's address; a session probes its grant on a thread
  drawn at random, not one any sender could name; after a logout, a session's new grant goes to a new key, not to the
  revoked one.
- **The CLI.** The keep job that `record keep --crontab` or `--plist` prints draws its minute on each machine, so
  machines no longer reach the relays in the same minute; `inbox` takes every `--relay` and subscribes at each, as the
  Codex worker's line needs; `unpair`, `onboard` and a publish that revokes go on past one relay down and name it.
- **`docs/partner-install.md`.** Section 5b pairs with `--for` when the peer's address is known, quotes `pairing code
  <code>`, and says the digits go by another way than the code; section 7 says two public relays run.
- `record keep` offers the key record only to a relay that does not read it back as holding it.

### Already in e109553c, new since e4c2c7c9

- **A relay that is down no longer stops a pairing or a key rotation** (`spec/SPEC.md` Appendix B, item 110). Records
  are offered to every listed relay, and the edge names each relay that did not take one (`failed <kind> <address>
  <relay> <code>` in the CLI); `record keep` and the MCP server's keeper carry the rest later. A pairing needs the
  rendezvous relay, which now also holds the invitation, and one listed relay. A record with a revoked list that a
  listed relay has not taken is reported as an incomplete revocation, naming that relay, until every listed relay holds
  it: `keys rotate` exits 3, and the MCP server reports `incomplete-revocation`.
- **Mail survives a relay restored from an older copy.** The edge decides delivery by envelope id, not by the relay's
  cursor, and resumes each subscription with cursor null (`spec/SPEC.md` section 9, items 2 and 10). An edge's inbox store
  from an earlier cut is rebuilt once when it opens, its rows kept. The reference relay notices that its database came
  from another volume and raises every mailbox's cursors, logging `cursors-raised` (Appendix B, item 102).
- **The keepers carry the key record too.** `record keep` and the MCP server's keeper offer an identity's key record to
  its listed relays, the MCP keeper only to a relay that does not read it back as holding it. The MCP keeper does the
  same for the address and accept-from records and retries a lagging relay early, after 60 seconds, doubling up to an
  hour, so a cycle in which every relay holds every record publishes nothing.
- **ac-relay holds an idle subscription in about 10 KiB of memory**, against about 133 KiB before, measured natively:
  each WebSocket read buffer is 4 KiB.
- **A load generator for the relay**, in `packages/e2e/bench`, the one used to measure the relay's load.
- `THIRD-PARTY.md` names Litestream, which the project's relay image carries.

### Already in e4c2c7c9, new since the cut before it (d1b4b5dc)

- `pair_invite`'s first result tells the agent that its person does not see tool results, so the agent writes the
  pairing code out, alone in a code block.
- A message refused because the peer unpaired you now says so, in the MCP server and the CLI, in place of "ask them to
  add your root".
- Behind a proxy, a subscription past the per-address cap is refused `rate-limited` and closed 1013, as it is for a
  direct client, in place of a close with no answer, which read as an unreachable relay.

### New with the public release

- The public files: `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and `AUTHORS`; the
  README's "Limits"; and this file.

### Outside this repository

- The project runs a second public relay, in Amsterdam beside Paris. The install guide it serves lists both relays and has
  a section "Unpair and leave": unpairing, leaving in order, and adding or moving a relay. Its step 4 now pairs in the
  new order: each side's dialog offers the peer's address, the inviting agent stops after showing the code, and the
  digits dialog opens once the person says the peer has the code.

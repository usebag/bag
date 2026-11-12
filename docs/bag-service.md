# The bag service

From bag 0.4.0, one program, the bag service, runs for your login and holds every bag identity of your machine. Your
agent hosts (Claude Code, Codex, omp) no longer start an identity's server from a folder's files: each session starts a
small bag shim that talks to the service, and you give a window an identity by typing one word. This page says what
runs, how a window gets its identity, what the login agent does, what happens when the service is not running, and how
to stop it. [Identities and windows](one-identity-per-folder.md) says what one identity in several windows does, and
how to go back to one identity per folder.

## What runs

| What | Where | What it holds |
|---|---|---|
| the bag service, one per home | started by your login agent, or by the first window that needs it | every identity of the home: its keys, mailbox, cursor, records and audit log |
| the bag shim, one per host session | started by the host, from its user-level configuration | nothing of an identity: no key, no store, no token of its own |
| the login agent | `~/Library/LaunchAgents/dev.bag.service.plist` on macOS, `~/.config/systemd/user/bag.service` on Linux | a command that starts the service at login and restarts it if it stops; one per user, for one home |

The home is `~/.bag` unless `AC_HOME` names another. A second home has its own service, and in 0.4.0 no login agent:
its first window starts it.

The service is the single owner of every identity's mailbox: it alone fetches mail from the relays, acknowledges it,
keeps the cursor and republishes the records. However many windows are open, each message is fetched once and
acknowledged once. Its working files are in `<home>/run/`, a directory it makes itself with mode 0700; never make it
yourself. An existing `<home>/run` that is group- or world-accessible (for example 0755) is refused `unsafe-path`, and
the service does not replace it: `chmod 700` it, or move the folder to `~/.Trash` so the service makes a fresh one:

- `service.lock`: held for the service's whole life; a second service of the same home exits at once with `busy`.
  The lock is the kernel's, so it is released when the process ends by any means and is never left stale.
- `service.sock`: the socket the shims connect to (mode 0600).
- `service.token`: a launch token, new at every start of the service; a shim presents it, and a connection without it
  is refused `bad-auth`.
- `service.json`: the running service's pid, start time, version and package directory, for `status` and the CLI.

- `service.log`: the service's log, JSON lines of events, codes and labels, never a key, a token or a message body
  (mode 0600, readable by you alone). It is not rotated: it grows by a few lines per start, connection and drain, and
  you may empty it at any time with `: > ~/.bag/run/service.log`.
- `shim/`: one small file per window while it uses an identity (`<host pid>.bound`, the names it uses) and its last
  ring (`<host pid>.ring`), which the wake hooks read; and, for an omp window, the folder where the service writes a
  pairing's questions for omp's extension. The service is the only writer of those questions.

The service's list of identities is `<home>/identities.json`; it serves only the identities listed there. `bag keygen`,
`bag init` and `bag restore` add a new identity to it (with the relays they know), `bag host migrate` adds the
identities of the folders it moves, and `bag identity relays <name> --relay <url>...` adds one that is missing; the
service reads the list again at each window's start and each `use`, so a new identity is offered without a restart. The copies
of bag the service and the shims run are under `<home>/package/versions/`, one directory per version, with
`<home>/package/current` naming the one in use, and small launchers beside them (`<home>/package/bag-shim.js`,
`bag-mcp.js`, `bag.js`, `bag-omp-wake.js`) that every host entry names. An install writes a new directory and moves
the pointer; it never writes into a directory a running service loaded.

## How a window gets its identity: "use"

A new window has no identity. It can tell you its status, and nothing else, until you give it one. Type, as the whole
message:

```
use omp-3
```

with the name of one of your identities. On Claude Code and omp, bag's hook reads your typed word before the model sees
it, so the model cannot type it for you. On Codex, and on any host where the word cannot be read that way, bag shows a
dialog instead, the same on every host: "Act as omp-3 in this window? Its tools then act as omp-3 until it closes.",
with one box, "Yes, act as omp-3": only a ticked Yes gives the window the identity. Asked with no name, the dialog is
"Which bag identity should this window act as?", with the identity a folder offers first already chosen. A window that cannot show a
dialog cannot take an identity.

The window then speaks as that identity until it closes: every tool answer says which identity it acted as (`as`). To
switch, type `use` with another name. The identity a window had last time in a folder may be offered first, but it is
never taken without your word, and nothing in a folder can choose for you: bag keeps no file in your project folders.

A message from a peer can never give a window an identity. A model that tries to switch on a message's say-so is
refused unless you type the word or answer Yes.

There is no word that takes an identity back from a window: closing the window ends every identity it uses.

## Pairing in a window

A pairing's dialogs (the code, the check digits) open in the window that started it, and only there. Another window
that uses the same identity is not interrupted and cannot answer them; it sees the new peer in the name book once the
pairing is done. Closing the window that started a pairing ends it, and nothing is written. `pair_cancel` works from
that window only.

## The login agent

The login agent is what keeps the service running while you are logged in. `bag host install service` prints it, for
the platform it runs on, and you load it yourself (the bag 0.4.0 install page's step 6c, "The bag service, started at login"), in your own terminal; bag never touches launchd or systemd on its own. It:

- starts the service when you log in, from the copy of bag in `<home>/package/`;
- restarts it if it stops or crashes;
- gives it a clean start: a fixed working directory, an environment with nothing but the variables bag needs (your
  proxy settings among them), no `NODE_OPTIONS`, no debugger signal and no core dumps. A service started any other way
  checks the same and refuses to run if they do not hold.

Old keep jobs from an earlier install (`bag.keep.<name>`) must go when the login agent comes: two keepers of one record
race and the relay refuses the loser. The bag 0.4.0 install page retires them in the same step: one `launchctl bootout` per job, and its file moved to
the Trash.

## Keep-alive

Your address and key records live 24 hours each and must be renewed, or senders get `resolve-failed`. Your word
decides, per identity. With no word, the service renews an identity's records while a window uses it and for 24 hours
after the last window closed, so an identity you stopped using lapses on its own and stops being a reachable address.
Each identity is renewed at its own times, which hides the schedule; it does not hide that a home's identities renew
from one service at one address, so a relay can still tell they share a source. You choose per identity:

```sh
bag identity keep-alive on omp-3
bag identity keep-alive off omp-3
bag identity keep-alive default omp-3
```

`on` keeps the records while the service runs, whether or not a window uses the identity; `off` renews them only while
a window uses it; `default` is the 24-hour rule. A folder an upgrade moved whose old entry kept the records alive is set
to `on`. `bag status --as <name>` shows the choice. A machine that sleeps lapses as before and renews when it wakes.

It runs on a terminal only and prints one line, for example `keep-alive omp-3 on`.

## When the service is not running

- **No login agent.** The first window that needs bag starts the service. It runs while any window is connected and
  stops a minute after the last one closes. Records then lapse while no window is open, as with bag 0.3.0.
- **It crashed.** The login agent starts it again. Every window loses its identity at that moment: type `use` again.
  Nothing is lost: the mail, the cursor and the records are on disk, and the service picks up where it stopped.
- **It is restarting for an upgrade.** It first refuses new `use` words and new pairings with `draining`, cancels any
  pairing that is running (its code and check digits are not carried over), lets running tool calls finish for up to
  10 seconds, saves everything and exits; the login agent starts the new version. A window that sees `draining` waits a
  few seconds and tries again; a send is never sent twice.
- **The socket path is too long.** A Unix socket path must fit in 104 bytes on macOS and 108 on Linux. With a very long
  `AC_HOME` the service does not start and says so (`unsafe-path`); set a shorter home, or use one identity per folder.

## The command line beside the service

`bag` commands that act on an identity (`inbox`, `send`, `pair`, `unpair`, `identity remove`, `record keep`) still
work while the service runs: the command line asks the service to lend it the identity for one act, runs the act with
its own terminal questions, and gives it back, and the service reads the trust file and the name book again after it.
While a window uses the identity, or a pairing of it runs, the identity is not lent: the command answers `held` (or
`busy`), naming the window, until that window is closed. `bag status --as <name>` always works, and prints a line
`service bag <version> pid <pid> contract 1 <socket>` while the service runs.

A borrowed act prints one line first, `the bag service (pid <n>) lent <name> to this command; it takes it back
after`. A command that names no identity it can lend (`publish`) is refused `held` while the service runs.

## How to stop it

On macOS:

```sh
launchctl bootout "gui/$(id -u)/dev.bag.service"
```

On Linux:

```sh
systemctl --user stop bag
```

That stops it until your next login. To stop it for good, also move the login agent's file to the Trash (on Linux,
`systemctl --user disable bag` first). Without it, the first window that needs bag starts the service again;
to keep bag from running at all, take the shim out of your hosts as well (the bag 0.4.0 install page, "Leave": `bag host remove` with the host and `--user`).



## What it protects, and what it does not

- Keys never leave the service. Shims and models see addresses only. On macOS the keys are in your login Keychain by
  default, so another program of yours cannot copy them from a file. That stops the keys being copied, not their use.
- The socket and the token keep other users out. They do not keep out a program running as you that can read
  `<home>/run/`: a process of the same user is not a boundary, before 0.4.0 or after. On Claude Code the install adds
  two layers: deny rules for `<home>/run/`, which stop the model's built-in tools and the file commands Claude Code
  recognises but not a script that opens the file itself, and, if you say yes, Claude Code's sandbox with the same
  entry, which confines every command the model's shell runs. Codex and omp have no such rule: there a model's shell
  can read the token and drive the service as any identity of the home, dialogs included.
- An identity whose keys an agent holds: the first window that uses it meets two `y`'s at the agent, one for the
  service's open of it and one for the window's own grant; each later window meets one. A window acts with its own
  grant under the agent's hop, never with the principal's key. The identity is reachable from a `login` until about 24
  hours after that login began, when its address and key records lapse; the service keeps none of them alive, and
  running `login` again refreshes them. In 0.4.0 a send from such a window under an organisation's members record is
  refused `not-authorized`, and a lost or revoked grant answers `not-authorized` until the window binds again or the
  service restarts.
- Names ending in `.service`, `.session` or `.signin` are kept for the service's own files; bag refuses them as
  identity names.
- Where the host's sandbox denies `<home>/run/` to the model, the worst a model can do through bag is ask: giving a
  window an identity and pairing still need your word or your Yes.
- One owner per mailbox, as before: an identity that a per-folder server or a CLI command holds is not taken by the
  service until they let go.

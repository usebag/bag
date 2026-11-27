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
- `service.json`: the running service's pid, start time, version and package directory, for `status` and the CLI,
  and what runs now: `pairings`, the pairings running in any window; `lends`, the identities lent to a `bag` command
  or held for an act in a window; `asking`, the questions waiting on your answer in any window. It is rewritten as
  these change, so a restart can tell what it would cut. The counts hold only while that pid runs.

- `service.log`: the service's log, JSON lines of events, codes and labels, never a key, a token or a message body
  (mode 0600, readable by you alone). It is not rotated: it grows by a few lines per start, connection and drain, and
  you may empty it at any time with `: > ~/.bag/run/service.log`.
- `shim/`: one small file per window while it uses an identity (`<host pid>.bound`, the names it uses) and its last
  ring (`<host pid>.ring`), which the wake hooks read; omp's questions come over its extension's own link, not a file
  (0.4.2). Codex runs one server
  process for all of its windows, so a Codex window's files carry its Codex session id as well
  (`<host pid>-<session id>.bound` and `.ring`, keyed from the session id of the window's first tool call); its Stop
  hook finds them by the `session_id` of its input, so each window wakes for its own identity's mail only. Codex's
  SessionEnd hook (a window closed or quit, or `/new`, about a minute late) releases that session's binding and
  removes its files; the shim stays and connects again unbound.

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

with the name of one of your identities. Typing `use` and its name binds at once in omp, and in Claude Code with bag's
plugin on; where the plugin is off, Claude Code asks for your Yes first. bag's hook reads the word before the model
sees it, so the model cannot type it for you. In omp the host says which messages you typed; in Claude Code bag's
plugin (the question card's, below) does, so a `use` that a schedule, a script or another session submits never binds
by itself. Without the plugin bag cannot tell your typing from such a message, so `use` brings bag's question (below),
and only your Yes binds. Two limits: another plugin loaded above bag's is installed code and is trusted like bag's
own, and an agent you have given control of your desktop types as you. On Codex, and on any host where the word cannot
be read that way, bag shows a dialog instead, the same on every host: "Act as omp-3 in this window? Its tools then act
as omp-3 until it closes. No: not asked again in this window for 5 minutes; typing use omp-3 binds it at any time. Say
Yes only if you asked for this." (the clause about typing in omp only; the last sentence, which also ends the question
with no name, on every host but omp: on those, a message you did not type could have led the agent to ask), with one
box, "Yes, act as omp-3": only a ticked Yes gives the window the
identity. Asked with no name, the dialog is "Which bag identity should this window act as?", with the identity a folder
offers first already chosen. In a window that already acts as an identity, the question names it: "Act as work in this
window, in place of omp-3?", or "Which bag identity should this window act as, in place of omp-3?". A window that
cannot show a dialog cannot take an identity. In Claude Code's VS Code extension and in Claude Desktop, the dialog is Claude Code's own
question card ([below](#bags-questions-in-claude-codes-question-card)).

The window then speaks as that identity, through restarts of the service, until you unbind it or the window closes:
every tool answer says which identity it acted as (`as`). Giving it another replaces the first: the window then acts
as the new one alone. In omp, and in Claude Code with bag's plugin on, typing `use` and its name replaces at once (omp
says so: "bag: this session now acts as work, in place of omp-3."); in Claude Code with the plugin off, typing it
brings bag's question, which says "in place of" the first, and only your Yes replaces it; elsewhere you ask the agent to
use it and say Yes in the bind dialog. The identity a window had last time in a folder may be offered first, but it is never taken
without your word, and nothing in a folder can choose for you: bag keeps no file in your project folders.

A message from a peer can never give a window an identity. A model that tries to take one on a message's say-so is
refused unless you type the word or answer Yes.

To take an identity back from a window, type `unbind` as the whole message in Claude Code or omp (`unbind` and a name
ends that one only, in a window that acts as several); on any other host, ask the agent to unbind, which it does with
its unbind tool. It asks nothing, since it only takes authority away, so in Claude Code it acts even on a message you
did not type: at worst a window loses its identity, and you bind it again. The window then acts as no identity, as a new
window does, and a restart of the bag service does not bring the identity back. Typed, the word does not reach the model
while bag's helper runs in the window, and the window shows what happened: "bag: this session now acts as no identity
(it acted as omp-3).", with another left "bag: this session no longer acts as omp-3; it still acts as work.", and with
nothing to take back "bag: this session acts as no identity: nothing to unbind." (for a name, "bag: this session does
not act as work: nothing was unbound."). While the bag service cannot be reached, the line says so, and the identity
does not come back when the service does. After the agent's unbind, the window's next answer says so once: "omp-3
unbound by an unbind call at 16:58 UTC: this window acts as no identity now". A window unbound three times within ten
minutes says that too, with the likely cause: a scheduled prompt or a message may be doing it, and you can list the
session's scheduled tasks. Other windows that act as the same identity keep it, and its mail keeps arriving. Closing the
window ends every identity it uses too.

A window that acts as an identity whose key is in your home or your Keychain can make a new identity and propose one
for its folder. You are still asked, as from any window, and the question's last line names the window: "Asked from a
window used as omp-3", every identity it acts as and every one it acted as before an unbind. After a restart of the
bag service, that line names only the identities the window still acts as, no longer one it was unbound from before
the restart. The new identity is not bound to the window that made it. A window of an agent or an organisation's grant
cannot; the login agent is written only from a window that acts as no identity.

A window that acts as an identity sees that identity's address in full, and your other identities by name, each with a
short address (`ed25519:` and its first 8 and last 4 hex digits, which is no address), as a window that acts as no
identity sees them all. The full addresses of the others are shown only after your Yes to "Show the full addresses of
this machine's identities to this window?" in that window, until it closes. An identity you keep apart (`bag
local-delivery hide`) is not shown at all to a window that acts as another identity: not its name, its address or that
it exists; and a window that acts as it is shown only itself. A window that acts as no identity yet still lists every
identity, one kept apart too, by name with its short address; a window that acts as none after an unbind is not shown
one kept apart that it was not used as, until a restart of the bag service: after it, that window lists every
identity again, one kept apart too.

Which identities you keep apart is written in your home's `run/local.json`, a file only you may read and write (mode
0600). If it is not (another mode, a link, or a file that does not read), bag cannot trust which ones are apart, so it
keeps local delivery off, shows each window that acts as an identity only that identity, and refuses to write the file
(`bag local-delivery`, a window's hide or show), until you fix it. `status` in a window and `bag status --home` say why
and the fix for its case: for a mode, `chmod 600` and then a look at `bag status --home` before you rely on it; for a
link, a file of another user or one that does not read, remove it, then turn local delivery off (`bag local-delivery
off`), hide the identities you keep apart again and turn it on: with the file gone, local delivery is on and nothing is
hidden, so off comes first.

## Pairing in a window

A pairing's dialogs (the code, the check digits) open in the window that started it, and only there. Another window
that uses the same identity is not interrupted and cannot answer them; it sees the new peer in the name book once the
pairing is done. Closing the window that started a pairing ends it, and nothing is written. `pair_cancel` works from
that window only. If the agent's host gives up on the call that starts a pairing (omp's own timeout, for example), that
pairing ends too, and the next call starts afresh. While a pairing runs, a new one in its window is answered `busy` with
a token to go on with the running one; another window is told only where it runs.

## bag's questions in Claude Code's question card

bag asks you through your host: a form (an MCP elicitation) for "Act as omp-3 in this window?", each pairing step and
each act that changes your home. Most hosts draw that form themselves. Claude Code's VS Code extension shows no form
for any MCP server and answers it at once without showing it (Claude Code issue 98256), and the Code tab of Claude
Desktop shows none either (Claude Code issue 105334). There bag asks in Claude Code's own question card instead,
through a small plugin of bag's.

| Host | Who draws bag's question |
|---|---|
| Claude Code in a terminal | Claude Code itself; bag adds nothing |
| Claude Code's VS Code extension | Claude Code's own question card, through bag's plugin |
| Claude Desktop, the Code tab | Claude Code's own question card, through bag's plugin |
| Codex (the interactive `codex`, 0.113.0 or later) | Codex itself; bag adds nothing |
| opencode | opencode itself; bag adds nothing |
| omp | bag's omp extension, over its own link to the bag service |

**Getting the card.** `bag host install claude-code --user` stages bag's plugin, named `bag`, in
`<home>/package/claude-code/` and turns it on in Claude Code's user settings; `bag host remove claude-code --user` takes
it out. The update page runs it again for a Claude Code wired that way, and a card you switched off stays off.
Reload each Claude Code window once after the install or the update (start a new session, or run `/reload-plugins`).
The card acts only in the VS Code extension and in Claude Desktop, and only on bag's questions; in a terminal it
passes each question on untouched, and Claude Code shows its own form. In every Claude Code window the plugin also tells
bag which messages you typed, so that a typed `use` binds at once (above).

**Reading a card.**

- Every bag question starts with `bag: `.
- The first choice grants and refuses nothing. A Yes-or-No question offers "Not now", then No, then bag's own Yes
  words; a choice of identity offers "Not now" first, then the identities; a question that asks you to type offers
  "Ask me later", then "Cancel". A card answered by habit, or in its first place, grants nothing.
- **No** (and "Cancel" on a question that asks you to type) is your No, as in any dialog: the act is refused. A No to
  "Act as omp-3 in this window?" stops the agent asking for omp-3 in that window for five minutes (typing `use omp-3`
  still binds at once, in omp and with bag's plugin on); a No to an Allow between two of your own identities holds for 24 hours, and the mail that
  waited on it goes back to its sender as declined.
- **Not now**, "Ask me later" and closing the card are no answer: nothing is written, granted or refused, and the
  question can come again later. In Claude Desktop, Skip is no answer too. A card that closes faster than a person could
  read it is taken as never shown. A question left unanswered closes after two minutes (a pairing step, when its
  invitation ends) and can be asked again; an answer after that does nothing.
- bag's own Yes words come after the harmless choice and the No, and only they say Yes.
- A question that asks for text (a pairing code, your peer's address, a name) takes it in the card's row for your own
  words. Typing one of the card's own choices there ("Cancel", "No", "Not now" and the like, in any case) is no answer.
- An identity whose name reads like one of the card's choices or like a Skip ("no", "Cancel", "skip", in any case) is
  not offered on the card: type `use` and its name in the window to act as it.

The same rule holds on every host: a form left untouched is not a No, and only a No you give (the card's No, or
declining the form) is one.

**What runs.** bag's plugin folder, staged under the bag home at `<home>/package/claude-code/`, runs inside Claude Code
at every session start, and each bag update replaces it. It reads one setting (which Claude Code surface it runs in),
draws the card and hands your choice to bag; it writes no file and keeps no log.

**Who else can answer.** Other plugins or hooks installed in Claude Code can answer a question in your place: Claude
Code passes the card through every installed plugin's hooks and through the hooks in its settings, including a hook an
agent writes into your settings, which Claude Code asks you about first, and any of them can fill in an answer that bag
cannot tell from yours. That is true of every Claude Code dialog, the terminal's included.
`bag host install claude-code --user` and `bag status --home` list the plugins and settings hooks that could (each a
`card_answerer` line in `status --home`); install only plugins and hooks you trust.

**Imitations.** A question can be imitated: the model can raise a card of its own with bag's words, `bag: ` included. An
imitation grants nothing: only an answer that reaches bag's own check counts, and the model's card never reaches it.
What you type into an imitation goes to the model, not to bag, so type a pairing code only into a question you asked
for, in a pairing you started.

**Where text typed into a card goes.**

In Claude Code, what you type into a card goes to bag through the card's own hook. It is not added to the
conversation: the model does not receive it, and bag's answer to the model does not repeat it. Claude Code does pass
it to any plugin or hook that watches its question tool, as it does with every answer you give there, and keeps it in
its own log on this machine: in VS Code, the Claude Code extension's log (its output channel, a file under VS Code's
logs folder); in a terminal, Claude Code's debug log when debug logging is on.

In Claude Code, the plugins and hooks above see the question and your answer. On every host, the screen shows the
text as you type it, and bag never writes it to a log or returns it in a tool's answer.

**The pairing code.** On the accepting side, you type your peer's pairing code into the card. A code expires within ten
minutes, and the six check digits protect it: the accepting side reads them out by voice, the inviting side types what
it hears into its own card, and someone who only saw the code cannot finish the pairing without them. Wrong digits
write nothing.

## The login agent

The login agent is what keeps the service running while you are logged in. `bag host install service` prints it, for
the platform it runs on, and you load it yourself (the install page's step 6c, "The bag service, started at login": there the `service` tool writes it and you run the one line it returns), in your own terminal; bag never touches launchd or systemd on its own. It:

- starts the service when you log in, from the copy of bag in `<home>/package/`;
- restarts it if it stops or crashes;
- runs it at the normal priority of a program you use, so your windows get their answers quickly (from bag 0.4.6 on
  macOS; a login agent installed by an earlier bag keeps the lower background priority until it is installed again);
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
- **A login agent is loaded, and the service stopped.** A window that needs bag asks the login agent to start it, and
  does not start its own copy, so the service keeps running under the login agent. Only if the login agent's service
  is not answering within 20 seconds does the window start one itself. If another copy holds the home when the login
  agent's starts (one an older window started), the login agent's copy waits for it to stop and then takes over.
- **It crashed.** The login agent starts it again. Each window keeps its identity: when the service is back, the
  window binds again to the identities you gave it, with no `use`, and its next answer says so once. Nothing is lost:
  the mail, the cursor and the records are on disk, and the service picks up where it stopped. A window opened before
  bag 0.4.6 was installed binds one last time.
- **A window that cannot keep an identity says why.** If the identity was removed (or removed and made again under the
  same name), or a `bag` command is using it, the window's next answer says so; when you want it again, type `use` and
  the name in Claude Code or omp, or elsewhere ask the agent to use it and say Yes in the bind dialog. An identity in
  your Keychain opens at the window's first act after the restart, so its Keychain question comes when you are using
  the window, never at the restart itself.
- **It is still opening your identities.** Right after a start the service answers every window at once and opens your
  identities one after another. A window whose identity is not open yet hears "the identity <name> is still opening:
  try again in a few seconds" (or, for an identity in your Keychain, that a Keychain dialog may be waiting); a window
  that kept its identity through the restart simply waits for it to open.
- **It is restarting for an upgrade.** It first refuses new `use` words and new pairings with `draining`, cancels any
  pairing that is running (its code and check digits are not carried over), lets running tool calls finish for up to
  10 seconds, saves everything and exits; the login agent starts the new version. A window that sees `draining` waits a
  few seconds and tries again; a send is never sent twice. Each window keeps its identity through it, as after a crash.
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
  service's open of it and one for the window's own grant; each later window meets one. A window acts with its own grant
  under the agent's hop, never with the principal's key. The identity is reachable from a `login` until about 24 hours
  after that login began, when its address and key records lapse; the service keeps none of them alive, and running
  `login` again refreshes them. A send from such a window under an organisation's members record is refused
  `not-authorized`. The service renews the identity's grant through the agent before it ends, with no `y`; a window's
  own grant renews while the window is bound, idle or not, pauses while the identity is lent or held for an act, and
  tries once when it comes back. A grant that ends with the agent's login is used to its end with no `y` before it. When
  a grant is revoked (a logout) or has ended, nothing is asked on a timer: the next send answers `grant-pending` with
  the agent's request code, one `y` per grant (the identity's, and each window's own) grants a fresh key, and the window
  carries on with its threads; the grant stays lost until that `y`. The agent's prompt carries a note written by the
  service: the identity, the kind of window and the reason. A `no` at the agent holds until you type `use` and the name
  again in Claude Code or omp, or elsewhere say Yes in the bind dialog the agent's `use` opens. After a regrant the old
  session key is deleted and revoked at the agent, at once or, when the agent could not take it, at the next start or
  regrant; an older agent, which has no revoke, leaves the old key signing to its grant's end. The grant events are in
  the identity's audit log, or the service's log while the identity is not open. Limits: a service restart ends the
  identity's session, so after it the identity asks one `y` again, and each window that keeps
  it asks its own `y` at its first act; its threads start afresh; near the agent's window end a send can ask one `y` up
  to 5 minutes early (a renewal waits for the agent's pace, so the last grant can end up to one pace before the login,
  never after it); a grant the agent signed for another key at the old key's request, and an old window key, are not
  revoked and last to their grant's end (at most 8 hours).
- Names ending in `.service`, `.session` or `.signin` are kept for the service's own files; bag refuses them as
  identity names.
- Where the host's sandbox denies `<home>/run/` to the model, the worst a model can do through bag is ask: giving a
  window an identity and pairing still need your word or your Yes.
- One owner per mailbox, as before: an identity that a per-folder server or a CLI command holds is not taken by the
  service until they let go.

## Known limits

- After a window's bag process is killed (not closed) and the system gives its process number to another program,
  `bag status --home` can list that closed window as bound, and that window's wakes can be missed until it binds again.
- An omp window opened before the Mac's time zone changes stops binding until omp is restarted.

# Running bag in omp

omp (oh-my-pi, a coding agent) runs bag like any MCP host, but it has no hook that wakes an idle session when mail
arrives, and no MCP dialogs. From bag 0.4.0, `bag host install omp --user` wires omp once for every folder: the bag
shim in omp's user-level MCP configuration, which connects each omp session to the bag service
([bag-service.md](bag-service.md)), and bag's wake extension, which reads your `use`, opens bag's dialogs and starts a
turn when a message is delivered. The per-folder form of bag 0.3.0 stays as the way back (section 5). This page is about
omp 18.17.0; [partner-install.md](partner-install.md) covers identities, relays and pairing, which come first. `c` is
the function of partner-install.md section 1a.

## 1. Install, for every folder

You need an identity (`bag keygen`, partner-install.md section 2) whose records are published at your relays
(section 4). Then:

```sh
c identity relays alice --relay https://relay1.bag.dev --relay https://relay2.bag.dev
c host install omp --user
```

The first, on a terminal with one `y`, puts `alice` and its relays into the bag service's list, `<home>/identities.json`;
the second writes, once per user, the shim into omp's user-level `mcp.json` and the link `bag-wake.js` to bag's wake
extension into omp's user-level `hooks/pre/`. Start omp in any folder and type `use alice`: the
extension reads the word before the model sees it, and the window speaks as `alice` from then on. Start the service at
login as the install page's step 6c says.

omp's user-level files are `<agentDir>/mcp.json` and `<agentDir>/hooks/pre/`, where `<agentDir>` is
`~/.omp/agent` unless `PI_CODING_AGENT_DIR` names another. A folder's own `.omp/mcp.json` entry named `bag` wins over
the user's, which is why section 5 moves them.

The extension finds its own session's shim by omp's process id, through `<home>/run/shim/`, a directory the shim
keeps inside the service's 0700 run directory; your `use` goes to that shim only, with a secret the shim made at its
start, so no other session can bind your window.

`host install omp --user` takes no `--as` and no relays (the identity's relays are in the service's list, which `bag
identity relays` sets), and prints `wrote <agentDir>/mcp.json: mcpServers.bag, the bag service's shim` and a line for
the wake link, then that omp has no sandbox or path-deny setting, so the model's shell can read and write `<home>/run`,
and that the wake extension starts a turn on a ring in the main interactive omp session.

### The per-folder form

The rest of this section is the form of bag 0.3.0, one folder for one identity, which section 5 keeps as the way back.
In this form omp cannot show pairing dialogs: the pair tools answer `no-elicitation`; pair with `bag pair` in a
terminal (pairing-without-dialogs.md section 2).

```sh
c host install omp --as alice --relay https://relay1.bag.dev --relay https://relay2.bag.dev \
  --rendezvous https://relay1.bag.dev --project /path/to/folder
```

From an agent window of the bag service, the `host_wire` tool writes neither of these. After you type, in its dialog,
the label of an identity, it proposes that identity for the window's own folder: every new window opened there has it
preset in its bind dialog, and acts as it only after your Yes or your typed `use` and the name, while the bag service
keeps holding it. With `action: unwire` it takes that proposal out, and the two things below if an earlier bag wrote
them. The dialog shows the folder whole, so a folder path longer than 60 characters (or one with a character the
dialog cannot show) is refused there. This command is the way back to a folder's own server, which holds the identity
apart from the bag service.

`--dir <home>` names a home other than `$AC_HOME`, else `$HOME/.bag`. `--trust-root <domain|address>` is passed to the
server as for `host install claude-code`. The command writes two things, and prints each:

- **`<folder>/.omp/mcp.json`**, `mcpServers.bag`: `{"type": "stdio", "command": "<node>", "args": ["<home>/package/bag-mcp.js",
  "--as", "alice", "--relay", ..., "--dir", "<home>", "--keep-alive-records", "--push", "log"]}`. Other servers and keys
  of the file are kept.
- **`<folder>/.omp/hooks/pre/bag-wake.js`**, a symbolic link to `<home>/package/bag-omp-wake.js`. omp loads every
  file in `.omp/hooks/pre/` as an extension. The link points into the copy of the package in your home, which the
  same command writes, so one maintained file serves every folder and is replaced when bag is: never a copy in the
  project.

Run it again and it changes nothing and says so. It refuses, writing nothing, when `mcpServers.bag` is there with other
settings, or when `.omp/hooks/pre/bag-wake.js` or `bag-wake.ts` is a file that is not bag's link (a wake written by
hand): move it away first. omp also loads the servers of `.claude/mcp.json` and `.claude/.mcp.json` in the same folder;
if one of those names a bag server too, the command warns, since two servers for one identity cannot both run.

It also reads the identity's address and accept-from records at each relay. A relay that lacks one, while another
named relay or the home's copy (`<home>/records/`) holds it, gets the newest copy published as it is, re-signing
nothing, and a line says so (an identity paired through `bag pair` often has its records at the rendezvous relay
only). A record that no relay and no copy holds gets a warning line instead, since that relay refuses mail to the
identity until it is published: `bag onboard` publishes them (partner-install.md section 4); the server's
`--keep-alive-records` keeps records alive but never makes the first ones. A relay that does not answer is named as
unchecked.

The change takes effect with the next omp session in the folder. To undo it:

```sh
c host remove omp --as alice --project /path/to/folder
```

It takes out the `mcpServers.bag` entry of that identity and bag's link, and nothing else.

## 2. How the wake works

With the service, the extension rings for the identity its window uses: the service tells the window's shim when mail
for that identity arrives, and only the window you last typed in starts a turn; another omp window that uses the same
identity shows a quiet notice. The text of the turn, the loop guard and the pending wake below are the same.

The ring reaches the window's shim over its socket; the shim writes it to `<home>/run/shim/<omp pid>.ring` beside
the `.bound` file that names the window's identities, and the extension watches that file instead of the doorbell
while `.bound` exists. A window that is not speaking starts no turn and shows, in the footer:
`bag: 2 unread for omp, shown in the window you last typed in for omp; type here to have the next mail shown here`.

In the per-folder form, the bag server moves the mtime of the identity's doorbell, `<home>/state/<name>/doorbell`, once
for each message it accepts. The extension, loaded in the omp session, reads the identity from the bag server's `--as`
and `--dir` in `.omp/mcp.json` and watches the doorbell:

- by file-system events on `<home>/state/<name>/`, with a look every 30 s as a fallback (a missed event, the machine
  waking from sleep);
- on a ring, it waits 300 ms for the rest of a burst (several messages land as several rings a few milliseconds
  apart), then, if the session is idle, starts exactly one turn whose text is `bag: mail arrived for alice: read it
  with the bag inbox tool and show it to your person. Answer only when your person asks, or when it plainly asks a
  question they already told you to answer.` The model reads with the inbox tool; it needs no `wait` or `ask` loop.
  It is never told to answer on its own: two agents told so answer each other without end;
- when one peer has sent 3 or more messages in the last ten minutes since you last typed in the session, the turn's
  text adds `3 unread from bob in ten minutes: this looks like a loop: show your person and do not answer.`, with the
  count, and the peer named as your name book names it (else by its short address). The count is read from the
  identity's store without its lock, so it holds whatever the model does;
- a ring while a turn runs is kept as one pending wake and fires when that turn ends, so a ring is never lost and two
  wake turns never overlap;
- the mtime it handled is written to `<home>/state/<name>/wake-seen`, the file the Claude Code and Codex hooks use, so
  a ring is woken for once. It is the newest mtime when the turn starts: every message delivered before then is read
  in that turn;
- when omp starts in the folder again, a doorbell newer than `wake-seen` wakes the new session at once, for mail that
  came while omp was closed;
- when the identity's server runs in another session (its `mcp.lock` names a live process that is not this session's
  server), the ring is shown in the session, naming that process, and no turn is started: read the mail there, or
  close that session.

The extension also writes `<home>/state/<name>/host-facts.json` at session start, after each turn and every 4
minutes: the model (`provider/id`), the session's cost and context use as omp computes them, the session id and
whether this is the main session. bag's `facts` tool reads them, so an agent reports its model and cost from data.

## 3. Windows, identities and the main session

Any omp window can use any identity of the home, and two windows can use one: the service owns the mailbox, and one
window speaks for it ([one-identity-per-folder.md](one-identity-per-folder.md)). In the per-folder form, run one omp
session per folder and identity: a second session in the same folder starts a second bag server for the same identity,
and only one of them can hold it.

Only the main session the person opened speaks for the identity. The extension wakes nothing, and says so on stderr,
in a session omp starts with `-p`/`--print`, in `--mode rpc` or `--mode json`, and in a subagent. A session you spawn
from the folder for a side task:

- passes `--model` explicitly (`omp -p --model <provider/id> ...`): omp's configured default model is not the agent's
  model, and a session that inherits it reports itself as something it is not;
- does not load the bag server unless it has an identity of its own: start it with `--no-extensions` and outside the
  folder, or in a folder wired with `host install omp` for its own identity.

## 4. Pairing inside the omp session

omp shows no MCP dialogs, so when a pairing needs your word bag asks through the wake extension instead. The questions
come over the extension's own connection to the bag service, registered for this omp process, never through a file, and
only to the window that started the pairing; closing the window ends the pairing. They need the bag service: the
per-folder form (section 1) cannot pair inside omp and answers `no-elicitation`, so pair there with `bag pair` in a
terminal (pairing-without-dialogs.md section 2). The invite code shows only in omp, above the editor, until the pairing
ends, never in a tool result: a person who loses it asks the agent to cancel the pairing (`pair_cancel`) and invite
again, and the new code shows in its place. Between two identities of one home (0.4.1) there is no code: the first
message from one to another asks once, in the recipient's speaking window, "<a> on this machine wants to message <b>.
Allow both ways?", and hiding or showing an identity asks the same way. All of these need the extension of 0.4.2 or
later for pairing (0.4.1 for the local prompts): run `bag host install omp --user` again and restart omp (a running omp
keeps the extension it started with); without it the tool answers `no-elicitation` and says so. `bag host install omp
--user` also sets omp's own timeout for the bag server to 130 seconds (`"timeout": 130000` on `mcpServers.bag`), so a
question can stand for up to 120 seconds inside the call that asks it. No answer is not a No: only your own No declines;
a prompt that times out (after omp's timeout for the call less 10 seconds, from 15 to 120 seconds: 120 with bag's
130-second entry, 20 under omp's own 30-second default or an `OMP_MCP_TIMEOUT_MS` of 30000; with an `OMP_MCP_TIMEOUT_MS`
from 1 to 19999 no question can be asked at all, and 0, omp's no-timeout, gives 120), is taken off the screen or is
aborted leaves the pairing or request waiting, asked again at the agent's next call. One limit: omp's yes-or-no prompt
cannot tell Esc from No, so Esc on this prompt counts as No.

- you accept a code: omp asks you to paste it (a text field with a countdown); then, during the agent's next call, a
  Yes/No dialog shows the six check digits to read out to your peer, and Yes sends the request (arrows and Enter:
  typing y does not answer it);
- someone accepts your invite: omp asks you to type the six digits your peer reads to you;
- you invite someone: the invite code shows above the editor until the pairing ends; give it to them yourself (read
  it out or send it), never through an agent;
- no answer is not a No: the agent asks again on its next call, until the invite ends (in any 10 minutes, at most 3
  answered and 6 unanswered questions of one kind in a window, twice that over all windows of this bag home, and 6
  never shown in a window because too little of the agent's call was left; at most 6 pairings started in a window and
  12 over all windows of this bag home; past any of these, `rate-limited`). Only No declines;
- while a question waits, the footer reads `bag: pairing request pending`.

Only the answer goes back to the service, which pairs with the peer of its own request. A print session (`omp -p`)
never binds an identity, since no one is there to answer the binding's question, so its pair tools refuse `not-bound`
before any question is asked, never `no-elicitation`. A session in `--mode rpc` or `json`, or a subagent, registers no
link, so the pair tools refuse `no-elicitation`, which names omp's interactive session and how to update the extension
(pairing-without-dialogs.md, section 3).

## 5. Moving wired folders, and the way back

`c host migrate --dry-run` lists every folder an earlier bag wired for omp (its `.omp/mcp.json` entry and wake link)
and changes nothing. `c host migrate`, on a terminal, asks once, keeps a journal of every file it edits, takes only
bag's entries out of each folder and remembers each folder's identity as the one a window opened there is offered
first. `c host migrate --undo` puts every journalled file back, byte for byte: the way back to the per-folder form.
Close the omp sessions in those folders first.

A folder wired by hand, before `host install omp` existed, has a wake file of its own in `.omp/hooks/pre/`, which the
migration does not take: move it away first, with the folder and the identity of that agent, one per line:

```sh
FOLDER=/path/to/folder
NAME=alice
mv "$FOLDER/.omp/hooks/pre/bag-wake.ts" "$HOME/.Trash/bag-wake.ts-$NAME-$(date -u +%Y%m%dT%H%M%SZ)"
c host remove omp --as "$NAME" --project "$FOLDER"
```

Then start omp anywhere and type `use` and the name. The first session takes the doorbell's mtime as `wake-seen` only
when none is there; with one, mail that came while the folder moved wakes it.

`host migrate` takes a folder's `mcpServers.bag` entry of `.omp/mcp.json` that names this home and an identity it
holds; a hand-written wake file is not bag's entry, so move it as above.

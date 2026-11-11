# Running bag in omp

omp (oh-my-pi, a coding agent) runs bag's MCP server like any MCP host, but it has no hook that wakes an idle session
when mail arrives. `bag host install omp` wires one project folder with one command: the bag server in
`.omp/mcp.json`, and bag's wake extension, which starts a turn in the omp session when a message is delivered. This
page is about omp 18.17.0; [partner-install.md](partner-install.md) covers identities, relays and pairing, which come
first.

## 1. Install

You need an identity (`bag keygen`, partner-install.md section 2) whose records are published at your relays
(section 4), and the folder omp will run in. Then, from the npm package:

```sh
c() { npx --yes --package=@usebag/bag@0.3.0 bag "$@"; }
c host install omp --as alice --relay https://relay1.bag.dev --relay https://relay2.bag.dev \
  --rendezvous https://relay1.bag.dev --project /path/to/folder
```

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

The bag server moves the mtime of the identity's doorbell, `<home>/state/<name>/doorbell`, once for each message it
accepts. The extension, loaded in the omp session, reads the identity from the bag server's `--as` and `--dir` in
`.omp/mcp.json` and watches the doorbell:

- by file-system events on `<home>/state/<name>/`, with a look every 30 s as a fallback (a missed event, the machine
  waking from sleep);
- on a ring, it waits 300 ms for the rest of a burst (several messages land as several rings a few milliseconds
  apart), then, if the session is idle, starts exactly one turn whose text is `bag: mail arrived for alice. Read it
  with the bag inbox tool, then answer it.` The model reads with the inbox tool; it needs no `wait` or `ask` loop;
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

## 3. One identity per folder, one main session

Run one omp session per folder and identity. A second session in the same folder starts a second bag server for the
same identity; only one of them can hold it.

Only the main session the person opened speaks for the identity. The extension wakes nothing, and says so on stderr,
in a session omp starts with `-p`/`--print`, in `--mode rpc` or `--mode json`, and in a subagent. A session you spawn
from the folder for a side task:

- passes `--model` explicitly (`omp -p --model <provider/id> ...`): omp's configured default model is not the agent's
  model, and a session that inherits it reports itself as something it is not;
- does not load the bag server unless it has an identity of its own: start it with `--no-extensions` and outside the
  folder, or in a folder wired with `host install omp` for its own identity.

## 4. Pairing inside the omp session

omp shows no MCP dialogs, so when a pairing needs your word the bag server asks through the wake extension instead.
In the main interactive session the extension writes `<home>/state/<name>/consent/.bridge`, refreshes it every few
minutes and removes it when omp ends; the server writes a request beside it and the extension asks you in the TUI:

- someone pairs with you: a Yes/No dialog, `bag: <peer> asks to pair as <name>` with the check digits to compare
  with what your peer reads out (arrows and Enter: typing y does not answer it). Yes pairs; No, or no answer within
  two minutes, does not;
- you invite someone: the invite code shows above the editor, and a Yes/No dialog asks that you gave it to them
  yourself (read it out or send it; never through an agent);
- while a request waits, the footer reads `bag: pairing request pending`.

Only the answer goes back to the server, which pairs with the peer of its own request. A session with no dialogs
(`omp -p`, `--mode rpc` or `json`, a subagent) writes no `.bridge`, so the server answers as it does without
elicitation: with the `bag pair` command to run in a terminal (pairing-without-dialogs.md).

## 5. Moving a folder wired by hand

A folder wired before this command has a bag entry in `.omp/mcp.json` and a wake file of its own in
`.omp/hooks/pre/`. Close the omp session in the folder, then run these, one per line, with the folder and the identity
of that agent:

```sh
FOLDER=/path/to/folder
NAME=alice
mv "$FOLDER/.omp/hooks/pre/bag-wake.ts" "$HOME/.Trash/bag-wake.ts-$NAME-$(date -u +%Y%m%dT%H%M%SZ)"
npx --yes --package=@usebag/bag@0.3.0 bag host remove omp --as "$NAME" --project "$FOLDER"
npx --yes --package=@usebag/bag@0.3.0 bag host install omp --as "$NAME" --relay https://relay1.bag.dev --relay https://relay2.bag.dev --rendezvous https://relay1.bag.dev --project "$FOLDER"
```

Then start omp in the folder as before, with its `--model`. The first session takes the doorbell's mtime as
`wake-seen` only when none is there; with one, mail that came while the folder moved wakes it.

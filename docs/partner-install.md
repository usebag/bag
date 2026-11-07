# Partner install guide

A step-by-step install and first exchange for the bag reference implementation. The README, `LICENSE`,
`SECURITY.md` and `CONTRIBUTING.md` in this repository are the authority on status, licence, reporting a security issue
and contributing.

This guide is the route by hand. The agent route, [bag.dev/install](https://bag.dev/install), is a page for a coding
agent, Claude Code: it installs the npm package and makes an identity, and leaves pairing and wiring Claude Code to
you. The package, which section 1a runs, has its page on the npm registry:
[npmjs.com/package/@usebag/bag](https://www.npmjs.com/package/@usebag/bag).

This guide takes you from a clean machine to a working identity, a relay, published records, a message sent and
received, and a verified audit log, and then to serving your own record at an origin you control. It goes deeper than
the quick path in `README.md`; read that first if you want the shortest route. Every command below is a command of this
repository; from source, run everything from the root of the clone (section 1b). Commands are written for a Unix
shell with `bash`.

## 1. What you need

There are two routes to the same programs. The npm package (1a) needs Node 24 and nothing more: nothing is cloned or
built, and `npx` runs it without installing anything globally. It holds the command line, the MCP server and the A2A
bridge, but not the relay. From source (1b) builds everything here, the relay included, and every byte the package
runs can be built and checked that way. Take 1a for the shortest start; take 1b to read or build the source, run the
checks, or build a relay. Sections 3, 5c and 6 say where a step differs between the two.

### 1a. The npm package

You need Node 24 or later. bag is the npm package `@usebag/bag`, one bundle with no dependency and no install script.
Name the version and the program every time. Define a shell function once per terminal and use it for every command
below:

```sh
c() { npx --yes --package=@usebag/bag@0.2.0 bag "$@"; }
c --version                            # prints: bag 0.2.0 <the commit it was built from>
npm view @usebag/bag@0.2.0 gitHead     # prints the commit npm records for 0.2.0
c help                                 # prints every command
```

The package is published from a commit of this repository by a workflow with npm provenance, and
`npm view @usebag/bag@0.2.0 gitHead` names that commit. The two commits above must be the same, and must be the
published commit of this release, which the agent route's page names; if they differ, or `npm view` fails (`E404`
among the errors), stop and do not use the package. The first run fetches the package into npm's cache, `$HOME/.npm`,
so it needs the network once.

The package holds three programs: `bag`, the command line, which `c` runs; `bag-mcp`, the MCP server (section 5c);
and `bag-a2a`, the A2A bridge, which this guide does not use. Run `c` outside any project that has a `bag` command of
its own, so that the package's is the one that runs (the agent route starts its `c` from a working folder of its own
for this reason). The package holds the programs only: the files this guide cites, such as `spec/SPEC.md` and the
READMEs under `packages/`, are in the source repository.

### 1b. From source

Clone the repository, work inside the clone and run everything below from its root:

```sh
git clone https://github.com/usebag/bag.git bag
cd bag
```

If you received this copy as one file, `<file>.bundle` (a git bundle), clone the file instead of the repository, from
the directory that holds it, then check it from inside the clone (`git bundle verify` needs a repository to run in).
The check must print `../<file>.bundle is okay`, the refs `refs/heads/main` and `HEAD` at the same commit ("The
bundle contains these 2 refs"), and "The bundle records a complete history."; if the clone or the check prints an
error, any other ref, refs at different commits or an incomplete history, stop, do not use the clone, and ask the
person who sent it:

```sh
git clone <file>.bundle bag
cd bag
git bundle verify ../<file>.bundle
```

| need | version | where it is pinned |
|---|---|---|
| Node | 24 or later | `.nvmrc` (24), `package.json` `engines` |
| Rust, through `rustup` | 1.95.0 | `rust-toolchain.toml`; rustup installs it on the first `cargo` call |
| Python 3 | 3.11 or later, for the checks only | `scripts/requirements-dev.txt`, built by `scripts/last_step.sh` |

Build once:

```sh
npm ci
cargo build --release --locked -p ac-relay
```

`npm ci` installs the TypeScript workspaces; the CLI needs nothing more. The second command builds the relay to
`target/release/ac-relay`. To check the whole repository, run `scripts/last_step.sh` (see `README.md`, "The checks").

From source the CLI has no `bin` entry. Define a shell function once per terminal and use it for every command below:

```sh
c() { node packages/cli/src/main.ts "$@"; }
c help          # prints every command
```

For the onboarding path, see docs/onboarding.md.

## 2. Identities

An identity is a name on your machine and two keys: a signing key and a separate sealing key. Its address is the public
form of the signing key, `ed25519:` and 64 hex characters.

```sh
c keygen alice          # prints the address only, never a key
c keygen bob            # the sender in section 5
c address alice         # prints it again
c keys list             # one line per identity: <name> <address> <custody> <created>
```

Where things live. The home is `--dir <home>`, else `$AC_HOME`, else `$HOME/.bag`. With none of the three, a
command fails with a usage error. Under the home:

- `keys/` holds one key file per identity, mode 0600 in a directory of mode 0700. `keygen` never overwrites an existing
  file and refuses a name already in use.
- `state/<name>/` holds that identity's `edge.sqlite`, its `audit.jsonl` and its `doorbell`; the directory is made 0700,
  the audit log and doorbell 0600.
- `names.json` and `trust.json`, when they exist, are 0600.

On macOS, `keygen --custody keychain` keeps both keys in one keychain item instead of a file. `keys list` shows which
custody each identity uses and never prints a key.

Never copy, send, commit or paste anything under `keys/`, and never give anyone your home directory. Share addresses and
records: they are public by design. Back up `keys/` yourself, offline; there is no recovery for a lost key file.

## 3. A relay

A relay is a store-and-forward server. It stores sealed envelopes and signed records, and holds a mailbox open for a
subscriber. It cannot read what you send. You either run your own or use the URL of one you were given; in both cases
every command takes it as `--relay <url>`. Two public relays run, `https://relay1.bag.dev` and
`https://relay2.bag.dev`, and either stands in for one of your own (`README.md`, "Public relays").

The relay is Rust and is not in the npm package. On the package route (section 1a), use a relay you were given or a
public one, or run the relay's container image, built from a clone or pulled as `ghcr.io/usebag/relay:<commit>`
(`docs/self-host.md`, "Run it with Docker"); that needs Docker with Compose and a clone of this repository for its
compose files, but no Rust and no Node. The command below runs the binary that section 1b builds.

Running your own:

```sh
target/release/ac-relay --port 8787 --db "$HOME/ac-relay.sqlite"
```

- `--port` is the port; the default is 0, which picks a free one. `--bind` is the address to listen on and defaults to
  `127.0.0.1`, so only your machine can reach it. `0.0.0.0` or `::` listens on every interface.
- `--db` is required. It is a SQLite file, created when missing; its directory must already exist.
- Once listening, the relay prints exactly one line to stdout, `AC_RELAY_URL=<url>`, and writes its log to stderr.
- It speaks plain HTTP and WebSocket and has no TLS of its own. To serve it beyond your machine, put a TLS proxy in
  front, then give the relay `--advertise https://<host>`, and `--trust-proxy <cidr>` so that it counts and logs the
  client the proxy names. `ac-relay --help` lists every flag; `--ttl`, `--skew` and `--max-envelope-bytes` set how long
  and how large an envelope may be, and the `--rate-*` flags set the publish limits.
- SIGINT (Ctrl-C) or SIGTERM stops it cleanly.
- Check a relay from a CLI: `c health <relay-url>` prints `ok`.

A relay on a loopback or private address is refused by the CLI as a recipient's relay unless you pass
`--allow-private-relays` to `send` or `inbox`; the relay you name with `--relay` is exempt.

### What the relay logs

Each log line is one JSON object on stderr, with a timestamp, a level, a `target` and a `fields` object whose `event`
member names what happened. The events you will see first:

| event | meaning |
|---|---|
| `listening` | start-up is done: the bind address, port, URL, database file and the limits in force |
| `publish` | an envelope was accepted: its id, the `from` key, the `root`, whether it was a `duplicate`, whether it was `delivered`, and the client address |
| `publish-record` | a record was accepted: its kind, signer and `iat` |
| `publish-refused` | a publish was refused: the HTTP status and the error code (or `body-timeout`) |
| `fetch`, `fetch-refused` | an authenticated fetch of an envelope succeeded or was refused, with the code |
| `fetch-chain-refused` | a fetch was refused because the chain of the signer did not pass, with the code |
| `subscribe` | a subscriber was admitted: the mailbox, the signer and the cursor it starts from |
| `subscribe-refused` | a subscriber failed its proof or was not allowed: the code |
| `subscribe-closed` | a subscription ended: the mailbox, the last cursor sent and the reason |
| `connection-refused` | a client held more connections than `--connections-per-ip` allows and was closed |
| `connection-closed` | a WebSocket connection ended and freed its place (plain HTTP requests write none) |
| `stopped` | a clean shutdown |

Others you may meet: `rate-limited` (a publish over a limit), `pending`, `pending-delivered` and `pending-dropped` (an
envelope waiting on a domain root that was not yet resolved), `domain-roots`, `well-known`, `well-known-refused` and
`txt` (the relay resolving a `domain:` root, section 6), `revoked-hop`, `sweep` (expired rows removed),
`resolutions-capped`, `store-error`, `store-corrupt`, `accept-error`, `fatal` (it could not start), `stdin-eof` (the
end of stdin stopped it, with `--exit-on-stdin-eof`) and, for the operator's pin override, `pin-reset` and
`pin-reset-refused`. A pin reset is queued beside the database with `--pin-reset <domain> --queue` and the operator's
record (`--new-key`, `--operator`, `--channel`, `--reason`), and applied at the relay's next start: `pin-reset` names
the domain, the `old_key` and the `new_key`; `pin-reset-refused` names a request that was skipped, and the relay still
starts. A flag that is for tests only adds a warning line after `listening`.

What it never logs: message bodies. An envelope body is sealed to its recipient's key before it reaches the relay, and
no log line in the relay carries a body, a plaintext or a key. A line carries ids, public keys, record kinds, codes
and the client address. `--log-ip` chooses how the address is shown: `prefix` (the default: a /24 for IPv4, a /48 for
IPv6), `full`, or `none`.

## 4. Records

Other parties find you through two signed records at a relay.

- The address record says where your mailbox is (its relays) and, with `--sealing-key`, the key that seals messages to
  you. Without it nobody can send you a sealed envelope.
- The accept-from record says whose messages the mailbox takes: the `--root` addresses (a `domain:<host>` root, or `*`),
  the largest envelope in bytes, and a retention.

```sh
R=http://127.0.0.1:8787
c record address alice --relay "$R" --sealing-key --out alice.json && c publish "$R" alice.json
c record accept-from alice --root "$(c address bob)" --max-bytes 65536 --ttl 604800 --out alice.accept.json \
  && c publish "$R" alice.accept.json
```

`publish` prints `ok <kind> <signer>`. A relay takes a record only if it is newer (by `iat`) than the one it holds
(`stale-record` otherwise). An envelope to a mailbox with no accept-from record at that relay is refused `not-hosted`.

Lifetimes. An address record has a `ttl` of at most 86,400 seconds (a day), the default; once `iat + ttl` has passed,
a peer can no longer use it, and sends to you fail with `resolve-failed` (its detail ends `(record-expired)`, or
`(none)` once the relay has swept the record; section 8). The accept-from record's `--ttl` is its retention, and a
newer accept-from record replaces it. So an address record must be signed again at least daily.

`record keep` does that:

```sh
c record keep --as alice --relay "$R"            # runs until Ctrl-C
c record keep --as alice --relay "$R" --once     # republish now, then exit
```

It reads your newest address record (and accept-from record, if any) back from the relays you name, signs both again,
unchanged but for a newer `iat`, and publishes each at every relay, printing `republished <kind> <address> iat <iat>
<relay>` per republish and `next <unix seconds>` while it waits. It republishes at half the address record's `ttl`
(12 hours for the default), or every `--every <seconds>`, which must be below the `ttl`. A republish that no relay
took is retried after 60 seconds, doubling to an hour. It takes no lock on your home, so it runs beside `inbox`. It
refuses a record that names `rotated_from`: publish a fresh `record address` first.

`record keep` is not a service. It runs in the foreground until you stop it, and nothing restarts it after a reboot or
a crash. To keep it standing, run it under a supervisor you already use (a systemd unit with `Restart=always`, a
launchd agent with `KeepAlive`, or a process manager); if it is down for more than your `ttl`, your address record
lapses, and the fix is `c record keep --as alice --relay "$R" --once`: it re-signs the copy this home keeps, with its
rotation key and revoked list. Do not sign a new one with `c record address`, which replaces the revoked list. `c keys
rotate alice --relay "$R" --accept-loss` is for a home that has lost that copy, and starts both empty. This repository
ships no unit file or installer for it.

## 5. Sending and receiving

```sh
c send --as bob --to "$(c address alice)" --relay "$R" --type chat.v1 --body '{"text":"hi"}'
c inbox --as alice --relay "$R" --once --trust-root "$(c address bob)"
```

- `send` prints the envelope id, then one line per target relay: `published <relay> tries=<n>`, or a retry or failed
  state with a reason. `--to` takes a raw address, a name from your name book (`c name add <name> <address>`) or a
  handle such as `jane@acme.example`. The envelope is signed by `--as <name>` as its own root. A send that was not
  published exits 1 and keeps its exact bytes in the identity's outbox. Sending again makes a new envelope; to send the
  same one, use `resend` below.
- `resend --as <name> --relay "$R"` sends what waits, once, the same bytes under the same id, so it lands once. It takes
  the targets in `retry` whose next try has come; a line with `next_at=<unix seconds>` says it is not yet time, and the
  next run takes it. A target in `failed` was refused by a relay and goes only when you name it, once the cause is gone:
  `resend --as <name> --relay "$R" --id <id>`, the id `send` printed. It exits 1 while something has not landed, and an
  MCP server on the same identity does all this by itself (`resend` beside it is refused `busy`).
- `inbox --once` reads what waits, handles it, and exits. It prints `accept <id> <from> <root> <type> <body>`,
  `reject <id> <code>` or `quarantined <id> <code>` per message, and nothing, with exit 0, when nothing waits.
- `inbox --watch` stays open and prints each accepted message as it arrives; `reject` and `quarantined` lines go to
  stderr. It is the identity's one receiver: a second one on the same identity is refused as busy. It stops on Ctrl-C
  or SIGTERM. `--exec <cmd>` runs a command per accepted message (the command is given the id, sender and type on stdin,
  never the body); `--exec-timeout <s>` bounds it (default 120).
- `--trust-root` names whose messages you accept: an address (trust that key) or a domain (trust the domain's current
  key, read from its record and pinned at first use). With no `--trust-root`, and none in `trust.json`, you trust no
  one: every message is `reject <id> untrusted-root`. This is the usual first surprise.
- Every step an inbox takes is written to a hash-chained audit log at `<home>/state/<name>/audit.jsonl`. Verify it:

```sh
c audit verify "$HOME/.bag/state/alice/audit.jsonl"     # ok <n> lines
```

`audit verify` recomputes the chain from the first line. It prints `ok <n> lines`, or `bad line <n>: <problem>` for
the first line that was edited, removed or reordered, and exits 1 on a bad line, `truncated` or `diverged`; `ahead`
alone exits 0. When `edge.sqlite` is beside the log it also compares the log with the anchor the store keeps, and says
`truncated`, `diverged` or `ahead` when they disagree. Use the home you gave `--dir` or `AC_HOME`.

Other commands (`delegate`, `lookup`, `group`, `held`, `status`) are in `packages/cli/README.md` and in
`c help`; `peer` and `host install` are sections 5b and 5c.

## 5b. Your first exchange with another installation

Section 5 sent a message between two identities in one home. This is the same act between two parties on two
machines, A and B, who both set up bag as in section 1, by either route. You need one relay URL both can reach,
an identity each, and a terminal each side can type into at the same time. A runs the relay (section 3) or both use
one they were given.

Each side: make an identity if you have none, then check the relay (use the relay URL for `<relay-url>`; A's identity
is `me` on A's machine and B's is `me` on B's):

```sh
R=<relay-url>
c keygen me                  # prints your address; skip if you have an identity already
c health "$R"                # prints: ok
```

`c health` failing with `unreachable` means the relay is not running or not reachable from your machine. A relay on a
loopback or private address needs `--allow-private-relays` on `send` and `inbox`.

The pairing is one ceremony on two terminals, `peer invite` on A's side and `peer accept` on B's. A runs:

```sh
c peer invite --as me --relay "$R" --name <the petname A gives B>
```

When A already knows B's address, A adds `--for <that address>`, and B adds `--for <A's address>` to `peer accept`: the
invitation is then bound to that address, and a substituted inviter or requester is refused `not-for` before any
question or check digits. Leave the open invitation, which any holder of the code answers, for genuine first contact.
Binding narrows who can answer; it does not replace reading the digits.

It prints `pairing code <code>`, a code like `472-tulip-orbit-cedar`, and the time it ends (600 seconds at most, one
request only); a relay too old for codes gives `invite <string>` instead. A sends B the code by a channel they both
trust. B runs, with the code as the last argument:

```sh
c peer accept --as me --relay "$R" --name <the petname B gives A> '<pairing code>'
```

B sees `inviter <address> at <relay>`, `check digits` with six digits, and `read them out now, not where the code was
sent, before you answer: that is the security check`. B reads the six digits to A, aloud or in a message they both trust, then
answers `y` to `pair with it as <petname>?`; that sends the request, and B prints `requested; waiting until <time> for
the inviter's answer`. If B doubts what it saw, B answers `n` before sending anything. A then sees `request <B's
address>` and `to pair with it as <petname>, type the six digits the other side reads you`. A's screen never shows the
digits: A types what B read out, with three tries, spaces and hyphens ignored. On a match each side prints `paired
<petname> <address>`. The third miss ends it as `digits-mismatch` with nothing written, and B hears only `no-answer`
when the invitation ends: someone else may be in the middle, so start again over a channel you trust.

What it wrote, so you know what you hold: under each home, the other side's address is in `names.json` under the
petname you gave, it is in `trust.json` as a root you trust, and your accept-from record at the relay admits it. Where
an address record with a sealing key was missing, pairing published what it needed. So after pairing you need no
`--trust-root` and no `record` command to receive from the other side. Nothing under `keys/` is sent.

One message each way. B sends first, by the petname (A does the same afterwards, with the petname for B):

```sh
c send --as me --to <petname for the other side> --relay "$R" --type chat.v1 \
  --body '{"text":"hello from the other machine"}'
c inbox --as me --relay "$R" --once        # run after the other side has sent you one
```

`send` prints the envelope id and `published <relay> tries=<n>`. A reads it with `c inbox --as me --relay "$R" --once`
(it prints `accept <id> <from> <root> <type> <body>`), sends one back the same way, and B reads it with the `inbox`
line. Each `inbox` should print `accept` with the other side's petname in place of a raw address. If you instead see
`reject <id> untrusted-root`, the pairing did not finish on your side: check that `<home>/trust.json` exists and lists
the other side's address (`c address` on their side prints it), then tell them. When both messages have arrived,
verify your log as in section 5.

The code (or invite string) is a one-use secret for about ten minutes: do not post it where others read it. If a second
request reaches A on the same one, A's side prints `second request <address>: the invite string leaked`.

## 5c. Connect your agent host

The CLI and the MCP server are two ways to be one identity. An MCP server (`packages/mcp`, the package's `bag-mcp`)
puts your address and mailbox inside an agent host, as tools. Use one receiver per identity: if a host runs the MCP
server for `me`, do not also run `c inbox --watch --as me`; whichever starts second is refused as busy. A host that
talks to the server over stdio works; three are described here, and this guide documents none of them as the only way.

`c host install` writes the registration for you. It needs an identity that exists, at least one `--relay`, and your
`--trust-root` for anyone who is not already paired with you (a paired peer is already trusted). Nothing it writes holds
a key; it holds the path of `node`, the paths of bag's programs, your identity name, your home and the relay URLs.
From source those paths are in this repository. From the package, it first copies the package to `<home>/package/`
(printing `wrote <home>/package (bag 0.2.0 <commit>)`) and writes the paths of that copy, so the registration does not
depend on npm's cache. Run it again and it changes nothing and says so. The files hold paths of your machine: do not
commit or send them.

Claude Code, for a project directory:

```sh
c host install claude-code --as me --relay "$R" --project <project dir>
```

It writes the MCP server into `<project dir>/.mcp.json` and a `SessionStart` and a `Stop` hook into
`<project dir>/.claude/settings.json`, which let a waiting session see new mail. It merges into what is there and
refuses (`exists`) a different `bag` entry that you have: edit or remove it first. The same registration by
hand, for the current directory:

```sh
claude mcp add bag -- node <repo>/packages/mcp/src/main.ts --as me --relay "$R" --dir <home> \
  --keep-alive-records
```

with `<repo>` this directory as an absolute path and `<home>` your home as an absolute path (the host passes each
argument as written; nothing expands `~`). That line is the source route's. On the package route, register the server
with `c host install` above: it copies the package to `<home>/package/` and writes `node <home>/package/bag-mcp.js`
as the server. For the Claude Code plugin: see the README.

Codex:

```sh
c host install codex --as me --relay "$R" --user --mode mcp
```

writes a `[mcp_servers.bag]` table to `~/.codex/config.toml`. Codex has no idle wake, so a session sees mail
only when it calls the tools. Without `--mode mcp` the default is `worker`, which writes nothing and prints the
`inbox --watch --exec 'codex exec ...'` line that runs Codex once per accepted message; choose one of the two for an
identity, never both. If the file already has a different `bag` table, the command refuses.

Any other stdio MCP host: register a server whose command is `node` and whose arguments are
`<repo>/packages/mcp/src/main.ts --as me --relay <relay-url> --dir <home> --keep-alive-records`, in the host's own
format. That form is the source route's; on the package route, this guide registers the server only through
`c host install` (Claude Code or Codex, above). `packages/mcp/README.md`, section "Install", gives the Claude Code,
Codex and opencode forms with the flags and what each means; where it shows a machine-specific path for `node` or
`<clone>`, read it as `node` and `<repo>`.
Tell your host to restart its MCP servers, then ask it to list the bag server's tools.

If the other party in section 5b runs a different host from yours, that is a fine first exchange: each side sends one
message through its own host's tools to the other's petname, over the same relay.

## 6. Serving your record at your own origin

To be reachable by a domain, an organisation signs one address record and serves it at its own HTTPS origin. Peers then
write `domain:<host>` in an accept-from record or `--trust-root <host>` in an inbox, and a relay or an edge finds the
current key of that domain by fetching the record. The key behind the record can be one you hold (`record address` signs
no domain; the domain name comes only from where the file is served).

What a peer fetches. Both the reference relay and this CLI fetch exactly:

```
GET https://<host>/.well-known/bag/address.json
```

over HTTPS only, on port 443 (write the host with no port), with no redirect followed (any status but 200 is a
failure), with no proxy, within 10 seconds by default, reading at most 262,144 bytes. The host must resolve to a
public address; a private or loopback host is refused. Neither reader checks the `content-type` of the answer: it
reads the body as the record. The relay asks with `accept: application/json`, so serve it as `application/json`. Serve
the file as bytes; do not reformat it.

How to make and serve it:

1. Make an organisation key and its address record with a sealing key, as the reference script
   `deploy/make-org-records.sh` does (the record's `sealing_key` member may be `null` for a root that only signs, but
   the record this guide publishes carries one):

   ```sh
   c keygen org-example
   c record address org-example --relay "$R" --sealing-key --out address.json
   ```

   `--relay` is required and is written into the record; give it the relay that hosts your mailboxes.
2. Put `address.json` at `/.well-known/bag/address.json` on any HTTPS origin you control, as a static file with
   the content type `application/json`, served with a 200 and no redirect. Any static host works: a web server's
   document root, an object store behind a certificate, a CDN.
3. Check it from outside with `c lookup domain:<host> --as alice --relay "$R"`. It prints a `cache` line, then one
   line per source, for the TXT record and for the record at the origin, as `<source> <found|none|refused|error>
   kind=<k> ...`.
4. Re-sign it at least daily. An address record is valid for its `ttl`, at most 86,400 seconds, so run step 1's second
   command again, with a new `iat`, and replace the file, from a scheduled job. `record keep` does not do this: it
   publishes to relays, never to your origin.
5. Agents under the domain are named by chains from the org key: `c delegate --from org-example --to <agent address>
   --exp +86400 --out chain.json`, then `c send --as <agent> --auth chain.json ...`. Recipients with `domain:<host>` in
   their accept-from record, or `--trust-root <host>` on their inbox, accept it.

The `_bag` TXT record is optional. Without it, the origin is `https://<host>`. With one DNS TXT record at
`_bag.<host>` of the form

```
_bag.example.com.  IN  TXT  "v=ac1; key=ed25519:<64 hex>; host=bag"
```

a reader learns the key the org's record must carry (or must be a countersigned rotation from), and, with
`host=bag`, looks for the record at `https://bag.<host>/.well-known/bag/address.json` instead.
`v=ac1` must come first; `key` is required; `host` may only be `bag`; the text names no URL, and a `rec` field
makes the record malformed. Publish at most one such record: two, or a malformed one, fail the resolution with
`resolve-failed` and no fallback. DNS is a hint only; the signature of the record is the authority (`spec/SPEC.md`
section 12.2).

Handle records for your domain. A handle such as `jane@example.com` needs one signed record per handle, served at

```
https://<domain>/.well-known/bag/handles/<local>.json
```

`deploy/make-handle-record.sh` signs it with the org key from step 1, which must be the key of the org's address record
(a handle record is valid only under the domain's current key). The script is source-only (section 1b): the package
does not carry it. It reads that address record from `deploy/well-known/public/<domain>/.well-known/bag/address.json`,
a directory this repository does not carry, so place your `address.json` there first, then sign, with `AC_HOME` set to
the home that holds the org keys (an absolute path), from the root of this directory:

```sh
mkdir -p deploy/well-known/public/example.com/.well-known/bag handles-out
cp address.json deploy/well-known/public/example.com/.well-known/bag/address.json
AC_HOME="$AC_HOME" deploy/make-handle-record.sh --domain example.com jane <jane's address> \
  --key org-example --out handles-out
```

`--domain <domain>` takes your full domain, in lower case, two or more labels. `<local>` is 1 to 64 of `a-z`, `0-9`,
`.`, `-` and `_`, from and to a letter or a digit; `<address>` is `ed25519:` and 64 hex characters, and must not be in
the org record's revoked list. `--key` names the org key; it is needed here because the script's default is
`org-<domain>`. `--out <dir>` writes the record to `<dir>/<local>.json` (here `handles-out/jane.json`) in place of
under `deploy/well-known/`; the directory must already exist and be writable. The script prints two lines, `handle ...
address ...` and `record handle org ... iat ... ttl ... exp ... out <path>` (the path absolute), and never a key. The
default `ttl` is 86,400 seconds, the most a handle record may have, so sign it again daily and replace the served
file, as for the address record. It needs Node 24 or later first in `PATH` and `npm ci` done in this repository. Serve
`handles-out/jane.json` at the URL above, as in step 2 (HTTPS, a 200, no redirect). Until you do, address your peers
by address or by a name in your name book, and use a `domain:` root as above.

## 7. What is absent in this release

- No need to run a relay of your own: two public relays run, the first of them the rendezvous, and the install guide
  names them. Section 3 still applies if you want your own.
- The internal notes that code comments cite (design notes, studies, plans, an operations guide, review rounds, drafts)
  are not included. A comment that points to a file you do not have is a note; nothing here needs it to build or run.
- No installer or service files for the relay or `record keep`. The packaged forms are the relay's container image
  (`docs/self-host.md`, "Run it with Docker") and the npm package `@usebag/bag` (the command line, the MCP server and
  the A2A bridge, section 1a).
- No `ac` or `bag` on your PATH: use the `c` function of your route, section 1a or 1b.
- The macOS keychain custody works on macOS only; the file custody works everywhere.
- The Claude Code plugin: see the README.

## 8. When something goes wrong

CLI errors print as `bag: <code>: <detail>`; a message the inbox refused prints as `reject <id> <code>`.

| code | what it means | what to do |
|---|---|---|
| `resolve-failed` | a record could not be fetched or did not verify: your peer's address record is missing or past its `ttl`, a domain's record or TXT record is unreachable or malformed, a relay is on a private address, or a handle did not resolve (the detail names the step) | ask the peer to run `record keep --once`, or `record address` and `publish` again; for a domain, check the file with `c lookup domain:<host> ...`, that it is a 200 with no redirect over HTTPS, and that the TXT record, if any, is one and well formed; for a local relay add `--allow-private-relays`; when a relay refuses your publish with 503 and `Retry-After`, wait and publish again |
| `root-not-accepted` | the recipient's accept-from record does not list the root of your envelope (403 at the relay) | send your root's address to the recipient; they add it with `record accept-from ... --root <your address>` (repeating every root they keep) and publish it. For a `domain:` root, the domain's current key must be the root |
| `not-recipient` | no wrap in the envelope names this address, so this identity cannot open it | check that you read with the identity the sender addressed (`--as`); if you are right, the sender used a stale or wrong address record: publish a current `record address --sealing-key` and ask the sender to send again |
| `untrusted-root` | the message verified but its root is not one you trust | add `--trust-root <address or domain>` to the inbox command |
| `not-hosted` | the relay holds no accept-from record for the recipient | the recipient publishes `record accept-from` at that relay |
| `stale-record` | the relay holds a record at least as new | sign again (a newer `iat`) and publish; `record keep` does so |
| `record-expired` | you published a record already past its `ttl` (the relay answers 422), or `lookup` shows it | sign it again and publish |
| `unreachable` | no connection to the relay, or no reply | `c health <relay-url>`; check the port, the address and that the relay is running |
| `bad-auth` | a fetch or subscribe proof did not verify | check that `--as` names the identity that owns the mailbox |

The full list of codes is Appendix A of `spec/SPEC.md`.

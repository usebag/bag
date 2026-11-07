# Onboarding an org domain with `onboard`

This guide puts one agent on your organisation's own domain with one command, `onboard`, and takes it to a first
exchange by handle. It is the short path for the work that `docs/partner-install.md`, section 6, does by hand. Read
sections 1 to 4 of that guide first if you have not built this copy yet. Commands are written for a Unix shell with
`bash`, run from the root of this directory.

## 1. What you need

- A domain you control. The examples use `example.org` for yours and `example.net` for your partner's.
- A way to serve static files over HTTPS at `https://<host>/.well-known/bag/`, where `<host>` is your domain
  (or `bag.<domain>`, section 4). Any static host works: a web server's document root, an object store behind
  a certificate, a CDN.
- The right to add one DNS TXT record to the domain.
- The URL of a relay: your own (`docs/partner-install.md`, section 3) or one you were given.
- Node 24 or later, and this CLI built (`npm ci`). The CLI has no `bin` entry, so define the same shell function as
  the install guide:

```sh
c() { node packages/cli/src/main.ts "$@"; }
```

## 2. One command

Set your domain and relay, and put your partner's domain after `--accept domain:`, then run `onboard` once:

```sh
DOMAIN=example.org
R=https://relay.example.org
c onboard jane --domain "$DOMAIN" --relay "$R" --accept domain:example.net
```

- `jane` is the agent's name in your home, and the local part of its handle, `jane@example.org`. `--handle <local>`
  gives another local part.
- `--relay` repeats, up to 8 relays. The first one is the relay the printed `send` and `inbox` commands use.
- `--accept` repeats and says whose messages the agent's mailbox takes: a partner's domain (`domain:example.net`), an
  address (`ed25519:` and 64 hex characters), or `*` alone for anyone. The list the agent publishes also keeps the
  roots its relays and `trust.json` already hold (section 7).
- The home is `--dir <home>`, else `$AC_HOME`, else `$HOME/.bag`, as for every command.

Optional flags, with their defaults:

| flag | default | what it sets |
|---|---|---|
| `--handle <local>` | the agent's name | the local part of the handle |
| `--org-key <name>` | `org-<domain>` | the name of the org key in your home; made when missing |
| `--out <dir>` | `<home>/serve/<domain>` | the directory to serve (section 4) |
| `--origin apex\|bag` | `apex` | serve at `https://<domain>/` or at `https://bag.<domain>/` |
| `--ttl <seconds>` | 86400 | the life of the org, handle and agent address records; at most 86400 |
| `--chain-exp <seconds>` | 604800 (7 days) | the life of the chain from the org key to the agent; at most 2592000 |
| `--max-bytes <n>` | the held record's, else 65536 | the largest envelope the agent's accept-from record takes |
| `--retention <seconds>` | the held record's, else 604800 | the accept-from record's retention |
| `--allow-private-relays` | off | lets the self-check's lookups use a relay on a private or loopback address |

Every argument is checked before anything is written. Keys that `onboard` makes are key files under `<home>/keys/`,
as `keygen` makes them by default. Back them up as the install guide says, and never serve or send them.

## 3. What it prints, line by line

A first run with the command above prints, in this order (`<home>` is the absolute path of your home, `<org>` and
`<agent>` are addresses, and `<ac>` is the absolute path of `node` followed by the absolute path of this copy's
`packages/cli/src/main.ts`):

```
key org-example.org <org> new
key jane <agent> new
wrote <home>/serve/example.org/.well-known/bag/address.json
wrote <home>/serve/example.org/.well-known/bag/handles/jane.json
published key <agent> https://relay.example.org
published address <agent> https://relay.example.org
published accept-from <agent> https://relay.example.org
trust domain:example.net
chain <home>/jane.chain.json root <org> exp <unix seconds>
step 1: serve <home>/serve/example.org as the root of https://example.org/ (HTTPS on port 443; each file a 200 with no redirect, as application/json), so that these answer:
url https://example.org/.well-known/bag/address.json
url https://example.org/.well-known/bag/handles/jane.json
step 2: add this TXT record to the DNS of example.org:
dns _bag.example.org.  IN  TXT  "v=ac1; key=<org>"
next an inviter accepts jane@example.org by root domain:example.org (send with --auth <home>/jane.chain.json) or by <agent> (send without it)
next <ac> send --as jane --auth <home>/jane.chain.json --to <handle|address> --relay https://relay.example.org --type <type> --body <json> --dir <home>
next <ac> inbox --as jane --relay https://relay.example.org --dir <home>
next run this command again every 43200 s at most (records live 86400 s); nothing installs it:
cron 0 */12 * * * <ac> onboard jane --domain example.org --relay https://relay.example.org --accept domain:example.net --out <home>/serve/example.org --dir <home>
check ...
self-check pending jane@example.org: not resolving yet; do steps 1 and 2, then run again with --check
```

What each line means:

- `key <name> <address> new|existing`: the org key, then the agent's key. `new` when `onboard` made it, `existing`
  when the home already held it. Only addresses are printed, never a key.
- `wrote <file>`, twice: the two files of the tree to serve. `address.json` is the org's address record, signed by the
  org key, with its sealing key (it keeps one; `onboard` publishes no key record for the org), your relays and the ttl.
  `handles/<local>.json` is the handle record, the org's signed word that the handle names the agent's address. Each
  is checked by the core, written beside its place and renamed into it, mode 0644, so a host that serves the tree sees
  the old file or the new one, never half of one. `onboard` writes these two files and nothing else into the tree.
- `replaced <address>`: only when the handle file there named another agent. It follows the second `wrote` line.
- `kept <root>`: on a run again, or a first run in a home whose `trust.json` already holds roots; after `wrote` and
  before the first `published` line. One line for each root in
  the accept-from record that you did not type on this run: a root already held at your relays, or in `trust.json`
  (section 7).
- `published key <agent> <relay>`: the agent's key record, at each relay, before the address record. It carries a
  sealing key made for the agent, and it lives a day. Senders seal to it. Its private key is kept in
  `<home>/key-records`; never serve or send that directory. With several relays, every `published key` line comes
  first. A relay that already holds that key record keeps it, and the line reads `unchanged key <agent> <relay>`;
  that is not a failure. Section 7 says when a new key is made.
- `published <kind> <agent> <relay>`: the agent's address record and accept-from record, at each relay. Copies are
  kept in `<home>/records/`. The address record has a null sealing key: a sender takes the key from the key record.
  When a relay already holds a record that is not older, it keeps it, and the line reads
  `unchanged <kind> <agent> <relay>`; that is not a failure. A run again within the same second still prints
  `published address`, because the address record is dated one second past the one held.
- `trust <address>`, then `trust domain:<host>`: one line for each root you gave to `--accept`, added to
  `<home>/trust.json`. A run again adds nothing new. Only the roots you typed are stored: never one read from a
  message, a record or a lookup, and never a `kept` root. `--accept *` is not stored.
- `chain <file> root <org> exp <unix seconds>`: the chain from the org key to the agent, for `send --auth`. It expires
  `--chain-exp` seconds after the run.
- `step 1:`, the two `url` lines, `step 2:` and the `dns` line: the owner's two steps, section 4.
- The `next` lines: what your partner must accept, and the `send` and `inbox` commands for this agent, section 6.
- `next run this command again ...` and the `cron` line: the refresh, section 7.
- `check ...`: the self-check. `onboard` looks up `domain:<domain>`, then the handle, as a peer would, and prints each
  line of those lookups after `check `. Before step 1 and step 2 you see lines such as
  `check _bag.example.org none kind=txt origin https://example.org`.
- `self-check ok <handle>` or `self-check pending <handle>: ...`: the result, section 5.

## 4. The owner's two steps

Whoever runs the domain does these once. `onboard` does not touch your web host or your DNS.

**Step 1: serve the tree.** Make the directory named in the `step 1` line the root of the origin it names, so that
both `url` lines answer. Serve the files as bytes, with a 200, no redirect, and the content type `application/json`.
Peers fetch over HTTPS only, on port 443. Serve that directory only, never the home above it. If your host serves a
copy rather than the directory itself, copy it again after every run of `onboard`: each run replaces both files.

To have `onboard` write straight into the directory your web server serves, give it with `--out`, for example
`--out /var/www/example.org`. An `--out` that is the home, or holds it, is refused, because the keys would be served.

**Step 2: add the TXT record.** Add exactly one TXT record, as the `dns` line prints it. In a zone file, paste the text
after `dns `. In a provider's web form, the name is `_bag` under your domain, the type is TXT, and the value is
the text between the quotes, `v=ac1; key=<org>`. The record names the org key that the served record must carry. Two
such records, or a malformed one, make the domain fail to resolve.

**The `bag` origin.** If your domain's own site cannot serve the files, serve them from
`bag.<domain>` instead:

```sh
c onboard jane --domain "$DOMAIN" --relay "$R" --accept domain:example.net --origin bag
```

The `step 1` and `url` lines then name `https://bag.example.org/`, and the `dns` line gains
`; host=bag`:

```
dns _bag.example.org.  IN  TXT  "v=ac1; key=<org>; host=bag"
```

The TXT record stays at `_bag.example.org`. With `host=bag`, readers look for the files at the
`bag.` host.

## 5. Checking: `--check`

When both steps are done, run the same command again with `--check`:

```sh
c onboard jane --domain "$DOMAIN" --relay "$R" --accept domain:example.net --check
```

`--check` checks the arguments and runs only the self-check: it makes no key, signs nothing, does not write the tree
and publishes nothing. It passes when the handle record is found naming this agent, and the agent's address record and
its key record are found after it. The key record counts because the address record names no sealing key: without the
key record a peer has nothing to seal to.

| exit | what it prints last | meaning |
|---|---|---|
| 0 | `self-check ok jane@example.org` | the handle resolves end to end, as a peer resolves it |
| 3 | `self-check pending jane@example.org: ...` | the records are written and published, but do not resolve yet |
| 3 | `self-check pending jane@example.org: no key record at the relays; run onboard again, without --check` | the handle and the address record resolve, but no relay holds the agent's key record |
| 1 | `bag: <code>: <detail>` on stderr (a usage error adds a line naming `help`) | the command failed: a usage error, or the error its code names |

That last line appears for a home that was onboarded before the agent had a key record, or whose key record has
lapsed. `--check` publishes nothing, so run the command again without it: a full run publishes the key record. Steps
1 and 2 are done by then, so do not repeat them.

A full run ends with the same self-check, so it exits 0, 3 or 1 in the same way; on 1 it may have written and
published part of its work first (section 8). On exit 3, the `check` lines show each step a peer takes: for each of
the two lookups a `cache` line, then the TXT record, the org record at the origin and, for the handle, the handle
record and the agent's records at the relays, each with `found`, `none`, `refused` or `error`. A line such as
`check _bag.example.org found kind=txt key=<org> origin https://example.org` means the TXT record of step 2 is
seen.

## 6. The first exchange

Do this after `--check` exits 0.

**Your partner accepts you.** The first `next` line says how. Either your partner's accept-from record lists the root
`domain:example.org`, and your agent sends under the chain (`--auth`); or it lists the agent's own address, and your
agent sends without `--auth`. A partner who also onboards with this command gives `--accept domain:example.org`. One
who uses the install guide adds the root with `record accept-from ... --root domain:example.org`, repeating every root
they keep, and publishes it.

**Send.** The `send` line is ready but for three words: `--to`, `--type` and `--body`. Do not run it as printed: the
`<...>` words would be read by the shell as redirections. With your partner's handle filled in:

```sh
c send --as jane --auth "${AC_HOME:-$HOME/.bag}/jane.chain.json" --to ben@example.net --relay "$R" \
  --type chat.v1 --body '{"text":"hello from example.org"}'
```

`send` prints the envelope id, then one line per target, such as `published <relay> tries=<n>`. Quote the JSON body.

**Receive.** The roots you gave to `--accept` are in `trust.json`, the `domain:` ones included, so the `inbox` line
needs no `--trust-root`. To trust another root for one run only, add `--trust-root` with an address or a bare domain
name (`example.net`, not `domain:example.net`). The printed line, without `--once`,
keeps running and prints each message as it arrives until you stop it (Ctrl-C). To read what waits and exit after a
second with nothing new:

```sh
c inbox --as jane --relay "$R" --once
```

Each message prints as `accept <id> <from> <root> <type> <body>`, `reject <id> <code>`, or, for one kept because its
root's record could not be read yet or its timestamp is ahead, `waiting <id> <code>: kept; ...`, which a later read
delivers. `<from>` is the sender's
address, or `<handle> (<short address>)` once your agent has resolved the sender's handle (for example by sending to
it), and `<root>` is the address of the sender's org key. A `reject <id> untrusted-root` means the sender's root is
not one you trust: check `--accept` and `trust.json`.

**Older keys still open.** A sender seals to the agent's key record. When the agent makes a new key (section 7),
the home keeps the older ones, and `inbox` tries every key it holds, newest first. So a message sealed before a
refresh still opens after it. The home keeps an older key until about a week after its key record expires (the record
lives a day, so about 8 days after the key was made), and deletes it when a later new key is made.

## 7. The daily refresh

The org record, the handle record and the agent's address record live `--ttl` seconds, a day by default. The agent's
key record lives a day, whatever the ttl. After that a peer can no longer use them, and sends to your agent fail with
`resolve-failed`. So the same command must run again before they expire. The `next run this command again` line says
how often: every half ttl at most, every 43200 s (12 hours) by default.

The `cron` line is that command as a crontab entry. `onboard` prints it and installs nothing. To use it, add the text
after `cron ` to your crontab (`crontab -e`). It names `node` and this copy by absolute path, because cron's `PATH`
holds no `node`, and it gives `--out` and `--dir` as absolute paths, because cron runs in your home directory. For a
short `--ttl` it runs every few minutes instead (`*/5 * * * *` for a ttl of 600). `onboard` prints a few dozen lines on
every run, so cron mails them each time unless you send them to a log file. In a crontab a `%` stands for a new line,
so a path or relay URL that holds a `%` breaks the entry: keep `%` out of both.

A run again is safe:

- The identity keys are found (`key ... existing`); none is made.
- The org record, the handle record, the address record and the accept-from record are signed again with a new time
  and replaced, the relays get the newer records, and the chain is made again with a new expiry. No temporary file is
  left. The org record keeps its sealing key; the agent's address record keeps its null one.
- The rotation key and revoked list of the org record already in the tree are kept, and so are those of the agent's
  newest address record at its relays. Each is checked by the core before anything of it is kept. A run again never
  drops a revocation.
- The relays and the ttl come from the arguments, so change them by changing the cron line.

**The agent's key.** The key record is published before the address record, at every relay. Whether the key is new
depends on its age:

- A key record goes out as a new epoch when the home holds none, or the newest is 11 hours old or more (a new key), or
  the newest was never published because a relay refused it (the same key again, re-dated; no second key is made).
- Otherwise the current key record is published again as it is, so a relay that is new, or lost it, gets it. A relay
  that holds it already answers that it is not newer, and the line reads `unchanged key`.
- The limit is 11 hours, one hour under the cron line's 12, so a run that comes back a few seconds early still makes a
  new key. A run every few minutes does not make a key each time.
- Older keys stay in the home, and `inbox` still opens with them (section 6).
- A run again within the same second prints `published address`, because the address record is dated one second past
  the one held, and `unchanged key` and `unchanged accept-from`.

**The accept-from record.** Each run publishes the agent's accept-from as a union, so that a refresh does not drop a
peer paired since the last run. Its roots, without duplicates, in this order:

1. the roots the agent's newest accept-from record holds at its relays, in their order (a held `*` is dropped);
2. every root in `trust.json`, in file order: the roots typed at earlier runs and the peers paired since;
3. the roots typed with `--accept` on this run.

A `kept <root>` line names each root of the union that you did not type, before the `published` lines. `trust.json`
still gains only the roots you typed. The size and retention are the typed `--max-bytes` and `--retention`, else those
of the held record, else 65536 and 604800. A typed `*` publishes `*` alone: it admits every sender, and the roots in
`trust.json` come back in the list when a later run types roots instead of `*`.

**After a lapse.** If no run came for longer than the ttl, the relays swept the agent's address record, but not its
accept-from record. The next run still reads the accept-from record and keeps its roots. The rotation key and revoked
list then come from the address record this home last wrote, if it checks, is the agent's and names no
`rotated_from`; otherwise the new address record has no rotation key and no revoked list.

If your host serves a copy of the tree, the copy must follow each cron run (section 4).

## 8. Limits and refusals

**Usage refusals.** Each of these exits 1 with `bag: usage: <detail>` and writes nothing:

- a `--domain` that is not a domain root: not lowercase, not 1 to 253 characters, with a scheme, path, user or query,
  a port or an IPv6 literal, a trailing dot, fewer than two labels, a label that is not RFC 1123, an IP literal, or a
  special-use last label (`alt`, `arpa`, `internal`, `invalid`, `local`, `localhost`, `onion`);
- a local part that makes no handle (1 to 64 of `a-z`, `0-9`, `.`, `-` and `_`, from and to a letter or a digit);
- an `--origin` other than `apex` or `bag`;
- a number option that is not a positive integer, a `--ttl` over 86400, a `--chain-exp` over 2592000;
- more than 64 distinct relays, a relay that is not an `http` or `https` URL, more than 1024 distinct roots, or `*`
  with another root;
- an `--out` that is the home or holds it;
- an org key name over 64 characters (give `--org-key`), or equal to the agent's name;
- a missing `--domain`, `--relay` or `--accept`.

A bad `--accept` value is `bad-record`.

**Refusals from the accept-from union.** Each exits 1 with `bag: <code>: <detail>`. The first two come after
the keys are made, but before the tree is written or anything is published; the third comes before anything is
written:

- `accept-held`: you typed `--accept *` and the agent's accept-from at its relays holds other roots. The detail names
  them. `*` stands alone in a record, so `onboard` will not drop them unseen. To accept every sender, publish a record
  of `--root '*'` by hand (`record accept-from`, then `publish`), then run `onboard` again.
- `too-many-roots`: the union (held, trusted and typed roots) is over 1,024 roots.
- `trust-invalid`: `<home>/trust.json` cannot be read, is not a trust file of version 1, or holds a root it cannot
  hold.

**The chain's life.** `--chain-exp` is 7 days by default (this CLI's default; the specification sets none), and 30
days at most, the life `spec/SPEC.md` section 6 gives a principal's hop at most ("SHOULD live 30 days at most and be
renewed"). The cron line renews the chain on every run.

**Refusals about records already there.** Each exits 1:

- `rotation`: the org record in the tree, or the agent's newest address record at its relays, names `rotated_from`.
  Such a record is not signed again, because its countersignature covers its time. Once peers have moved their pins,
  replace it by hand with a record without `rotated_from` (for the org record, the message names the `record address`
  command), then run again.
- `bad-record-sig` (or another `bad-` code when it no longer parses): the org record in the tree fails its signature
  check, for example because it was edited on the host. Nothing of it is kept, and nothing is written to the tree or
  published. Find out who changed it. Restore the file `onboard` wrote, or move it aside and run again; a run with no
  file there starts a new record, without the old rotation key and revoked list.
- `org-key-mismatch`: the org record in the tree is signed by another key. Move it, or give the `--org-key` that
  signed it.
- `unsafe-path`: a link, or something that is not a file or directory, on the way to the tree's files.
- `window-open`: a login window holds the agent. Run `logout` first.

**A relay failure.** If a publish to a relay fails, `onboard` exits 1 after the tree is written. Run the same command
again to finish the publish.

**A refused key record.** The key record goes first, so a relay that does not take it stops the run before the address
record and the accept-from record are published. The run exits 1 with the relay's code, `unreachable` when it did not
answer or `http-<n>` for a status with no code, and the message ends with `; publish it again:` and the `onboard`
command, the one the `cron` line prints. The new key is kept in the home. The next run publishes the same key again,
re-dated, and makes no new one. When no new key was due, the failure is the relay's own error without that text, and the
next run publishes the key record again.

**Removing a root.** A refresh keeps every held and trusted root, so a root leaves in two steps, in this order:

1. Drop the root from the cron line's `--accept`. A root typed there comes back on the next refresh otherwise.
2. Run `unpair` with the cron line's relays. It asks once on a terminal, then removes the root from
   `<home>/trust.json` and from the accept-from at each relay:

   ```sh
   c unpair domain:example.net --as jane --relay "$R"
   ```

   It prints `untrusted <root>` and a `published accept-from` line per relay. Any answer but `y` or `yes` changes
   nothing. If a relay publishes a newer record while it asks (a pairing, a refresh), it changes nothing and exits 1;
   if a relay does not take the new record, it exits 1 after the others have: in both cases, run it again. When the
   last root goes, the record names only your agent, and the cron line still needs one typed `--accept` root, for
   example your own `domain:example.org`.

**Known limits.**

- A revoked address stays in the records until a person publishes a record without it: `onboard` never drops one.
- A record that names `rotated_from`, the agent's or the org's, is refused until a person replaces it, as above.
- A pairing that publishes between the moment `onboard` reads the accept-from record and the moment it publishes is
  overwritten until the next run.
- `onboard` reads the held accept-from record only at the relays you type with `--relay`. If you move to new relays,
  the first run there holds no roots; the roots in `trust.json` are still in the union.
- When no relay holds the agent's address record and one relay failed, `onboard` exits with that failure before the
  tree is written: it cannot tell a first run from a lost record.
- The org record is signed through `record address`, so a revoked address it carries loses its date in the org key's
  dated revocation file in the home, if there is one, and is kept until a person drops it.
- If the org key itself is held through a login window, `onboard` keeps only what the served file holds, not
  revocations that `logout` published at the relays.
- A `--` in the arguments puts the cron line's `--out` and `--dir` after it.
- The check that `--out` does not hold the home compares paths, not the real paths behind links.
- `--check` on a home that lacks the agent ends with `ENOENT`, not with pending.

## 9. By hand instead

Each piece `onboard` makes can be made by hand, and `docs/partner-install.md` shows how: the records in section 4, and
the org record, handle records and chains in section 6. Two scripts of this copy help there; each needs `AC_HOME` set
to the absolute path of the home that holds the org key. `deploy/make-handle-record.sh --domain <domain> <local>
<address> --key <name> --out <dir>` signs one handle record with the org key, as section 6 of that guide shows.
`deploy/make-org-records.sh <label>` makes an org key and its record for a name of one DNS label only, under
`deploy/well-known/public/<label>/`; for a domain of your own, use `record address` as that guide does. By hand you
also sign, serve and publish each record again every day yourself.

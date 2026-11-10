# @usebag/cli

The command line of bag v0: one command per run, `node packages/cli/src/main.ts <command> [options]`, over the
edge library (`@usebag/edge`) and the core (`@usebag/core`). It makes identities and their records, publishes
them, delegates, sends, receives, holds and releases, pairs two identities, runs groups, keeps a local name book and
looks records up. Pre-release, v0.

Every line below is read from the usage text (`USAGE` in `src/cli.ts`, which `help` prints) and from the command files
in `src/commands/`, as of 2026-10-26, the group commands included. Where the two differ, this page follows the
command file and names the difference ("Where the usage text is behind its commands", below).

## Running it

- **`node packages/cli/src/main.ts help`** (also `--help` or `-h`, anywhere on the line) prints the usage text. There is no `bin` entry, so
  no `ac` on PATH (`src/main.ts`: a `bin` entry would change the npm lock). Node 24 or later
  (`package.json`, `engines`), with `npm ci` done in the checkout.
- **Arguments are parsed strictly** (`src/args.ts`, on `node:util`'s `parseArgs`): an unknown option, a missing value,
  a required option left out, or a positional too many or too few is `usage`, and a `usage` error adds the line
  `run "node <this CLI's main.ts, as it was run> help" for the commands`. A relay URL is `http` or `https` (a trailing slash is
  dropped). `--ttl`, `--max-bytes` and `--every` are decimal integers from 1.
- **No command prints key material**: `keygen`, `address` and `keys list` print addresses, which are public by design
  (`src/cli.ts`).
- **Node 24's SQLite warning is dropped**: `src/main.ts` installs `dropSqliteWarning` (`src/warnings.ts`), which takes
  `ExperimentalWarning: SQLite is an experimental feature ...` off stderr and passes every other warning on.

## The home

The home is `--dir`, else `$AC_HOME`, else `$HOME/.bag`; with none of the three a command fails `usage`
(`src/home.ts`).

| path | what | written by |
|---|---|---|
| `<home>/keys/` | key files, a signing key and a separate sealing key per identity: 0600 files in a 0700 directory | `keygen` (`--custody file`, the default) |
| `<home>/keychain/<name>.json` | the pointer to an identity's macOS keychain item, which holds both keys | `keygen --custody keychain` |
| `<home>/state/<name>/` | the identity's edge state: `edge.sqlite` and `audit.jsonl` (the directory made 0700) | `send`, `inbox`, `held`, `lookup` |
| `<home>/names.json` | the name book: 0600, written whole to a temporary file beside it and renamed; the home made 0700 when missing | `name add`, `name forget`, `peer` |
| `<home>/trust.json` | the roots `peer` granted (version 1): 0600, written whole and renamed; `inbox` and the MCP server read it | `peer` |
| `<home>/groups/<name>/<group hex>/` | the group store of the identity `<name>` (0700): `g<n>.json` per generation it holds, as it received it (the wrap, never the private key), and, for the group's own identity, the admin's `state.json`; each 0600 | `group` (as the group), `inbox --group` (as a member) |
| `<home>/orgs/<domain>/enterprise/` | one bag enterprise session per organisation (each directory 0700): `session.json`, a waiting sign-in's `pending.json`, `chain.json`, `records.json`, `refresh.lock`; each file 0600 | `connect`, `sign-in`, `status`, `sign-out` (below, "Enterprise: connect through your agent") |
| `<home>/enterprise/` | `current.json` (the most recently connected organisation) and the hourly job's `refresh.log` | the same |

Every command that signs finds the identity in the custody `keygen` chose (`src/home.ts`, `HomeCustody`). Only `send`,
`inbox`, `held`, `lookup` and `group` open the edge store (`openEdge` in `src/home.ts`); `record keep` and `peer` open none
(`src/commands/record.ts`, `src/commands/peer.ts`), so they run beside an `inbox` or an MCP server of the same
identity. Outside the home, `record address` and `record accept-from` write to `--out` (else stdout) and `delegate` to
`--out`, each with the default mode: records and chains are public (`src/commands/record.ts`, `src/chain.ts`). The
group store's layout is the edge's `GroupKeyStore` (`packages/edge/src/custody/groups.ts`); the CLI puts it at
`<home>/groups/<name>` (`groupStore` in `src/commands/group.ts`).

## The commands, by purpose

### Identities

- **`keygen <name> [--custody file|keychain] [--keychain <file>] [--keychain-access prompt|security] [--dir <home>]`**:
  a signing key and a separate sealing key; prints the address only. `--custody keychain` keeps both in one item of
  the default macOS keychain or `--keychain`, read only after a dialog (`--keychain-access prompt`, the default) or by
  `/usr/bin/security` while the keychain is unlocked (`security`). `--keychain` and `--keychain-access` without
  `--custody keychain` are `usage`; a name either custody holds is refused (`src/commands/keygen.ts`).
- **`address <name> [--dir <home>]`**: the identity's address. It reads no keychain and raises no dialog
  (`src/commands/address.ts`).
- **`keys list [--dir <home>]`**: one line per identity, sorted by name, `<name> <address> <custody> <created>`: the
  custody `file`, `keychain` or `agent`, `<created>` an ISO 8601 UTC instant to the second (`2026-10-25T15:11:44Z`),
  `-` when unknown; an agent pointer made with `keygen --recovery personal|none` adds a fifth field, `recovery=<setting>`.
  No keychain read, no dialog, never a key (`src/commands/keys.ts`).
- **`keys prune <name> [--dir <home>]`**: replaces the identity's long-term sealing key, in its key file or keychain
  item, by a fresh random seed that no record names (the signing key is kept, and a key file keeps its mtime, so `keys
  list` shows the same created time), and prints `pruned <address> long-term sealing key`. Allowed once epoch 1 is
  deleted: epoch 1 goes at its key record's exp + 605,100 s (its iat + 691,500) at the first `keys rotate` after; the
  rule's horizon is the cutover + 605,100 s, so the trigger is conservative. Refused before any write:
  `custody-unsupported` (an agent identity), `not-individual` (the org of an onboarded agent: a `<home>/*.chain.json`
  rooted at it, under any name), `group-admin` (the home keeps admin state for the group), `no-forward-secrecy` (no
  epoch held), `before-horizon` (epoch 1 still held, with the instant after which a rotation deletes it) and
  `window-open` (an `ac login` window holds it). The key is then read back: `prune-unverified` when the keychain still
  gives the old one (an update matches only within the pointer's keychain). Publishes nothing; one audit line; a second
  run replaces the seed again. A running `inbox` or MCP process keeps the old key in memory until it restarts
  (`src/commands/keys.ts`).

### Records

- **`record address <name> --relay <url>... [--sealing-key] [--ttl <seconds>] [--rotated-from <name>]
  [--rotation-key <address>] [--revoke <address>...] [--out <file>] [--dir <home>]`**: a signed address record,
  printed or written to `--out`. `--sealing-key` includes the sealing key (else none, as for an org root that only
  signs); `--ttl` is at most 86,400 s, the default. `--rotated-from <name>` makes it a rotation from that identity's
  key, which countersigns it. `--rotation-key` names a separate key that may countersign this key's next rotation.
  `--revoke` (repeatable, up to 1,024: `too-many-revoked`; a duplicate is `bad-record`) names a key whose hops the
  record revokes; keep each entry until its hop's `exp` + TTL + skew, 604,800 + 300 s after the hop's `exp` with the
  relay defaults. A `--rotated-from`, `--rotation-key` or `--revoke` naming the identity itself is `usage`; a
  `--rotation-key` or `--revoke` that is not an address is `bad-address`.
- **`record accept-from <name> --root <address|domain:<host>|*>... --max-bytes <n> --ttl <seconds> [--out <file>]
  [--dir <home>]`**: a signed accept-from record: the roots the mailbox accepts (a `domain:<host>` root accepts the
  domain's current key, which the relay resolves and pins), its largest envelope and its retention. The core checks
  each root first (`bad-record` names a bad one).
- **`record keep --as <name> --relay <url>... [--every <seconds>] [--once] [--dir <home>]`**: keeps the identity's
  records alive. It reads its newest address record, and its accept-from record when it has one, at the relays named,
  signs both again unchanged but for one newer `iat`, and offers each to every relay until each holds it (spec/SPEC.md
  Appendix B 110), one line per republish: `republished <kind> <address> iat <iat> <relay>` or `failed <kind> <address>
  iat <iat> <relay> <code>`, with `incomplete revocation <address> <relay> <code>: ...` after it when the address record
  carries a revoked list, since that relay still honours the keys it revokes. The newest epoch's key record is offered
  beside them to each relay that does not read back as holding it, silent where one takes it, `failed key <address>
  <relay> <code>` where it does not. A republish is due at half the address record's ttl, or every `--every` seconds
  (which must be below the ttl: `usage`); it
  prints `next <unix seconds>` while it waits, tries a republish no relay took again after 60 s, doubling to an hour,
  and runs until SIGINT or SIGTERM. `--once` republishes now and fails with the first failure's code. With no address
  record at any relay the copy in the home goes on, re-signed, and the run prints `healed <address> from the record kept
  here, signed <instant>`; a home that never published is
  `not-found`, and one that did and has lost its copy is `no-held-record`; a record that names `rotated_from` is refused `rotation`
  (`src/commands/record.ts`).
- **`publish <relay-url> <record-file>`**: an address record that revokes also goes to every relay it lists, and each
  that did not take it is named (`failed`, `incomplete revocation`), exit 3 (spec/SPEC.md §8.7). It checks the file is a
  record and publishes it; prints
  `ok <kind> <signer>` (`src/commands/relay.ts`).

### Delegation

- **`delegate --from <name> --to <address> [--caveat <caveat>...] --exp <unix seconds|+seconds> [--chain <in.json>]
  --out <chain.json> [--dir <home>]`**: one hop from the identity `<name>` to `<address>`, under the caveats it adds,
  appended to `--chain` when given. The whole chain is verified for the subject before the file is written: an issuer
  that is not the last subject is `chain-broken`, an expiry after the previous hop's `exp-not-monotone`, one already
  past `hop-expired`, a `--to` that is not an address `bad-address`. Prints the subject, then
  `root <address> hops <n> exp <seconds> caveats <JSON list>`, the effective caveats (`src/commands/delegate.ts`).

### Onboarding an agent on its org's domain

- **`onboard <name> --domain <host> --relay <url>... --accept <address|domain:<host>|*>... [--handle <local>]
  [--org-key <name>] [--out <dir>] [--origin apex|bag] [--ttl <seconds>] [--chain-exp <seconds>]
  [--max-bytes <n>] [--retention <seconds>] [--check] [--allow-private-relays] [--dir <home>]`** (added
  2026-10-28): puts the agent `<name>` on its org's own domain in one run, with no hand step but the owner's two. It
  calls `keygen`, `record`, `publish`, `delegate` and `lookup` in-process and never shells out
  (`src/commands/onboard.ts`). Every argument is checked before anything is written: a `--domain` that is not a
  domain root (lowercase, two or more labels, no trailing dot, port or IP literal, not special-use), a local part that
  makes no handle, an `--origin` other than `apex` or `bag`, a `--ttl` over 86,400, an org key name over 64
  characters or equal to `<name>`, more than 64 distinct relays, more than 1,024 distinct roots, `*` with another root,
  an `--out` that is the home or holds it (its keys would be served), and a missing `--domain`, `--relay` or
  `--accept` are `usage`; a bad `--accept` is `bad-record`. A `--relay` whose host is a private IP literal or a
  `localhost` name (the classes of the edge's private-relay guard) gets one stderr warning, `bag: warning:
  relay <url> is a private address (<class>); peers' edges refuse to deliver there unless they pass
  --allow-private-relays`, and never a refusal or another exit code: none with `--allow-private-relays`, none under
  `--check` (nothing is written), and none for a name that resolves to a private address, since onboard does no DNS
  lookup. Then, in order, one line each:
  - `key <name> <address> new|existing`, for the org key (`--org-key`, default `org-<host>`) and for `<name>`, each
    made by `keygen` when the home lacks it.
  - `wrote <file>`, twice: the tree a static host serves, `<out>` (default `<home>/serve/<host>`), holds
    `.well-known/bag/address.json`, the org's address record (its sealing key, the `--relay` relays, the ttl,
    and the rotation key and revoked list of the record already there, kept as `record keep` keeps them), and
    `.well-known/bag/handles/<local>.json`, the handle record of `<local>@<host>` (default local part:
    `<name>`; the same ttl). Each is verified by the core, written to a temporary file beside it and renamed into
    place, mode 0644, so a host serving the tree sees the old file or the new one; `<out>` (when it makes it) and
    the directories below it are 0755 whatever the umask; the directories above `<out>` keep their modes. A link or a non-file on the way is refused (`unsafe-path`). The record already at
    `address.json` is checked by the core (form and signature) before anything of it is kept, so one edited on the
    host is refused (`bad-record-sig`); one of another key is not replaced (`org-key-mismatch`), nor one that names
    `rotated_from` (`rotation`, as `record keep` refuses one: replace it by hand once peers have moved their pins).
    `replaced <address>` follows when the handle record there bound another address.
  - `published key <address> <relay>` at each relay first, then `published <kind> <address> <relay>` for the agent's
    address record and accept-from record, kept in `<home>/records/`, at each relay. Under forward secrecy (since
    2026-10-29) the agent's address record has a null sealing key, and senders seal to
    its key record: a short-lived X25519 sealing key, its epoch's, living a day (`exp` = `iat` + 86,400), whose
    private key is kept in `<home>/key-records` (the edge's `KeyRecordAdmin`, through `rotateEpoch` in
    `src/epochs.ts`, as `ac login`, `record keep` and `ac keys rotate` publish one). The key record goes out before
    the address record. A new epoch is published when none is held or the newest is 11 hours old or more (the 12
    hours of `ac login` and `record keep`, less an hour, so a cron run every 12 hours that comes back seconds early
    still rotates) or the newest was never published (a refused publish: the same key is published again, re-dated,
    and none minted); otherwise the newest epoch's key record is published again. Mail sealed to an older epoch still
    opens: `inbox` tries every epoch the home holds, newest first, until its horizon (`exp` + 604,800 + 300 s), and
    the long-term key while epoch 1 is held. onboard publishes no key record for the org key, whose address record
    keeps its sealing key. The agent's address record is dated one second past the one held (`max(now, iat + 1)`,
    as `record keep` dates a re-sign), so a run again within the same second is still newer. `unchanged ...` for a
    relay that holds the same key record, or an accept-from of the same second (`stale-record`). A relay that
    refuses the key record stops the run before the address record goes out, with the relay's code (`unreachable`
    with no answer, `http-<n>` for a status with no code), and the error names this onboard command again (`publish
    it again: ...`); any other relay failure exits 1 after the files are written; running the command again
    completes it.
    Before anything is written, `<home>/trust.json` is read (one that does not read is
    `trust-invalid`). Before the tree is written, the agent's newest address record and newest accept-from record at
    its relays are read and checked by the core, as `record keep` reads them, and the address record's rotation key
    and revoked list are kept in the new one (a `--revoke` added by hand, and `ac logout`'s revocations); one that
    names `rotated_from` is refused (`rotation`). No address record (a first run, or one lapsed and swept: a relay
    sweeps an address record at `iat + ttl`, never an accept-from) gives one with no rotation key or revoked list,
    but those of `<home>/records/<name>.address.json` when the core verifies it, it is the agent's and it names no
    `rotated_from`; the accept-from is read all the same.
    The accept-from record merges (since 2026-10-28; before, each run replaced the roots, so the cron refresh dropped a paired peer). Its roots, deduplicated,
    in this order: the held record's in their order (a pairing appends to it, as `peer` does), then the trust
    file's in their file order (typed `--accept` roots and pairing y's, so a peer paired under a held `*` comes
    back), then the typed `--accept` roots. A `kept <root>` line names each root in it that was not typed, held or
    trusted alike. A held `*` is not kept (it stands alone in a record, and a pairing adds nothing to it), so typed
    roots replace it. A typed `--accept *` publishes `["*"]` alone, since the core refuses `*` beside other roots;
    the paired roots in trust.json are still admitted by `*`, and come back on a later narrowing. Beside held
    roots a typed `*` is refused (`accept-held`), and more than 1,024 roots in all is `too-many-roots`,
    both before the tree is written or anything published. Its `--max-bytes` and `--retention` are the typed ones,
    else the held record's (as `peer` keeps them), else 65,536 and 604,800.
    Removing a root takes two steps, in this order, since a refresh keeps every held and trusted root:
    (1) drop it from the cron line's `--accept`; (2) `node packages/cli/src/main.ts unpair <root> --as <name>
    --relay <url>... --dir <home>` with the cron line's relays ("Names and pairing", below), which removes it
    from `<home>/trust.json` and from the accept-from at each relay after one y on a terminal. A root typed in
    onboard's `--accept` comes back on the next refresh unless it is dropped from the cron line: that run
    writes it to trust.json again and publishes it. (Before 2026-10-29, this took four hand
    steps: trust.json edited by hand, then `record accept-from` and `publish` at each relay.)
    Limits: a pairing that publishes between onboard's read and its publish is overwritten until the next run.
    onboard reads only the typed `--relay` list, so a move to new relays starts with no held roots (the trust
    file's are still in the union).
  - `trust <address>` for each `--accept` address, then `trust domain:<host>` for each `--accept domain:<host>`,
    added to `<home>/trust.json` (an entry it has stays, so a run again adds nothing). A domain root is stored in
    SPEC.md §7.2's grammar, with no port; `inbox` and the MCP server trust it as `--trust-root <host>`, so the inbox
    line below needs no `--trust-root`. Only the typed `--accept` roots are written, with no further y (the SPEC
    owner's decision of 2026-10-28): the file holds the typed `--accept` roots and the peers paired with a y, never
    a root from an incoming message, a resolved record or a default, so a held root onboard keeps in the
    accept-from (a `kept` line) is never written here. `*` is not stored. A `--trust-root <host>:<port>` is another anchor than the stored
    `domain:<host>`: `inbox` accepts it, but resolves `https://<host>:<port>` with no TXT lookup and pins it apart,
    and neither `--accept` nor the trust file can hold a port (`bad-record`, `trust-invalid`).
  - `chain <file> root <org address> exp <unix seconds>`: the chain from the org key to the agent,
    `<home>/<name>.chain.json`, for `send --auth` to a peer that accepts `domain:<host>`. `--chain-exp` defaults to
    604,800 s (7 days) and is refused above 2,592,000 s (§6.1's 30 days of a principal's hop).
  - The owner's two steps: `step 1: serve <out> as the root of https://<host>/ ...` with the two `url` lines that must
    answer 200 (with `--origin bag`, the origin is `https://bag.<host>/`), and `step 2: add this TXT
    record to the DNS of <host>:` with the `dns` line, `_bag.<host>.  IN  TXT  "v=ac1; key=<org address>"`
    (`; host=bag` added with `--origin bag`).
  - `next` lines: what an inviter adds to its accept-from record, the `send` and `inbox` commands for this agent, and
    the refresh: the records live `--ttl` seconds, so the command is run again with the same arguments at least every
    half of it. A `cron` line does that (every 12 hours by default); nothing installs it. Cron runs in `$HOME`, so the
    line gives `--out` and `--dir` as absolute paths, in place of the ones typed.
  - The self-check, `lookup domain:<host>` and `lookup <local>@<host>` as the org key, through the edge's own
    Resolver and the io's record source (system DNS and HTTPS in a real run), each line after `check `; then
    `self-check ok <handle>` and exit 0 when the handle record is found naming the agent and the agent's address
    record and key record after it (with no key record a peer has nothing to seal
    to), or
    `self-check pending <handle>: ...` and exit 3 when the domain does not resolve yet, or `self-check pending
    <handle>: no key record at the relays; run onboard again, without --check` when the handle and address record
    resolve but no key record does (a home onboarded before 2026-10-29, until a run without `--check`
    publishes one). `--check` runs only the
    self-check, and is the command to run once the host and the TXT record are up.

  Running it again is idempotent: the keys are found (`existing`), every record is signed again at the clock's now and
  replaced, the relays get the newer records, and no temporary file stays. Both address records keep the rotation key
  and revoked list they had; the relays and the ttl come from the arguments; the org's names its sealing key and
  the agent's none (its key record is published again, or a new epoch's: above). The accept-from record
  keeps the roots held at the relays and the trust file's beside the typed ones (above).

### Sending

- **With a live enterprise session** (after `bag connect`): **`send --to <name|label|address> --body <json>`** and
  nothing else (`--type` is `chat.v1` unless given). For text that comes from elsewhere (a message, a file, a model's
  output), pass the body on stdin so that nothing is quoted into the command line:
  `printf '%s' "$text" | jq -c '{text: .}' | bag send --to <name> --body @-`. The session gives the rest: `--as` its session key (`<name>.session`), `--relay` the
  organisation's first relay and `--auth` its chain (`<home>/enterprise/chain.json`). A flag given wins; another
  `--as` takes neither the relay nor the chain. A `--to` the name book lacks is looked up as an agent's label in the
  organisation's directory (any case; two agents under one label is `ambiguous-label`), so an agent of the
  organisation is addressable from the moment it connects. A session that is not live fills in nothing, and the
  usage error says why (`--relay is required (the enterprise session of <domain> is frozen: bag status)`). With
  several organisations in the home, `--org <domain>` picks one; without it the most recently connected is used and
  named on stderr with the others, as `status` does: `bag: using <domain>, the most recently connected; also signed
  in to <other> (--org)`. The directory's copy is kept per organisation, in
  `<home>/orgs/<domain>/enterprise/directory.json`, so one organisation's list never answers for another's.
- **`send --as <name> --to <name|address|handle>... --relay <url> --body <json|@-|@file> [--type <type>] [--auth <chain.json>]
  [--thread <id> [--prev <id>...]] [--policy <file>] [--members <file>] [--allow-private-relays] [--dir <home>]`**: one
  envelope (of `--type`, default `chat.v1`) to every recipient (`--body @-` reads the JSON from stdin, whole; `--body
  @<path>` from a regular file, never through a symbolic link; each at most 65,536 bytes, else `body-too-large`), signed by `<name>` as its own root, or with `--auth` as a session under the chain
  `delegate` wrote (its last hop must be to `<name>`: `chain-not-to-sender`). `--to` repeats and takes a name from the
  name book (`name-unknown` when the book lacks it; the book is read only when a `--to` is neither an address nor a
  handle), an address, or a handle such as `jane@acme.example`, which the edge resolves through the domain's TXT
  record, its org record and the handle record the org signs (`resolve-failed` naming the step, or `revoked`; nothing
  is sent). `--body` must be JSON and `--prev` needs `--thread` (`usage`).
  It prints the id, then one line per target, `<state> <relay> tries=<n>[ reason=<code>][ next_at=<n>]`. A target
  that was not published fails with its reason as the code and `<relay> <state>; the bytes stay in the outbox, and
  resend --id <id> sends them`. Sending again with `send` makes a new envelope; `resend` sends the same one. For a 403
  `root-not-accepted` the detail adds the next step, naming the root (the chain's first issuer under `--auth`, else
  the identity's own address): `the recipient does not accept this identity's root yet: ask them to add <root> (or
  your org's domain root) to their accept-from record, or send under a chain from a root they accept (send --auth /
  delegate)` (`src/commands/send.ts`, `rootHint`). One recipient that a finished pairing left in this home (its address
  is a name's current one in `names.json` and a root of `trust.json`), under this identity's own root, gets instead
  `<petname> no longer accepts mail from you (it unpaired you): ask them to pair again, or run unpair <address> --as
  <name> --relay <url> to stop keeping their root (this is not a relay ban)`, as `resend` does for a kept envelope.
  Anything else keeps the first: a stranger, several recipients, a former address, a file that does not read.
  With `--members`, a recipient the org denies is `policy-refused` before sealing, and a send a breaker trips prints
  `held <id> <rule>` and `nothing was sealed or sent: a person releases or drops it on a terminal (held release|drop
  <id>)`, and exits 0.
  **To a group**: when there is exactly one `--to`, it resolves to an address, and the store at `<home>/groups/<name>`
  holds that address's generations but not its admin state (a member, not the group itself), the envelope goes under
  the member's membership hop instead of as its own root; `--auth` takes precedence. The group itself (`send --as
  <group>`) signs as its own root (`openSender` in `src/commands/send.ts`).
- **`resend --as <name> --relay <url> [--id <id>] [--members <file>] [--policy <file>] [--auth <chain.json>]
  [--allow-private-relays] [--dir <home>]`**: one flush of the identity's outbox, the flush a started edge runs. `send`
  makes one attempt and exits, so what it leaves waits for this, or for an MCP server on the same home. It publishes the
  exact bytes of every due target through the edge's retry and failover (`src/commands/resend.ts`), with no sending
  logic of its own, and a relay takes an id once, so an envelope lands once however often this runs. A target in `retry`
  keeps its `next_at`, a 429's `Retry-After` among them, so a run before that time leaves it and prints it. A `failed`
  target, one a relay refused, goes only under `--id <id>`, the id `send` printed, which seals that envelope's failed
  targets again: run it once the cause is gone, say when the recipient accepts your root. `not-found` for an id the
  outbox lacks. It prints each envelope it tried or left waiting as `send` does, the id and one line per target, then
  `waiting <to,...> tries=<n> next_at=<n>` per send that has not resolved, or `nothing is waiting`; a `failed` target
  not named by `--id` is not listed. It fails, once all are printed, with the reason of the first that has not landed.
  Beside an edge of the same identity it is `busy`, as `send` is: that edge flushes by itself.
- **`held list | held release <id> | held drop <id>`, each with `--as <name> --relay <url> [--members <file>]
  [--policy <file>] [--auth <chain.json>] [--allow-private-relays] [--dir <home>]`**: the sends the outbound gate
  holds. `list` prints `<id> <rule> <type> <to,...>`, never a body (a `type` that is not a short token shows as
  `(not shown)`). `release` and `drop` need a terminal (`no-tty`
  otherwise): they print the send's line, ask `<release|drop> held send <id>? [y/N]`, and anything but `y` or `yes` is
  `declined` (`send <id> stays held`). `release` needs `--members` (`usage` otherwise), checks the deny list again and
  seals the send with a fresh `ts`, printed as `send` prints; `drop` prints `<id> <state>`. An id that is not pending is
  refused with the edge's message before any question (`src/commands/held.ts`).

### Receiving

- **With a live enterprise session**: **`inbox --once`** (or `inbox` to keep reading) and nothing else. The session
  gives `--as` its agent (`<name>`, the agent's mailbox), `--relay` every organisation relay, and `--trust-root` the
  organisation's root as an address, so no domain lookup runs. A flag given wins; another `--as` takes neither the
  relays nor the root. With a session, its domain given as `--trust-root <domain>`, or held in `trust.json` as
  `domain:<domain>`, reads as that root address too: an instance on one machine has no DNS record for its domain.
  `--org <domain>` picks the organisation as for `send`, and the same stderr line names the one used.
- **`inbox --as <name> --relay <url>... [--once] [--quarantined] [--group <group>] [--trust-root <domain|address>...] [--honor <profile>...]
  [--accept-type <type>...] [--policy <file>] [--members <file>] [--allow-private-relays] [--doorbell-path] [--dir <home>]`**: receives
  at the identity's mailbox and prints one line per message: `accept <id> <from> <root> <type> <body>`,
  `reject <id> <code>`, or `quarantined <id> <code>` for a row the org's policy holds (no body). A message refused for
  a cause that can pass, `resolve-failed` or `future-ts`, is kept, not rejected: `waiting <id> resolve-failed: kept; the
  next read after the trust root is fixed delivers it` (`future-ts`: `... after its timestamp is past ...`); the next
  read checks it again at its start, and prints `accept` or a final `reject` for it then.
  - The roots trusted are the `--trust-root` values (an address, or a domain whose record is pinned at first use) and
    the roots in `<home>/trust.json`; none of either, and every message is `untrusted-root`. A `--trust-root
    <host>:<port>` is accepted but is not the file's port-less `domain:<host>`: it resolves `https://<host>:<port>`
    with no TXT lookup and is pinned apart, so it trusts a chain only under the key served there.
  - `--honor` names a caveat profile to evaluate; the one profile is `coding` (another is `usage`). Without it any
    caveat fails closed, `unknown-caveat`. Without `--accept-type` every type is accepted.
  - `--once` ends 200 ms after the relay admits the subscription and no frame has come since (a relay sends its
    backlog at once after admitting it, and its protocol has no end-of-backlog frame); before the relay admits it,
    after a second with no frame. Without it inbox runs until SIGINT or SIGTERM.
  - The doorbell: each accepted message moves the mtime of `<home>/state/<name>/doorbell`, an empty
    file of mode 0600 in the 0700 state directory, made at the first one. Nothing is written into it. The edge's
    Receiver rings it at most once per message, after the message is routed: live, after a retry that ends accepted,
    finished after a crash, or released with `inbox release`. A refusal, a hold, a row waiting for a retry, a frame
    the relay sends again and a subscription never ring it. The writer (`src/home.ts`) refuses a symlink at the path
    itself (`O_NOFOLLOW`, ELOOP); that flag guards only the last component, so a link among the directories above it
    is followed: a symlinked `state` or `<name>` would be, and the guarantee rests on no other local user
    being able to write `<home>` or `<home>/state`, both made 0700 (the security relay's note of 2026-10-27
    00:32 UTC (01:32 Madrid)); it opens with `O_NONBLOCK` too, so a FIFO at the path fails the open with ENXIO
    and never blocks delivery (unit test, `test/send-inbox.test.ts`); a touch that fails prints one stderr
    line, `bag: doorbell <code>: <detail>`, and the message is printed and acked all the same.
    `--doorbell-path` prints `doorbell <absolute path>` once, as the first
    line, before anything is received (with `--once` too), after the name and the identity are checked. The MCP
    server rings the same file (`packages/mcp/src/open.ts`).
  - The name book is read once, at start. A `<from>` or `<root>` it knows prints as `<name> (ed25519:<8 hex>…)`; a
    name's former address as `<name>? (ed25519:<8 hex>…) WARNING: former address of <name>, replaced <ISO time>`; any
    other address in full. A `<from>` whose principal has a handle this home resolved (by `send --to`) and holds,
    unexpired, signed by the chain's root under the domain's pinned key, prints `[<name> ]<handle> (ed25519:<8 hex>…)`.
  - `--policy` and `--members` are the org's records, verified at start (exit 2, below). `--quarantined` prints
    `<seq> <id> <from> <root> <rule>` per held row and ends.
  - **`inbox release <seq>` and `inbox drop <seq>`** (with inbox's options) need a terminal (`no-tty` otherwise):
    they print the row's line, ask `<release|drop> quarantined row <seq>? [y/N]`, and anything but `y` or `yes` is
    `declined` (`row <seq> stays quarantined`). They then print `<seq> <state> <reason>` (`-` for no reason) and, for a
    row that has content, its `accept` line. A release checks the row again with its held rule waived, so pass the
    `--trust-root` and `--members` of the receiving inbox; a drop rejects it `policy-refused`.
  - `--allow-private-relays` turns the edge's guard off, as for `send`; without `--group` the receive path calls only
    `--relay`, which the guard always allows (`src/commands/inbox.ts`).
  - **`--group <group>`** (a name of the book or an address; one per run) reads a group as a member, in two passes.
    First the identity's own mailbox once (as `--once` would), with the group added to the trusted roots and the
    group caveat profile honored: each `group-key.v1` message is kept in `<home>/groups/<name>/` and printed as
    `group-key <group> generation <n> <kept>` (`<group>` through the name book; `<kept>` is the edge's
    `acceptGroupKey` result, `new`, `renewed` or `held`), other messages as usual. Then the
    group's mailbox, with the keys and the membership hop the edge derives from the store (`memberKeys`,
    `membershipHop`), at the first relay of the group's address record, printing its mail as above; live unless `--once`. With `release`, `drop` or
    `--quarantined`, `--group` is `usage`. A plain `inbox` does not trust the group.
- **`inbox --watch [--exec <cmd> [--exec-timeout <seconds>]] --as <name> --relay <url>`** with inbox's other options but `--once`, `--quarantined`,
  `release` and `drop` (`usage` for those): the live inbox (`inbox` without `--once`) with two additions. A refusal or
  a hold prints its line, `reject`, `waiting` or `quarantined` as `inbox` prints it, on stderr and never
  on stdout, so a refused message still shows; and `--exec` runs a command per accepted message. **Its stdout holds
  three kinds of line: `doorbell <path>` first (with `--doorbell-path`); with `--group`, `group-key ...` lines during
  the first pass, among that pass's `accept` lines; then `accept` lines only**, each printed at once, exactly as `inbox` prints it; `--exec` sees accepted messages only (`src/commands/watch.ts`).
  `inbox` (with `--watch` or without) shows a type that is not a short token (`[A-Za-z0-9_.+*-]`, 1 to 64) as `(not
  shown)`: the core takes any non-empty string, and a newline in it would forge a second line. `--watch` also sends a
  line to stdout or stderr by its row's state (accepted, refused, held), never by the printed text.
  - **A type holds no control character.** A `type` with a Unicode control character (`Cc`) or U+2028 or U+2029 is
    `bad-content`, refused at encode and at decode (`packages/core/src/seal.ts`; spec §5.2, the adopted rule of
    2026-10-27); the displays here still show a type that is not a short token as `(not shown)`.
  - **One receiver per identity at a time: `inbox --watch` or the MCP server, never both.** The edge's writer lock
    refuses whichever of the two starts second with `busy` (e2e scenario 21), and the doorbell is rung by
    whichever holds the identity. (Corrected 2026-10-28: the usage text has said whichever starts second is refused since 7efdadb.) So
    `inbox --watch` watches no doorbell: it is the receiver and acts on each message itself. The doorbell serves a
    process that is not the receiver, such as a Claude Code session watching the MCP server's doorbell.
    The lock lasts the whole watch, not each delivery (added 2026-10-28): while `inbox --watch` (or `--exec`) runs
    for a name, `send`, `held`, `lookup`, `group` and any other `inbox` as that `--as` name exit 1 with
    `bag: busy: <home>/state/<name>/audit.lock is held by ...`; stop the watch first, or use another name.
  - **`--exec <cmd>`** runs `<cmd>` with `sh -c` once per accepted message, after its line prints, with one summary
    line on its stdin, `message <id> from <address>, type <type>` (the same three fields as the MCP server's push
    notice, without the notice's trailing sentence; a type that is not a short token prints `(not shown)`), never the
    body. Runs go one at a time in arrival order, each awaited, so a slow command delays the runs after it (not the
    prints). A run's first failure, a spawn error, a stdin it closed unread (EPIPE, ECONNRESET or ENOTCONN, whichever the kernel gives, always the detail
    `stdin closed unread`), a non-zero exit or a signal, is
    one stderr line, `bag: exec-failed: <detail>`, and the watch goes on. The command's stdout and its stderr both go to the watch's stderr, so its stdout stays the
    lines above.
  - **At most once, and once on every path.** The message is acked before its command runs: a run lost to a crash, a
    kill or a supervisor's stop timeout is not repeated. Each accepted row prints its line and queues its run once, from
    the edge's `accepted` call when the edge acks it in the store, on every path: a frame; the retrier, at any cursor (a
    row it accepts after a restart, with nothing acked before it, included); and `recover()`, for a row a crash left
    received, verified, routed or queued. A frame the relay sends again after its row was acked prints and runs nothing.
    An output sink that throws on an accept line (the line is printed inside the `accepted` call) is not fatal: the edge
    reports it and `inbox` writes one stderr line, `bag: accepted: <message>`; the row stays acked, its doorbell
    already rang, and the next row goes on.
    The unit tests in `test/watch.test.ts` stage each of these. One gap: a crash between the store's commit of the ack
    and the edge's call loses that row's line and run. A row that waits for a retry prints its `reject` line on stderr
    each time the relay sends its frame again, and runs nothing.
  - **A retried row that ends rejected can go silent.** The edge's seam is for accepted rows only. A row the retrier
    rejects for good while its cursor is above the highest cursor the subscription had handed over when that retry pass
    began is acked in the store with no `reject` line: a refused row prints only from the subscription's ack
    (`#retryDue` in `packages/edge/src/receiver.ts`). The audit log records it. A known gap.
  - **`--exec-timeout <seconds>`: a run is limited, the queue is not.** A run that is still going after the limit
    (default 120; a plain number, fractions allowed, at most 2,000,000; `0` is no limit, the behaviour before this
    flag) gets SIGTERM, then SIGKILL 5 s later if it is still alive. Each signal is one stderr line, `bag:
    exec-timeout: message <id> got <signal> after <seconds> s`, where `<seconds>` is the limit, not the time the run
    took; the run's exit then adds its `exec-failed: exit SIGTERM` (or `SIGKILL`) line; the next queued run starts at
    once. **A command that needs longer than the limit must background itself** (start the work detached and return),
    or be run with `--exec-timeout 0`, which gives back the hang: a command that does not end holds every later run,
    and the exit after SIGTERM, until it ends. The signal reaches the shell only, not what it started: a command that
    runs another program without `exec` can leave it running after the kill. **The queue of pending runs is
    unbounded**: a flood of messages grows it without limit, one run at a time (a known gap; a message is acked before
    its run, so a dropped run is not repeated). Without `--exec`, `--exec-timeout` is accepted and ignored (not a
    usage error); a second `--exec-timeout` silently replaces the first. Tested: a run past the limit gets SIGTERM and
    the line; a command that ignores SIGTERM gets SIGKILL after the grace; the next run proceeds
    (`test/watch.test.ts`).
  - **Prompt injection by mail.** The command sees who wrote and what kind, never the text, so a command that hands
    its input to a model passes it no sender prose. Still treat it as data: the sender chose the type, and the address
    is public. The `accept` line on stdout carries the body verbatim; whatever hands that line to a model hands the
    sender a prompt, and "read it as data" in that prompt is a request, not a boundary. `--trust-root` limits who can
    write to the mailbox, not what they write.
  - SIGINT or SIGTERM stops the edge; the pending runs then finish, each awaited (a line received before the stop runs
    its command after the edge stopped), and the watch exits 0. A supervisor whose stop timeout is shorter than those
    runs kills them, and they are lost. A second signal of the same kind (SIGINT twice, or SIGTERM twice) kills the
    watch at once; one of each does not, since each signal has its own one-shot handler (`src/io.ts`).
  - Codex (untested here): `--exec 'codex exec --skip-git-repo-check --sandbox read-only "bag: $(cat)"'` (the flag, because `codex exec` needs a git repository without it; this is the line `host install codex` prints) hands a run with no write
    access the summary only; a model run often takes longer than the default 120 s, so add `--exec-timeout 0` (or a
    longer limit) there. A shell: `--exec 'umask 077; cat >> ~/mail.log'`.
  - At boot: cron's PATH lacks Homebrew, so name Node by its path: `@reboot umask 077; cd <checkout> &&
    /opt/homebrew/Cellar/node/24.4.1/bin/node packages/cli/src/main.ts inbox --watch --as me --relay <url> --trust-root
    <root> --exec 'umask 077; cat >> $HOME/mail.log' >> $HOME/inbox-watch.log 2>&1`. Cron does not restart a watch that
    died, and under cron a keychain identity has no one to answer its access dialog. A launchd LaunchAgent with
    `KeepAlive` (macOS) or a systemd unit with `Restart=always` (Linux) restarts it; prefer those.

### Waking a session

- **`wake-hook --as <name> [--session auto|auto:codex] [--dir <home>] [--max <seconds>] [--exit-code <n>] [--no-idle-wake] [--print]`**: for a host hook that
  wakes a session when something is delivered. It opens no edge and no store; it
  reads the mtime of the identity's doorbell, `<home>/state/<name>/doorbell`, and one small state file beside it,
  `wake-seen` (one line, the mtime as a number, 0600), which holds the mtime this command last reported. The first run,
  with no `wake-seen`, takes the current mtime as the baseline and reports nothing. It then looks once a second. When
  the mtime differs it stores the new one, writes one stderr line, `bag: a message was delivered to <name>;
  read it with the inbox tool and report it`, and exits
  `--exit-code` (default 2, the code that wakes a Claude Code `asyncRewake` hook). At `--max` seconds (default 3500;
  the hooks `host install` writes pass 86000, about a day)
  it wakes once per mail-free stretch, counted from the lock holder's start, which is the newest hook's (a session busy for 3,500 s with no mail
  gets the wake mid-turn): it writes `bag: no message for <name> in <max> s`, makes the one-line marker
  `wake-idle` (`1`, 0600, created exclusively after any link or file there is removed, so a link is replaced, never
  followed) beside `wake-seen`, and exits `--exit-code`; the next deadline with no ring between finds the
  marker and exits 0, silent, until a ring clears it (a ring behaves as above and removes the marker). `--max 0` looks
  once and never wakes on silence. `--no-idle-wake` makes a bounded wait behave the same: at `--max` it exits 0, silent,
  and makes and removes no `wake-idle` (a marker already there is left as it is); a ring during the wait still behaves
  as above. It is for a host that spends a model turn on every wake: the Codex `Stop` hook below waits `--max 30` with
  it, so a Stop after a continuation with no new ring waits again and ends silent (the ring is the loop guard, not
  `stop_hook_active`), and the exported `CODEX_STOP_WAIT` (30) and `CODEX_STOP_TIMEOUT` (60) are that hook's wait and
  its `timeout` (`host install codex --mode mcp`, below). With `--print` it writes `doorbell <mtime>` on stdout per change instead
  and runs until SIGINT or SIGTERM (a loop for Claude Code's Monitor tool); it reads `wake-seen` for its baseline and
  keeps that and each mtime it printed in memory, never writing `wake-seen` or `wake-idle`, so a Monitor loop cannot
  move `wake-seen` past a ring before a hook reports it. Mtimes are milliseconds as the OS gives them,
  fractional where it does, printed as JavaScript prints the number; a doorbell that is not there reads as 0. A missing
  home or `--as`, an identity the home lacks, or a `--max` or `--exit-code` that is not a whole number in range is
  refused (`usage`, `ENOENT`). It does not tell which message or who sent it: the session reads the inbox
  (`src/commands/wake-hook.ts`, `test/wake-hook.test.ts`).
  - **`--session auto:codex`** (a Codex `Stop` hook): `--as` is the principal's name, and the session's name is
    `codexSessionName(<the principal's address>, <session_id of the Stop JSON on stdin>)`, the name the MCP server
    `--session auto:codex` gave that Codex session at its first tool call (both ids are the root thread's id). Stdin is
    read to its end, to the line past 64 KiB or for 2 s at most, so a stdin that stays open cannot hang the hook; the
    lines are joined by spaces (readline also splits at U+2028), and a JSON cut at 64 KiB gives its first unescaped
    `"session_id"` field. JSON that is not
    an object with a string `session_id` is exit 1 `bad-hook-input`; an id that is not a uuid is exit 1 `no-session`
    (Codex reads exit 1 as a failed hook and the turn ends normally). With no identity of that name yet (no tool call
    has bound the server) it exits 0 at once, silent, with no wait. Otherwise it watches that identity as `auto` does.
  - **One at a time per identity.** A session runs several of these at once (one from `SessionStart`, one from every
    `Stop`), and all of them would fire on one ring. So a run takes `<home>/state/<name>/wake-hook.lock` (its pid
    written to a temp file and linked into place, so it is never seen empty and an existing lock fails the link; 0600;
    `--print` takes none) right after the identity check. The newest run takes over: a lock held by a live wake-hook
    (the pid answers a signal 0, or refuses it with EPERM, the file is not older than `--max` plus 60 s, and one word of
    its command line, `/proc/<pid>/cmdline` on Linux and `ps` elsewhere, is `wake-hook`) gets SIGTERM, which ends that
    hook 0, silent, and removes its lock; the new run waits up to 3 s, in 100 ms steps, while the lock still holds that
    pid and the pid lives, then removes a lock still holding it. A lock whose pid is dead or no wake-hook, that holds
    anything but a pid, or that is too old is removed at once. Either way the lock is then taken once more, and losing
    that race is a silent exit 0 before `wake-seen` is read or written, so of two runs started together one watches.
    A run that finds its lock holding another pid at a look (a newer run took it over) exits 0, silent. So an orphan
    watcher of an exited session, or a pid reused after a SIGKILL, no longer keeps the next hooks silent for up to an
    hour. Known residual, same user only: the holder's pid can be reused between the check and the SIGTERM, and the
    check-then-remove gap can remove a newer lock; each corrects itself within about 1 s and costs at most one
    duplicate wake, never a dropped one. The lock is removed on every way out, a fire, the deadline, a signal, and only while it still holds
    this pid. `wake-seen` is written whole to a temp file beside it (exclusive create, 0600) and renamed over it, so a
    reader never sees it empty, and a link at `wake-seen` is replaced, never followed. The lock is per name, not per
    session: when two sessions run the hook with one fixed name (the same `--as`, without `--session auto` or `auto:codex`), each
    hook takes the lock over from the other's, so a ring wakes only the session whose hook started last; `--session auto` (Claude Code) and `--session auto:codex` (Codex) give each session its own name, and so
    its own lock (`src/commands/wake-hook.ts`, the `lock` function and the `release === null` exit; added at
    22:51 UTC on 2026-10-28).
  - **`--session auto`: one session of many on one principal.** `--as` is then the principal's name, and the hook
    does no hashing: the MCP server of the Claude Code session wrote the session's name to
    `<home>/state/sessions/<pid>-<start>.json` (`{v, name, principal, pid, start}`; `principal` is an address), and the
    hook finds that file by the same anchor, the topmost `claude` process above it (`sessionAnchor`, `@usebag/edge/agent`).
    It polls for the file once a second, takes the file's `name`, waits for the identity of that name to exist, and then
    everything above runs on that name. Four refusals are exit 1 (a non-blocking hook error in Claude Code, never 2,
    which wakes the model), each printed by `run()` as `bag: <code>: <why>`: no `claude` process above the hook
    (`no-session`); no session file by `--max` (`no-session-file: no file for pid <pid> in <home>`; a wrong `--dir` ends
    this way too); a file whose `principal` is not the address of `--as` in this home (`session-principal: the session
    file is not <name>'s address`); a file that is there but malformed (`bad-session-file: ...`, from
    `readSessionFile`: junk JSON, `v` not 1, a name that is not `s-` and 16 hex, a `principal` that is not a string, or a
    `pid` or `start` that is not the anchor's). Only the stop signal ends the wait 0, silent. If the file is there but
    its identity never appears, the hook ends 0, silent, at `--max`. An identity that appears in the last poll before
    `--max` can be followed by the one idle wake (`no message ... in <max> s`), since the waits and the watch share one
    `--max`. Any other value of `--session` is refused (`usage`).
  - **What Claude Code does with the hook, as observed on 2026-10-28 (not measured here).** For a plugin installed with `--scope local` from a path marketplace, Claude Code 2.1.312 ran the
    hook command from the source folder's `plugins/claude-code/hooks/hooks.json`, not from the installed copy in the
    plugin cache, so an edit there reaches a session without a reinstall. It records the hook's exit 2 in its log as
    "Stop hook blocking error" while the session shows it as "Stop hook feedback": the wake, not a failure.
  - **The hook is a request to read, not to send.** The line says only to read the inbox and report it: the hook is
    not a standing instruction to answer, and a send needs the user's word.
  - **Gaps, stated.** At `--max` (3500 s by default, 86000 s in the hooks `host install` writes) the watcher wakes the
    session once on silence (adopted decision 9, "a deadline
    that wakes it on silence", read as one wake per mail-free stretch because the waiting rule bars periodic turns); it
    exits 0 at the next deadline, and nothing re-arms it until the next `SessionStart` or `Stop`, so after that silent
    deadline an idle session is deaf until a turn runs: after about two hours of silence at the default, about two days
    (47.8 hours) with `host install`'s hooks. `host install` fixes the hook's `timeout` at 86400, above its `--max`,
    with no flag to change it. Claude Code 2.1.316 kept such an `asyncRewake` hook alive past 3600 s and woke the idle
    session at its exit 2 (measured 2026-11-03 with a hook of `timeout` 86400 that exited at 3700 s; a wait of a day
    was not run). There is no re-arm after a user interrupt or a Claude Code `StopFailure`: the hook ends with the
    turn, and the next `SessionStart` or `Stop` starts it again; the process is not detached, since a detached process
    cannot deliver the exit-code wake. Claude Code documents exit code 2 under `asyncRewake` as the wake of an idle
    session; whether it is non-blocking on the `Stop` event itself is not confirmed here, which is why the stderr
    message is one line. `claude -p` kills async hooks, so for a non-interactive run use the worker path, `inbox
    --watch --exec`, above. Empty wakes happen: `wake-seen` moves when the hook reports, not when the model reads, so
    a message the model already took in-turn still wakes the next `Stop`, and a doorbell that is deleted (its mtime
    reads 0) fires once.
  - **`--identities <file>`** in place of `--as`, `--session` and `--dir` (refused beside them): one hook watches every
    identity of an identities file (`packages/mcp/README.md`, "Many identities in one server"), each by its own
    doorbell, `wake-seen`, `wake-idle` and `wake-hook.lock` in its own `<home>/state/<key>/`. It takes every lock or
    none: each is taken over as above, and a race lost on any releases the ones taken and ends 0, silent. A ring writes `bag: a message
    was delivered to <label>; read it with the inbox tool as <label> and report it`; several rings seen in one poll give
    one line naming each. At `--max` one line, `bag: no message for any identity in <max> s`, once per
    mail-free stretch: `wake-idle` is made in every state directory, a ring removes its own, and the line is skipped
    while every identity holds one. `--print` writes `doorbell <label> <mtime>`. An identity its home lacks, or whose
    key is refused, is skipped with one stderr line, `bag: <label> skipped: <code>: <detail>`, and the rest are
    watched; none left is exit 1, `no-identity`. The hook command names the file, not the identities, so adding or
    removing one never touches `settings.json`.
- **`session-code --as <principal> --session auto [--dir <home>]`**: for a **synchronous** `SessionStart` command hook
  (not `asyncRewake`: Claude Code never shows an async hook's output to the user, and `wake-hook` is async). It finds
  the session's name exactly as `wake-hook --session auto` does (the same function, the same four exit-1 refusals),
  then waits for `<home>/state/<name>/grant-request.json` (`{"v":1,"code":"<code>","at":<unix s>}`, written by the agent
  while it shows the code and removed at the `y`, a refusal or close) and prints one line of JSON on stdout:
  `{"systemMessage":"bag: session <name> waits for y at the agent, request code <code>. Type y there only if the
  codes match.","hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"<the same sentence>"}}`. Claude
  Code shows `systemMessage` to the user and gives `additionalContext` to the model, which can repeat it on request. If
  `grant.json` is already there (a grant given), or no request appears within the wait, it prints nothing and exits 0; a
  request file that does not parse is read as absent and the poll (every 250 ms) goes on. The wait is 10 s for the
  session file and the request together, so it delays session start by at most 10 s, and only while a grant is pending
  (in `src/commands/wake-hook.ts`, `test/session-code.test.ts`). `host install claude-code` writes only the async wake-hook entries, not `session-code`: a stated debt; the plugin's `hooks/hooks.json` carries it.
- **`host install <claude-code|codex> --as <name> --relay <url>... [--rendezvous <url>] [--trust-root <address>]... [--grant-caveat <caveat>]... (--project <dir> | --user) [--mode worker|mcp] [--dir <home>]`**:
  writes the MCP server's registration and, for Claude Code, the wake hooks, into the places the repo documents, and
  prints each file and the entries it added (no key is read; the entries hold paths, the name, relay URLs and trust
  roots). `claude-code --project <dir>` writes `<dir>/.mcp.json` (`mcpServers.bag = {command, args}`, as
  `packages/mcp/README.md` shows it, with `--dir <home>` added) and `<dir>/.claude/settings.json`, a `SessionStart`
  and a `Stop` hook, each `{"hooks": [{"type": "command", "command": "<node> <this checkout>/packages/cli/src/main.ts
  wake-hook --as <name> --dir <home> --max 86000", "timeout": 86400, "asyncRewake": true}]}` in the event's list.
  That is the
  interim form, until an `ac` bin exists: the MCP entry names the checkout's `packages/mcp/src/main.ts` the same way,
  and both run on Node 24's type stripping with no flag. The `--max` of 86000 and the `timeout` of 86400 above it are
  this command's own choice (`WAKE_MAX`, `WAKE_TIMEOUT`): one idle wake a day instead of one an hour ("Gaps, stated",
  above); the nested group shape is not documented in the repo, which documents `type`, `asyncRewake` and
  `timeout` as fields only. **Upgrading an earlier install:** an install made by an earlier checkout keeps `timeout`
  3600 and no `--max`, so its idle session goes deaf after about two hours of silence until `host install` runs again.
  Re-run the same command (the same `--as`, `--dir` and `--project`, or the same `--identities` file): it removes
  that earlier hook group from `SessionStart` and `Stop`, adds the new one, prints the earlier command as `removed`,
  and leaves every other hook as it was. Then restart Claude Code in the project: a session that is already running
  keeps the hooks it read at its start (Claude Code's hooks documentation; not measured here). `--trust-root` values are checked as `inbox` checks
  them (an address or a domain). `codex --user` takes `--mode worker|mcp` (`claude-code` refuses `--mode`), and an
  identity has one receiver: the MCP server and the `inbox --watch` worker are refused `busy` beside each other, so the
  install writes one of them. `--mode worker`, the default, because Codex has no idle wake, writes
  nothing and prints the line that runs `inbox --watch --as <name> --exec 'codex exec --skip-git-repo-check --sandbox read-only "bag: $(cat)"'`, the form of the `--exec` bullet above (every `--relay` and
  `--trust-root` is on it). `--mode mcp` appends the `[mcp_servers.bag]` table of the mcp README to
  `~/.codex/config.toml` (0600 when it makes the file), with the server as `--session auto:codex --principal <name>`
  (one server per Codex session, each named from Codex's session id at its first tool call, and the person types
  `y` at the agent for each session's grant; no `--as`, no `--keep-alive-records`) and one `--grant-caveat <caveat>`
  per flag given, which `--mode mcp` requires (a `usage` error without it) and every other host and mode refuses, and
  merges a `Stop` hook into `~/.codex/hooks.json`,
  `{"hooks": [{"type": "command", "command": "<node> <this checkout>/packages/cli/src/main.ts wake-hook --as <name>
  --session auto:codex --dir <home> --max 30 --no-idle-wake", "timeout": 60, "statusMessage": "bag: waiting for mail"}]}`, in the
  event's list (an entry that already carries the same command counts as there; every other key and event stays). When
  a turn ends, the hook waits up to 30 s for the doorbell and, on a ring, exits 2 with one stderr line, which Codex
  takes as the prompt that continues the turn; with no ring it exits 0, silent, and the turn ends, so an idle session
  is not woken. The wait is short because Codex awaits the hook inline: a message the person types meanwhile is held until it ends, and Esc interrupts it; raise `--max`, and keep `timeout` above it, for an unattended session. It reads only the doorbell, so it is no receiver and runs beside the MCP server. It needs Codex
  rust-v0.114.0 or later, and Codex runs it only after the person trusts it with `/hooks`; before the session's first
  tool call the hook exits 0 at once, silent. The note it prints names the wait and the trust step. Both
  Codex files are worked out before either is written, so a `hooks.Stop` that is not a list, a hooks.json that is not a
  JSON object, or a table that is `exists` leaves both as they were. Earlier, the install wrote the table and printed the worker line too, so a worker's `codex exec`
  started the MCP server that was refused `busy`. The Claude Code files and the Codex table merge into what is there without touching another key, and a second run
  changes nothing: `unchanged <file>` per file and `nothing to change`. A `bag` entry or table that is
  there with other settings is `exists`, never overwritten (a Codex header in a comment counts as there); a file that
  is not valid JSON, a member that is not an object, or a `hooks.<event>` that is not a list is
  `host-file-invalid` (host install). Both Claude Code files are checked before either is written, so a
  refusal leaves neither changed.
  The places the repo does not document are `usage` errors, "not documented yet": `claude-code --user` and `codex
  --project`. Any other host is a `usage` error naming the two (`src/commands/host-install.ts`,
  `test/host-install.test.ts`).
  - **What `claude-code --project` does to the project.** `--user` is refused, so the install is per project
    directory, and it rewrites `.mcp.json` and `.claude/settings.json` with absolute paths in two-space JSON, a noisy
    diff in a git project. Both entries carry `--keep-alive-records`, as the Codex table does: without it the
    identity's address record lapses a day after its last publish and peers get `resolve-failed`
    (`packages/mcp/README.md`). The paths come from `process.execPath` and this module's own location, so run the
    install from the merged main checkout, never from a worktree that is later pruned; after a Node upgrade a re-run is
    refused `exists` (the entry differs), so edit or remove the old entry first. To be
    confirmed: Claude Code asks once to approve a project `.mcp.json` server and reads hooks at session start, so the
    install takes effect after a session restart.
  - **The Codex file.** The table is found by its header with spaces or a quoted name, by a dotted key
    (`mcp_servers.bag.command = ...`) and by `bag = {...}` under `[mcp_servers]`; a match in a comment
    counts as there. The file is appended to in place (not a temp file and a rename), so it is not atomic.
- **`host install claude-code --project <dir> --identities <file> --as <key> [--label <label>] --relay <url>...
  [--rendezvous <url>] [--trust-root <address>]... [--dir <home>]`**: many identities in one server
  (`packages/mcp/README.md`, "Many identities in one server"). It adds the identity, labelled `--label` (default the key
  name), to the identities file and wires the project to the file: `.mcp.json`'s `bag` becomes `{command:
  <node>, args: [<mcp main>, "--identities", <file>]}` and the `SessionStart` and `Stop` hooks run `wake-hook
  --identities <file>`. The file is made at version 1, or the identity appended, members in the order `label`, `key`,
  `home`, `relays`, `rendezvous`, `trust_roots`, `keep_alive_records` (true), two-space JSON, written whole to a
  temporary file of mode 0600 and renamed, its directory made 0700. The suggested place is
  `$HOME/.bag-identities/<project directory name>.json`. The same identity again is `unchanged`; its label, or
  its home and key, there with other settings is `exists`; another identity's home is `home-shared`. Refused: a file
  inside the project (`identities-in-project`: a project is often committed, and the file links every identity it
  lists), a relative path, `codex` ("not documented yet"), a label that is not one, and a 65th identity
  (`identities-invalid`). A project wired for one identity, with exactly the entry and hook this command writes without
  `--identities`, is migrated: that identity goes first in the file, as the default, the entry is replaced, and the
  hook groups that ran the old command are removed. Any other `bag` entry is `exists`. All three files are
  worked out before any is written, so a refusal leaves all three as they were. It prints `wrote` or `unchanged` per
  file, then `the change takes effect when Claude Code starts the server again`.
- **`host remove claude-code --project <dir> --identities <file> --label <label>`**: takes the identity out of the
  file, and `default` with it when it named it (the output names the new default, the first identity). It touches no
  key, home or state, and neither `.mcp.json` nor `settings.json`. Refused: an unknown label (`unknown-identity`,
  naming the labels), the last identity (`last-identity`: keep one, or remove the server entry by hand), and any of
  `--as`, `--dir`, `--relay`, `--rendezvous` or `--trust-root`.
- **The identities file's reader** (`src/identities.ts`, which owns the format; `packages/mcp/src/identities.ts` reads
  it by the same rules): a regular file of mode 0600, read through one descriptor opened without blocking; version 1;
  no unknown member; 1 to 64 identities; unique labels; key names by the custodies' own rule (edge's `checkName`);
  absolute homes, one per identity by real path (a home not made yet is compared resolved, case-folded on macOS; any
  other failure to resolve it is refused); 1 to `MAX_RELAYS` distinct relays; `honor` values that are profiles; no empty accept type;
  `receipts_to` entries that are addresses, never names, since a pairing can fill a name; a `default` that names a
  label. `host install` compares and writes only its own members, so `receipts_to`, `honor` and the like stay. A fault is `identities-invalid` naming it, or `home-shared`. The shared fixture
  `test/fixtures/identities-v1.json` is read by both packages' tests.

### Names and pairing

- **`name add <name> <address> [--replace] [--dir <home>]`**, **`name list [--dir <home>]`**, **`name forget <name>
  [--dir <home>]`**: the home's name book, `<home>/names.json`. A name is `[a-z0-9][a-z0-9._-]`, at most 64 (`bad-name`
  otherwise), pinned to one address: another address for a known name is `name-exists` unless `--replace`, which keeps
  the old one as former. `add` prints `<name> <address>`; `list` prints `<name> <address>` per name, sorted, and
  `  former <address> replaced <unix>` per former address; `forget` prints nothing (`name-unknown` for a name the book
  lacks). A file that is not a book is `names-invalid`. Names are resolved here, never sent on the wire
  (`src/commands/name.ts`, `src/names.ts`).
- **`peer invite --as <name> --relay <url> --name <petname> [--for <address>] [--ttl <seconds>] [--dir <home>]`** and
  **`peer accept --as <name> --relay <url> --name <petname> [--for <address>] <code or invite> [--dir <home>]`**: pairs
  two identities on two terminals. Both need a terminal (`no-tty`, before any network). `--name` must be a
  name; `--for` takes an address; `--ttl` is at most 600 s, the default. A `--name` the book holds stops either command
  at once with `name-exists`, naming the entry, before a code goes out or a person is asked: the peer's address may come
  only with its request, after the whole ceremony. It goes on only under `--for`, that entry's address (the same peer
  again; the entry does not change). `invite`'s `--for` is the only address that may answer; `accept`'s is the only
  inviter it accepts (`not-for`, before the digits, nothing sent, and the invitation stays open).
  - `invite` prints `pairing code <nameplate>-<word>-<word>-<word>` when the relay offers the pair rendezvous
    else `invite <string>`, and `one request until <ISO time>; the
    other side reads you six digits, and you type them here`; then, per request: `refused <address> <code>` (under a
    pairing code, `bad-code` is refused and the invitation stays open), or for the first good one `request <address>`
    and `to pair with it as <petname>, type the six digits the other side reads you`. The digits are never shown on
    this side: a person types them (spaces and hyphens are ignored), with 3 tries, each miss printing `no match; tries
    left: <n>; ask the other side to repeat them`; the third miss is `digits-mismatch` (`the typed digits did not match;
    nothing was written`), local to this side: it counts toward no relay's bound, and the acceptor hears nothing but
    `no-answer` at the invitation's end. The end of input is `declined`. A later request prints `second request
    <address>: the invite string leaked`.
  - `accept` takes the pairing code (its nameplate claimed at `--relay`, or at `--rendezvous` when given) or the invite
    string, prints `inviter <address> at <relay>`, the relay that holds the invitation, which is the inviter's
    `--rendezvous` when it gave one, `check digits <six digits>` and `read them out now, not where the code was sent, before you answer:
    that is the security check`, asks `pair with it as <petname>? [y/N]`
    (a no is `declined`: `no request was sent; nothing was written`), then prints `requested; waiting until <ISO time>
    for the inviter's answer`.
  - Both end with `paired <petname> <address>`. Each side has then named the other in `names.json`, trusted it in
    `trust.json` and added it to its accept-from record (`src/commands/peer.ts`; the protocol is the edge's,
    `packages/edge/src/pairing.ts`). A pairing needs the relay that holds the invitation and one listed relay; a listed
    relay that does not take a record prints `failed <kind> <address> <relay> <code>` and `record keep` carries it there
    (spec/SPEC.md Appendix B 110).
- **`unpair <address|domain:<host>> --as <name> --relay <url>... [--dir <home>]`** (a relay that does not answer stops
  nothing: the trust file changes, the others take the record, and it is named, exit 1; since
  2026-10-29): ends a pairing, or removes a root a typed `--accept` stored; the inverse of `peer`'s y
  (`src/commands/unpair.ts`). The trust invariant holds both ways: a root enters `trust.json` only by a person's
  explicit act (a pairing's y, a typed `--accept` or `--trust-domain`) and leaves it only by this one, on a
  terminal after one y; never by an incoming message, a resolved record or a default. In order:
  - A root that is not an address or a `domain:<host>` with no port (`*` included), or the identity's own
    address, is `usage`, as is more than 64 distinct `--relay` URLs (as onboard refuses them). A terminal is
    needed (`no-tty`, before any network).
  - `<home>/trust.json` is read (`trust-invalid` when it does not read), then the identity's accept-from at each
    `--relay` on its own, checked by the core as `record keep` checks it. A relay that fails the read fails the
    command with its code; nothing is asked or written.
  - When the newest of those records is `*`: `accept-all`, since `*` admits every root and none can leave it.
    Publish the roots to keep first (`onboard --accept`, or `record accept-from` and `publish`), then run unpair
    again. When neither trust.json nor any relay's record holds the root: `not-trusted`, exit 1, nothing asked or
    written. A run again after a complete one ends there; exit 1, not 0, so a mistyped root never reads as a
    removal. Under a held `*`, a root in trust.json alone cannot be unpaired until the accept-from is narrowed
    (`onboard --accept`), which puts it back into the record from trust.json; unpair then removes it from both.
  - The question, on stderr: `unpair <root> from <name> (<address>): remove it from <home>/trust.json and the
    accept-from at <relay>...? [y/N]`. It names trust.json when the file holds the root, and the accept-from at
    every `--relay` when any relay's record holds it. Anything but y is `declined` (`nothing was changed`),
    exit 1.
  - After the y, every relay's accept-from is read again before anything is written. A record published at a
    relay while the question waits (a pairing, an onboard refresh) is `stale-record`, exit 1, nothing written:
    run unpair again.
  - On y, one line per effect: `untrusted <root>` (trust.json written whole, 0600) or `not trusted <root>`; then
    `not accepted <root>` when no relay's record holds it (nothing is published), or else the newest record is
    re-signed without the root, its `max_bytes` and `ttl` kept, at max(now, its iat + 1), as the edge's `admit`
    re-signs one, and published at every `--relay`: `published accept-from <address> <relay>`,
    `unchanged accept-from <address> <relay> stale-record` (the relay holds a newer record, a pairing's perhaps),
    or `failed accept-from <address> <relay> <code>`. Either of the last two exits 1 with the first one's code,
    after every relay is tried.
  - With no root left the record names only its owner, `[<address>]`, and `last root: the accept-from of
    <address> now names only <address>, its owner` is printed first: the core refuses empty roots (`roots is a
    non-empty list`, `packages/core/src/records.ts`), and the edge's `admit` rolls back to the same `[owner]`. The
    mailbox then admits only envelopes rooted at the identity itself. After such a run, onboard prints
    `kept <owner address>` on each refresh (the held root it keeps). onboard needs at least one typed `--accept`,
    so a cron line whose only typed root is the one unpaired needs another root, the org's own
    `domain:<org host>` for example.
  - A relay down at the publish: trust.json and the relays that answered no longer hold the root; the down relay
    keeps its old record. Run unpair again once it answers: it finds the root there, asks again (naming the
    accept-from only), and publishes the newest record without it at every relay.
  - Limits: the name book is not touched (`name forget` removes the petname). After a `--trust-domain` pairing,
    trust.json holds `domain:<host>` and the accept-from the peer's address: unpair each. A root that onboard's
    cron line types in `--accept` comes back on its next run unless it is dropped there ("Onboarding", above). A
    record published after the second read and before the publish gives an `unchanged ... stale-record` line at
    that relay, exit 1: run unpair again.

### Groups

`group <verb> <name> ...`: the identity `<name>` of this home becomes a group, run by its admin, which is whoever holds
its keys here (`keygen <name>` first); there is no `--as` (`src/commands/group.ts`; the steps are the edge's
`GroupAdmin`). Every verb takes `[--allow-private-relays] [--dir <home>]`, opens the group's edge store and writes its
audit log, `<home>/state/<name>/audit.jsonl`; no line holds a key.

- **`group create <name> --relay <url>... --rotation-key <address> [--root <address>...] [--ttl <s>] [--max-bytes <n>]
  [--retention <s>]`**: generation 1, and the group's address record and accept-from record published at every
  `--relay`. `--relay` and `--rotation-key` are required. The defaults: `--ttl` 3,600 s (the core's `GROUP_RECORD_TTL`),
  `--max-bytes` 65,536 (`MAX_ENVELOPE_BYTES`), `--retention` 604,800 s (`DEFAULT_TTL`). Prints
  `group <address> generation 1`, then `published <kind> <address> iat <iat> <relay>` per relay for each kind,
  `address` then `accept-from`. Only `create` takes `--relay`: the other verbs use the relays in the group's state
  (`--relay` there is `usage`).
- **`group add <name> <member> [--exp <unix seconds|+seconds>] [--relay-hint <url>...]`**: sends the member the
  current generation under a membership hop; `<member>` is an address or a name of the book. `--exp` defaults to now +
  604,800 s (the core's `MEMBERSHIP_SECONDS`); `--relay-hint` names the member's relays. Prints
  `added <member> exp <exp>`, then the send's id and its targets as `send` prints them, failing as `send` fails. Adding
  a member again renews its hop.
- **`group remove <name> <member>`** and **`group rotate <name>`**: a new generation to every remaining member, then
  the record (the edge's `GroupAdmin`), which the CLI also publishes at the
  members' relays that are not the group's. Prints `generation <n> sent <k> record iat <iat>`.
- **`group keep <name> [--every <s>] [--once]`**: re-signs the group's address record at once and publishes it at the
  group's relays and the members' relays, `published address <address> iat <iat> <relay>` per relay; then
  `next <unix seconds>` and again every `--every` seconds, or half the record's ttl (`--every` must be below the ttl:
  `usage`), until SIGINT or SIGTERM. `--once` publishes once and ends.

Not built: `record keep --as <group>` does not refuse a group identity. That refusal is a correction not made, since it re-signs the relay's newest
copy, which a rotation can race and revert; run `group keep` for a group, never `record keep`.

### Looking up and checking

- **`lookup <address|domain:<host>|handle> --as <name> --relay <url>... [--at <url>...] [--allow-private-relays]
  [--dir <home>]`**: where an address's records live. The first line is the identity's cache, `cache <subject> none`
  or `cache <subject> kind=<k> iat=<n> valid_until=<n> source=<url|->`. Then one line per source asked, in the order a
  send asks (the `--at` hints first, then the `--relay` relays), for the address record and then the key record:
  `<source> <found|none|refused|error> kind=<k> [iat=<n>] [valid_until=<n>] [key=<address>] [<detail>]`. For
  `domain:<host>` the lines are its TXT record and its org record at the origin; for a handle, those, its handle
  record, then its address's records. `refused` marks a source the private-relay guard refused. A subject that is none of the three is
  `usage`. It writes no cache entry, pin or audit line (`src/commands/lookup.ts`).
- **`audit verify <file>`**: recomputes an audit log's hash chain and prints `ok <n> lines`, or
  `bad line <n>: <problem>` for the first line edited, removed or reordered. When an `edge.sqlite` sits beside the file
  (as in `<home>/state/<name>/`), it also compares the log with the anchor the store keeps: `truncated: ...` or
  `diverged: ...` in place of the `ok` line, `ahead: ...` after it. It exits 1 on a bad line, `truncated` or
  `diverged`, and fails `ENOENT` for a missing file (`src/commands/audit.ts`).
- **`status --as <name> [--dir <home>]`**: prints first, always, `doorbell <absolute path>`, the identity's doorbell
  (`inbox`, above), a fact before the file exists. Then, when the last `subscribe` line of the identity's
  audit log is the edge's end of a subscription (three permanent refusals in a row, `subscribe reject <code>` with
  `subscription-ended`), a second line, `mailbox refused: <code> at <relay> after <n> refusals; edge errors
  <e>, last <code> at <time>` (`<time>` ISO 8601 UTC); otherwise nothing more. (Note of 2026-10-26 23:00 UTC (00:00
  Madrid on 2026-10-27): before it, status printed nothing in that case; a script that counts
  its lines counts one more.) `<e>` is like the MCP server's `edge_errors`, but counts the
  log's audited subscribe errors, retry and reject lines, three per end, where the MCP server counts one per ended
  subscription. The line names a relay, not a mailbox: an identity's one log holds its own mailbox's subscriptions
  and those of its groups (`inbox --group`), so in e2e scenario 43 carol's own mailbox works while the group's is the
  refused one. The `subscribe retry` and `subscribe reject` lines carry the receiver's `mailbox` in their detail
  (older lines carry none), but `status` reads `relay`, `refusals` and `end`
  only: it prints no mailbox, and a later retry at one mailbox still hides another's end. The edge audits no
  subscription that succeeds, so the line stays after a later `inbox` subscribed, until any later `subscribe retry`
  line, at whichever mailbox, follows it: one refusal or one coded transient error is enough. (Note of 2026-10-28
  02:00 UTC (03:00 Madrid): this paragraph said the lines "carry no mailbox"; they do since
  a later edge change. Naming the mailbox in the line is a code change, not made.)
  A log whose chain, or whose anchor in the `edge.sqlite` beside it (read before the log, so a log read beside a
  running `inbox` is at worst ahead of it), does not verify is `bad-audit`, as `audit verify` reads it. It reads no
  key: the custody checks the name, and the key file `<home>/keys/<name>.json` or the keychain pointer
  `<home>/keychain/<name>.json` must exist (`ENOENT` otherwise); no dialog (`src/commands/status.ts`).
- **`health <relay-url>`**: prints `ok` when the relay answers its health probe with 200, else fails `unhealthy`
  (`src/commands/relay.ts`).

### Telemetry

- **`telemetry on | off | status | preview [--date <YYYY-MM-DD>] | send | forget`**: the machine's telemetry
  (opt-in; `src/commands/telemetry.ts` over the edge's `telemetry.ts` and `telemetry-send.ts`), with one choice and one
  install id per machine in `~/.bag/telemetry.json`, `HOME`'s, whatever `--dir` or `AC_HOME` names; it takes no
  `--dir`. `on` makes the id, or keeps it; `off` removes it, the spool of counts and the sender's mark, with no network
  call. Each, and `status`, prints `telemetry <on|off> reason=<reason> choice=<on|off|none> id=<32 hex|none>
  spool=<bytes> sent=<YYYY-MM-DD|none>`: the install id, which a request to erase the machine's reports names (the
  telemetry design note's §3), and the last day the sender took. `off` then prints `telemetry off: reports already
  sent stay up to 90 days; to erase them, send <id> to privacy@bag.dev` when it removed an id. `preview` prints the
  exact report the machine would send for a UTC date (today, or `--date`, at most 7 days back) as one JSON line on
  stdout, and `telemetry preview: <n> bytes for <date>; sent once, from 01:05 UTC the day after` on stderr. Before
  `on` its id is 32 zeros and it holds no counts. `send` sends the reports that are due and prints nothing; `forget`
  posts the id to `https://telemetry.bag.dev/v1/erase` and, on its 204 only, turns telemetry off and prints the state
  and `telemetry forget: the erasure of <id> was accepted; telemetry off`; any other answer, or none, is
  `unreachable` or `http-<status>`, and nothing changes. Without `HOME`: `usage`.
- **The sender**: while telemetry is on, from 01:05 UTC, the first command line after a day ends starts `node <this
  main.ts> telemetry send` detached, with no stdio, and never waits for it (`io.spawnSender`, `telemetryDue`). It
  sends each finished day's report once, exactly as `preview --date` prints it. `telemetry` itself never starts it.
  The unit tests' io has neither a fetch nor a spawner, so no test sends.
- While telemetry is on, `run` counts each command line into the machine's spool by its verb, its exit and its code,
  and how long it took. The verb is the command, or one of `record-keep`, `peer-invite`, `peer-accept`,
  `keys-rotate`, `host-install-claude-code` and `host-install-codex`, or `help` for any `--help`, or `version` for
  `--version`. The command's edge
  counts its audit lines, relay calls and pairings beside it. The line that turns telemetry on is not counted; the
  count of the line that turns it off goes with the spool.
- The notice: while no choice is made, after a command a person runs at a terminal and after `host install`, once per
  machine, on stderr. It names `npx --yes --package=@usebag/bag@<version> bag telemetry preview` when run from the
  package, the install guide's form, which still works after npm clears its cache, and `node <this main.ts> telemetry
  preview` from source; never `ac telemetry on`, which a guide install does not have (the spec owner's decision).

### Enterprise: connect through your agent

Added 2026-11-07: one public client, as `gh`, `glab` and the HashiCorp CLIs are. The
agent side of a bag enterprise session is in this package, built on `@usebag/enterprise-client`; what an agent may do
is decided by the organisation's instance on the server, not by the client. The commands are `src/commands/connect.ts`,
`sign-in.ts` (sign-in and sign-out), `status.ts` (with no `--as`), `mcp.ts` and `refresher.ts`.

A person gives their agent the prompt the console shows beside a minted connect code. The console fills in the exact
version it pins (the current cut, `@usebag/bag@0.2.3`), never `@latest`:

    1. Register once: claude mcp add bag -- npx -y @usebag/bag@<version> mcp (or run directly: BAG_ORG_CODE=<code> npx -y @usebag/bag@<version> connect)
    2. Paste the code into the chat and ask the agent to connect with the bag tool `connect`.
    3. Then `status` (the tool, or `npx -y @usebag/bag@<version> status`) shows the session: Connected as <label>; relay round trip <n> ms, or waiting for the organisation's signer.
    Without a code: npx -y @usebag/bag@<version> sign-in <domain> --instance <console origin> --no-wait, then the same line again once the person approved.

Without a code, the person gives the domain and the console's address instead, and the agent runs, for example:

    npx -y @usebag/bag@<version> sign-in example.com --instance https://console.example.com --no-wait

Exits, for every command here: 0 done, 1 refused or failed, 2 usage, 3 the session has ended or none exists, 4
waiting on a person of the organisation or its signer. An error is one line on stderr, `bag: <code>: <detail>`.

- **`connect [--as <name>] [--label <text>] [--verbose] [--dir <home>]`**: the console's one-time code, from
  `BAG_ORG_CODE`, else one line of stdin (on a terminal it asks `Paste the code: ` on stderr first). **Never from the
  command line**: an argument that starts with `bag` is `usage: the code is read from stdin or BAG_ORG_CODE, never from
  the command line`; no code is `usage: no code: paste the code from the console, or set BAG_ORG_CODE`. The code names
  the instance and the organisation, so nothing else is typed. Once the organisation approves, the same command proves
  the path a message takes, so nothing else is run before a send: (a) it publishes the agent's address and accept-from
  records at every relay of the organisation; (b) it sends the agent one envelope of type `bag.connect-check` from its
  own session key, through the organisation's first relay and the same send path as `bag send`, and reads it back on
  the agent's own subscription there (acknowledged, so the agent's inbox does not show it). It prints one line:

      Connected as <label>; relay round trip <n> ms

  where `<n>` is the round trip of (b) on a monotonic clock. A step that fails is one line naming it and the relay,
  exit 1; the session stays, and `status` tries again:

      Connected as <label>, but its records were not published at <relay> (<code>): bag status tries again
      Connected as <label>, but the relay round trip failed at <relay> (<code>): bag status tries again

  **The label** is the organisation's: a connect code carries the label its agent is to hold (by default the domain
  with dashes and a number, `example-com-1`, the next free number when that is held), connect sends none unless
  `--label` is given, and `<label>` is the label the grant returns, kept in the session file for `status`. A `--label` a
  live agent of the organisation already holds is refused, exit 1, the code left unused: `bag: label_taken: the label
  <label> is held by a live agent of <domain>: connect again without --label, or with another`.
  Each relay step is bounded at 5 s (code `timeout`). On a home already signed in to another organisation, connect
  adds this one beside it and revokes nothing; the line names both:

      Connected as <label> (<domain>); relay round trip <n> ms; also signed in to <other>: bag status --org <other>
 While the organisation's signer has not signed yet, the line is
  `Waiting for the organisation's signer: run bag status in a minute` (exit 4). `--verbose` adds, before that line,
  `Connecting to <domain> at <origin>`, `Approved: agent <fingerprint, four groups of eight hex>` and one `records
  <kind> <relay> published|failed <code>` line per record and relay; without it no fingerprint, key or address is
  printed.
- **`sign-in <domain> [--instance <origin>] [--as <name>] [--label <text>] [--code] [--no-wait] [--dir <home>]`**: the
  device flow a person approves. It makes the agent's key `<name>` (default: the domain with dashes), its sign-in key
  `<name>.signin` and its session key `<name>.session`, then prints `open <link> and enter the code <user code>`,
  `fingerprint <four groups of eight hex> (the agent's key, as that page shows it)` and `approve only a code you started
  yourself`. `--no-wait` exits 4 at once; the same line run again resumes the same sign-in: exit 4 while still
  waiting, exit 0 with the session lines (as `status`) once approved, exit 1 if refused. `--code` redeems a console
  code from `BAG_ORG_CODE` or stdin, never argv. Without `--instance` the instance is found from
  `BAG_ENTERPRISE_INSTANCES`, the domain's `.well-known/bag/enterprise.json`, then `BAG_ENTERPRISE_URL`.
- **`status [--org <domain>] [--chain | --plist | --crontab] [--dir <home>]`**, with no `--as` (`status --as <name>` is
  the identity's, above): the session of `--org`, else of the only organisation, else of the most recently connected,
  which one line on stderr names with the others (`bag: showing <domain>, the most recently connected; also signed in
  to <others> (--org)`; every organisation is refreshed). One refresh tick, then `signed-in <domain> agent <address> state <state>`, `instance <origin> generation <n>
  refreshed <time>`, `token-until <time> hop-until <time> local-hop-until <time>`, a line for a state that is not live,
  and `chain <path>: bag send --as <name>.session --auth <path> ...`. A live session then gets one probe of the path
  that sends nothing (the agent's address record read back from the organisation's first relay, bounded at 5 s) and
  its line, `Connected as <label>; relay round trip <n> ms` (`<label> (<domain>)` when the home holds several), or `Connected as <label>, but the relay round trip failed
  at <relay> (<code>)` with exit 1. A waiting sign-in prints `waiting <domain>: ...`
  (exit 4); none is `bag: signed-out: not signed in: bag sign-in <domain>` (exit 3). `--chain` prints the chain JSON
  (for an MCP server's `--chain-cmd`). **The hourly refresh job**: `--plist` prints a launchd job, `--crontab` a
  crontab line, each running `status --dir <home>` every hour into `<home>/enterprise/refresh.log`; they write
  nothing, and the person installs the one line (launchd runs a job missed asleep at the next wake; cron does not).
- **`sign-out [--org <domain>] [--dir <home>]`**: ends one organisation's session at its instance (the agent's address is
  revoked for good), then removes that organisation's roots from `trust.json`, its session's files and its sign-in and
  session keys; the identity, its mailbox and every other organisation's session stay. With one organisation `--org` is
  implied; with several it is required, and without it sign-out removes nothing and exits 2 naming them: `bag: usage:
  signed in to <a> and <b>: bag sign-out --org <domain>, one of them`. With only a waiting sign-in, it drops it.
- **`mcp [--dir <home>]`**: a stdio MCP server with three tools and nothing else: `connect` (argument `code`),
  `sign_in` (`domain` and `instance`) and `status`. Register it with
  `claude mcp add bag -- npx -y @usebag/bag@<version> mcp`. Each result holds only the lines the commands print;
  stdout is the transport, so the command prints nothing else. It runs until the host closes it or stdin ends.

The home is `--dir`, else `AC_HOME`, else `~/.bag`, the same home as every other command. Each organisation's session
lives in its own profile, `<home>/orgs/<domain>/enterprise/`; the keys stay in `<home>/keys` and the trust roots in
`<home>/trust.json`, each organisation's tagged with its source. A home from before profiles, its one session's files
directly in `<home>/enterprise/`, is moved into the profile of that session's domain the first time the client reads
it; nothing else changes. `--org <domain>` picks a profile for `status` and
`sign-out`; the MCP `status` tools take an optional `org`. The client holds the home to its owner: the home becomes 0700 and every file it writes there
0600; another user's home is refused. **Nothing printed holds a key, a token or a code**: not on stdout, not on
stderr, not in a tool result (each result is also scrubbed of the code given and its secret part, the device code and
the token).

**The pinned instance.** When a code or `--instance` names the instance, no discovery runs: no TXT record and no
`.well-known` file is read. The origin must be https, or http only on a loopback host (an instance on this machine);
anything else is usage. A non-loopback origin passes the private-address guard before any call, and every call to
the instance refuses a redirect. The scrub, the pin and the guard are `@usebag/enterprise-client`'s; these commands
call them.

**The honest limit.** With the MCP server, the code reaches it as a tool argument, so it sits in the host's
transcript (and wherever that transcript is kept or sent). Its defences are its life (15 minutes by default) and its
single use: once redeemed, the string opens nothing.

## Behind a proxy

In a network where every outbound connection must go through an HTTP proxy, set the proxy in the environment that
runs the CLI, the MCP server (the environment the host, such as Claude Code, starts with) and the bridge:

```sh
export HTTPS_PROXY=http://proxy.example.corp:3128
export HTTP_PROXY=http://proxy.example.corp:3128
export NO_PROXY=localhost,127.0.0.1,.example.corp
```

- **What reads them.** Node's built-in fetch and WebSocket send through the proxy only when `NODE_USE_ENV_PROXY=1`
  is set as the process starts. Each entry point therefore runs itself again once, in the same process (the same pid,
  arguments and stdio), with `NODE_USE_ENV_PROXY=1` when a proxy is set and it is not (the edge's `src/proxy.ts`). The
  relay calls, the subscription WebSocket, record lookups at relays and telemetry then go through the proxy by CONNECT.
  On a platform without `process.execve` (Windows) the CLI prints one line asking you to set `NODE_USE_ENV_PROXY=1`
  yourself.
- **The names.** Each name is read in either case, the lowercase one first. `HTTPS_PROXY` is for `https:` and `wss:`
  relays, `HTTP_PROXY` for `http:` and `ws:` ones. A proxy that needs a user and password takes them in its URL
  (`http://user:password@proxy:3128`, Basic). A proxy that needs NTLM or Kerberos needs a local forwarding proxy that
  speaks it.
- **NO_PROXY** is read as Node reads it: `*` for every host; a name or an address for itself only; `.example.corp` or
  `*.example.corp` for its subdomains, not the name itself; `name:port` for that port only. Entries are split by
  commas or spaces.
- **An org's well-known record** (an address on its own domain) is fetched with node:https, which the variable does not
  reach, so the edge tunnels that one request itself. It asks the proxy for a CONNECT to the address the private-address
  guard checked, never to the name, and keeps the TLS name the host's, so the guard's pinning holds. Many proxies
  refuse a CONNECT to a bare address; then that lookup fails, `resolve-failed: the proxy http://proxy:3128 refused
  CONNECT to <address>:443: 403`, and never falls back to the name.
- **A proxy that inspects TLS** presents its own certificates. Give Node the company's root certificate, as a PEM file,
  with `export NODE_EXTRA_CA_CERTS=/path/to/company-root.pem`. Never turn certificate checks off
  (`NODE_TLS_REJECT_UNAUTHORIZED=0`): it would let anyone on the path read and change what the client sends and gets.
- **What shows it.** `status` prints `network proxy https=<scheme://host:port|none> http=<...> no_proxy=<list|none>
  active=<yes|no: set NODE_USE_ENV_PROXY=1>` when a proxy is set. The MCP server's `status` tool has `network`, and
  its log a `network` line at start. Each names the proxy's scheme, host and port, never its user or password.
  NO_PROXY's list appears as written, and it may name internal domains. It stays on the machine, unless the host's MCP
  log is sent elsewhere.
- **A proxy that cuts long WebSockets.** The subscription reconnects with the edge's backoff and resumes from the ack
  the relay stores. There is no polling fallback yet: the relay has no route that lists a mailbox.

## Errors

An error exits 1 with one line on stderr, `bag: <code>: <detail>` (`src/cli.ts`, `run`). The code is, in this
order (`codeOf`): the code of the core's or the CLI's error; a relay error's own code, or `unreachable` when the relay
did not answer, or `http-<status>`; a system errno such as `ENOENT` or `EEXIST`; else `error`.

- **The CLI's own codes**: `usage`, `unhealthy` (`health`), `no-tty` and `declined` (`release`, `drop`, `peer`,
  `unpair`),
  `rotation` (`record keep`), `bad-name`, `name-exists`, `name-unknown` and `names-invalid` (the name book),
  `not-for` (`peer accept --for`),
  `trust-invalid` (the trust file), `accept-held` and `too-many-roots` (`onboard`), `accept-all` and `not-trusted`
  (`unpair`), `bad-audit` (`status`),
  `no-held-record` (a swept identity that published from this home and has no readable copy of its address record:
  `record keep`, `keys rotate`, `onboard`, `ac login`),
  `host-file-invalid` (`host install`: a host file that is
  not a JSON object, a key under it, such as `mcpServers` or `hooks`, that is not an object, or a `hooks.<event>` that
  is not a list), `exists` (`host install`: a `bag` entry in `.mcp.json`, or a `[mcp_servers.bag]`
  table in Codex's `config.toml`, already there with other settings; with `--identities`, an identity there with other
  settings), `identities-invalid`, `home-shared`, `identities-in-project`, `unknown-identity` and `last-identity` (the
  identities file, `host install` and `host remove`), `no-identity` (`wake-hook --identities`).
- **The codes the usage text names**: `unknown-caveat` (inbox), `resolve-failed` (a handle's failed step, or the
  private-relay guard), `revoked` (a handle), `name-unknown`, `policy-refused` (`send --members`), `no-tty` (`release`,
  `drop`).
- **Exit 2, not 1**: a `--policy` or `--members` file that cannot be read, a members file that is not a regular file
  with no group or other permissions (`bad-mode`; a symlink is not followed), a record that does not verify (the
  core's code), or the two records signed by two roots (`bad-record`). The line is
  `bag: <code>: --policy|--members <file>: <detail>` (`src/policy.ts`, `PolicyFileError`).
- **Not an error line**: `audit verify` prints its finding on stdout and exits 1; `lookup` exits 0 whatever it finds.

## The private-relay guard

The edge refuses a relay URL on a private, loopback or link-local address that is not the edge's own
(`packages/edge/README.md`, "Guard"). In the CLI:

- **`send` and `held`**: a recipient relay on such an address other than `--relay` is refused `resolve-failed` unless
  `--allow-private-relays` is given (`src/commands/send.ts`; `held` opens the same sender).
- **`lookup`**: a private relay that is not a `--relay` prints `refused` unless the flag is given
  (`src/commands/lookup.ts`).
- **`inbox`**: takes the flag; without `--group` its receive path calls only `--relay`, which the guard always
  allows; with `--group` it also reads the group's mailbox at the relay the group's record names.
- **`group`**: every verb takes the flag.
- **`record keep`, `publish`, `health` and `peer`** take no such flag.

Leave it off unless several relays share a LAN or a tailnet.

## The scripts that call it

- **`deploy/make-org-records.sh <label> [<relay URL>] [--ttl <seconds>] [--key <name>] [--rotated-from <name>]
  [--rotation-key <address>] [--revoke <address>]...`**, with `AC_HOME` the org keys' home: runs `address <key>`, and
  `keygen <key>` when the key does not exist, then `record address <key> --relay <url> --sealing-key --ttl <ttl> --out
  deploy/well-known/public/<label>/.well-known/bag/address.json`, adding `--rotated-from`, `--rotation-key` and
  each `--revoke` it was given. It calls the CLI as `node --disable-warning=ExperimentalWarning
  packages/cli/src/main.ts`.
- **`deploy/resign-org-records.sh [--home <dir>] [--log-dir <dir>] [--keychain-service <name>]
  [--allow-shared-checkout] [--dry-run]`**: re-signs both org records and every handle record beside them and deploys
  the well-known Worker. It runs `address org-<org>` as a guard (the key must exist and match the served record) and
  again after signing, and calls the two scripts here. The Cloudflare token: a `CLOUDFLARE_API_TOKEN` already in the
  environment wins; when it is unset or empty, the script reads it from the login Keychain item of service
  `bag-cloudflare-resign` (or `--keychain-service <name>`) and account the current user, with
  `security find-generic-password -w`, into that variable. It never traces or prints the value, drops `security`'s
  stderr, logs only the source (`guard token-source keychain` or `guard token-source environment`) or
  `fail guard CLOUDFLARE_API_TOKEN keychain read failed (exit <n>)`, and still refuses the `REPLACE_WITH_`
  placeholder. `CLOUDFLARE_ACCOUNT_ID` comes from the environment; the LaunchAgent plist
  (`deploy/launchd/com.bag.resign-org-records.plist`) sets it and carries no token key (the script's header,
  lines 7 to 25).
- **`deploy/make-handle-record.sh <label> <local> <address> [--ttl <seconds>] [--key <name>]`** does not run the CLI:
  it reads the org key through the edge's `HomeCustody`, as the CLI reads it, and signs with the core's
  `signHandleRecord`.

## CLI only

Release and drop of quarantined rows and held sends exist only in the CLI behind a terminal confirmation; no MCP tool
releases, drops, pairs, edits policy, adds or removes a trust root or writes the name book (`packages/mcp/README.md`,
"The delegate tool"). In the CLI that is: `inbox release|drop`, `held release|drop`,
`peer invite|accept` (which write `names.json` and `trust.json`), `unpair` (which writes `trust.json`),
`name add|forget`, and `group create|add|remove|rotate|keep`: the usage text says the group commands are "CLI
only", and no MCP tool creates, adds, removes or rotates a group. Only
`release`, `drop`, `peer` and `unpair` ask at a terminal; `group` and `name` run without one. The terminal check reads
stdin only (`src/policy.ts`, `needTty`): it keeps scripts and tool calls out, not an agent that drives a
pseudo-terminal.

## Not built

- **The group refusal in `record keep`** (above, "Groups").
- **`peer list`, `peer forget`** and other pairing grants: `peer` takes `invite` and `accept` only.
- **A session receiving at its principal's mailbox**: `inbox` takes no `--auth`.

## Where the usage text is behind its commands

- `keys list`: the usage text says `<created>` is Unix seconds; `src/commands/keys.ts` prints an ISO 8601 instant.
- `inbox --honor`: the usage text shows `[--honor coding]`; the option repeats, and `coding` is its one profile.
- `publish`: the usage text omits the line it prints, `ok <kind> <signer>`.
- `audit verify`: the usage text omits the anchor's `truncated`, `diverged` and `ahead`.
- `group` and `inbox --group`: the usage text gives the flags and one line of purpose, none of the printed lines.
- Its last line says errors exit 1; a policy file's exit 2 is named only in the `inbox` entry.

## Tests

`npm test -w packages/cli` (Vitest with coverage, `package.json`). The tests inject their own io (`src/io.ts`), which runs no
`/usr/bin/security`, so no test reaches a real keychain unless it passes a runner.

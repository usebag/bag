# Changelog

What changed in each published cut of bag, newest first, written for someone who installs it. Each published
cut adds one dated entry at the top, written from the entries of the project's change log (one entry per change, kept in
the source repository) made since the cut before it.

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
  (`spec/SPEC.md` §2.4, §8.10), pair/open takes 1 to 64 relays, a nameplate's `ttl` is required, 1 to 600 seconds
  (Appendix B, item 89), and §7.2 states the relay URL form once, as every record reader checks it.
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
  other, through a rendezvous relay (`spec/SPEC.md` §8.10).
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
- **Pairing and resolving follow three new rules** (`spec/SPEC.md` §8.10 and §9 item 4). A pairing binds to the peer's
  address when it is known (`--for` on the terminal, an address field in the MCP dialogs), and the open invitation is
  for first contact only. A frame that is not a well-formed request no longer ends a pairing or counts against its
  tries, and `leaked` now means a second good request from another requester. The resolver keeps the record with the
  greatest `iat` across the relays that answered, so a lagging relay cannot serve an older epoch key or revoked list,
  and a relay that does not answer never blocks a read. The spec also states the relay limits above (§8.2 to §8.4,
  §8.9).
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
  cursor, and resumes each subscription with cursor null (`spec/SPEC.md` §9, items 2 and 10). An edge's inbox store
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

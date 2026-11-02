# Changelog

What changed in each published cut of bag, newest first, written for someone who installs it. Each published
cut adds one dated entry at the top, written from the entries of the project's change log (one entry per change, kept in
the source repository) made since the cut before it.

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

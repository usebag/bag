# bag threat model

*Prepared for an outside security reviewer. Draft, 2026-10-29. Grounded against the final launch assembly
of 2026-10-29. Every security claim below carries a citation to the spec (`spec/SPEC.md §`) or to
code (`path:line`); where a claim is weaker than it first reads, or where this document could not verify it against the
code, that is said in place rather than asserted.*

This document is the protocol's security model and its residuals. The companion `docs/audit/stream-10-review.md`
records the two adversarial review rounds, the findings and their dispositions, and what is built versus deferred.

---

## 1. What bag is, and the layers this model covers

bag is an asynchronous, store-and-forward messaging protocol for agents and the people who run them. A sender
seals content to one or more recipients and publishes the sealed bytes to the recipients' relays; a recipient fetches
or subscribes and opens. Relays are dumb: they carry no semantics and only enforce the policy a mailbox owner signed
(`spec/SPEC.md §8`, intro). The wire format, sealing, the authority chain and the records are the **frozen core**
(`§2`-`§9`). Two sections sit outside that core and an implementation conforms without them: naming/handles/discovery
(`§12`, L2) and **the agent seat** (`§13`), a local socket between an agent process and one user's sessions; nothing in
`§13` is sent on the wire (`§13` preamble, `§13.0`).

The reference implementations this model is grounded on: the TypeScript core and edge (`packages/core`,
`packages/edge`) and the Rust reference relay (`crates/ac-relay`).

### Assets
- Private keys (signing, sealing/epoch, group generation, rotation). Never logged, never in argument lists, env vars or
  audit detail; held to the key store only (`spec/SPEC.md §3.3`, `§10` "Keys and logs").
- Message confidentiality and integrity.
- Mailbox policy (who a mailbox accepts mail from).
- The local trust anchors a person types (`--accept`, `--trust-root`, a pairing `y`).

### Principal adversaries
- A malicious or compromised relay (and the network between sender and relay).
- A compromised web host or certificate authority for a domain used as a root.
- A party on a reader's DNS path.
- A local process of the same uid as the agent (the agent seat's floor, `§13.1`).
- A sender that is a listed recipient of a multi-recipient envelope (`§4.3`, `§10` "Binding").

---

## 2. Identity, keys and records

**Two separate keys per identity.** A signing key is an Ed25519 private key (RFC 8032); a sealing key is an X25519
private key (RFC 7748); v0 key generation makes both from independent CSPRNG draws and they are never shared
(`spec/SPEC.md §3.3`). An address is `ed25519:` + 64 lowercase hex of the public signing key and nothing
else (`§3.2`).

**Three record kinds** carry an identity's current facts, each a signed JSON object whose `sig` is over its own
preimage digest (`§7.1`):
- **address record** (`§7.2`): relays, revocation list, rotation key, TTL (1 s to 86,400 s); valid `iat - skew` to
  `iat + ttl`, so it is unusable more than a day after `iat` and an org re-signs daily.
- **key record** (`§7.4`): binds a key to its current sealing key until `exp`, at most `iat + 86,400`. This is the
  forward-secrecy epoch key (section 3 below).
- **accept-from record** (`§7.4`): the mailbox policy; `roots` (addresses and/or `domain:` roots, or exactly `["*"]`).
  Does not expire; a newer `iat` replaces it.

**Pinning at first contact.** An edge caches an org/domain record no longer than its TTL and pins its key at first
contact (`§7.2`; `§9`). A record whose `key` differs from a pinned key is accepted only as a countersigned rotation:
`next.rotated_from` is the pinned key and `next.rotation_sig` verifies under the pinned key or its `rotation_key`
(`§7.3`). The rotation check is structural; `next` is independently verified under `§7.5` first. So a compromised web
host cannot silently swap a pinned peer's root (`§7.3`, last sentence; `§10` "Domain roots: the trust assumption"). The
relay performs the same claim-only check at publish for a signer it holds no record of
(`crates/ac-relay/src/policy.rs:401`-`412`, `verify_rotation` / `verify_rotation_claim`).

**Revocation lives at most a day and is bounded in time.** A root revokes principal/session keys in its address
record's `revoked` list; an entry is kept until its hop's `exp + TTL + skew` (the last second mail under that hop still
passes the stale-ts check), so a late-verifying recipient still finds the entry, and the list stays bounded
(`§7.2`, `§10` "Revocation after expiry"). Because the address record expires in a day, an old record with a shorter
revocation list cannot be replayed afterward (`§10` "Replay").

**Rotation recovery.** A rotation key kept offline lets an org recover a lost root by publishing a new record
countersigned by the rotation key, at a relay that never held the old one (`§7.3`, `§10` "Root compromise").

---

## 3. Forward secrecy for individuals

**Claim.** An individual's content is sealed only to a short-lived epoch key, never to a long-lived key, and the
recipient deletes the old epoch private key after a bounded horizon, so a stolen sealing key reads no mail older than
that horizon.

**Grounding.**
- An individual's address record carries `sealing_key: null`; the long-lived address sealing key is forbidden for an
  individual, and the individual publishes a key record instead (`spec/SPEC.md §7.2` sealing_key row; `§4.3` step 3;
  `§7.4` key record).
- The sender seals the content key to the recipient's **current key record** sealing key, not the address record's
  (`§4.3` step 3, last sentence). The resolver prefers the key record and uses the address record's sealing key only
  when it is non-null (`packages/edge/src/resolver.ts:385`-`426`, `recipient()` and `toAddressKey()`). For a born-FS
  identity the address sealing key is null, so no address-key path exists and a withheld key record simply fails
  resolution rather than downgrading (`resolver.ts:389`-`390` comment and the `toAddressKey()` null return).
- The epoch key MUST be fresh CSPRNG output, independent of the signing seed; a derived epoch key would let a stolen
  signing seed re-derive it (`§7.4`, "MUST be fresh CSPRNG output ... never derived from the signing seed").
- The recipient rotates the epoch key and deletes the old private key after the **deletion horizon**
  `exp + TTL + skew` (TTL the `§8` envelope TTL, default 604,800 s) (`§7.4` last paragraph; `§10` "Forward secrecy").

**Bound, stated honestly.** The forward-secrecy horizon is about the key lifetime plus retention. This is **inherent to
asynchronous delivery**, where a sender seals before the recipient is reached; MLS carries the same
retention-plus-key-lifetime bound (`§10` "Forward secrecy"). One-time per-message prekeys, which would tighten the
horizon toward a single message, are a **deferred tier** (`§10`; see review, built-vs-deferred).

**Residual (a transition downgrade), carried P2.** An identity that migrated from pre-FS to FS signed a legacy address
record with a non-null sealing key, valid up to its TTL (<= 24 h). In that window a malicious relay that serves that
still-valid legacy record while withholding the new key record can downgrade a **first-contact** sender to the
long-lived address sealing key; the record is genuinely signed, so it is not rejected
(before the mitigation, `toAddressKey()` returned the non-null address key as a fallback with no "is this identity known-FS?"
check). Bounds: transition-only, <= 24 h, confidentiality-only (the recipient still opens the mail), born-FS
identities immune, and it needs a malicious relay controlling all of the victim's relays. Disposition: **mitigation
landed** (merged 2026-10-29): the resolver now refuses the non-null address-key fallback for an identity it has
seen resolve a key record (a durable `fs_known` ratchet, `resolver.ts` `recipient()`/`#keep`), failing `resolve-failed`
rather than downgrading. What remains after it: a genuine **first-contact** sender that has never once seen the
identity use a key record is still exposed within the <= 24 h window; born-FS and repeat-contact senders are immune.
Test: `packages/edge/test/d52-resolver-known-fs.test.ts`. See review section 2.2.

---

## 4. Forward secrecy for groups

Groups do not use per-epoch key records; their forward secrecy is **generation rotation**.

- A group's generation is its n-th X25519 sealing key, the current one published as the group's `sealing_key`; a
  generation change is not a key rotation. Generation 1 is a fresh CSPRNG draw, not
  the identity sealing key.
- A removed member is listed in the group record's `revoked` (kept per the `§7.2` rule) and is **cut at the next
  generation**: until the admin rotates the generation, a removed member keeps reading the generation it already holds
  This is the group analogue of the async FS bound; it is not immediate revocation of
  read access to already-distributed generations.
- The admin re-signs the group record at half its TTL from its own state, never from a relay's copy, so a rotation is
  never re-signed back to an older generation.

**Durable custody of a generation key.** A member keeps an opened generation key at rest under the KEYS tree
(`<home>/keys/groups/<name>/<group hex>/g<n>.key`), 0600 in a 0700 dir, **written once**, decoupled from the member's
short-lived epoch sealing key so the member can open a generation it accepted after that epoch key is deleted
(`packages/edge/src/custody/groups.ts:22`-`28`, `:152`-`164`). The sealed body (`g<n>.json`) holds no private key
(`groups.ts:18`-`20`). The key lives inside `keys/` so the secret scans that read the rest of the home never see it
(`groups.ts:24`-`26`). Only the generation's public key appears in the agent's audit; the `rotate` audit line carries
`sealing_key` as the public key, never the private one (`spec/SPEC.md §13.11` rotate row). Group forward secrecy is
therefore unweakened by the agent seat.

---

## 5. Sealing, binding and multi-recipient integrity

Sealing is HPKE RFC 9180 base mode with suite 1 (DHKEM X25519 / HKDF-SHA256 / AES-256-GCM); a small-order X25519 public
key aborts the KEM (`spec/SPEC.md §4.1`). One content key per envelope is drawn fresh from a CSPRNG and sealed once per
recipient; the content AAD binds the ciphertext to `[v, to, from]` and each wrap's AAD binds it to its recipient
(`§4.3`). The id commits to every outer member and, through the sealed hash, to every wrap and the ciphertext; the
signature commits to the id. So a relay cannot add, drop or reorder recipients, move a wrap, strip or append a caveat,
extend an expiry, change `ts` or re-attribute an envelope without breaking the id or a signature (`§10` "Binding").

**Honest limit (no key commitment).** Suite 1 has no key commitment. "One content key for every recipient" holds only
for an honest sender: a sender can give a listed recipient a wrap that does not open, or opens to another key, and no
other recipient can tell (`§4.3`, `§10` "Binding"). The strict JSON of the content (at least 114 bytes, `§5.2`) stands
in for a commitment; a profile whose plaintext is not JSON would need a real one (`§4.3`, `§10`).

**Malleability.** Ed25519 is verified strictly, cofactorless, with small-order and non-canonical `A`/`R` refused and
`S >= L` refused before any library sees them; the id excludes `sig`, so a malleated signature neither verifies nor
moves an id (`§2.3`, `§10` "Malleability"; 45 vector cases pin the strict refusals, `§11`).

**Metadata a relay sees** (`§10` "Metadata"): `v`, `id`, `to`, `from`, `auth` (every hop's keys, caveats, expiry),
`suite`, `ts`, sizes, timing and the client IP. Never `type`, `thread` or `body`. Hiding `from` and sealing the caveats
are left to later suites; this is a stated limitation, not a defect.

---

## 6. The agent seat (local, §13)

The agent is a long-lived local process that holds a principal's keys for an `ac login` **window** of at most 8 hours
and answers sessions over `<home>/agent.sock` (`spec/SPEC.md §13.0`; window cap `Appendix B 77`). A session holds its
own short-lived signing key and no principal key. What the seat buys for an identity in `agent` custody: the
principal's sealing key never enters a session's process or files, a copied session key opens nothing off the machine,
every opening is audited, and `ac logout` ends every session's use (`§13.0`).

**The floor is a uid, not a session.** The socket is created 0600 in a 0700 directory, so only the agent's uid can
connect; the agent does not read SO_PEERCRED (Node does not expose it) (`§13.1` "The peer check"). The residual is
stated plainly in the spec: every process of the same uid, and root, can connect, and a session key file and chain are
readable by every process of that uid, so **"session isolation" MUST NOT be claimed** (`§13.0` "What the agent seat
does not buy"; `§13.1`). A principal in **file** custody gets none of the seat's gains: the same uid reads the key
files directly (`§10` "What a session reads").

**What a session may send vs. read.** A session request is signed by the session key over the fixed preimage
`["ac/agent/1", nonce, seq, session, op, argsHash]` (`§13.1`). The connection nonce (32 random bytes) and the rising
`seq` make a captured request un-replayable; a `bad-sig` frame does not advance `seq`, so a forged frame cannot burn
the sequence (`§13.1` "The seq high-water"). The agent judges the chain at **its own clock** (never the session's,
never a relay's), and the chain's held-key hop must be one this agent signed in the current window (the **grant-set**),
which is what makes `ac logout` end every session's use (`§13.2`).

**The read rule** (`§13.8`). On `open`, the agent parses and verifies the envelope, judges the chain at its clock,
opens in its own memory, and releases content to a session only for (a) a thread the session registered or (b) a root
message whose every effective caveat holds. A read admitted by neither returns exactly `not-in-grant`, with the precise
reason kept only in the audit, so the socket does not leak whether the envelope is a root (`§13.8`).

**The one named exception.** The uid-only `group-key` op opens a wrap addressed to the principal outside the read rule,
gated to the sealed type `group-key.v1` before the body is used, releasing only `{group, generation, body}`; two
residuals inside the uid floor are disclosed (a one-bit `type-not-accepted` side channel; no rate cap on the
principal's `group-key` frames) (`§13.1` "group-key").

**Logout and the back-dating gap.** The window end (timer, SIGINT/SIGHUP/SIGTERM, or process death) re-signs the
address record to revoke grants still live and zeroes the held key; an explicit `ac logout` additionally revokes every
subject the agent granted this window whose `exp + TTL + skew >= now` (`§13.3`). The residual, stated in the spec: a
window that ends **without** a later `ac logout` leaves its just-expired hops unrevoked for about 7 days
(`exp + TTL + skew`), and a stolen session key (readable by the same uid) can back-date mail over that span; on a
device the person's `ac record address --revoke <D>` closes it (`§13.3`; `§10` "The agent's custody and its limit").

**Hash-chained audit.** The agent keeps a hash-chained JSONL log in the `§9` item 8 format, each line
`{seq, prev, ts, event, decision, reason, id, from, root, detail, hash}` with `prev` the previous line's hash (64 zeros
first); no line holds key material and `detail` never names the sealed type or a thread id (`§13.11`). An agreement
check ties the agent's `open accept` ids to the session's own receive path (`§13.11` "Agreement check").

**Many sessions behind a front desk** (`§13.11` "Many sessions on one principal"). When several sessions of one
principal run behind the MCP-server front desk, the desk admits a root to one session at a time. It is **routing above
the seat, not a read boundary**: `§13.8` (b) still releases every root to every session whose caveats hold, so each
equal-caveat session still receives each root in plaintext
(`packages/edge/src/agent/front-desk.ts:26`-`33`). The "at most once to a model" property is enforced by writing and
`fsync`-ing the ledger line before the edge accepts/acks the root (`front-desk.ts:35`-`44`, `:92`, `:265`); the
measured-not-guaranteed target is **0 duplicate answers** among sessions running the wrapper
(`front-desk.ts:44`). See residuals.

---

## 7. The public relay

The reference relay is `crates/ac-relay` (Rust). It makes no network call for a plain publish, stores nothing for an
envelope with no hosted recipient, applies the owner's roots and size limit before storing, and limits rates per
sender, root and IP (`spec/SPEC.md §10` "Denial of service").

**The network front (trusted proxy and client IP).** With `--trust-proxy <cidr>` and `--client-ip-header`, a request
whose TCP peer is a trusted proxy has its client taken as the **right-most** header address that is **not** a trusted
proxy's; a non-address value voids the header and the request becomes the proxy's own (fail-safe), and a peer outside
every trusted network is its own client whatever it sends (`§8.9` item 1;
`crates/ac-relay/src/net.rs:194`-`209`, `Front::client`, reads the values with `.rev()` and skips trusted addresses).
This is what stops a client choosing the IP it is rate-limited as.

**Abuse controls**:
- **Operator blocklist**, `--blocklist <file>`: `ed25519:` addresses and `domain:` roots, reloaded when the file's
  mtime/size/inode changes (no restart), a bad file keeps the last good list and logs `blocklist-invalid`, edited by
  `ac-relay block` with a temp-file rename so the relay never reads half a file
  (`crates/ac-relay/src/abuse.rs:1`-`6`, `:36`-`80`, `:99`-`121`). Enforcement: 403 `not-authorized` for a listed
  `from`, root, hop key or record signer, or the pinned key of a listed domain
  (`crates/ac-relay/src/policy.rs:308`-`318`, `:502`-`515` `refuse_blocked`).
- **Per-sender-domain daily quota**, `--domain-publishes-per-day`: envelopes per UTC day from the domain whose current
  key is the chain's root; 429 `rate-limited` to the next 00:00 UTC. Code default **10,000 a day** (the `main.rs`
  clap default and `crates/ac-relay/src/config.rs:133`), with an explicit `--domain-publishes-per-day 0` turning it off
  (`ratelimit.rs:141`-`150`); the Fly deploy sets the same 10,000 (the relay's Fly deploy config,
  `--domain-publishes-per-day 10000`). Per-`from` (120/min) and per-root (1,200/min) and
  per-IP (600/min) limits are always on (`config.rs:129`-`131`).
- **Abuse contact**, `GET /v0/abuse`: `{"contact": ...}` or 404 when unset (`crates/ac-relay/src/http.rs:52`, `:172`-
  `:176`). At the launch assembly the Fly config carries a placeholder `mailto:abuse@example.invalid`, with the real contact
  to land before the first deploy (the relay's Fly deploy config `--abuse-contact`, and step 0 of the relay's operator
  runbook).

**SSRF guard on domain roots.** A `domain:` root could aim the relay at the owner's own network. The relay fetches only
a fixed well-known path, GET, over HTTPS, following no redirect, refusing a host any of whose addresses is not public
and connecting only to the addresses it checked, and an IP literal is not a domain root at all
(`spec/SPEC.md §8.8` item 2, `§7.4`; `§10` "Domain roots: the private-address guard"). One publish fetches at most 8
domains, capping an amplifier that an accept-from record naming 1,024 roots would otherwise create (`§10` "Denial of
service"; `§8.8` item 4).

**Delivery-side private-relay guard (edge).** A recipient names its own relays, so a recipient-named private relay
could aim a sender's delivery at the sender's network. The edge's `RelayGuard` refuses a relay URL whose host resolves
to any non-public address (unless it is one of the edge's own relays or `allowPrivate` is set)
(`packages/edge/src/net.ts:6`-`13`, `:135`-`209`). In the send path the guard check runs **before both** the
record-leave and the envelope publish: `guardRefusal` is awaited first, and only a `null` refusal proceeds to
`#leave()` and `relay.publish()` (`packages/edge/src/sender.ts:334`-`341`). The record-read path in the resolver is
guarded the same way (`packages/edge/src/resolver.ts:443`-`450`).

**Fly deploy**: one Machine (`--ha=false`, one SQLite file on one
volume, in-memory counters, auto-stop off), `--trust-proxy 172.16.0.0/12` with `--client-ip-header fly-client-ip`,
`force_https`, SIGTERM drain. The relay keeps no credential and no file in the relay's deploy directory holds a secret
(the Fly deploy config header; the runbook intro).

---

## 8. Pairing and recovery

**Pairing (`peer` grant).** One side invites with a one-time identity and secret; the requester sends one request under
the invite secret; six digits are compared out of band; then each side admits the other in its accept-from. Under FS the
request carries the requester's current key record, the invite code and the HMAC bind its **sealing key**, and the
inviter shares that key into the address record while the side's own address record is kept with a null sealing key
(no write-back) (`packages/edge/src/pairing.ts:6`-`14`, `:42`-`50`). The MAC is compared in constant time
(`pairing.ts:1` `timingSafeEqual`). Trust is pinned to the identity (written to accept-from), so pairing survives epoch
rotations and a malicious relay cannot MITM a paired peer (review section 3).

**Pairing inside Claude Code (elicitation, 2026-10-29).** The same `invitePeer`/`acceptPeer` edge ceremony can now be
driven from inside Claude Code through the MCP server's `pair_invite`/`pair_accept` tools, which raise the invite string,
the six-digit comparison and the `sent`/accept step as MCP **elicitation** dialogs instead of a terminal paste of
`peer accept`. The wire protocol and the six-digit SAS are unchanged. The invariant kept is that the model cannot answer
an elicitation (the client renders the dialog, and `claude -p` cancels it and runs no hook), so completion still needs a
person's keystroke -- except against a hostile folder/user `Elicitation` hook (R17), which is same-uid code bounded by
R5 and §6. The secret S reaches neither side's model: the acceptor pastes it into a dialog, never a tool argument, and
no result, progress notification or `pair` audit line carries S, the six digits or a key. The `pair` audit event is
`spec/SPEC.md §13.11`.

**Recovery (the sheet, the ceremony).** `ac init` prints a one-time sheet (two seeds under FS: the signing seed and the
rotation seed, no sealing seed, since mail is sealed to short-lived epoch keys that never leave the device), a primary
relay line, and an 8-hex checksum; `ac restore` reads it back with **echo off** on a TTY
(`packages/edge/src/custody/recovery.ts:16`-`29`, `:60`-`97`; `packages/cli/src/commands/init.ts:150`-`151`). The
relay line is **inside** the sheet checksum (`recovery.ts:60`-`61`). A restore recovers the identity, not past mail, and
starts a fresh epoch (`recovery.ts:22`-`27`; `init.ts:286`). Two safety invariants:
- A record that revokes the address stops the restore; nothing here undoes a revocation (`init.ts:178`-`184`).
- Because a restore cannot prove it holds the newest record (a relay it cannot reach may hold a newer one of the same
  keys, revoking a device), it **confirms before any republish**, warning that publishing may un-revoke a key
  (`init.ts:198`-`208`).

---

## 9. Residuals (stated honestly)

| # | Residual | Bound / why it is accepted | Grounding |
|---|---|---|---|
| R1 | **Root compromise is unsolved**, for everyone. | Bounded by short-lived principal and session keys, day-long revocation in address records, and countersigned rotation against pinned keys; an offline rotation key recovers a lost root. | `spec/SPEC.md §10` "Root compromise"; `§7.3` |
| R2 | **Forward-secrecy horizon** ~= key lifetime + retention. | Inherent to async delivery (sender seals before recipient is reached); MLS shares the bound; per-message prekeys deferred. A relay run with a `--ttl` longer than the recipient's assumed retention does not lengthen the confidentiality horizon (the recipient has deleted the epoch key) -- such late mail is simply undeliverable (ops gap 6). | `§10` "Forward secrecy"; `§7.4` |
| R3 | **Transition downgrade (P2) -- mitigated (2026-10-29).** A pre-FS -> FS identity's still-valid legacy non-null address record could downgrade a first-contact sender to the long-lived sealing key. The resolver now refuses the address-key fallback for any identity it has seen use a key record (`fs_known` ratchet); only a sender that has never seen this identity's key record is still exposed, within the <= 24 h window. | Transition-only, <= 24 h, confidentiality-only, born-FS and repeat-contact immune, needs a malicious relay over all the victim's relays (at a single-relay deployment this reduces to one Fly-account compromise). Remainder accepted for a born-FS launch (2026-10-29). | `packages/edge/src/resolver.ts` (`recipient`/`#keep`); `packages/edge/test/d52-resolver-known-fs.test.ts` |
| R4 | **Group removal is cut at the next generation**, not immediately. | A removed member keeps the generation it already holds until the admin rotates; the group analogue of the async FS bound. | the group rotation bound in section 4 above |
| R5 | **The agent seat is no session isolation.** Same-uid processes and root can connect; session key files and chains are readable by the uid. | Stated as a floor, not a boundary; "session isolation" MUST NOT be claimed; file custody gets none of the gains. | `§13.0`, `§13.1`; `§10` "What a session reads" |
| R6 | **Back-dating after an un-logged-out window.** Just-expired hops stay unrevoked ~7 days; a stolen same-uid session key can back-date mail. | `ac logout` closes it; on a device `ac record address --revoke` does; otherwise the exposure is that span, not the hop's `exp`. | `§13.3`; `§10` |
| R7 | **"0 duplicate answers" is a measured target, not a guarantee.** The front desk is routing, not a read boundary; every equal-caveat session still receives each root. | At-most-once is enforced by ledger-before-ack; the number is measured, not proven. | `packages/edge/src/agent/front-desk.ts:26`-`44` |
| R8 | **Group-key equivocation.** A group admin (or any org key holder) could sign two bindings and show each to different askers; only a records log would show it. | The same shape as DKIM-key or handle equivocation; bounded by org rotation and revocation. | `§10` "Handles" |
| R9 | **Metadata to relays** (`to`, `from`, caveats, `ts`, sizes, timing, IP). | Hiding `from` and sealing caveats are left to later suites. A relay's volume snapshots (the Fly volume keeps retention 5, scheduled) retain this metadata past the TTL; they hold no private keys, so they do not extend R2's confidentiality horizon (S2). | `§10` "Metadata" |
| R10 | **DNS discovery is a hint, not an authority.** TXT is read without DNSSEC. | A pin never moves by DNS; a forged/stripped TXT can only fail or weaken a first-contact check, never forge an identity. | `§10` "Discovery by DNS" |
| R11 | **Domain-block reliability depends on resolution.** A `domain:` blocklist entry is bypassed when the relay has never pinned that domain and recipients admit the root by address or `*`. | Recommend operators also list the key; blocking by domain is reliable only after the relay has resolved the domain. | `crates/ac-relay/src/policy.rs:502`-`515`, `:308`-`318` (see review R1) |
| R12 | **Fixed-window rate limits allow a boundary burst.** Up to ~2x a window's worth across a window boundary. | Inherent to fixed windows; counters are in memory and reset on restart. | `crates/ac-relay/src/ratelimit.rs:90`-`102`, `:141`-`150`; `§10` "Denial of service" |
| R13 | **Long-term sealing key retained in custody.** Until a transitioned individual deletes its long-term sealing key, a device stolen after epoch 1's horizon still opens pre-changeover mail sealed to that key. | Pre-changeover mail only; born-FS identities have no such key. Ruling: delete only for an individual, after a long-term-key horizon (cutover `iat` + relay TTL + skew); NOT for a group admin until it keeps its own `g<n>.key`, and NOT for an org (its address sealing key is active). Deletion is deferred until the ruling. | `spec/SPEC.md §7.4` |
| R14 | **Idle home retains epoch keys.** An edge that stops rotating keeps epoch private keys past their horizon (deletion happens at the next rotation), so an idle identity's FS horizon is unbounded until it next rotates or prunes. | Self-inflicted (the identity's own device); a periodic rotation or prune closes it. | R2 |
| R15 | **Agent custody does not rotate epochs.** While an identity is agent-held (the MCP keep-alive), no epoch rotation occurs; its current epoch key lives the whole `ac login` window and is pruned only after it. | Horizon = the window (<= 8 h) + the normal horizon; `keys rotate` and `record keep` refuse an agent-held identity, so epochs come only from `login`. Mitigation: rotate on login or in the keep-alive (a build item). | `spec/SPEC.md §13` |
| R16 | **Group generation keys at rest (`g<n>.key`).** A member keeps each accepted generation key durably (`g<n>.key`, a 32-byte seed, 0600 under `keys/groups`) to open across epoch deletions; a device stolen later reads every generation the member accepted, regardless of the epoch horizon. | Group read access is not forward-secret at the member once accepted (the group analogue of holding decrypted history); file-mode protection only; per-generation re-encryption deferred. | `packages/edge/src/custody/groups.ts:23`, `:153` |
| R17 | **A hostile `Elicitation` hook can complete a pairing without the person (pairing in Claude Code).** A folder- or user-scope `Elicitation` hook matched to the MCP server can auto-answer the `pair_invite`/`pair_accept` dialogs with `action: accept` and content, computing the six-digit comparison code itself, so pairing no longer always needs a person's keystroke. | Bounded by R5 (same-uid floor) and §6: the hook is same-uid code, which already reads the identity's keys and writes `trust.json` directly, so it adds no capability a same-uid attacker lacked; the six-digit SAS defends the channel between two honest endpoints, never a compromised one, and is not claimed to give session or endpoint isolation. The model itself still cannot answer an elicitation (`claude -p` cancels it and runs no hook). | `spec/SPEC.md §13.11`; R5, §6 |
| R18 | **The invite string reaches the inviter's model and the chat transcript (pairing in Claude Code).** `pair_invite` returns the ~280–340-char invite in its tool result and the model shows it verbatim in chat for the person to hand over out of band; `S` is thus in the inviter model's context and persisted in the transcript (same-uid readable). Amendment 3's clipboard copy is removed — Universal Clipboard clobbered it. | Inside the R5 same-uid floor (same-uid code already owns the identity). Pairing integrity rests on the out-of-band six-digit SAS, not on `S`'s secrecy: a thief's `S` still yields different digits (the code binds the requester's sealing key, never surfaced), caught by the human compare, and the model cannot answer the approval with `S` alone. The marginal risk over Amendment 1's "`S` reaches neither model" is a remotely-injected inviter model exfiltrating the invite and racing a request, whose worst case is the real peer seeing `leaked` and restarting — availability, not integrity. Mitigations: the six digits never appear in any result (dialog-only); the tool description and INSTRUCTIONS forbid the model to send the string anywhere; `S` is in no audit or log; an expired `S` in the transcript is dead (a request under it is `403`). | `packages/mcp/src/pairing.ts`; R5, R17 |
| R19 | **Pairing code: online-guessing and rendezvous metadata (pairing by a short code, 2026-10-30).** The short pairing code (a relay nameplate + 3 words, ~31 bits) is online-guessable in principle, and the relay's rendezvous learns the invitation's reach metadata (the invitation identity I, its relays, and the open/expiry times). | Integrity is never at risk — it rests on the out-of-band six **check digits**, not on the code's secrecy (a guesser or interceptor who reaches the invitation yields different check digits and the person declines), the same principle as R18; the code carries no integrity. Availability only: the guess bound is enforced at the inviter edge (the only party that checks the MAC), which counts `bad-code` requests and ends the invitation after N = 20, so it holds whatever relays are used, including cross-relay where the nameplate's rendezvous relay and I's message relay differ — ≈ 20 / 2^31 ≈ 1 in 107 million; a single `bad-code` does not consume the invitation (typo tolerance), and the relay's own caps (a 1/s token bucket, burst 5, across all IPs, and 10 per (nameplate, IP)) are a second layer that bites when the rendezvous is also the message relay. The invitation lives ≤ 600 s. An attacker who holds the nameplate gains at most a burned invitation (a restart). The relay sees only reach metadata (never the words, `S`, the check digits, or any key beyond I's public address); a malicious relay still cannot MITM a paired peer (the check-digit SAS). A rendezvous host supplied in a `code@host`, and the blob's `relays` read from an untrusted rendezvous, are attacker-influenced, so pair/open, pair/claim and the acceptor's publish and fetch to those relays apply the §9 item 11 private-address guard — a loopback, link-local, RFC 1918, unique-local or unspecified host (or a name that resolves only to such) that is not a configured relay is `resolve-failed` before any request, unless `--allow-private-relays` — which blocks an SSRF from a hostile peer's code or invite and also closes the pre-existing invite-string relay gap (built). (Refined 2026-10-30, ruling §2: the out-of-band check-digit compare is a one-sided **typed** entry at the inviter, the admitting party, which does not display the digits it checks against; the acceptor shows the digits once and reads them out before confirming and asserts no match of its own, so a two-sided visual compare ends. A typed mismatch is `digits-mismatch`, a distinct local inviter event, bounded to three typed tries in the one dialog, non-consuming and silent to the acceptor (no oracle), and **not** counted in this N = 20 MAC-guess bound; the N = 20 bound and the relay caps above are unchanged. `ac peer invite` types on the CLI too, with no yes/no confirm.) | `spec/SPEC.md §8.10`; R5, R18 |
| R20 | **Two identities in one server are not fully unlinkable (multi-identity, 2026-10-30).** One MCP server may hold many identities, each with its own keys, records, relays, store, name book, trust file, audit and subscription sockets; no byte this software sets on the wire names another identity, and the timing it sets is jittered. | What is separated is measured — each identity's subscription is its own WebSocket per relay and nothing it sends names a sibling — and full unlinkability is NOT claimed. Two identities remain linkable by: the network address a relay or observer sees for all of them; activity timing (jitter widens the windows, it does not remove them, and a machine going offline drops every identity at once); shared public record contents (identical relay lists, a peer paired with two identities listed in both accept-from records, the same ttl and keep-alive cadence); the common client fingerprint (Node's `fetch` and TLS hello); the single model context (one context holds every identity, and an injected message may make the model name another in prose, which the literal body guard does not catch); and local machine access. At a shared relay two identities may also share a pooled TCP connection and a resumed TLS session (scenario 50a–50f), subsumed by the network-address linker. Guidance: for unlinkability give each identity its own relays and do not pair one peer with two identities; a per-identity network path (a proxy or Tor) is out of scope. | `packages/e2e/test/scenarios/50-connection-isolation.test.ts`; `packages/mcp/test/server-multi.test.ts`; R5, R19 |
| R21 | **Offline identity reachability (records offline past the key-record cap, 2026-10-30).** An identity whose Claude Code stays closed past the key-record 24-hour cap lapses: the relay sweeps its key record, a new sender gets `resolve-failed`, and a `resolve-failed` send waits on the sender side. The baseline (scenario 51) measured that reopening alone does not restore reach and that `keys rotate`'s first publish after a sweep wiped the record's `revoked` list and `rotation_key`. | The 24-hour cap is retained, not widened — a deliberate forward-secrecy / rotation bound (§10 Forward secrecy, D31); widening it (lever c) is rejected. Offline-past-cap is unreachable to new senders, fail-closed (`resolve-failed`), never a downgrade to a stale or expired record. Three levers: (a) opt-in `record keep` re-signs a fresh record within the cap (prevention) and, after a sweep, heals from the last-written local copy — `record keep --once` exits `not-found` only for an identity that never published; (b) a durable waiting send on a fixed `--as` identity's own disk survives the sender's restart (plaintext at rest on the sender's own machine, 0700/0600, no network exposure; a `--session` server stays memory-only); (c) longer horizons rejected. The primary cure is heal-on-reopen: re-sign from the last-written local record, carrying the full `revoked` list and the `rotation_key` forward and advancing `iat`, never publishing `revoked = []` (a revocation rollback that re-admits a revoked key) and never leaving the identity to a bare first publish (which drops the rotation-continuity countersignature a sweep removes). A missing or unreadable local copy for an identity that held revocations fails closed to the offline backup or an acknowledged rotation. `keys rotate`'s wipe is fixed regardless. Residual: cross-device revocation drift, surfaced via `stale_since`. The relay-side consequence — its kept revoked list emptying when an empty-`revoked` record is published — is measured (scenario 51, the kept-list arm) and is the relay-side reason recovery never publishes `revoked = []`. | `spec/SPEC.md §10 Offline reachability`; e2e scenario 51; R19, D31 |
| R22 | **Concurrent audit writers fork the chain (audit-chain integrity, 2026-10-30).** A hash chain tolerates one live writer; a measurement showed that a `record keep` rotation run beside a live MCP server wrote `audit.jsonl` from its own `Audit` while the server appended from its in-memory head, reusing a `seq` and forking the chain — `audit verify` then reported `diverged` and the server refused to start until the anchor row was deleted by hand (measured on 2026-10-30 for the MCP case; `inbox --watch` beside it and `keys rotate` via the same path are read from the code, not yet measured). | The fix is a single-live-writer invariant, not a lock: exactly one live process writes a given audit file, and any other writer uses its own anchored chain file (a sidecar `cli-audit.jsonl`). Each file is its own hash chain from genesis, independently verifiable and independently anchored; `audit verify` and start read the enumerable set of anchored files and fail closed on an anchored-but-missing file, so truncation, rewrite or deletion of any file is caught. The sidecar's anchor is a single lock-free disjoint-row upsert that must not block the MCP open path; a lock was rejected because it would let a background renewer delay the server's open (today a no-wait 249 ms). Residual: no cross-chain total order between files — each is independently complete and tamper-evident, and `ts` gives the approximate interleaving. One measure is open — a server start and append concurrent with the anchor write against the 249 ms baseline — and no claim rests on it until it is measured. | `spec/SPEC.md §9 item 8`; R9 |
| R23 | **Read receipts (optional profile, 2026-10-30).** When a reader enables receipts, a receipt reveals that the reader's identity processed a specific message, binds that act to the reader's signing key, and — because a receipt is an ordinary envelope whose outer `ts` is mandatory and in clear, and the relay sees reader-to-sender traffic right after delivery — approximately when they read; genuine read-receipt leakage, traded for the sender's delivery confirmation. | Off by default and reader-controlled, never sender-controlled: a sender may request a receipt with a sealed `ac.receipt: true` body member (relay-invisible, uncompellable) and the reader chooses per peer. The receipt is a sealed, signed envelope of a distinct content type (`ac.receipt`, the §5.2 `type`) carrying only the acknowledged id in a reserved member `ac.ack` — the body holds `ac.` members only, a member outside `ac.` is refused and an unknown `ac.*` ignored — no content, quote, metadata or free-text; authenticity is the envelope's own signature, with no inner signature by default, so the default mints no portable proof-of-reading. Declining is indistinguishable from unsupported and from unread — a decliner emits nothing — so the absence of a receipt leaks nothing, the central mitigation. Time cannot be removed at the envelope level (the outer `ts` is clear), so it is stated as a limit: the reader SHOULD apply the system's timing jitter and MAY delay or coarsen, widening the read-time window without removing it (as R20). Residual non-repudiation: full deniability is unachievable in a signed-envelope system, but proving reading to a third party needs the whole sealed receipt revealed and opened, not a one-line token; a transferable opt-in tier (a detached reader signature) is possible, never the default, and not built. A receipt is terminal and never triggers a receipt (no amplification). The profile sits above the core as a distinct sealed content type with a reserved `ac.` body-member prefix (unknown `ac.*` ignored), so it adds no relay or core knowledge and inherits §10 Binding and Replay. | `spec/SPEC.md §10 Read receipts`; R9, R20 |
| R24 | **A refused local name write after a pairing leaves a dangling admit (pairing by name, 2026-10-30).** A pairing's local `write` — the name book and the trust pin, together — reads the name book at the write, not at the ceremony's start, so a name added meanwhile survives and a name already held for another address keeps its pin, the colliding write refused rather than replacing it (since 2026-10-30). The inviter admits the requester to its accept-from and awaits the mutual admit before that write; the acceptor runs its write before it admits the inviter (`packages/edge/src/pairing.ts:362`, `:368`, `:427`-`428`). So a name taken for another address during the window collides at the write: on the acceptor the write throws before the admit, so the pairing fails closed on both sides — the inviter's mutual-admit wait then fails and it rolls its own admit back (`:363`-`365`) — but on the inviter the write throws after the admit is already live, leaving the peer admitted and deliverable in the inviter's accept-from yet unnamed in the book and unpinned in trust: a dangling admit. | Inside the R5 same-uid floor and not remotely triggerable — the collision needs a local name-book write at this uid during the ≤ 600 s pairing window, and a remote peer names nothing on the inviter. Deliverability is not a trust grant: an unpinned root's mail is admitted to the mailbox but never routed as a known peer, and the refused write writes no trust, so a dangling admit must not be read as a trust grant. Nor is it a reason to undo the admit — a rollback would re-sign accept-from and, like a revocation rollback (R21), is not done here; the admit stands, and the person re-pairs under another name, which writes the name and trust the collision withheld. | `packages/edge/src/pairing.ts:362`, `:368`, `:427`-`428`; R5, §6, R21 |
| R25 | **Telemetry adds one observer, the opt-in endpoint (telemetry, 2026-11-01).** With a person's opt-in, a client sends one report a day to `telemetry.bag.dev`, so that endpoint — a Cloudflare Worker — learns, per opted-in machine, an install id (random, 128 bits, made at opt-in, one per machine and shared by every identity whatever their homes), the build (a published cut commit, else `other`), `node` from a supported list, OS family and arch, host kind, the public relays used as power-of-two buckets, and daily counts — themselves power-of-two buckets — keyed by closed sets (CLI command verbs with exit, 3 included, and code; MCP tool/ok/code and sessions by host kind; the a2a surface with its bridge from a closed set; audit `(event, decision, reason)`; pairing outcome; relay error codes; durations by command and tool); Cloudflare sees the client IP as the endpoint's processor, and the backend does not (the Worker never forwards the IP). A report **never** carries a body, type or thread, any key or seed, a pairing digit, word, nameplate, invite string or `S`, an address or handle raw or hashed, a petname or session name, an IP, any file path, a hostname, user or machine id, a relay URL beyond the two public names, or a free-text error. The relay's own optional metrics are aggregate counts on a private listener (never the public API) and carry route, status, closed-set codes, limit names, reasons, counts, gauges, durations and the build rev, never an address, id, root, domain, nameplate, IP or prefix as a label. | Outside the protocol, no wire change, off by default: the clients need the person's opt-in, one consent per machine (opt-out is not consent under ePrivacy Art. 5(3) / LSSI art. 22.2, EDPB Guidelines 2/2023) and `ac telemetry off` withdraws it and drops the id; the relay metrics ride the legitimate-interest basis the privacy draft already names and add no IP data the relay does not already hold. The install id is one per machine, shared by every identity, a random value never derived from an address, key, host, user, machine or path, and carries no per-identity field, so a machine sends one report rather than one per identity and the id does not become a new linker across identities (R20, C-38). Telemetry feeds no security decision: forged reports only skew counts. The endpoint is a new public surface bounded by a closed schema at both ends, a 4 KiB size and a per-IP rate limit, failing closed at the free plan's daily cap; its guard against an address or path leaking through a free-text error is the schema plus a property test (`no report carries an address, key, body, path or IP`). §10's relay-observer bound and `cut/SECURITY.md` are unchanged (R0/R1 teach a relay nothing new). | `spec/SPEC.md` Appendix B item 111, §10 "Metadata", §8.9 item 4; R9, R20 |
| R26 | **Log shipping adds one observer, Grafana Cloud EU (log shipper, 2026-11-02).** The relay's structured logs are copied to a Grafana Cloud EU stack by a shipper app (`deploy/relay/log-shipper`, not deployed before this row). A Vector allow-list transform inside the shipper drops every address, id, mailbox, signer, domain, nameplate, IP or prefix, path and free-text error before the Loki sink, so the copy holds only what the R25 metrics endpoint already exposes: closed-set codes, counts, durations, route, status and level. | The transform is an allow-list, not a deny-list, so a field no rule names is dropped by default; it is the sole guard, pinned by a property test, and only a bug in it or a widened list would disclose an identity to a third party. The copy is kept 30 days at most and read behind a Grafana access-policy token; the shipper reads only the two relay apps' log stream over the private 6PN with a read-only token and writes with a logs-write-only token. The EU stack keeps the backups-and-telemetry-in-EU posture R25 names. Shipped logs feed no security decision — forged or dropped lines only skew dashboards, never a protocol outcome. | R25 (the sibling telemetry observer); R9 |

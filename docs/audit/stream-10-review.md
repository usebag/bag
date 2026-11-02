# Stream 10: adversarial review summary

*Prepared for an outside security reviewer. Draft, 2026-10-29. Grounded against the final launch assembly
of 2026-10-29. This is the adversarial review record: two rounds, their findings, the dispositions,
and what is built versus deferred. Security claims carry a `spec/SPEC.md §` or `path:line` citation; weaker-than-they-
read claims say so. The four claims an earlier draft could not fully ground have since been traced against the code and
folded into the body; section 5 records their disposition.*

The protocol's security model and its residuals are in the companion `docs/audit/threat-model.md`.

---

## 0. The two rounds, in one paragraph

**Round 1** was a four-head pre-launch review across the public relay, recovery, local trust-anchor writes, and the
many-sessions front desk. **The FS red-team pass** was a focused adversarial pass over the forward-secrecy scheme on
the final launch assembly. Round 1 surfaced exactly one launch blocker, and it is a **deploy-verify, not a code
defect**. The FS pass confirmed the scheme's core invariants and left one bounded residual (P2), since **mitigated**
(merged 2026-10-29; section 2.2). No code defect blocks launch at the launch assembly.

---

## 1. Round 1 (four heads, pre-launch)

### 1.1 Public relay (hosted abuse)

**Launch blocker (deploy-verify, not a code defect): client-IP trust.** The relay must honor a client-IP header only
from a trusted-proxy peer and select the right-most untrusted address, failing safe to the proxy's own address
otherwise. This is implemented (`crates/ac-relay/src/net.rs:194`-`209`, `Front::client`: values read with `.rev()`,
trusted proxies skipped, a non-address value voids the header and the request becomes the proxy's own;
`spec/SPEC.md §8.9` item 1). Launch is gated on the **forged-header test passing on Fly**: a direct
`curl` with a forged `Fly-Client-IP` must show the real client's /24 in the log line, proving Fly's proxy replaced the
forged header. Disposition: **not a code change**; the gate is the
deploy verification.

**One narrow real gap (R11): domain-block reliability.** A `domain:` blocklist entry is bypassed when the relay has
never pinned that domain and recipients admit the root by address or `"*"` -- no resolution is forced, so the
domain's current key is never computed and the entry never matches. Grounding: the sender-domain block only matches
domains the relay resolved to the root (`crates/ac-relay/src/policy.rs:308`-`318`), and `refuse_blocked` checks a
listed domain's key only via `store.domain_pin`, which is empty for an unpinned domain
(`policy.rs:502`-`515`). Disposition: **document** that domain-blocking is reliable only after the relay resolves the
domain, and advise operators to also list the key. No code change for launch.

**Sound controls.**
- Per-domain quota and `/v0/abuse` are sound. The "bare-root -> per-root-only" decision closes a counter-minting
  amplifier (a sender cannot mint fresh per-root counters from a bare root) (`crates/ac-relay/src/ratelimit.rs:134`-
  `150`). The per-domain quota's **code default is 10,000 a day** (the `crates/ac-relay/src/main.rs` clap default,
  which drives a running relay, and `crates/ac-relay/src/config.rs:133`), so a self-hosted relay ships the quota **on**
  at 10,000; an explicit `--domain-publishes-per-day 0` turns it off. The Fly deploy's `--domain-publishes-per-day
  10000` now matches the default (kept explicit, harmless).
- The fixed-window day boundary allows a ~2x burst (R12), inherent to fixed windows (`ratelimit.rs:90`-`102`); grounded
  from the fixed-window counters, with no test pinning the exact factor. Accepted as inherent.

### 1.2 Recovery

**Closed: the restore un-revoke hold.** Restore cannot prove it holds the newest record, so a reachable older
same-key record would otherwise drop a revocation on republish. Restore therefore **confirms before every republish**,
warning that publishing may un-revoke a key (`packages/cli/src/commands/init.ts:198`-`208`). Revoking does not rotate
the keys, so a record that revokes the address stops the restore outright; nothing here undoes a revocation
(`init.ts:178`-`184`).

**Sound.**
- Seed input is **echo-off** on a TTY (`init.ts:150`-`151`).
- The relay line is **inside** the sheet checksum (`packages/edge/src/custody/recovery.ts:60`-`61`).
- `rotated_from` / `revoked` handling is sound: the restore unions the revoked lists it saw and respects a revocation
  as a stop (`init.ts:178`-`184`, `:215`).

### 1.3 Local trust-anchor writes

**The write invariant HOLDS.** A trust/accept root is written only on an **explicit human act** -- a pairing `y` or a
typed `--accept` / `--trust-domain` (including a cron re-run of the operator's own config) -- never from an incoming
message, a resolved record, or a default. Grounding: onboard writes accept roots from the typed `--accept` list, and
the SPEC owner's ruling (2026-10-28) counts the typed `--accept` as the human act with no `y`
(`packages/cli/src/commands/onboard.ts:116`-`118`, `:278`-`303`); `--trust-root` is parsed as an address or a domain
pinned at first use (`packages/cli/src/commands/inbox.ts:65`-`69`).

**Two documented seams.**
- **A port-bearing `--trust-root` resolves fail-closed (traced, not a downgrade).** The `--trust-root` grammar accepts
  an optional port (`packages/cli/src/commands/inbox.ts:47`, `(?::\d{1,5})?`) and `trustedRoot()` carries it verbatim
  into `{domain: "host:port"}` (`inbox.ts:66`-`69`); nothing strips or canonicalizes the port. In the admit path
  `Policy.#rootRecord` resolves each domain root and returns it only when `record.key === chain.root`
  (`packages/edge/src/policy.ts:288`-`296`). The resolver treats `host:port` as a non-DNS host: `isDomainHost("host:port")`
  is false because the colon fails the DNS-label grammar (`packages/core/src/records.ts:146`-`150`), so the DNS/TXT
  discovery step is skipped and the origin falls back to a bare `https://host:port` with a null discovery key
  (`packages/edge/src/resolver.ts:259`-`271`); the well-known fetch honors the port (the fetch-side `DOMAIN` regex admits
  it, `packages/edge/src/adapters/well-known.ts:19`, and `originUrl` builds `https://host:port/.well-known/...`, `:52`-
  `:59`), and `checkDiscovered` is a no-op under the null key (`packages/core/src/discovery.ts:193`-`194`). So the root is
  pinned under the distinct subject `domain:host:port`: if the org's canonical well-known is served at the default HTTPS
  port (the port-less host), the port-bearing fetch hits a different endpoint, fails to resolve, and the
  `record.key === root` test never matches -- **trust simply never applies (fail-closed): a dead config line, no security
  loss.** It is *not* a downgrade -- it pins TOFU at that exact `host:port` exactly as a domain with no TXT record does
  (same no-discovery branch), and it never silently swaps an existing port-less pin, which is a different subject. Any
  wrong trust would require controlling what `host` serves over HTTPS, the standing domain-root trust assumption (R1),
  which the port does not widen.
- `onboard` **replaces** the accept-from roots where pairing **merges**, so an onboard cron refresh would drop a paired
  peer. **Resolved:** onboard now unions the pairing-`y`'d peers held at the relays with the typed roots
  (`onboard.ts:45` comment "keeps the accept-from roots held at the relays (a pairing's) beside the typed ones";
  `:147`-`148` `accepted = acceptRoots(held, trusted, roots, agent)`; `:211` prints `kept <root>`).

### 1.4 Many sessions (the front desk)

**No live exploit under the shipped plugin defaults.** No duplicate-answer or read-boundary exploit was found. The
front desk is explicitly **routing above the seat, not a read boundary**: `§13.8` (b) still releases every root to
every equal-caveat session (`packages/edge/src/agent/front-desk.ts:26`-`33`; `spec/SPEC.md §13.11` "Many sessions").

**Two latent fragilities, HARDENED.**
- The regrant lock ordering now halts the receiver before releasing the desk lock, so a root in flight at handover does
  not fall on both sides (`front-desk.ts:45`-`47` "The desk lock must be released only after the receiver has halted").
- The FrontDesk dedup window is threaded from the edge, not hardcoded (`front-desk.ts:75`-`78` `readonly window?:
  TimeWindow`, default `DEFAULT_WINDOW`; `:249`-`251`), with a synchronous-check-then-append guard: the ledger check
  and the fsynced append are one synchronous step with no `await` between (`front-desk.ts:92` `appendDurable`,
  `:265` comment).

**Two latent items, DISCLOSED (not fixed, harmless under the plugin's defaults).**
- The ledger-as-seed does not cover pre-ledger non-wrapper reads. The dedup binds only sessions running the MCP
  wrapper: the measured target is "0 duplicate answers **among the sessions that run this wrapper**"
  (`packages/edge/src/agent/front-desk.ts:45`), and the desk is "**not a read boundary** ... best-effort answer dedup in
  the MCP server, routing above the seat" (`front-desk.ts:30`-`33`). A session that does not run the wrapper consults no
  ledger and is outside the dedup by construction; so is any read that happened before the ledger was seeded. This is the
  disclosed bound of the measured property, not a defect (verified by the SPEC owner in review, 2026-10-29).
- The grant confirmation code is a 32-bit digest prefix (`packages/edge/src/agent/server.ts:394`
  `hopDigest(pending.hop).slice(0, 8)`), grindable only if sessions have differing caveats (the digest covers the hop's
  caveats); harmless under the plugin's single caveat list.

---

## 2. FS red-team pass (over the launch assembly)

### 2.1 Confirmed

- **Pairing pins to the identity and survives epoch rotations (no MITM).** The invite code and HMAC bind the
  requester's current sealing key, and trust is written to the address (accept-from), not to a transient key
  (`packages/edge/src/pairing.ts:6`-`14`, `:42`-`50`; constant-time MAC, `pairing.ts:1`).
- **The delivery-side private-relay guard is applied at BOTH publish sites.** A recipient-named private relay cannot
  aim a sender's delivery at the sender's own network: in the send path the guard refusal is awaited before the
  record-leave and before the envelope publish (`packages/edge/src/sender.ts:334`-`341`), and the resolver guards the
  record-read path the same way (`packages/edge/src/resolver.ts:443`-`450`). The guard refuses any non-public host
  (`packages/edge/src/net.ts:135`-`209`).
- **Group generation-key custody is sound and group FS is unweakened.** `g<n>.key` is 0600 in a 0700 dir, write-once,
  under `keys/`, with only the generation's public key in the audit
  (`packages/edge/src/custody/groups.ts:22`-`28`, `:152`-`164`; `spec/SPEC.md §13.11` rotate row). Group FS is
  generation rotation; a removed member is cut at the next generation.

### 2.2 One bounded residual (P2, low-moderate): transition downgrade

An identity transitioning pre-FS -> FS signed a legacy non-null address record valid up to its TTL (<= 24 h). In that
window a malicious relay serving that still-valid record while **withholding** the new key record can downgrade a
**first-contact** sender to the long-lived sealing key; the legacy record is genuinely signed, so it is not rejected.

Grounding (before the mitigation): the resolver fell back to the address record's sealing key whenever it was non-null, with no check
that the identity was already known to be FS (`toAddressKey()`). A born-FS identity has a null address sealing key, so
this path does not exist for it. The mitigation added the known-FS check -- see the disposition.

Bounds: transition-only; window <= 24 h; **confidentiality-only** (the recipient still opens the mail); born-FS
identities immune; requires a malicious relay controlling all of the victim's relays.

**Disposition: mitigation landed** (merged 2026-10-29): the resolver now refuses the non-null address-key
fallback for any identity it has seen resolve a key record -- a durable one-way `fs_known` ratchet (`resolver.ts`
`recipient()`/`#keep`, the `fs_known` table in `ports.ts`/`adapters/sqlite-store.ts`; test
`packages/edge/test/d52-resolver-known-fs.test.ts`), so a withheld or faulting key record fails `resolve-failed`
instead of downgrading. What remains: a genuine first-contact sender that has never once seen this identity use a key
record is still exposed within the <= 24 h window; born-FS and repeat-contact senders are immune. That remainder is
**accepted for a born-FS launch** (2026-10-29): at a fresh launch every identity is
born-FS, so the transition window never opens.

---

## 3. Built vs deferred

### Built (at the launch assembly)
- **The FS scheme:** core seal to the current key record and the record and resolver path
  (`packages/core/src/seal.ts`, `packages/core/src/records.ts`, `packages/edge/src/resolver.ts:385`-`426`), `ac-core`
  verification, the Python vector verifier (`spec/vectors`, `§11`), the edge epoch lifecycle and resolver
  (`packages/edge/src/key-records.ts`, `packages/edge/src/custody/key-records.ts`), and the group durable-key seam
  (`packages/edge/src/custody/groups.ts`).
- **The public relay abuse controls:** reloadable operator blocklist (`crates/ac-relay/src/abuse.rs`), per-sender-domain
  daily quota (`crates/ac-relay/src/ratelimit.rs`, `config.rs`), `GET /v0/abuse` (`crates/ac-relay/src/http.rs:172`),
  the trusted-proxy / client-IP front (`crates/ac-relay/src/net.rs`), and the Fly deploy config.
- **The front-desk hardening:** receiver-halt-before-unlock and the threaded dedup window with the synchronous
  check-then-append guard (`packages/edge/src/agent/front-desk.ts`).
- **The recovery fixes:** confirm-before-every-republish, echo-off seed input, relay-in-checksum
  (`packages/cli/src/commands/init.ts`, `packages/edge/src/custody/recovery.ts`).

### Deferred
- **One-time per-message prekeys (Tier-2 FS)** -- would tighten the FS horizon toward a single message
  (`spec/SPEC.md §10` "Forward secrecy").
- **Agent seat, held for a later section** (not security-regressions, scope boundaries stated in the spec): the
  `member` grant, any org mode, the work-escrow wiring, and the recovery wrap and its restore command (recovery here is
  a format field only) (`spec/SPEC.md §13.0` "Held for a later section").
- **Later-suite privacy:** hiding `from` and sealing the caveats (`§10` "Metadata").

---

## 4. Launch gate (summary)

| Item | State |
|---|---|
| Client-IP trust (the one launch blocker) | Code present and correct; gated on the Fly forged-header deploy-verify. **Not a code change.** |
| Domain-block reliability (R11) | Documented; advise operators to also list the key. No code change for launch. |
| P2 transition downgrade | Mitigation landed (2026-10-29): resolver refuses the fallback for a known-FS identity; only a never-seen-FS first-contact sender remains exposed within <= 24 h. |
| Abuse contact | Placeholder at the launch assembly; real contact to land before the first deploy. |
| Front-desk, recovery, trust-anchor, FS core | Hardened / confirmed; no open code defect. |

---

## 5. Reviewer notes

Nothing remains open here. The four claims this draft originally could not fully ground were all traced against the code
at the launch assembly on 2026-10-29 and moved into the body:

- **Flag 1 -- trust-root port seam: traced, folded into section 1.3.** A port-bearing `--trust-root` is accepted at
  parse, resolved by a direct well-known fetch at that exact `host:port` with the DNS/TXT discovery cross-check skipped,
  and pinned under the distinct subject `domain:host:port`; against an org served at the default port it fails to
  resolve and trust never applies. **Fail-closed, not a downgrade** (decisive: `packages/edge/src/policy.ts:288`-`296`,
  `packages/core/src/records.ts:146`-`150`, `packages/edge/src/resolver.ts:259`-`271`).
- **Flag 2 -- front-desk pre-ledger/non-wrapper bound: folded into section 1.4.** The dedup binds only wrapper sessions
  by construction; a non-wrapper or pre-ledger read is outside the ledger by design -- the disclosed bound of a measured
  property, not a defect.
- **Flag 3 -- per-domain quota default: folded into section 1.1** (and the relay model, section 7 of the threat model).
  Code default 10,000 a day (the `main.rs` clap default and `config.rs:133`); a self-hosted relay ships it on, and
  an explicit `--domain-publishes-per-day 0` turns it off.
- **Flag 4 -- fixed-window ~2x burst: section 1.1 and R12 in the threat model.** Grounded from the fixed-window counters
  (`ratelimit.rs:90`-`102`); no test pins the exact burst factor, and the doc does not claim one does.

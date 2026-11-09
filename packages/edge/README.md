# @usebag/edge

The agent-side library of bag v0 (`spec/SPEC.md` §9): it sends, receives, verifies, unseals, evaluates
caveats, routes and audits. TypeScript on Node 24 with no build step and no native module; its one workspace
dependency is `@usebag/core`, and it has no other.

## What it does

- **Send** (`Sender`): resolve each recipient's address or key record, build one envelope with the core, persist its
  exact bytes in the outbox, and publish those bytes to every recipient relay. Per relay: sealed, publishing, then
  published, or retry until the relay TTL has passed since the envelope's ts, then failed, kept for `resend` of the
  same bytes (the state machine is below). A 4xx other than 408 and 429 fails at once; a 429 waits for its
  Retry-After. (Earlier versions gave up after 20 tries, about 8.1 hours; the outbox now outlasts any outage a relay does.)
- **Receive** (`Receiver`): every frame becomes an inbox row before anything is checked, then: verify (parse, id,
  signature, ts window, a recipient), policy (the chain's rules, a trusted root, the root's revoked list), dedup,
  unseal, caveats and type, route, ack. Each step writes an audit line, and the ack comes after the row is routed,
  queued or rejected. A redelivered frame finds its row; `recover()` finishes rows a crash interrupted. A transient
  rejection (`resolve-failed`, `future-ts`) waits and is retried (below); `run` subscribes again when the relay ends a
  subscription with an error frame (below). Since 2026-10-25 15:01 UTC (16:01 Madrid) the policy step also applies
  the receipt bound: the row's `received_at` is the relay's stamp on the frame, or the receiver's first sight when the
  frame has none, and a chain is rejected `hop-expired` once that second is past the earliest `exp` of its hops plus
  the skew (`receiptBound`), at first sight and on every retry alike ("What the receipt bound changed", below).
- **Resolve and pin** (`Resolver`, `Pins`): an org's record from `https://<domain>/.well-known/bag/address.json`,
  address and key records from relays, the greatest `iat` that verifies among the relays that answered and never
  below one seen before (`resolve-failed`); each verified, cached no longer than it is valid, and pinned at first
  contact.
  A new key is accepted only through the core's `verifyRotation`, else `pin-mismatch`.
- **Policy** (`Policy`): trusted roots (a domain with an optional pinned key, or a key), honored caveat evaluators
  (anything they do not know fails closed), accepted types (`chat.v1`, `coding.*`, `*`).
- **Route** (`Router`): a thread goes to the session that registered or opened it (`threads` is persisted); a root
  message on an unknown thread goes to the default handler, else to the spawn hook; anything else is queued.
- **Audit** (`Audit`, `verifyAuditLog`): hash-chained JSONL; `verifyAuditLog(lines)` names the first edited, removed
  or reordered line, and `verifyAuditLog(lines, anchor)` also a log cut short of its anchor (`truncated`) or rewritten
  (`diverged`), which the chain alone cannot see (below). No line holds key material.
- **Guard** (`RelayGuard`): refuses relay URLs on private addresses that are not the edge's own (below).

## What the outbox and inbox state machines changed

**The outbox state machine** (`outbox.ts`), one envelope at one relay:

```
sealed -> publishing -> published
                     -> retry(next_at) -> publishing ...      a failed try, while now < ts + TTL
                     -> failed(code)                          a 4xx but 408 and 429: at once, the relay's code
                     -> failed(publish-failed)                a failed try at or after ts + TTL
failed -> sealed                                              resend: the same bytes, tries from 0
```

The wait after the n-th failed try is `retryWait(n - 1, jitter)`: 1 s × 2^(n-1), capped at 3,600 s, less a jitter of
up to 10% drawn from the edge's rng (so the cap holds, and many targets do not retry in step), in whole seconds; a
429's Retry-After wins when it is longer; no wait runs past the horizon, ts + TTL, where one last try is made. TTL is
the edge's `window.ttl`, 604,800 s by default. A relay silent for two days now gets the envelope within an hour of
its return (61 failed tries); one that never returns fails the target at ts + 604,800 after 189 tries.
`resend` still reseals failed targets; a resent target whose try fails past the horizon fails again at once.

**The inbox state machine** (`inbox.ts`): `received -> verified | rejected | received`, `verified -> routed | queued`,
`rejected | routed | queued -> acked`. A check that ends in a transient code (`TRANSIENT_CODES`: `resolve-failed`, a
record that could not be read yet; `future-ts`, a ts ahead of this clock that time heals) keeps the row `received`
with one more `tries` and a `next_at` after the outbox's backoff (never past ts + TTL), audited
`<step> retry <code>`; it is acked to the relay (it is durable) but not marked acked at the edge. A receiver that runs
at the row's relay retries it when due (every `flushEveryMs`), and so does `recover()` at start; a retry that reaches
an outcome is acked to the relay again when its cursor is at most the highest the subscription delivered, and marked
acked in any case. A subscription's observers see only the relay acks, so an accepted row reaches its consumers
through `accepted` (below), not through them. At ts + TTL a transient rejection becomes final (`rejected`, then acked). Every other code is final at
first sight, as before.

**The doorbell and `accepted`** (`doorbell` and `accepted` in the options): both
fire in `Receiver.ack`, once per row, at the row's store transition from `routed` or `queued` to `acked`: the doorbell
first, then `accepted(row)` with the row as accepted (state `routed` or `queued`). `ack` reads the row's state from the
store, not the caller's copy, and the store moves a row to `acked` once, so a second ack, a stale copy or a frame sent
again fires nothing. Every path that acks a row passes there: a frame (after `sub.ack`), the retrier (at any cursor,
including a row past the highest cursor the subscription delivered, which gets no `sub.ack`), `release`, and
`recover()`, which finishes rows a crash left `received`, `verified`, or `routed` or `queued` but not acked, acks each
that reached an outcome, and returns them as they were before the ack (a caller's ack of them is a no-op). A refusal,
a drop, a hold and a row waiting for a retry fire nothing. The edge writes no file: the CLI and the MCP server pass a
writer that touches `<home>/state/<name>/doorbell` (empty, 0600, in the 0700 state directory, `O_NOFOLLOW`; its mtime,
the wall clock's, is the signal). Both callbacks are synchronous: a returned promise is ignored (its rejection is not
caught), and a slow callback blocks the frame loop, the retrier tick and `Edge.start`. A callback that throws loses that
row's call; the error goes to the edge's `onError` (none set, none reported), the row stays acked, and the other
callback is still called. At most once: a crash between the store's commit of the ack and the calls loses them for that
row; a crash before the ack leaves the row for `recover()`. `Edge.receive` alone no longer rings or fires `accepted`: a
caller outside a started edge must call `edge.receiver.ack(row)`, else the next `recover()` acks the row and fires them
late. One time at the upgrade: a row the old code rang for and left unacked rings again, and reaches `accepted`, at the
first `recover()`. A retried row past the highest cursor that ends rejected still gets no `sub.ack`, as before.

**A position is not an identity** (2026-10-31; spec/SPEC.md §9 item 2): cursors are
monotonic across a sweep and a restart, not across a restore of the relay's store from an older copy, which issues used
numbers again. So `receive` looks up every row at `(relay, mailbox, cursor)` (`inboxAt`) and takes the one holding the
same envelope, by its exact bytes or its id. A frame that matches none is a new envelope: a row of its own, checked and
run through the id dedup, never dropped or acked on the cursor alone; bytes that do not parse claim no id, so they get a
row too, and are refused on it. `inboxFind` gives the newest row at a position. The table has no unique position: a store
from before this has its `UNIQUE (relay, mailbox, cursor)` removed at open, by one rebuild of the table in one
transaction, every row and seq kept.

**A subscription resumes with `cursor: null`** (same branch; spec/SPEC.md §9 item 10): `Receiver` and the WebSocket
adapter's reconnect both let the relay resume from the ack it stores. A remembered cursor is in a restored relay's old
numbering: the relay frames only rows after the cursor a client resumes from, clamped to its own last, so rows it issued
again at or below that one would never come, and the id check runs only on a frame that arrives. A frame whose ack was
lost comes again, finds its row and is dropped there. Scenario 55 measures both, with the edge connected and closed.
`RelayClient.subscribe` keeps its cursor for a caller that wants one, sent on the first connection only; `inboxLastAcked`
no longer sets a resume point.

**Subscription recovery** (`Receiver.run`): when the relay ends a subscription with an error frame (a `RelayError`
with a code), run subscribes again with `cursor: null` after `resubscribeDelay(n)` (250 ms ×
2^n, at most 30 s; `resubscribeDelayMs` in the options), audited `subscribe retry <code>` (detail `{"relay", "mailbox", "attempt", "wait_ms"}`). Three permanent refusals in
a row (`REFUSALS`: `bad-auth`, `not-authorized`, the chain codes and, since edge/policy-gate-inside, `revoked`) end it for good: the audit line
`subscribe reject <code>` with `{"relay", "mailbox", "refusals": 3, "end": "subscription-ended"}` in its detail, and run rejects
with the refusal, so a started edge's `onError` fires. A delivered frame or another error starts the count again. A
closed socket is still the adapter's to reconnect (forever by default); a client that gives up by its own limit (the
CLI's `inbox --once` sets `maxReconnects: 0`) ends the run at once, as before.

**The writer lock** (`adapters/fs-lock.ts`): a `SqliteStore` on a file takes `<dir>/audit.lock` when it opens and
releases it at `close()`, so every writer the CLI, the MCP server and the e2e harness compose holds it for as long as
its store is open. The file names the holder's pid, start time and a token; it is written to a temporary file with
O_EXCL and linked into place, so it is never seen half-written. A second store on the same directory, in this process
or another, refuses with `EdgeError` `busy`; a lock whose pid is gone, or alive with another start time (`ps -o
lstart`; a reboot or a pid reused), is stale and taken over, after a check that the file moved aside is the one judged
stale. `new SqliteStore(path, { lock: false })` opens without it. The MCP server keeps its own `mcp.lock` as well.

**The audit anchor**: the store's `audit_anchor(name, seq, hash)` row, keyed by the sink's `name` (an
`FsAuditSink`'s file name), is put after every append. A new `Audit` with the anchor (the `Edge` passes it) adopts the
last line when there is none, moves it past lines a crash left after it (`ahead`), and refuses a log that is
`truncated` (fewer lines than the anchor's seq) or `diverged` (the line at that seq has another hash) with
`EdgeError`, so a cut or rewritten log is never continued and its evidence never overwritten. `readAuditAnchor(path,
name)` reads it from a read-only connection, without the lock; `checkAuditAnchor(lines, anchor)` compares. To start
again after an investigation, keep the evidence, then remove the row
(`sqlite3 <dir>/edge.sqlite "DELETE FROM audit_anchor"`) or start a new state directory.

**The private-address guard** (`net.ts`): a relay URL whose host is a loopback, link-local, RFC 1918, unique-local,
multicast or unspecified address (IPv4 and IPv6, an IPv4-mapped or IPv4-compatible address read as its IPv4,
`0.0.0.0/8` unspecified), `localhost` or a `.localhost` name, or a name whose every address is one of those, is
refused with `resolve-failed` before any request: a publish target (failed at once, audited with `refused` and the
range), a record lookup at a hint relay, `Edge.fetch`, `Edge.publishRecord` and `Receiver.run`. The edge's own relays
(`relays.urls`) are always allowed: the operator chose them, so a local or LAN relay works as before; the guard is
for URLs a third party names, a recipient's record above all. A name that does not resolve is not refused (the call
then fails on its own). `allowPrivateRelays: true` turns the guard off (tests; several relays on a LAN); `lookup`
replaces getaddrinfo. It checks a name's addresses once per call and the HTTP client resolves again, so DNS
rebinding between the two is not covered. The table moves to `packages/core/src/net.ts` when the relay's guard lands there.

## What first contact changed

A test with two MCP hosts on two machines and two relays found that A's first question to B failed `resolve-failed` (B
had published only at its own relay and A had no hint), and B's reply failed the same way in mirror; each record had
to be republished at the other relay by hand.

**Leaving records** (`Sender`, `leaveRecords`, default true): before an envelope's first try at a relay the guard
allows, the sender makes sure that relay holds a current address record of the edge's mailbox (a session edge's
principal, whose record a reply needs). Only the address record: never the accept-from record, which its owner
publishes at its own relays, since a foreign relay given one would host a mailbox nobody asked it to host and
the owner's trust list would spread to every relay it writes to. Per relay, memoized per process:
(1) ask the relay for the mailbox's address record; one that verifies, is the mailbox's and is current counts as
kept there until its `valid_until`; (2) otherwise read the newest address record the edge's own relays serve (one GET per own relay,
kept until its `valid_until`); none, and there is nothing to leave for 60 s; (3) publish those bytes as they are.
The edge never signs a record here. A 409
`stale-record` counts as kept there; a 429 or any other failure waits `retryWait(n)` or the Retry-After, whichever is longer;
none fails the envelope. Each record publish writes one audit line, `publish accept ok` or `publish reject <code>`,
detail `{record, relay, signer, iat, status}`. An own relay is treated as any other unless the memo says it holds the
record (reading the own records marks those that serve a current one).

**Waiting** (`Edge.sendOrWait`, `Edge.waiting`): `send` still throws `resolve-failed`; `sendOrWait` keeps such a send
waiting, with its thread (made here when absent), in the store and returns a `WaitingSend` `{waiting, key, thread, to,
tried, reason, tries, nextAt, until}`: `tried` the relays the resolution asked, `nextAt` by the outbox's `retryWait`,
`until` its creation plus the relay TTL. `flush` (so a started edge's tick) tries each due waiting send once: sent, it
leaves the waiting list (its targets are in the outbox and in flush's result); `resolve-failed` again, it backs off;
at `until`, or on any other failure (a `pin-mismatch`, say), it is dropped. Audit lines: `publish queue
resolve-failed` when it starts waiting, `publish retry resolve-failed` on a failed try, `publish reject <code>` when
dropped, detail `{waiting, thread, to, tried, tries, next_at, until}`. A waiting send has no envelope yet, so the
`waiting` table holds it in plaintext, in the identity's own 0600 store, and no audit line, result or log line carries
its body. It survives a restart: a started edge's first tick flushes it, under the writer lock, so one process of an
identity flushes. `until` bounds how long a send may be tried, not when its text is erased: a row found past it is
dropped with no try, when the identity's edge next flushes. The row leaves in the transaction that adds its envelope to the outbox, so a crash cannot send it under two
ids. At most `MAX_WAITING` (256) wait; past that, `sendOrWait` throws `resolve-failed`. A store opened with
`waitingInMemory` (a session server's, whose name dies with it) keeps them in memory, gone at close. (These were
called "held" at first; `held` names only the store's persisted quarantine.)

**Lookup and peers** (`Resolver.lookup`, `Edge.peers`): `lookup(address, hints)` never throws; it asks every relay in
the resolver's order (hints, then own) for both kinds, without reading or writing the cache past one look at what it
holds, and returns `{subject, cached, results}`, each result `{relay, kind, outcome: found | none | refused | error,
iat?, valid_until?, key?, detail?}`; a `domain:<host>` subject reads the well-known URL, after the host passes §7.4's domain-root grammar (refused otherwise, special-use names included) and the URL passes the private-address guard. `peers()` lists, for each
principal of an accepted inbox row, the relays its messages came by. **`resolve-failed`** from the relays is a `ResolveFailed` (an `AcError`
with the code `resolve-failed`) whose message and audit detail name each relay asked: `address:<key> from relay; tried
<url> (none), <url> (unreachable)`.

## What handles changed (spec/SPEC.md §12.2 and §12.4)

**Discovery** (`Resolver.domain`): a special-use domain is refused before any lookup; then, when the record source
reads DNS (`RecordSource.txt`, the `Dns` port; `createRecordSource` uses `systemDns`, `node:dns/promises`
`resolveTxt`, where ENOTFOUND and ENODATA mean no record and any other failure is `resolve-failed`) and the domain is
a DNS name, the TXT records at `_bag.<domain>` go through the core's `discover`: none, the origin is
`https://<domain>`; one, its key and its origin (`host=bag`: `https://bag.<domain>`); two or a
malformed one, `resolve-failed` from `dns`. The org record is fetched at the origin, verified, checked by the core's
`checkDiscovered` (the TXT's key, or one rotation it countersigned; else `resolve-failed` from `well-known`, before
any pin is read), then pinned and cached as before. A source without `txt` (the tests' fakes, the e2e harness's
`allowInsecureHttp` source) asks no DNS.

**The guard at the origin** (`RecordSource.wellKnown(host, guard)`, `handleRecord(host, handle, guard)`): the resolver
hands its guard to the source, and `createRecordSource` asks `RelayGuard.connectTo(url)` for the address to connect
to (the literal, or the first public answer of the one lookup the guard judged; `GuardRefused` for a refused URL;
`resolve-failed` for a name with no answer), then `httpGet` connects to that address through node:https with a pinned
`lookup` (`autoSelectFamily: false`), so TLS still checks the host's name and no second DNS answer is used: no
DNS-rebinding window. A URL the guard allows outright (`allowPrivateRelays`) connects as the host resolves. The
test-only `allowInsecureHttp` source applies no guard, since the e2e harness's stubs are on loopback.

**Handles** (`Resolver.handle`, `recipient`, `addresses`, `handleOf`): `handle(h)` resolves the org record (step 1),
fetches `<origin>/.well-known/bag/handles/<local>.json` (404: `resolve-failed ... from handle: no such handle
at <host>`), verifies it with the core's `verifyHandleRecord` under the org record's key, which is the domain's pinned
key, and the org's `revoked` list, and caches it in the record cache (kind `handle`, `CacheKind`) under
`handle:<handle>`, and under `handle-of:<address>` for the display, until `min(now, iat) + ttl`; one audit line,
`resolve accept`, detail `{subject, kind: handle, source: <origin host>, handle, address, org, expires_at}`. A cached
binding is used until it expires and checked at every call against the freshest org record's `revoked` (`revoked`,
audited); a binding under a key the domain no longer pins (a countersigned rotation moved the pin) is resolved again.
Shown, not followed: a handle record that moves to another address replaces the binding only when the cached one
expires, never by an early refresh. `recipient(handle, hints)` reads the address's records at the org record's relays,
then the hints, then the edge's own (step 3), so `Sender.send({to: ['jane@acme.example']})` works as for an address.
`addresses(to)` resolves the handles of a list and returns the org relays as hints: the CLI and the MCP server call
it before they send; the Edge's gate resolves a handle itself (below, "What the gate inside changed"). `handleOf(principal, root)` returns `{handle, domain, verified:
true}` only when the cache holds, unexpired, a binding naming that address, signed by `root`, under the key the
domain is pinned to now; a handle is shown only for a peer this edge has resolved by handle.

**Lookup**: `lookup(handle)` reports the TXT step (`kind: txt`, `key` and `detail: origin <url>`), the org record at
the origin, the handle record (`kind: handle`, `key` the org, `detail: address <address>`), then the address's
records at the org relays, the hints and the edge's own, stopping at the step that fails; `lookup('domain:<host>')`
gains the TXT step. A `resolve-failed` from a step other than the relays reads `<subject> from <step>: <why>`.

## What the unreachable reason changed

**The outbox reason `unreachable`** (`sender.ts`, `outbox.ts`): a try whose relay gave no answer at all is `retry`
with the reason `unreachable`, where it was `publish-failed`, when the edge is opened with `unreachableReason: true`
(the CLI's edge is). No answer means the relay client threw a `RelayError` with status 0 and no code (the connection
was refused or timed out, a DNS or TLS failure, or a redirect, which the HTTP adapter refuses) or anything that is not a
`RelayError` (which the Sender has always read as no response). The target is retried with the same backoff to the
same horizon, ts + TTL, where it fails `publish-failed`, the outbox giving up (Appendix A). An answer without a code (a
proxy's 503) stays `publish-failed`, a relay's code stays its code, and the guard's refusal stays `resolve-failed`.
(Corrected 2026-10-25 15:01 UTC (16:01 Madrid): a redirect is an answer: the HTTP adapter
follows none and the try fails with the 3xx status, not as `unreachable`.)

```
publishing -> retry(next_at, unreachable)       no answer from the relay, unreachableReason on (else publish-failed)
           -> retry(next_at, publish-failed)    an answer without a code, before ts + TTL
           -> retry(next_at, <the relay's code>) a 408, a 429 or a 5xx with a code
           -> failed(publish-failed)            any failed try at or after ts + TTL
```

The audit line keeps a code of Appendix A as its `reason` (`publish retry publish-failed`) and names the cause in its
detail, `"cause": "unreachable"`, with or without the option: SPEC.md §9 item 8 allows only the closed set's codes,
and `parseAuditLine` refuses any other, so a line with `unreachable` would stop the edge from opening its own log.
`OutboxReason`, the type of a target's reason, is the closed set's codes and `unreachable` until SPEC.md Appendix A
names the code. The option is off by default because a consumer reports a target's reason as a code of the
closed set (the MCP server's `send`, whose tests pin `publish-failed`); once Appendix A names the code, the default can flip
and the MCP server can read `unreachable` as well. (Corrected 2026-10-25 15:02 UTC (16:02 Madrid): the MCP server turns it on, and
the library's default is on; `unreachableReason: false`
keeps `publish-failed`; the audit line is unchanged.)

**Chain renewal** (`Edge.renewChain(auth)`, the edge's call): swaps the chain the edge signs
under for a renewed one, for every later send, subscription and fetch, and returns the root, the principal, the
effective caveats and the new earliest `exp`. The core verifies the new chain at the edge's clock, to the edge's
signing key (`chain-not-to-sender`, `hop-expired`, `bad-hop-sig`, the shape codes); it must keep the root and the
principal (the first and the last hop's `iss`) and, when the mailbox is not the signing key, a hop from the mailbox key,
else `EdgeError` `chain-mismatch` (also for an edge that signs as its own root), and end later than the current chain,
else `EdgeError` `chain-not-later`. A refusal changes nothing. The swap writes one audit line, `rotate accept`, whose
detail names `chain:<signing key>`, the principal, the hop count, the caveats and the earliest `exp` before and after
(public data, no key material); `rotate` is the closest event of SPEC.md §9 item 8's closed list. An open subscription
keeps the hops it was opened with; the next one presents the new hops, so a relay that ends a subscription at its
chain's `exp` is answered by the resubscription with the renewed chain. The edge keeps its own copy of the
chain. `edge.auth` reads the current one. The MCP server renews today by replacing the hops of the array it
handed the Edge and presenting the current hops through its relay-client wrapper; it moves to this call in a later PR.

## What the receipt bound changed (added 2026-10-25 15:01 UTC (16:01 Madrid))

**The receipt bound** (`receiver.ts`, `spec/SPEC.md` §9 item 3): verify, then policy (the chain, the receipt bound,
a trusted root, revocation), dedup, unseal, caveats and type, route. The bound is `receiptBound(hops, skew)`, the
earliest `exp` over every hop plus `window.skew`, none for an empty chain; a row whose `received_at` is past it is
rejected `hop-expired`, its audit line naming `received_at` and `until`. The inbox row keeps the relay's stamp
(`Frame.receivedAt`) as its `received_at`, else this edge's first sight, so a retry or a restart meets the same
second: mail a relay received in time is not refused for being read late. Since 2026-10-25 15:02 UTC (16:02 Madrid)
`Edge.receive(relay, cursor, bytes, receivedAt?)` forwards a stamp
and `Edge.fetch` returns `FetchedBytes`, so fetched mail handed to `receive` is judged at its relay's stamp.

**The WebSocket adapter** (`adapters/ws-relay.ts`) takes the `env` frame as `{t, cursor, received_at, envelope}` with
`envelope` only as a JSON string, whose UTF-8 bytes are the bytes the relay stored and are verified as they are; an
object envelope (the raw embedding of older relays) or a `received_at` that is not a plain integer is
`bad-shape`. A frame with no `received_at` is taken, and judged at first sight.

**The HTTP adapter** (`adapters/http-relay.ts`): `fetch` returns the bytes with the answer's `AC-Received-At` as
their `receivedAt` (`FetchedBytes`, a property that does not enumerate), `bad-shape` when the header is not Unix
seconds; a 3xx is the relay's answer with its status.

## What the gate inside changed

**One place that gates.** With `policy.members` set, the Edge composes one outbound `Gate` over its Sender, and
`send`, `sendOrWait` and `reply` go through it: a recipient the deny list names is a `PolicyRefusal`
before anything is sealed, and a send the echo or fan-out breaker trips is held. `send` and `reply` throw `SendHeld`
for a held send, so their type stays `SendResult`; `sendOrWait` returns it, `{held: true, id, rule, ...}` (a
`HeldSend`), beside `SendResult` and `WaitingSend`. `held()`, `release(id)` and `drop(id)` wrap the gate's; release and
drop are a person's acts. The option `gate` passes the gate's `breakers`, `maxHeld`, `domainOf` and
`recipientPolicy`. Each send is judged once: a `Gate` a caller composes over an Edge that has a members record judges
it twice (and the fan-out breaker counts it twice), so callers send through the Edge, as the CLI, the MCP server,
the org-policy test and e2e scenarios 36 and 37 do. A send `sendOrWait` keeps waiting is judged when it is given and not
counted as a send; the flush that sends it later does not judge it again. Without a members record the Edge sends as
before: no breaker, nothing held.

**Read receipts** (`receipts.ts`; spec/SPEC.md §10). An optional profile above the core: a sealed
envelope of type `ac.receipt`, which neither the relay nor the core knows of. `send({receipt: true})` asks for one, with
the sealed body member `"ac.receipt": true`, so it needs a JSON object body. The `ac.` prefix of body members is reserved
for the protocol, and an unknown one is ignored. The reader decides: `receiptsTo`, the addresses it answers, is the
person's choice, read at each message, and absent means none. So a sender can ask and never compel, and a reader who has
not named the peer emits nothing, exactly as a reader who never read it or has no receipts, so the absence of a receipt
says nothing. A receipt's body is `{"ac.ack": id}` and nothing else: its authenticity is its own envelope's signature,
with no inner signature, which would only mint a proof of reading a sender could show anyone. Showing a receipt to a third
party takes the whole envelope, opened. The body carries no time, but the envelope's `ts` is the moment it was sent, so
the reader waits a jitter first (up to `RECEIPT_SPREAD_S`, 20 s; the option `receiptSpreadS`), which widens the window and
does not close it; a receipt in its jitter is in memory, so a process that ends first sends none. It goes out when the row
is accepted, through `sendOrWait` and so through the gate, and a group's mailbox sends none. At the sender it stops in the
receiver, before the accept list: one that names an envelope of this outbox sent to that reader is kept and the row is
`consumed`; any other is refused `type-not-accepted`. So a receipt reaches no session, rings no doorbell, and never asks
for or answers a receipt. `Edge.receipts(id)` lists `{reader, at}`, `at` being its arrival here.

**A handle before the deny list.** The gate resolves a handle in `to` before it judges: a `domain:<host>` entry matches
a handle under that domain before any lookup of the domain's records; then `Resolver.handle` binds the handle to its
address, and the address entries, the recipient's scopes, the breakers, the held send and the Sender see the address,
the binding's relays first among the hints. A refusal's audit line names `to` and `handle`.

**`revoked` ends a subscription.** `revoked` joins `REFUSALS` beside `hop-expired`: a relay that refuses a revoked hop
at subscribe, or ends a live subscription with `revoked` (close 4001), is
refused three times in a row and the run ends as for any refusal (`subscribe reject revoked`, `subscription-ended`,
`onError`), instead of resubscribing forever.

**The membership hop** (`GroupAdmin.add`) lives 7 days by default (the core's `MEMBERSHIP_SECONDS`, 604,800 s, 86,400 s
before), the relay's cut ending a removed member's reading at once.

## What the threads prune changed (added 2026-10-29 03:30 UTC (04:30 Madrid))

Before this branch the `threads` table only grew: every bind and register left a row, and nothing deleted one. Each
A2A bridge call, GetTask polls included, left a row on both edges.

- **Last use.** `threads` gains a nullable `used_at` (added in place to an older store). `threadSet` writes it,
  `threadTouch` refreshes it, and the router calls `threadTouch` when it binds a thread that is already bound and when
  it routes a message on a bound thread, queued or delivered. A row from before the column counts its `created_at`.
- **Prune.** `threadsPrune(before)` deletes the rows last used before `before`. `Edge`'s tick runs it beside
  `seenPrune`, at the start and on every timer tick, with `before` = now - (2 x TTL + skew) (the edge's `window`; 14
  days and 300 s at the spec defaults). The factor is 2 because a peer may read our message as late as its TTL and
  reply then, and that reply may wait out its own TTL at the relay while this edge is down; the tick at the start
  runs before the receiver drains.
- A thread pruned and then reached by a reply behaves as any unbound thread: a root goes to the default handler, and
  a reply is queued.

## What partial publish changed (spec/SPEC.md Appendix B 110, 2026-10-31)

**Offer-to-all** (`offer.ts`): `offerRecord` offers a record to every relay in turn and returns `{held, lagging, first}`;
a relay's failure stops no other. `heldSomewhere` throws the first failure when no relay took it, which is what a step
that needs one relay asks. `Lagging` is `{relay, kind, code, revokes}`, the code the relay's, `unreachable` for no
answer, `http-<n>` for a status with no code, `error` otherwise. `staleHolds` counts stale-record as held, for bytes
offered again and a peer's record; a record that means to replace one leaves it a laggard, so `admit` never passes over
a newer accept-from unseen.

**Rotation** (`KeyRecordAdmin.rotate`) marks the epoch published once a relay holds each record and returns `lagging`;
when none takes one it throws and the epoch stays unpublished, as before. `offerBehind` offers a record signed before
to the relays that do not read back as holding it (its kind, signer and iat, checked by the core) and never throws for a
relay. `record keep` calls it with `publishedKeyRecord`, or a relay that missed a rotation would wait for the next
epoch; the MCP keeper does the same on its own read-backs. A relay that holds the record costs a read and no publish: a
stale-record still counts against the relay's limit per client address, which is what scenario 54 met.

**Pairing** (`pairing.ts`) needs the rendezvous, which holds the invitation now, the one-time identity and its mailbox as
well as the nameplate (`Inviter.rendezvous`, by default its first relay), and fails closed without it, and one listed
relay beside it: a first relay that is down no longer fails a ceremony whose rendezvous is up. The inviter puts its own
records at the rendezvous too, listed or not, where the acceptor reads them. `PairingPorts.lagging` hears of each relay that did not take this identity's record, never a peer's. `newest`
reads what answers and throws only when none does, which also ends a wait that a peer's down relay held up to
`no-answer` though the other relay showed the admit. `ownAddress` goes to the relays the home's copy lists when its first
relay gives no answer. Limit: an accept-from re-signed while the relay holding the newest one is down is signed from
the newest that answers, so a root only that relay holds is dropped from it: it fails safe, `root-not-accepted`, but it
takes a pairing again to mend.

**Incomplete revocation**: `Lagging.revokes` is true for an address record with a non-empty revoked list, since a relay
honours only the list it has stored (§8.7). A caller reports that as a security gap, not a benign not-yet, naming the
relay, with `INCOMPLETE_REVOCATION`.

## What the fetch audience changed (spec/SPEC.md §8.3, 2026-11-02)

`Edge.fetch(url, id)` signs `["ac/fetch/1", signer, id, ts, audience]` with the core's `signFetchAuth`, `audience`
being `url` byte for byte: the relays entry as the caller holds it, with nothing added or stripped (the HTTP adapter
drops trailing slashes from the request's path only, never from what is signed). A relay checks the audience against
its own base URLs, which are scheme and authority alone, and refuses any other, so a proof captured at one relay is
`bad-auth` at another. The four-field proof of before is refused too: relays and clients changed together, with no
window that accepts both. A fetch beside a chain (`AC-Auth`) signs the same five fields. No header carries the
audience, so a `RelayClient` sends a proof only to the relay its `url` names.

## The machine's telemetry: consent, the spool, the report and the sender (2026-11-02, the sender 2026-11-03)

`src/telemetry.ts`, `src/telemetry-report.ts`, `src/telemetry-schema.ts` and `src/telemetry-send.ts`, after
`spec/SPEC.md` Appendix B 111 and the telemetry design note (§2 to §5). Opt-in, with one consent and one install id
per machine, whatever the identity's home. While it is on, each finished UTC day's report goes once to
telemetry.bag.dev; `telemetry-send.ts` is the only file with network code.

- **The machine's directory**: `telemetryDir(env)` is `HOME/.bag`, read from the `env` the caller passes, never from an
  identity's home (`--dir`, `AC_HOME`). A test or an e2e process points it elsewhere with `HOME`. Without `HOME` there
  is no directory, and telemetry is off.
- **Consent and the id**: `telemetry.json` there, `{"version":2,"telemetry":"on","id":"<32 hex>","since":"<date>"}` or
  `{"version":2,"telemetry":"off"}`, 0600, written only by `setTelemetry(dir, choice, rng, now)`. `on` keeps the id and
  its date or draws 16 bytes from `rng`, never from the machine, a user or a path, and dates the choice; `off` drops
  both and deletes the spool, the sender's mark and the pairs snapshots, with no network call. A version-1 choice,
  made before the `pairs` family, reads as off with the reason `old-file`, and the notice asks again (the red team's
  Q2, 2026-11-03). `telemetryOn(env)` is the per-machine check (the variables first: `AC_TELEMETRY=off`,
  `DO_NOT_TRACK` and `CI` turn it off, never on); `telemetryState(env, dir)` adds the reason and the choice. C0's use
  of `telemetryState`, `telemetryNotice` and `setTelemetry` with an identity's home as the directory is deprecated.
- **The notice**: `machineTelemetryNotice(env, preview)`, once per machine (it makes `telemetry-noticed-2`
  exclusively, and the directory 0700 when missing), names the command that prints the report. No notice names `ac
  telemetry on`.
- **The `pairs` family** (`src/telemetry-pairs.ts`): a snapshot, never a spool count. For each finished day from the
  consent's date, a process that opens an identity (the CLI's `openEdge`, the MCP server, the bridge) writes the
  identity's four counts to `telemetry-pairs.json`: the address roots of the home's `trust.json` under 7 days old at
  the day's end or older, and of each, those its outbox sent to in the 7 days before, never before the consent's date
  (`SqliteStore.outboxBetween`, read only). Rows are keyed by 16-hex SHA-256 prefixes of the home's realpath and the
  identity's name, which never leave the machine. `withPairs` gives a report the largest of a home's identities,
  cell by cell, summed over homes and floored as every count; a long-running server's identities are written again
  before each try of its sender (`trackPairs`).
- **The spool**: `telemetry-counts.jsonl` beside the consent, 0600 and append-only, one line per flush:
  `{"v":1,"day":"<YYYY-MM-DD>","counts":{...}}`. `counts` is in the report's shape, the schema's member names keyed as
  the schema keys them, with raw counts at the leaves (a duration family: its key, then five counts in
  `SETS.duration`'s order). `addTelemetryCounts(env, day, counts)` is the one writer, for every package. It is a no-op
  unless telemetry is on and never throws; it stores every key outside its set as `other` and leaves out anything
  that is not a member, a key or a positive integer, so the file holds the schema's values only. Each line is one
  append under 4 KiB (`O_APPEND`, no lock). Past 256 KiB a writer folds the file: it takes it by renaming it
  (`takeSpool`), sums its lines by day, and writes back the days from seven before today to the day after.
  `readTelemetrySpool(dir)` sums every line by day: every home's counts, from every process.
- **The tally**: `startTelemetry(env, clock)` and `stopTelemetry()` bracket a process's counting (the CLI's `run` for
  each command line; a server once). `countTelemetry(member, keys)` and `countDuration(member, key, ms)` add to it;
  it is written at the first count a minute after the last write, else by a timer a minute after a count that did not
  write (so a server that goes quiet before midnight has the day written before 01:05), and at stop. While it is off a
  hook costs one comparison. The hooks: `Audit.record` (event, decision and reason, nothing else of the line); the HTTP and WebSocket
  relay clients (`relays` by the relay's name, `relay_errors` by name and code; the name is `relay1` or `relay2` for
  the two public relays, else `other`, never a URL); `invitePeer` and `acceptPeer` (`pairing` by outcome code).
- **The report**: `buildTelemetryReport(day, cells, facts)` builds exactly one schema-1 report: the members in the
  schema's order; each count family within `MAX_CELLS`, its largest cells less one kept and the rest summed into
  `other` at every level; each duration family within `MAX_KEYS`, likewise, bucket by bucket; every count bucketed to
  the largest power of two not above it, at most 2^19; ties in the sets' order, so the same counts make the same bytes.
  `build` is the package's npm version (`BUILD_INFO`), or from source the checkout's commit, when `BUILDS` lists it,
  else `other`; `node` is the major from the list, else `other`; `host` is the kind with the most of the day's MCP
  sessions, `other` on a tie or with none. `telemetryReport(env, day)` is the
  preview: the machine's spool for the day under its id, or `PREVIEW_ID` (32 zeros) before `on`.
- **The schema's copy**: `src/telemetry-schema.ts` copies `deploy/telemetry/src/schema.ts` and `builds.ts`, and
  `MAX_BYTES` of its `index.ts`, at `TELEMETRY_SCHEMA_COMMIT` (a1daf96f). The public cut carries `packages/` and never
  `deploy/telemetry/`, so the edge cannot import the Worker's file. `test/telemetry-report.test.ts` imports the
  Worker's files wherever the checkout holds them, fails on any difference, and runs the Worker's `checkReport` on the
  reports it builds.
- **The sender** (`src/telemetry-send.ts`; the W6 design note in the operations records, reviewed by the red team on
  2026-11-03). `sendDueTelemetry(env, clock, {fetch})` makes one try when one is due (`telemetryDue`: telemetry on,
  01:05 UTC passed, a spool, and yesterday not yet taken). It takes the spool's finished days by `takeSpool`, at most
  seven back, writes the mark `telemetry-sent` (yesterday's date), then POSTs each day's report, oldest first, to
  `https://telemetry.bag.dev/v1/report`: the bytes `telemetryReport` previews, with the content type the only header
  it sets, `redirect: 'error'`, and one 2 s budget for the whole try. Before each request it reads the switch and the
  id again (the privacy review's E7). A day goes after one try, whatever the answer; nothing of an answer is shown,
  logged or counted, and it never throws. `startTelemetrySender` is a long-running process's: a try now and hourly,
  its stop aborting a try in flight. `eraseTelemetry(env, id, {fetch})` posts `{"id"}` to `/v1/erase`. The caller
  passes the fetch, so code without one sends nothing. `AC_TELEMETRY_URL` replaces the endpoint only with an http URL
  whose host is exactly `127.0.0.1` or `::1` (a test's); any other value sends nothing.

## A corporate proxy (2026-11-03)

`src/proxy.ts`. HTTPS_PROXY, HTTP_PROXY and NO_PROXY are read in either case, the lowercase name first.
- **Re-run.** Node 24's fetch and WebSocket use them only when `NODE_USE_ENV_PROXY` is set as the process starts
  (measured on 24.4.1; set later, it changes nothing). So `useEnvProxy()`, the first call of the CLI's, the MCP
  server's and the bridge's main.ts, runs the process again once through `process.execve` with
  `NODE_USE_ENV_PROXY=1` and the guard `AC_PROXY_REEXEC=1`. That keeps the same pid, arguments and stdio, and it
  never loops.
- **What it covers.** The relay client, the subscription and telemetry then go through Node's own EnvHttpProxyAgent
  by CONNECT. Without `process.execve` it returns the line asking for `NODE_USE_ENV_PROXY=1`.
- **NO_PROXY.** `bypassed(list, host, port)` reads it as Node does, from a table measured against Node's agent.
- **Display.** `proxyShown` and `proxyStatus` show a proxy as `scheme://host:port`, never its user or password.
- **The well-known GET.** `src/adapters/well-known.ts`, `originGet(env)`: node:https, which the variable does not
  reach. Behind a proxy it opens a CONNECT tunnel to the address the private-address guard checked, never the name,
  with the TLS name the host's. A proxy's refusal is `resolve-failed` naming the proxy and its answer, and there is no
  retry by name, which would let the proxy resolve a hostile record to an internal host. A proxy's user and password
  go only in `Proxy-Authorization: Basic`.

## Ports and adapters

| port | what it is | adapter |
|---|---|---|
| `Clock` | Unix seconds | `systemClock` |
| `Rng` | random bytes | `systemRng` (node:crypto) |
| `KeyStore` | the signing and sealing keys, by name (`load`, `save`); kept for its users | `FsKeyStore`: `<dir>/<name>.json`, 0600 in a 0700 directory |
| `KeyCustody` | a custody of identities: `kind`, `list`, `entry`, `create`, `signer(address)`, `opener(address)`; `KeyEntry` is public data only | `FsKeyStore` (`file`); `KeychainCustody` (`keychain`: one macOS keychain item per identity through `/usr/bin/security`, a pointer `<home>/keychain/<name>.json`) |
| `Signer`, `Opener`, `KeyPair` | what a custody gives: `sign(message)` with its `address`, `open(enc, info, aad, ct)` with its `publicKey`; `EdgeKeys` is `KeyPair<SigningKey, SealingKey>` | the core's `SigningKey` and `SealingKey`, from either custody (a seedless signer waits for a core change) |
| (a home) | which custody holds a name, chosen at keygen | `HomeCustody(home)`: `keys(name)`, `list()`, `create(name, keys, target)`; `EEXIST` for a name both hold |
| `EdgeStore` | outbox, outbox_targets, inbox, seen, threads, pins, record_cache, audit_anchor | `SqliteStore` (node:sqlite, WAL; holds the writer lock of its directory) |
| `RelayClient` | publish, fetch, fetch a record, subscribe | `createRelayClient()`: global `fetch` and `WebSocket`, at most `RELAY_TURNS` (4) calls and upgrades at a relay at once; a process with several clients gives them one `RelayTurns` |
| `RecordSource` | well-known records and relay records | `createRecordSource(client)` |
| `AuditSink` | append-only lines, a name for the anchor, all lines to check it | `FsAuditSink` (JSONL, 0600) |
| `SpawnHook` | spawn-on-arrival, an interface only | none: v0 spawns nothing, and queues |

## How the CLI and the e2e harness compose it

```ts
import { codingEvaluator } from '@usebag/core'
import { createRelayClient, Edge, FsAuditSink, FsKeyStore, SqliteStore, systemClock, systemRng } from '@usebag/edge'

const edge = new Edge({
  keys: new FsKeyStore(`${home}/keys`).load('me'),
  store: new SqliteStore(`${home}/edge.sqlite`),
  relays: { client: createRelayClient(), urls: [relayUrl] },
  policy: { roots: [{ domain: 'acme.com' }], types: ['coding.*'], evaluators: [codingEvaluator] },
  clock: systemClock,
  rng: systemRng,
  audit: new FsAuditSink(`${home}/audit.jsonl`),
})
edge.setDefault({
  session: 'inbox',
  deliver: async (m) => {
    await edge.reply(m, { type: 'coding.result.v1', body: {} })
  },
})
await edge.start() // subscribes at every relay, publishes due outbox targets on a timer
await edge.send({ to: [peer], type: 'coding.task.v1', body: { repo: 'bag' }, session: 'inbox' })
```

The CLI maps its commands onto the same calls: keygen is `generateEdgeKeys` and `FsKeyStore.save` (corrected
2026-10-25 15:01 UTC (16:01 Madrid): `generateEdgeKeys` and `HomeCustody.create`; a command that signs or opens loads keys with
`HomeCustody(home).keys(name)`, `address` reads `HomeCustody.entry` and `keys list` `HomeCustody.list`), record is the
core's `signRecord` and `edge.publishRecord` (which returns each relay's
`{kind, signer, iat, valid_until}` or null from a relay that answers `{"ok": true}` alone), send and inbox are `edge.send` and `edge.inbox`, and audit verify is
`verifyAuditLog(readAuditLines(path))` with `checkAuditAnchor` against `readAuditAnchor` of the `edge.sqlite` beside
the file. `record keep` composes no edge: it reads the identity's own records with the relay client's
`fetchRecord`, signs them again with the core's `signRecord` and republishes them with the client's `publish`, so it
opens no store and takes no writer lock. The e2e harness points `urls` at the relay process it started and reads its
well-known stub with `records: createRecordSource(client, { allowInsecureHttp: true })`, an option for tests only. A
session that signs for a principal passes `keys: { signing: session, sealing: principal's }`, `mailbox` (the
principal) and `auth` (the chain to the session); replies address the principal.

## Tests

`npm test -w packages/edge` (Vitest, the 90 floors on all four metrics). `test/support/` holds the fakes: a fake clock,
a seeded rng, an in-memory relay, a scripted relay, an in-process HTTP server and a minimal RFC 6455 server, so the
WebSocket adapter runs against the real global `WebSocket` too. Temporary files go under `AC_TEST_TMP` and are removed
unless `AC_KEEP_TMP=1`.

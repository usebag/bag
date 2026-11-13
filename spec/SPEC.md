# bag v0 specification

*Pre-release draft of bag v0. It covers the Rust relay, the signed records, the agent seat (§13), pairing (§8.10) and many
identities in one server. Where a point is not otherwise settled, this document chooses and marks the choice
"(implementation default)"; Appendix B lists every one for review.*

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in BCP 14 (RFC 2119, RFC 8174)
when, and only when, they appear in capitals.

Implementations: `packages/core` (TypeScript; §2 to §7 in full), `crates/ac-core` and `crates/ac-relay` (Rust;
verification and the relay of §8, no HPKE and no caveat evaluation), and `packages/edge` (TypeScript; §9). The test
vectors of §11 bind all of them: an implementation conforms when it reproduces every vector that covers its part.
(Changed 2026-10-25: the vectors now hold the strict refusals of §2.3 and §2.5 as well, the degenerate keys,
S at or above L, the encodings of R, the mixed orders, duplicate member names and numbers that are not plain integers,
so an implementation that misses one fails a vector; until then a verifier on `cryptography` alone reproduced every
vector and accepted R = the identity, S = 0 under the identity key.)

## 1. Scope and terms

This specification defines bag v0. Its frozen core (L0) is the formats and preimages that travel on the wire
and that signatures cover, so that changing one needs a new wire version: the canonical form every signature covers
and the signature rule (§2), the `ed25519:` address format (§3), the envelope and its sealed part, the authority chain
and its caveats, and the signed records that relays store (§4 to §7), and the request preimages of §8.3, §8.5 and
§8.10. It also defines the relay API (three calls a relay must offer — publish, subscribe and fetch — and the two optional
pairing-rendezvous calls of §8.10) and what an edge must do; the relay's behaviour and limits (§8) and the edge's
requirements (§9) are pre-release and may change in place until v1 without a new wire version (narrowed 2026-11-01 to match the cut's README and CONTRIBUTING). It does not define presence, discovery, payload schemas, capability negotiation, group
semantics, wake, payments or user interfaces (§12, an L2 section outside the frozen core, defines how an org's records
are found through DNS and handles, names for addresses under an org's domain; presence and any directory of addresses
stay out). An implementation of §2 to §9 conforms without §12. The MCP edge is included in this release. Deferred, and
not in v0: deriving a sealing key from an Ed25519 key, the org relay's smarthost role, persistent rate counters, and
any Buzz bridge.

| term | meaning |
|---|---|
| address | the public name of a key: `ed25519:` and the 32-byte Ed25519 public key in hex (§3) |
| signing key | an Ed25519 key pair; its public key is its address |
| sealing key | an X25519 key pair, separate from the signing key, published as `sealing_key` |
| envelope | the unit of delivery (§5): outer members that relays see, and a sealed part they cannot read |
| content key | the 32-byte AES-256-GCM key of one envelope's sealed content (§4) |
| wrap | one recipient's copy of the content key, HPKE-sealed to its sealing key (§4) |
| hop | one signed grant: `iss` grants to `sub`, under the caveats the hop adds, until `exp` (§6) |
| chain | an envelope's `auth`: hops from a root to the sender; `[]` when the sender is its own root |
| root | the first hop's `iss`, or the sender for an empty chain; an org's root is anchored at its domain (§7) |
| principal | the key the chain names as acting through the sender: the last hop's `iss`, or the sender (implementation default) |
| session | a short-lived key that signs envelopes for a principal; by convention it signs and does not receive |
| caveat | a string predicate that must hold; the effective caveats are every hop's, in chain order |
| evaluator | a profile's judge of the caveats of its grammar (§6) |
| record | a signed address, accept-from or key record (§7) |
| handle | a name for an address under an org's domain, `<local>@<domain>`, bound by a handle record the org signs (§12.3, L2) |
| relay | a store-and-forward server with the API of §8: no semantics, but it enforces the mailbox owner's policy |
| mailbox | the queue a relay keeps for one address |
| edge | the agent-side library that sends, receives, verifies, unseals, evaluates and routes (§9) |

Every byte field is lowercase hex: keys and hashes are 64 characters, signatures 128. `ts`, `exp`, `iat` and
`ttl` are Unix seconds. JSON is RFC 8259. A canonical integer is an integer from 0 to 2^53 - 1.

## 2. Canonical form

The canonical form is a fixed-position JSON array, hashed with SHA-256.

**2.1 Values.** A canonical value is a string, a canonical integer, `null`, or a list of canonical values. Nothing else
has a canonical form: a fraction, a negative number, a number over 2^53 - 1, `true`, `false`, an object, or a string
that holds a lone surrogate. An implementation MUST refuse such a value (`bad-canonical`).

**2.2 Writing.**
- A list is `[`, the canonical forms of its items separated by `,`, and `]`, with no white space.
- An integer is written in decimal, with no sign, leading zero, fraction or exponent. `null` is `null`.
- A string is `"`, its characters, and `"`. Exactly these are escaped: `"` as `\"`; `\` as `\\`; U+0008, U+000C,
  U+000A, U+000D and U+0009 as `\b`, `\f`, `\n`, `\r` and `\t`; every other character from U+0000 to U+001F as
  `\u00xx`, with lowercase hex. Nothing else is escaped: not `/`, not U+007F, not U+2028 or U+2029, nothing outside
  ASCII. Nothing is normalized: a precomposed and a decomposed character stay distinct.

This is what ECMAScript's `JSON.stringify` writes for these values, and what Python's
`json.dumps(value, separators=(',', ':'), ensure_ascii=False)` writes. The vectors (§11) show both byte for byte.

**2.3 Digests and signatures.** The digest of a preimage is `sha256(utf8(canonical(preimage)))`, 32 bytes. Every
signature in this specification is Ed25519 (RFC 8032) over the 32 digest bytes of its preimage. An envelope's id is
that digest in hex, so its `sig` is over the 32 bytes of its id.

A signature (R, S) by the key A over the message M verifies only when, in this order (changed 2026-10-25;
until then §10, "Malleability", stated it): A and R are canonical encodings, their 255-bit y, the sign bit
aside, below p = 2^255 - 19; neither is one of the eight points of small order, the identity, the point of order 2, the
two of order 4 and the four of order 8, whatever its sign bit; S, read little-endian, is below L, the order of the prime
subgroup; and the cofactorless equation [S]B = R + [k]A holds, with k = SHA-512(R || A || M) mod L, checked by comparing
the 32 bytes of R with the encoding of [S]B - [k]A. A signature that fails any of these fails with its place's code:
`bad-sig`, `bad-hop-sig`, `bad-record-sig`, or a rotation's `bad-rotation`. A cofactored check, [8][S]B = [8]R + [8][k]A, is
not this rule: it accepts signatures with an R or A of mixed order (a point of the prime subgroup plus one of small
order) that the cofactorless equation refuses. Mixed order is not itself a reason to refuse: no check before the
equation looks at it, as one does at a non-canonical or small-order point, and the cofactorless equation alone decides.
So a signature under a mixed-order key A verifies exactly when [k] takes A's small-order part to the identity, one time
in eight for a point of order 8 (implementation default, what every reader of this repository does), and a signature
whose R has mixed order under a key of the prime subgroup never verifies, since [S]B - [k]A is then in the prime
subgroup. §11's vectors pin each case: a mixed-order `iss` with k = 0 mod 8 verifies (`chain-valid.json`); a
mixed-order `iss` or `from` with k not 0 mod 8, and a mixed-order R, fail (`chain-invalid.json`, `envelope.json`). An
implementation MUST verify with this cofactorless, strict rule: it MUST reject every non-canonical or small-order `R`
or `A`, and every signature whose cofactorless equation fails, a signature with a mixed-order `R` or `A` that a
cofactored or batch check would accept among them; and it MUST NOT reject a signature only because its `R` or `A` has
mixed order when the cofactorless equation holds (clarified 2026-11-03: this sentence read "MUST reject a ...
mixed-order `R` or `A` that a cofactored or batch check would accept", which could be taken to refuse every
mixed-order point; the code and the vectors have always let the equation decide). A verifier that accepts what this rule rejects is non-conforming,
because identity, deduplication and rotation all rest on one signature verifying under exactly one key; a cofactored
third-party verifier would split validity, accepting an envelope or record the reference refuses (added 2026-11-01; the reference is already strict).

**2.4 Position tables.** Position 0 of every preimage but the envelope's is a string domain tag, so a signature made for
one kind of object cannot be replayed as another; position 0 of the envelope's is the integer `v`.

| object | preimage | signed by |
|---|---|---|
| envelope id | `[v, to, from, auth, suite, ts, sealedHash]`, with `auth` written `[[iss, sub, caveats, exp, sig], ...]` | `from`, over the id |
| hop | `["ac/hop/1", iss, sub, caveats, exp]` | `iss` |
| sealed hash | `[wraps, nonce, ct]`, with `wraps` written `[[to, enc, ct], ...]`; position 6 of the id preimage is `sha256hex(utf8(canonical(this)))` | hashed only |
| address record | `["ac/addr/1", key, sealing_key or null, relays, rotation_key or null, revoked, ttl, iat, rotated_from or null]` | `key`; a rotation also by the previous key or its rotation key (§7.3) |
| accept-from | `["ac/accept/1", owner, roots, max_bytes, ttl, iat]` | `owner` |
| key record | `["ac/key/1", key, sealing_key, iat, exp]` | `key` |
| handle record | `["ac/handle/1", org, handle, address, iat, ttl]` (added 2026-10-26; §12.4, L2) | `org` |
| subscribe response | `["ac/sub/1", nonce, signer, mailbox, cursor or null]` | `signer` |
| fetch auth | `["ac/fetch/1", signer, id, ts, audience]` (`audience` added 2026-11-02; §8.3) | `signer` |
| pair/open | `["ac/pair-open/1", inviter, invitation, relays, ttl]` (§8.10; added 2026-11-01; clarified 2026-11-03: position 3 is the open's list `relays`, 1 to 64 relay URLs each listed once, as signed and checked, where this row read `[relay]`) | `invitation` (the one-time invitation key) |
| audit line | `[seq, prev, ts, event, decision, reason, id or null, from or null, root or null, detail or null]` | hashed only (§9) |

§13.1 defines one local preimage, tag `ac/agent/1`, never on the wire; its tag differs from every tag above.

The pairing ceremony (§8.10) also takes position 0 as a domain tag in three constructions that are not signatures, listed here for completeness (added 2026-11-01): `ac/peer-code/1` is the HKDF `info` that derives the invitation MAC key `S` and the position-0 tag of the check-digit hash `sha256(canonical(["ac/peer-code/1", inviter, invitation, requester, sealing, S]))` (§8.10); `ac/peer-request/1` is the position-0 tag of the request MAC `HMAC-SHA256` under `S` over `canonical(["ac/peer-request/1", inviter, invitation, requester, sealing, exp])`; `ac/peer-invite/1` is the position-0 tag of the invite string `base64url(canonical(["ac/peer-invite/1", inviter, invitation, relay, S]))`, which carries `S` in the clear and is not signed. In these three preimages (clarified 2026-11-03) `inviter`, `invitation` and `requester` are addresses (§3.2); `sealing` is the requester's X25519 public key as 64 lowercase hex characters; `S` is written as a string of its 32 lowercase hex characters, and is keyed into the HMAC as its 16 bytes; `exp`, the invitation's end, is a canonical integer; and `relay` is one relay URL, a string, unlike the list `relays` of pair/open. §8.10, "The invite string and the pairing request", gives each field's source, and `pair-code.json` (§11) pins each construction. All four pairing tags differ from every tag above and from each other.

**2.5 Reading JSON.** Envelopes, records and sealed contents travel as UTF-8 JSON text. A reader MUST reject
(`bad-json`) bytes that are not UTF-8, text that is not one JSON value, a leading byte-order mark, and a string or
member name that escapes a lone surrogate (implementation default: such a string has no canonical form, and some JSON
readers cannot hold it). Writers MUST write integers as plain decimals. A reader MUST reject a number that is not
written as a plain decimal integer (`0` or `[1-9][0-9]*`) wherever this specification expects a canonical integer; the
sealed `body` is exempt (§4.2). (Changed 2026-10-25; was: a reader whose parser reports 1.0 as 1 may accept
it.) It rejects the number with the code of the place that reads it, as for a value of the wrong type (§5.4 steps 4, 5
and 11: `bad-version`, `bad-suite`, `bad-shape`; `bad-hop` in a hop; `bad-record` in a record), so `1.0`, `1e0`, `-0`,
`-1`, `0.5`, `1e-400` and `9007199254740990.9` are each refused, never rounded to an integer; `01` is not JSON, and a
number past the range of an IEEE 754 double, such as `1e400`, is `bad-json` (implementation default). A member name MUST
NOT appear twice in an object written by a conforming writer, and a reader MUST reject an object that names a member
twice, in every text a peer sends, the sealed content included, with the code of the place that reads it: `bad-json`,
and `bad-content` for the plaintext of §4.2. Two names are one when their decoded strings are equal, so `"a"` and
`"\u0061"` are one name. (Changed 2026-10-25; was: readers SHOULD reject duplicates, and the TypeScript
reader, which uses `JSON.parse`, keeps the last. Because the sealed content is parsed and never canonicalized, two
readers keeping different members would both accept one envelope with different meanings, §10.) This section sets no
JSON nesting limit: a nesting limit is an implementation default (the reference relay's, Appendix B 31), not a core
requirement, and a conformant reader need not impose one.

## 3. Identity and addresses

**3.1 Suites.** A suite fixes the algorithms of identity and sealing. v0 has one:

| suite | address prefix | signatures | sealing: RFC 9180 base mode |
|---|---|---|---|
| 1 | `ed25519:` | Ed25519 (RFC 8032) | DHKEM(X25519, HKDF-SHA256) (kem 0x0020), HKDF-SHA256 (kdf 0x0001), AES-256-GCM (aead 0x0002) |

An envelope carries its suite as the integer `suite`, and an address carries its identity suite in its prefix, so a
second identity suite (secp256k1) adds a prefix and a verifier, not a rewrite. A post-quantum suite would be a
new suite number. A reader MUST reject a suite it does not know (`bad-suite`).

**3.2 Addresses.** An address is `ed25519:` followed by the 32-byte Ed25519 public key as 64 lowercase hex characters,
and nothing else. A string with another prefix, upper-case hex, another length or any further character is not
an address (`bad-address`). Addresses are public by design; they may be printed and logged.

**3.3 Keys.** A signing key is the 32-byte Ed25519 private key of RFC 8032 (its seed). A sealing key is a 32-byte X25519
private key (RFC 7748), whose public key is published in hex as `sealing_key`. They are separate keys: v0 key
generation makes both, each from 32 bytes of a cryptographically secure random generator (CSPRNG). An
implementation MUST NOT print, log or return a private key except to a key store. **Carve-out: the
recovery sheet (added 2026-11-01).** The one exception is the recovery sheet that `ac
init` and `ac init --reprint` print — an identity's signing and rotation seeds — for the person to copy by hand and
keep offline. It MUST be written only to an interactive terminal, never to a pipe, a file,
an API return or a log, and SHOULD be shown once and gated by a typed-back checksum. This is the one place a private
key leaves the key store to a human, bounded to that out-of-band act; §9 item 9's "the CLI prints addresses only" and
§10 are read with this carve-out, and everywhere else the MUST NOT above holds in full.

Any key may be an address. By the principal-mailbox convention, principals receive and sessions only sign:
`from` is the session key, the chain names the principal, and replies go to the principal.

## 4. Sealing, suite 1

**4.1 HPKE.** Sealing uses RFC 9180 in base mode (mode 0x00: no PSK, no sender authentication) with suite 1's KEM, KDF
and AEAD, single-shot: SealBase(pkR, info, aad, pt) returns `enc` (32 bytes) and `ct`, and OpenBase(enc, skR, info,
aad, ct) returns `pt`, both at sequence number 0. A small-order X25519 public key gives an all-zero Diffie-Hellman
output, and the KEM MUST then abort (RFC 9180 §7.1.4). The RFC 9180 subset of §11 pins the construction.

**4.2 The plaintext.** The sealed content is the JSON object `{"type": ..., "thread": ..., "body": ...}` (§5.2). Its
plaintext is that object as UTF-8 JSON text, written as `JSON.stringify` writes `{type, thread, body}`, with no white
space. Because the plaintext is sealed, it is never hashed or signed: the id commits to the sealed hash
over the wraps, the nonce and the ct (§5.3), not to the plaintext, which a recipient only decrypts and re-parses and
no other party re-serializes, so its exact bytes are the sender's alone and a sender in another language MAY write
different bytes for the same logical content without moving the id or breaking interoperability. It is parsed, never
canonicalized, so `body` may hold any JSON value, fractions and booleans
included. A `body` keeps its value from one language's reader to another's only as I-JSON (RFC 7493): numbers that an
IEEE 754 double holds exactly, member names given once (which every reader requires, §2.5), and strings of Unicode
scalar values. Outside it two readers may read different values: `9007199254740993` has been read as
`9007199254740992`, `1.0` as `1` and `1e+16` written back as `10000000000000000`. A writer that needs a `body` read
alike everywhere keeps it within I-JSON. (Added 2026-10-25.)

**4.3 One envelope, many recipients.**
1. The sender draws a content key (32 bytes) and a nonce (12 bytes) from a CSPRNG, fresh for each envelope.
2. `sealed.ct` = AES-256-GCM(content key, nonce, aad = utf8(canonical([v, to, from])), plaintext), with the 16-byte tag
   appended. The AAD binds the ciphertext to the envelope's version, recipients and sender.
3. For each address in `to`, in order: (enc, ct) = SealBase(that recipient's sealing key, info = utf8("ac/seal/1"),
   aad = utf8(the recipient's address), pt = the content key), with a fresh ephemeral key. The wrap is
   `{"to": address, "enc": hex(enc), "ct": hex(ct)}`; its `ct` is 48 bytes, the key and the tag (checked exactly:
   implementation default). The AAD binds the wrap to its recipient, so a wrap moved to another does not open.
   That sealing key is the `sealing_key` of the recipient's current key record (§7.4) when it publishes one, else the
   non-`null` `sealing_key` of its address record (§7.2); with neither, the send fails `resolve-failed` (§9 item 4,
   which also keeps a recipient once seen with a key record from falling back). An individual recipient (a principal
   or a session) publishes key records and a `null` address-record `sealing_key`, so it is sealed to its current key
   record. A group recipient is an identity whose members share one sealing key at a time; each such key is a
   *generation*, and the group publishes no key record: its address record's `sealing_key` is the X25519 public key of
   its current generation, its *generation key*, and the group is sealed to that. How a generation reaches the group's
   members is outside this core (§1 puts group semantics out of scope; the agent seat's `group-key`, §13.1, is one
   holder) (forward secrecy; added 2026-10-28, clarified 2026-10-29; clarified 2026-11-03: "generation key" defined
   here, from `packages/core/src/groups.ts` and the resolver of `packages/edge/src/resolver.ts`, where it was used
   undefined).
4. `sealed` = `{"wraps": [...], "nonce": hex(nonce), "ct": hex(ct)}`, with one wrap per recipient in the
   order of `to` (implementation default).

Every recipient gets the same content key, so all read the same content and the envelope has one id, whoever reads it.
(Changed 2026-10-25: this holds for an honest sender. A sender can give a listed recipient a wrap that does
not open, or that opens to another key, and that recipient reads `open-failed` while the others read the content; no
one else can tell. Suite 1 has no key commitment, which a plaintext that is not strict JSON would need: a ciphertext
made to open under two keys opens to pseudorandom bytes under one of them, and those do not read as the content of
§5.2, at least 114 bytes of JSON; §10.)
An envelope has 1 to 16 recipients. A recipient's address or key record may list up to 64 relays; the sender publishes the same bytes to at most K = 3 of
each recipient's relays, taken in the record's listed order, and fails over to the next listed relay when a target is
given up. The sender keeps at most K live targets per recipient at any time and never retries a retired target, so it
never sprays the whole list; the envelope then rests on those K relays plus any target retired after an ambiguous
timeout, which the recipient dedups by id (§9).

A target is live from the moment the sender picks it — one of the first K distinct relays in the record's listed
order — not from when it first answers; distinctness is by exact URL string, so two listed entries that differ as
strings (for example `https://a/` and `https://a`) are two targets (the relay URL form is §7.2's `relays` row). A target is given up when it returns a permanent
refusal — a 4xx status other than 408 and 429 (a 404 among them), which the same bytes would meet again — at once, or when it is
unreachable (no answer, a refused connection, or a timeout) after three attempts; a 408, 429 or 5xx keeps it live and
retrying to the horizon (§9 item 1). When a target is given up and a later listed relay is still free, the sender
retires the target and promotes that next listed relay, keeping at most K live; when none is free, the envelope fails
on that target (`publish-failed`) and rests on whatever targets remain live. A relay the edge's own policy refuses
before any send (a private or otherwise disallowed relay) is not a retirement: that target fails at once as
`resolve-failed`, kept for resend, and no relay is promoted in its place. The failover plan is kept beside the envelope
in the edge's outbox, so a later process of the same identity can promote a listed relay it has not yet tried: the plan
holds only routing fields (the listed relays and which are counted), never a key or any unsealed content, and it stays
on that identity's own outbox row, never pooled across identities. A one-shot CLI send still makes one attempt per
target and exits, so three unreachable relays listed ahead of a live fourth leave the fourth untried in that run, until
a started edge of that identity flushes the outbox and promotes it (`resend` on the same identity reaches it too). An
outbox row written before plans were persisted carries none, and its targets keep only their own per-target retry to
the horizon, with no new promotion. On a one-shot send a permanent refusal on the
single attempt — a 404 among them — gives that target up at once, with no retry. The exit code of a one-shot send while
some targets are still live but unanswered is an implementation choice, not normative: the reference CLI exits non-zero
while any target is still retrying, so it exits zero only once every target has published or been given up, whereas an
implementation that counts one published target as success may exit zero sooner.

**4.4 Opening.** A recipient takes the wrap whose `to` is its address (none: `not-recipient`), opens it with its sealing
key, info `ac/seal/1` and its own address as AAD, and gets the 32-byte content key; then it opens `sealed.ct` with that
key, `sealed.nonce` and utf8(canonical([v, to, from])) of the envelope. Any failure is `open-failed`: a wrap or
ciphertext that does not authenticate, a small-order `enc`, a content key of another length, malformed hex. A plaintext
that is not the content of §5.2 is `bad-content`, `bad-thread` or `too-many-prev`.

## 5. Envelope

**5.1 Outer members.** On the wire an envelope is a JSON object with exactly these nine members. Writers
emit them in this order with no white space (implementation default); verification reads values, so neither is
significant to it, but an outbox keeps and resends the exact bytes (§9).

| member | value |
|---|---|
| `v` | the integer 1: the envelope format version |
| `id` | 64 hex: the envelope id (§5.3) |
| `to` | 1 to 16 distinct addresses |
| `from` | the address of the key that signs, the session key |
| `auth` | the chain: 0 to 8 hops (§6), each `{"iss", "sub", "caveats", "exp", "sig"}` |
| `suite` | the integer 1 (§3.1) |
| `ts` | a canonical integer: when the sender built it |
| `sealed` | `{"wraps", "nonce", "ct"}` (§4.3) |
| `sig` | 128 hex: `from`'s signature over the 32 bytes of `id` |

Relays see these members only; `type`, `thread` and `body` are sealed. An envelope is at most 196,608 bytes as
serialized, counted as the bytes received. (Changed 2026-11-11, W9: from 65,536, so that a body of 64 KiB fits. The
sealed content is hex, so one recipient's largest ASCII body is about 97,800 characters; the request body cap of
262,144 leaves room for a subscription frame, Appendix B 27.)

**5.2 The sealed content.**
- `type`: a non-empty string that contains no Unicode control character (General_Category `Cc`: U+0000 to U+001F,
  U+007F, U+0080 to U+009F) and no line or paragraph separator (U+2028, U+2029); a content whose `type` holds any such
  character is `bad-content` (a MUST; added 2026-10-27, the control-character half of the type finding of that day; the
  same class the relay URL rule bans). It is open like a MIME type and namespaced by profiles, such as
  `coding.task.v1`. The check runs on the parsed string, so an escaped C0 (`\u0001`) is caught
  as a raw C0 would be; a raw C0 is already `bad-content` at parse (invalid JSON). The rule changes no existing `id` or
  signature, the `type` being AEAD plaintext: the id covers the sealed ciphertext hash, not the plaintext, so no id
  moves and nothing is re-signed.
- `thread`: `{"id": 64 hex, "prev": [...]}`. A new thread's `id` is 32 random bytes and its `prev` is
  `[]`. A reply keeps the thread's `id` and lists in `prev` the ids of the envelopes it answers: 1 to 64 distinct ids
  (distinct is an implementation default). The thread is mandatory: it makes every conversation a signed,
  tamper-evident hash DAG. Because it is sealed, only recipients can rebuild the DAG, so a
  compliance vault must be a recipient of what it holds.
- `body`: any JSON value, defined by profiles.

The object has exactly these three members (implementation default).

**5.3 Id and signature.** `id = sha256hex(utf8(canonical([v, to, from, auth, suite, ts, sealedHash])))`, with `auth`
written `[[iss, sub, caveats, exp, sig], ...]` and `sealedHash = sha256hex(utf8(canonical([[[to, enc, ct], ...], nonce,
ct])))` over the sealed part. The id excludes itself and `sig`. `sig` is the Ed25519 signature of `from`
over the 32 bytes the id encodes. The id is the unit of idempotency: relays deduplicate by it, and receivers keep a set
of ids they have seen.

**5.4 Parsing.** A reader of envelope bytes MUST apply these checks in this order, and fail with the code of the first
check that fails (the order of steps 4 to 13 is an implementation default; the vectors pin it):
1. at most 196,608 bytes (`envelope-too-large`; changed 2026-11-11 from 65,536);
2. UTF-8 JSON text (§2.5; `bad-json`);
3. a JSON object (`bad-shape`);
4. `v` is a number (`bad-shape`) and is 1 (`bad-version`): before any other member, so that an envelope of a later
   version is reported as one;
5. `suite` is a number (`bad-shape`) and is 1 (`bad-suite`);
6. exactly the nine members of §5.1 (`bad-shape`);
7. `id` is a string (`bad-shape`) of 32 bytes of hex (`bad-hex`);
8. `to` is a non-empty list (`bad-shape`) of at most 16 entries (`too-many-recipients`), each a string (`bad-shape`)
   that is an address (`bad-address`), none twice (`bad-shape`);
9. `from` is a string (`bad-shape`) that is an address (`bad-address`);
10. `auth` is a list (`bad-shape`) that passes chain rules 1 to 4 (§6.2);
11. `ts` is a canonical integer (`bad-shape`);
12. `sealed` is an object with exactly `wraps`, `nonce` and `ct` (`bad-shape`), and `wraps` is a list of exactly one
    wrap per recipient (`bad-shape`); then each wrap in the order of `to`, checked fully before the next, is an object
    with exactly `to`, `enc` and `ct` whose `to` is the recipient at its position (`bad-shape`) and whose `enc` is 32
    bytes of hex and `ct` 48 bytes (`bad-shape` for a value that is not a string, `bad-hex` otherwise); then `nonce` is
    12 bytes of hex and `sealed.ct` hex of at least 16 bytes (`bad-shape` for a value that is not a string, `bad-hex`
    otherwise);
13. `sig` is a string (`bad-shape`) of 64 bytes of hex (`bad-hex`).

Parsing verifies no signature; that is §5.5 and §6.

**5.5 Outer checks.** Given its clock `now`, a TTL and a skew, a receiver checks, in this order:
1. `to` holds 1 to 16 distinct addresses (as in §5.4 step 8: a non-empty list, `bad-shape`; at most 16,
   `too-many-recipients`; each an address, `bad-address`; none twice, `bad-shape`);
2. the id recomputes from the other members (`bad-id`);
3. `sig` verifies under `from` over the id (`bad-sig`);
4. `now - (ttl + skew) <= ts` (`stale-ts`) and `ts <= now + skew` (`future-ts`).

The defaults are a TTL of 604,800 seconds (7 days) and a skew of 300 seconds. The stale bound, TTL plus skew,
is also the dedup window: a relay keeps envelopes for its TTL, so a receiver offline for nearly that long still
accepts them, and no one can replay an envelope after the window. A relay's policy runs the chain between
steps 3 and 4 (§8.2), so implementations expose the steps separately.

**5.6 Building.** A sender draws the content key, the nonce and one ephemeral key per recipient, seals (§4.3), computes
the id and the signature, and serializes. It MUST keep the exact bytes and retransmit those, never a re-seal: HPKE is
randomized, so a re-seal is a new envelope with a new id. A builder checks what parsing would reject, not the
meaning of the chain, so tests can build envelopes whose chains must fail (implementation default).

## 6. Authority chain and caveats

**6.1 Hops.** A hop is `{"iss": address, "sub": address, "caveats": [...], "exp": canonical integer, "sig": 128 hex}`:
`iss` grants authority to `sub`, under the caveats this hop adds, until `exp`. `sig` is the Ed25519
signature of `iss` over the digest of `["ac/hop/1", iss, sub, caveats, exp]`. A caveat is a non-empty string
(implementation default) of at most 256 UTF-8 bytes, and a hop carries at most 32 (the unit is an
implementation default). `exp` is a hop member; there is no `exp=` caveat. A principal's hop SHOULD
live 30 days at most and be renewed by the org's control plane, so that revocation is mostly not renewing.

**6.2 Verification.** Verifying a chain `auth` for the sender `from` at time `ts` applies these rules in this order, each
to every hop before the next rule, and fails with the code of the first rule that fails:

| rule | check | code |
|---|---|---|
| 1 | at most 8 hops | `too-many-hops` |
| 2 | each hop is well-formed: an object with exactly `iss`, `sub`, `caveats`, `exp` and `sig`; `iss` and `sub` addresses; `caveats` a list of non-empty strings; `exp` a canonical integer; `sig` 64 bytes of hex | `bad-hop` |
| 3 | each hop has at most 32 caveats | `too-many-caveats` |
| 4 | each caveat is at most 256 UTF-8 bytes | `caveat-too-long` |
| 5 | `hop[i].sub == hop[i+1].iss` | `chain-broken` |
| 6 | the last hop's `sub` is `from` | `chain-not-to-sender` |
| 7 | `hop[i+1].exp <= hop[i].exp` | `exp-not-monotone` |
| 8 | `ts <= exp` for every hop: validity is judged at the envelope's `ts` | `hop-expired` |
| 9 | each hop's `sig` verifies under its `iss` | `bad-hop-sig` |

The rule "each hop well-formed" is rules 2 to 4 here, so that each rule has one code (implementation default). An
empty chain is self-rooted: its root is `from`. A valid chain establishes its root (the first hop's `iss`, or `from`),
its principal (§1) and its effective caveats: the hops' caveats concatenated in chain order. Since a hop carries
only what it adds, a later hop can append caveats and never remove one: the prefix property is structural. The
chain proves only that the root granted the authority; whether the root is trusted is the edge's decision (§9).

**Rule 8 and live delivery** (a note added 2026-10-25; it amends
rule 8 for live delivery only). Rule 8 judges a chain at the envelope's `ts`, which keeps its meaning for archives and
for whoever verifies stored mail later; but `ts` is its signer's to pick, so the holder of an expired key could date
new mail inside the hop's life, and relays stored it for up to TTL + skew after `exp`. Live
delivery is therefore judged at the relay's clock as well, the receipt bound: a relay refuses a chained envelope
`hop-expired` once its clock at receipt is past the earliest `exp` of the chain's hops plus its skew (§8.2 step 6),
and hands the second it stored the envelope to the edge as `received_at` (§8.3, §8.5), where the same bound applies
(§9 item 3). An empty chain has no `exp`, and so no bound.

**6.3 Caveats.** A caveat is a predicate that must hold, never a grant. Effective authority is the conjunction of
all of them, so appending one can only narrow it. Profiles define caveat grammars; the core defines only the evaluator
contract. An evaluator answers each caveat with a verdict: `hold`, `fail`, `unknown` (not of its grammar) or
`needs-sealed` (it needs the sealed part to decide). The edge evaluates the effective caveats in chain order with every
evaluator it has, after unsealing:
- a caveat holds when at least one evaluator answers `hold` and none answers `fail` or `needs-sealed` (implementation
  default);
- a caveat that no evaluator knows fails closed, `unknown-caveat`; otherwise attenuation could be bypassed;
- `fail`, `needs-sealed` (the edge evaluated too early, or an evaluator is broken) and an evaluator that throws give
  `caveat-failed` (implementation default);
- the first caveat that does not hold decides.

The relay never evaluates caveats: it cannot see the sealed part, and policy is the edge's.

**6.4 The coding profile.** The first profile's grammar:

| caveat | holds when |
|---|---|
| `type=<type>` | the sealed `type` is exactly `<type>` |
| `type=<prefix>.*` | the sealed `type` starts with `<prefix>.` |
| `repo=<name>` | the sealed `body` is a JSON object whose member `repo` is the string `<name>` |

`<type>`, `<prefix>` and `<name>` are non-empty, and `<type>` and `<prefix>` contain no `*`. A caveat that starts with
`type=` or `repo=` but breaks these rules is `unknown`, as is any other caveat (implementation default). Before the
sealed part is open, `type=` and `repo=` caveats are `needs-sealed`; a `repo=` caveat against a body without a string
`repo` fails. A spawned agent's tool permissions derive from these caveats; v0 spawns nothing (§9).

## 7. Records

**7.1 Common rules.** A record is a JSON object with a `kind` member, `"address"`, `"accept-from"` or `"key"`
(implementation default names), and exactly the other members of its kind (implementation default). Its `sig` is the
Ed25519 signature of its own key (`key`, or `owner` for accept-from) over the digest of its preimage (§2.4). Records
are ordinary signed data that relays store without a fourth call: they are published with
publish and read with fetch's second shape. A record that breaks its form is `bad-record`; the caps give
`too-many-relays` and `too-many-revoked`, each checked when its list member is reached, in member order, before that
member's entries are checked for their form. (Added 2026-10-26: a fourth kind, `"handle"`, signed by its `org`
(§12.4, L2), which relays do not store: publish refuses it as any kind it does not know, `bad-record`, and a fetch of it
is 404. An org serves its handle records itself, at its origin, §12.1.)

**7.2 Address record.**

| member | value |
|---|---|
| `kind` | `"address"` |
| `key` | the address the record describes, which signs it |
| `sealing_key` | its X25519 public key in hex, or `null` (no sealing key: the derivation fallback is deferred). An individual (principal or session) address record carries `null` and publishes a key record; the resolver seals an individual to its current key record (§4.3, §7.4, §9). The individual still generates a sealing key (§3.3), but no record names it and no sender seals to it (§4.3, §9, §10): it serves only to open mail sealed to it before the identity's forward-secrecy cutover, tried after the epoch keys, and a born-FS individual, sealed to only through key records, need keep none (forward secrecy; added 2026-10-28, clarified 2026-10-29) |
| `relays` | 0 to 64 relay URLs (raised from 8 on 2026-10-30, 'relays N'), distinct by exact string. This row is the one statement of a relay URL's form, wherever a relay URL is listed (an address record, pair/open, §8.10): `http://` or `https://`, in lower case; then a first character that is not `/`, `?`, `#`, a space or a `Cc` control character, so the host is not empty; then any characters but a space or a `Cc` control character. Nothing further is parsed or normalized: userinfo, a port, a path, a trailing `/`, a query, a fragment, an upper-case host and a character such as U+2028 are kept as written, so `https://a/` and `https://a` are two entries (implementation default). (Clarified 2026-11-03: every reader of a record, `packages/core`, `crates/ac-core` and `scripts/verify_vectors.py`, checks exactly this form, and `records.json` holds a valid record whose relay URL contains U+2028; a tightening to scheme and authority only, written in this row on 2026-11-02, was never carried into a reader or a vector. That stricter form is now the relay base form below, which binds a relay's configuration and, through it, a fetch proof's `audience`, §8.3.) |
| `rotation_key` | an address that may countersign this key's rotation, or `null` |
| `revoked` | 0 to 1,024 distinct addresses of principal keys the root revokes |
| `ttl` | 1 to 86,400 seconds |
| `iat` | when it was issued |
| `rotated_from` | the previous key when this record rotates it, else `null` |
| `rotation_sig` | the signature over this record's preimage by the previous key or its rotation key, or `null`; not `null` only with `rotated_from` (implementation default) |
| `sig` | the signature of `key` |

An address record is valid from `iat - skew` to `iat + ttl` (implementation default: counting the TTL from `iat` means a
stale record, with an older revocation list, cannot be served after a day, so an org re-signs its record at least
daily). An org's record lives at `https://<domain>/.well-known/bag/address.json`, or, for a reader
that implements §12 (L2), at the org's origin, which its DNS TXT record may move to `https://bag.<domain>`
(§12.1; added 2026-10-26); edges cache it no
longer than its TTL and pin its key at first contact (§9). Relays read it too, for the `domain:` roots of the
accept-from records they hold, with the same rules and a pin of their own (§7.4, §8.8).
`revoked` lists the principal keys a root revokes while mail under their hops can still be delivered: an entry stays
until its hop's `exp` + TTL + skew, the last second at which an envelope sent under that hop still passes the stale-ts
check of §5.5, so a recipient that verifies after `exp` still finds the entry, and the list stays bounded, each entry
living a TTL and a skew past its hop (set on 2026-10-25; the writer is the CLI's
`record address --revoke`). (Changed 2026-10-25: this replaces "an entry drops out at
their `exp`, which keeps the list short"; dropped at
`exp`, an entry let a recipient that verified late accept mail its root had revoked.)

A relay URL is a base (added 2026-10-25): a client drops the URL's trailing slashes and
appends the path of §8 (`/v0/publish`, `/v0/fetch/...`, `/v0/subscribe` with the scheme `ws` or `wss`, `/v0/health`),
so `https://relay.example/` and `https://relay.example` name one relay, and a relay behind a path prefix, such as
`https://example.com/bag`, serves the API under that prefix (the edge and examples/python-join both drop
every trailing slash).

**The relay base form** (clarified 2026-11-03, from `crates/ac-relay/src/net.rs`) is the subset of relay URLs that a
relay's `--accept-base` values take (§8.3; `--advertise` keeps its own rule, which also allows an upper-case host):
`http://` or `https://`, then a host, either a name or IPv4 address of lower-case
letters, digits, dots and hyphens or an IPv6 address in brackets, then an optional port from 1 to 65535 that is not the
scheme's default (no `:80` on `http`, no `:443` on `https`), and nothing further: no userinfo, path, query, fragment or
trailing `/`. A fetch proof binds the `relays` entry its caller used byte for byte (§8.3), so only an entry in the relay
base form can match a relay's accepted base. An entry outside it (a path prefix, a trailing `/`, an upper-case host or a
written default port) still serves publish and subscribe, but a fetch proof naming it as `audience` matches no accepted
base and is `bad-auth`; a writer that wants fetch by id at a relay lists it in the relay base form.

**7.3 Rotation.** A record whose `key` differs from a pinned key is accepted only as a rotation:
`next.rotated_from` is `prev.key`, and `next.rotation_sig` verifies over the preimage of `next` under `prev.key` or
`prev.rotation_key`. Anything else, a bare rotation without `rotation_sig` included, is `bad-rotation`. The rotation
check itself is structural only: it tests `rotated_from` and `rotation_sig` and runs no §7.5 check on either record. A
reader (the edge at arrival, a relay at publish) MUST verify `next` on its own under §7.5, before the rotation check; `prev` is the pinned record, verified
under §7.5 when it was pinned and not re-verified at rotation (it may have expired since), and a pin held with no record
is treated as having no `rotation_key` (changed 2026-10-28: stated to match the edge and the relay). So a compromised web host cannot silently swap the root of a peer that pinned it.
A reader that holds no record of `next.rotated_from` checks the rotation's claim alone (changed 2026-10-25; the reference relay does so at publish): when `rotated_from` is set, `rotation_sig` must verify
over the preimage of `next` under `rotated_from`, so a bare rotation and a countersignature by any other key are
`bad-rotation`, and a record that names no `rotated_from` claims nothing. A rotation countersigned by the previous
record's `rotation_key` is then accepted only by a reader that holds that record, the one place the rotation key is
written: an org that recovers a lost root with its rotation key publishes the new record, at a relay that never held the
old one, without `rotated_from`. A demand rotation publishes the new key and address records to every listed relay but
succeeds once at least one holds them, keep carrying the rest (Appendix B 110); a relay still serving the pre-rotation
record is delayed adoption of the forward-countersigned key, not a downgrade.

**A rotation claim is self-consistency, not identity (added 2026-11-01, by design).**
A verifying `rotation_sig` proves only that the signer also holds `rotated_from`'s key; it does not prove
`rotated_from` is an identity the reader ever trusted, since `rotated_from` may name any address the signer controls.
Trust that `rotated_from` is the genuine prior identity comes only from the reader's own pin, discovery (§7.2's
well-known or §12's TXT) or an exact-address anchor — never from the claim's self-consistency. A reader or
UI that presented a valid `rotation_sig` as "the same identity you knew" without such an anchor would be fooled by a
stranger's self-made chain. The reference edge anchors every claim it accepts (its pin check and discovery), and the
relay's claim-only publish path is a store gate, not a trust statement.

**7.4 Accept-from record and key record.** An accept-from record (`kind` `"accept-from"`) has: `owner`, the
mailbox address, which signs it; `roots`, a list of 1 to 1,024 distinct entries (the cap: changed 2026-10-25), each an address or a domain root, or exactly `["*"]`, the wildcard (that `"*"` stands alone is an
implementation default); `max_bytes`, a positive
integer, the largest envelope the mailbox accepts (implementation default: the envelope cap; a re-sign that finds a
held `max_bytes` of exactly 65,536, the old cap and default, writes the envelope cap in its place and keeps any other
value, changed 2026-11-11); `ttl`, a positive integer, the seconds the relay keeps an envelope in
the mailbox, capped by the relay's own TTL; `iat`; and `sig`. It does not expire; a newer `iat`
replaces it (implementation default: its `ttl` is retention, not validity, and so has no 24-hour ceiling). A relay
without an accept-from record for any recipient of an envelope rejects the envelope. The ceiling of 86,400
seconds binds address and key records, the records that state a key's current facts, and not the accept-from `ttl`,
which is retention (changed 2026-10-25). Since an accept-from record does not expire, an old one can
be published to a relay that lacks the newer: that relay keeps it as the newest it holds, which costs it storage and the
owner its newer policy at that relay until the owner publishes the newer one there (§10).

A domain root is `domain:` followed by a host: a lowercase DNS name of at most 253 characters
and two or more labels, each of 1 to 63 letters `a` to `z`, digits and hyphens with no hyphen at either end, with no
trailing dot, and not an IP literal: its last label is neither all decimal digits nor `0x` followed by zero or more hex
digits (a bare `0x` too, which the WHATWG URL rule reads as the number 0), the rule that inet_aton-style resolvers follow too (implementation defaults: the label rules of RFC 1123 and
the literal rule). No port, scheme, path or user part can appear. Anything else in `roots` is `bad-record`. A domain
root admits the root that is the current key of the address record at the host's well-known URL (§7.2), as the
mailbox's relay resolves and pins it (§8.8); so the record follows the org's countersigned rotations (§7.3) and needs
no republish when the org rotates its key. Domain roots may stand beside addresses.

A key record (`kind` `"key"`) has `key`, which signs it; `sealing_key`, 64 hex; `iat`; `exp`, from `iat` to `iat` +
86,400 (changed 2026-10-25; was: not before `iat`); and `sig`. It binds a key to its sealing key until
`exp`, a day at most, and edges read it from relays. Its preimage is unchanged: a writer re-signs it at
least daily, as an org re-signs its address record. The key record's `sealing_key` is the sealing target for an
individual's `key` (§4.3, §9): the recipient publishes a current key record each epoch (its `exp` at most `iat` +
86,400), rotates it, and deletes the old epoch private key after the deletion horizon, so a compromise of that key
reads no mail older than the horizon (forward secrecy, §10; added 2026-10-28). The current key record is the
valid one with the greatest `iat` (two may be valid at once, since a recipient re-signs the next before the last one's
`exp`): the sender seals to that one, and the recipient opens under any epoch key it has not yet deleted during the
overlap. Should two valid key records share the greatest `iat` (a recipient that re-signed twice within a second), the
one a reader or a relay already holds stands and a later equal-`iat` publish is `stale-record` (§8), so the choice is
deterministic; both are signed by the recipient, so either seals safely (tie-break pinned 2026-10-29). The epoch sealing key MUST be fresh CSPRNG output, independent of the signing key and never derived from the
signing seed; a derived epoch key would let a stolen signing seed re-derive it and break forward secrecy. The deletion
horizon is `exp` + TTL + skew, where the holder uses its OWN assumed §8 envelope TTL (default 604,800 s) and skew
(default 300 s); it cannot learn a relay's configured TTL. A relay run with a longer TTL does not extend a holder's
horizon: mail that arrives after it is undeliverable, not readable (a holder that wants such late mail raises its own
assumed TTL). "Deletes" means the holder removes the epoch private key from its key store so the application no longer
holds it; forward secrecy is against an attacker who compromises the device after that removal, not a forensic recovery
of unlinked blocks (an overwrite is not required and is unreliable on modern media; a deployment wanting media-level
erasure uses full-disk encryption). (Clarified 2026-10-29.)

**7.5 Verification.** At time `now`, with a skew (default 300 s), a reader checks in this order: the form and the caps
(§7.1 to §7.4, a key record's `exp` at most a day after its `iat` included); the signature (`bad-record-sig`);
`iat <= now + skew` (`future-iat`); and the expiry, `now <= iat + ttl` for an address record and `now <= exp` for a key
record (`record-expired`), so neither is used more than a day after its `iat` (changed 2026-10-25).

(Discovery by DNS and handles were first written here, as §7.6 and §7.7, then moved out of the frozen core
into §12, an L2 section.)

## 8. Relay API

This section is the conformance target for a relay in any language. The reference relay is `crates/ac-relay` (Rust,
binary `ac-relay`). A relay is dumb: it has no semantics, but it enforces the
policy that a mailbox's owner signed. It has three calls a relay must offer — publish, subscribe and fetch — a health probe, and the two optional pairing-rendezvous calls `pair/open` and `pair/claim`
(§8.10).

**8.1 General.** One port serves HTTP/1.1 and WebSocket. Bodies are UTF-8 JSON. An error response's body is
`{"error": code}`, with a code and status from Appendix A. A relay's own failure (its store, say) is 500
`{"error": "internal"}`: a transport failure outside the closed set of Appendix A, which a client treats as a failed try
(implementation default). (Changed 2026-10-25: `internal` is now
a code of Appendix A, relay group, status 500, so a client reads it as a code and still treats it as a failed try.) A domain root that does not resolve at publish is 503
`resolve-failed` with `Retry-After` (§8.8), which a client also treats as a try to repeat. Defaults: TTL 604,800 s,
skew 300 s, envelope cap 196,608 bytes (changed 2026-11-11 from 65,536), request body cap 262,144 bytes, record cap
131,072 bytes (added 2026-10-25). The reference relay prints the line
`AC_RELAY_URL=http://127.0.0.1:<port>` when it is listening, so a harness can start it on port 0 and read its URL
(Changed 2026-10-25: with `--advertise` it prints that URL, a port written in it
kept, else none for `https` and the listening port for `http`, and health answers the same URL, §8.6 and §8.9.)

Slow clients (added 2026-10-25; implementation defaults): a connection that has not sent a whole
request head within the header timeout (10 s), its first bytes included, is closed with no answer; a publish whose body
has not arrived within the body timeout (30 s) is answered 408 with no body, and the connection is closed; and one
client address holds at most a configured number of connections at once (the reference default `--connections-per-ip`
79; raised 2026-10-31 from 72 for the reserve below, 2026-10-30 from 68. One direct client address running 64 identities, `MAX_IDENTITIES`, holds at most 68
connections whatever the load, because the reference edge opens at most four HTTP calls and upgrades per relay host per
process (`RELAY_TURNS`), so its own idle pooled connections cannot fill the cap; without that bound a client's pooling
alone exhausts any fixed cap and its calls are refused with no real demand. Reached directly, where it counts every
connection, the relay keeps an address's publishes and record fetches getting in by counting that address's
subscriptions against a limit set below the connection cap — the cap minus a reserve of `max(floor, round(fraction ×
cap))` places held for calls (the cap `--connections-per-ip` and the fraction `--connection-reserve-permille`, in
thousandths, default 125, configurable; the floor a constant `CONNECTION_RESERVE_FLOOR` of 8 that never takes more than
half the cap; a permille of 0 holds nothing back); without it, two such servers at one address take every place with
subscriptions and starve every call (measured 2026-10-31). At the default cap of 79 the reserve is 10, so a direct
address holds 69 subscriptions and 10 call places; 74 is the lowest cap that runs one 64-identity server beside a
one-identity server clean, and the default of 79 adds one more process's measured share of 5. A subscription past the limit is admitted at the WebSocket upgrade and then sent `{"t": "error", "error":
"rate-limited"}` and closed 1013, so the edge retries without ending (its status shows `last_code` `rate-limited`);
existing subscriptions are never revoked, and the refusal is logged `connection-refused` with reason
`subscriptions-per-ip`. Behind a trusted proxy the cap counts WebSockets only, next paragraph, where this reserve is not
needed; e2e scenario 54), a subscriber's
WebSocket among them until it closes, so that one
more is closed at once with no answer. A client treats each as a failed try. A conforming client SHOULD bound the
connections it opens to one relay host — as the reference edge does with `RELAY_TURNS` (4) HTTP calls and upgrades per
host per process — so that its own idle pooled connections do not fill the cap and have its subscriptions refused with no
real demand, which also keeps it from starving another process that shares its direct address (e2e scenario 54). The client address is the TCP peer's
(Appendix B 47): behind a proxy every client has the proxy's address, so this cap, the per-address limit and the record
signers' quota of §8.2 are each one bucket for every client until the relay reads client addresses from the proxy. (Changed 2026-10-25: a relay may trust proxies, and then the client of a request from
one is the address its header names; a client counts by the bucket of §8.9 item 2; a trusted proxy's own
connections are not counted, and a WebSocket through one counts under its client and, over the cap, is admitted at the
upgrade and then sent `{"t": "error", "error": "rate-limited"}` and closed 1013, logged `connection-refused` with reason
`connections-per-ip` (the proxied over-cap refusal; the direct path's reserve refusal above logs `subscriptions-per-ip`,
a distinct reason — corrected 2026-11-01, where this read `subscriptions-per-ip` "the same as
the direct path's reserve refusal"), not closed at once with no answer (changed
2026-10-31, from the earlier behaviour): §8.9.)

**8.2 publish: `POST /v0/publish`.** The body is an envelope, or a record when its top-level object has a `kind` member
(implementation default). For an envelope the relay applies this policy in order, and the first step that fails is
the response (changed 2026-10-25: steps 3a and 6a are new, the
client address's limit moved from step 8 to 3a and dedup from step 9 to 6a, the store is step 9, and the other steps
keep their numbers):
1. size: a body over 262,144 bytes is `body-too-large`; a record (§7) over 131,072 bytes is `body-too-large`; an envelope
   over 196,608 bytes (changed 2026-11-11 from 65,536) is `envelope-too-large`; all 413 (implementation default for the second and third statuses);
2. parse and caps: §5.4;
3. the id recomputes (`bad-id`): §5.5 step 2;
3a. the client address's limit: 600 publishes in a fixed 60-second window per client address. Every publish that reaches
   this step counts against its address, whatever happens to it next (refused, a duplicate or stored), and one over the
   limit is 429 `rate-limited` with a `Retry-After` header in seconds, before any signature is verified, so that the
   signature work one address can cause is bounded; a publish refused at steps 1 to 3 counts nowhere (implementation
   default);
4. the outer signature verifies (`bad-sig`): §5.5 step 3;
5. the chain: rules 1 to 9 of §6.2 at the envelope's `ts`, with no caveat evaluation;
6. the ts window: §5.5 step 4, against the relay's clock; then, for an envelope whose chain is not empty, the receipt
   bound (added 2026-10-25): the relay's clock at receipt must be at most the
   earliest `exp` of all the chain's hops plus the relay's skew (§8.1), else 422 `hop-expired`, whatever `ts` says, so
   that a `ts` dated back into a hop's life no longer delivers live (§6.2's note to rule 8). The window comes first: an
   envelope outside it is `stale-ts` or `future-ts` even when it is past the bound too, and one inside it and past the
   bound is `hop-expired`. The bound comes before dedup (6a), so a stored chained envelope published again past it is
   `hop-expired`, not a duplicate: a sender whose answer was lost and who tries again that late is told the try failed,
   though the first stored it;
6a. dedup by id: an id the relay holds, or one it swept while a replay of it could still pass step 6 (a tombstone,
   §8.7), is 200 with `"duplicate": true`, nothing is stored, and the publish counts against nothing but its client
   address (step 3a), so that replaying another sender's envelope costs that sender nothing;
7. hosted recipients: those for which the relay holds an accept-from record. None means `not-hosted`. A hosted recipient
   is delivered to only if its `roots` admit the chain's root and the envelope's size is at most its `max_bytes`.
   The roots admit it when they are `["*"]` or list its address, which needs no network; else when a domain root's
   current key is the chain's root (§8.8), and then only if no hop's `iss` or `sub` is in that domain's record's
   `revoked` list (403 `revoked`). (Changed 2026-10-26: roots that list
   the chain's root by its address admit it only if no hop's `iss` or `sub` is in the revoked list the relay keeps for
   that root, §8.7, else 403 `revoked`, in the order below; `["*"]` reads no list, Appendix B 54.) A domain's
   current key is the key of its fresh record, or, when a resolution
   fails, a pin mismatch included, the pinned key for as long as its stored record is valid (§8.8 items 5 and 6); a
   domain has none only when nothing resolves and no valid pinned record exists. Addresses and `"*"` are read first,
   then the domains, each resolved at most once per publish, its cache first (§8.8). When no recipient remains, the
   response is 503 `resolve-failed` with `Retry-After` if one of them waited on a domain with no current key, else 403
   `revoked` if one refused a revoked key, else 403 `root-not-accepted` if one refused the root (a domain whose current
   key is another included), else 403 `too-large-for-mailbox` (the partial case, and the order of the four,
   are implementation defaults);
8. the sender's limits, in the same windows: 120 envelopes per `from`, 1,200 per root. Over either is 429
   `rate-limited`, with `Retry-After`; both are checked before either counts, and only a publish that passes both counts
   against them. v0 keeps every counter in memory. (Added 2026-11-01: a
   per-client-address daily quota on **stored envelope bytes** also applies — the bucket of §8.9 item 2, charged the
   stored size of each accepted envelope (step 9), the reference default 100 MB per UTC day, over which a publish is 429
   `rate-limited` with `Retry-After` to the next 00:00 UTC, the same shape and code as the new-signer daily quota below.
   Without it one address could fill an 800 MB store in minutes with maximum-size self-mail, since `store-full` refuses
   all tenants' publishes alike and has no per-address purge; the quota holds one address's stored bytes far below the
   store so one tenant cannot deny publish to the rest.);
9. store once: the exact bytes once, and one mailbox row per delivered recipient, with
   `expires_at = now + min(relay TTL, that recipient's accept-from ttl)`, a per-mailbox cursor, and a push to live
   subscribers. An id stored meanwhile by another publish is a duplicate, as at step 6a. (Added 2026-10-25:
   a recipient that waited at step 7 on a domain with no current key, while another
   recipient took the envelope, is held in a pending row until `received_at` + the relay TTL, and the envelope is kept
   while such a row lives. After each sweep (§8.7) the relay judges the pending rows again by step 7 at its clock, the
   recipient's current accept-from record and the domain's current grant: admitted, the row becomes a mailbox row
   expiring at `received_at` + min(relay TTL, that recipient's ttl), pushed to live subscribers, its frame carrying the
   envelope's own `received_at`; refused, or with that expiry already past, it is dropped; still waiting, it stays.
   `delivered` counts the rows the publish itself wrote; a duplicate changes no pending row, so the id is still
   delivered once to each recipient. The reference relay retries at most 256 rows a sweep, the earliest to expire first;
   implementation defaults.)

Success is 200 `{"ok": true, "id": id, "duplicate": false, "delivered": n}`, where `delivered` counts the mailbox rows
written (implementation default).

For a record, the relay applies steps 1, 2 (the record's form, §7) and 3a, then verifies it at its clock (§7.5) and
keeps one record per signer and kind. A record whose `iat` is not newer than the stored one's is 409 `stale-record`
(newer `iat` wins). An address record with `rotated_from` is checked against the stored address record
of `rotated_from` by §7.3 when the relay holds one (`bad-rotation`), and stored on its own verification when it holds
none (implementation default). (Changed 2026-10-25: when it holds none, the relay checks the
rotation's claim alone, §7.3, so a bare rotation or a `rotation_sig` that does not verify under `rotated_from` is 422
`bad-rotation`.) Since 2026-10-25 (implementation defaults): a record whose signer
the relay holds no record of, of any kind, counts against its client address's quota of new record signers, 100 a UTC
day, past which it is 429 `rate-limited` with `Retry-After` to the next 00:00 UTC (behind a proxy, one quota for every
client: §8.1); a record counts against its signer as an envelope against its `from` (step 8); an address record is kept
until `iat + ttl` and a key record until `exp`, then swept (§8.7), so that a fetch of it is 404; an accept-from record
does not expire. At `store-full` (the byte bound, the security considerations): a record whose signer the relay holds
no record of, of any kind, is refused 503 `store-full` like an envelope, but a record that updates a signer the relay
already holds — a rotation, a revocation carried in a newer address record, or any re-sign — is still accepted, so
revocation and rotation keep working when the store is full (added 2026-11-01; a new
signer's records could otherwise grow the store past the byte bound, which gated envelopes only, into a hard
disk-full). Success is 200 `{"ok": true}` (implementation default). (Changed 2026-10-25: success
is 200 `{"ok": true, "kind": kind, "signer": address, "iat": iat, "valid_until": n}`, the record's kind, its signer,
its `iat`, and `valid_until`, the last second the relay holds the record valid: `iat + ttl` for an address record,
`exp` for a key record, `null` for an accept-from record, which does not expire. A client that reads `ok` alone, the
edge and examples/python-join among them, is unaffected; implementation defaults beside `ok`.) (Added 2026-10-26: a handle record (§12.4) is not stored: its `kind` is one the relay does not keep, so publish answers 400
`bad-record`, as for any unknown kind, and `GET /v0/fetch/record/{address}/handle` is 404 (Appendix B 25).)

**8.3 fetch by id: `GET /v0/fetch/{id}`.** The caller proves a key with three headers: `AC-Signer`, an address; `AC-Ts`,
Unix seconds; and `AC-Sig`, the signer's signature over `["ac/fetch/1", signer, id, ts, audience]`, where `audience` is
byte-identical to the §7.2 `relays` entry the caller used — the exact string that prefixes `/v0/fetch/{id}` — and
`signer` is the canonical address and `id` the 64-character lowercase-hex envelope id (§3, §5.5), each byte-for-byte as
signed. The relay rebuilds the preimage from `AC-Signer`, the `{id}` path segment, `AC-Ts` and its own configuration,
and accepts the proof only when `audience` is one of its configured accepted base URLs — the advertised URL
(`--advertise` / `config.url`, the value `GET /v0/health` answers) and each `--accept-base`, each in §7.2's relay
base form (clarified 2026-11-03: this paragraph cited §7.1 for §7.2 three times) — **never** a `Host` or forwarded header, which a caller controls and could use to re-open the
bypass. The `audience` is compared byte for byte with no normalization of it: an `audience` with a trailing slash, a
written `:443` or an upper-case host matches no configured base and is `bad-auth`. On the configuration side a single
trailing slash in an `--accept-base` value is dropped when the flag is read, and a value otherwise outside the relay base form (§7.2)
is refused at start (so an operator's typo fails fast rather than silently never matching); `--advertise` keeps its own
rule. The configuration holds a
**set** of accepted base URLs, so a hostname move (a relay reachable under two public names at once) is not an outage: a
proof whose `audience` is any accepted base verifies, and one that matches none is `bad-auth` (401). This closes the
cross-relay replay — a proof signed for relay A is refused at relay B. **Residual:** within the ±skew window (about
±300 s) a captured proof still replays to the *same* relay; its value is low — the response is the sealed ciphertext the
eavesdropper already holds and the signer must still be a party — and a relay-issued nonce is not worth a round trip on
a `GET`, so the preimage carries none. **Rollout:** this ships atomically before launch, the client and both relays as
one cutover, with no dual-accept window (an old four-field client is `bad-auth` at a new relay, a new client at an old
relay); any post-launch change to this preimage bumps the tag to `ac/fetch/2` or carries a dual-accept plan. (Added
2026-11-02; before this the preimage was `["ac/fetch/1", signer, id, ts]`, bound only to the id and a ±skew span, so a
captured proof replayed to the same or another relay.) The signer must be a party
of the envelope: its `from`, one of its `to`, or its principal, the last hop's `iss` (§1; added 2026-10-25, so that a principal reads by id what its sessions sent; the org root of a longer chain, the
first hop's `iss`, is not a party); or present in `AC-Auth` a chain from a party to itself: the
hops as UTF-8 JSON, base64url without padding (implementation default), verified by §6.2 for the signer at `AC-Ts`,
whose root must be a party of the envelope. `AC-Ts` must be within the skew of the relay's clock (implementation
default). The response is 200 with the exact stored bytes and the header `AC-Received-At`, the second the relay stored
them in Unix seconds, written as a plain decimal integer (added 2026-10-25; the header's name is an
implementation default), at which a reader of fetched mail judges live delivery as §9 item 3 judges a frame's; 401
`bad-auth` for a missing or malformed header, a
signature that does not verify, or an `audience` that is not one of this relay's accepted base URLs, and 401 `stale-ts` or `future-ts` for `AC-Ts` outside the skew; 403 `not-authorized`
for a signer who is not a party and has no chain from one; 404 `not-found` for an id the relay does not hold. (Added
2026-10-26: 403 `revoked` for a chain from a party whose `iss` or `sub`,
in any hop, is in the revoked list the relay keeps for the chain's root, that party (§8.7), judged after the party
check; a party with no chain reads as before.)
(Added 2026-11-01: fetch, unlike publish, ran the signer's signature check with no
per-address throttle, so an anonymous flood forced one Ed25519 verification each on the one shared vCPU. A
per-client-address rate window now bounds both fetch shapes together: a client — its bucket of §8.9 item 2 — gets at
most a configured number of fetch requests per fixed 60 s window, the reference default 6,000, counted at entry
**before** the signature is verified, as §8.2 step 3a counts a publish before its verify; over the window the request
is 429 `rate-limited` with `Retry-After` the seconds to the window's end. A relay MAY also keep a global fetch ceiling
as a backstop beyond the per-address window: the reference's `--fetch-global-per-minute` (default 30,000, a fixed 60 s
window whatever `--rate-window` says, `0` off) stands behind the per-address window and is checked only after it, so an
address already over its own window is refused there and spends none of the ceiling; a ceiling refusal charges the
address nothing and is 429 `rate-limited` with `Retry-After` (added 2026-11-01).)

**8.4 fetch, records: `GET /v0/fetch/record/{address}/{kind}`.** Returns 200 with the exact bytes of the latest stored
record of that signer and kind, without authentication (records are public), or 404 `not-found`. This second
shape of fetch is why "fetch" names two calls. The per-address fetch window of §8.3 applies here too,
charged at entry before the store read since this shape is unauthenticated and was otherwise unthrottled, and counted
against the one client bucket together with fetch-by-id; over the window it is 429 `rate-limited` with `Retry-After`
(added 2026-11-01).

**8.5 subscribe: WebSocket `GET /v0/subscribe`.** The WebSocket handshake is RFC 6455's; a relay MAY apply RFC
6455's handshake rules strictly — a `Sec-WebSocket-Key` of 16 bytes of base64 (RFC 6455 §4.2.1) among them — and the
reference is lenient where it MAY be (it accepts a key that is not), so a conformance test client must itself conform
(Appendix B 106). Frames are JSON text messages with a member `t`:
1. relay: `{"t": "challenge", "nonce": 64 hex, "ts": now}`; the nonce is 32 random bytes (implementation default);
2. client: `{"t": "auth", "mailbox": address, "signer": address, "auth": [hops], "cursor": integer or null,
   "sig": 128 hex}`, where `sig` is the signer's signature over `["ac/sub/1", nonce, signer, mailbox, cursor]`. The
   signer is the mailbox key with `auth` `[]`, or a key the chain `auth` delegates from the mailbox key, verified by
   §6.2 for the signer at the challenge's `ts`, with the mailbox as its root, and since 2026-10-26 with no hop's `iss` or `sub` in the revoked list the relay keeps for the mailbox (§8.7), else
   `revoked`;
3. relay: `{"t": "ok", "cursor": c}`, where c is the cursor it resumes after: the client's cursor, or, for `null`, the
   stored ack of this mailbox and signer, or 0 (implementation default);
4. relay: `{"t": "env", "cursor": n, "received_at": r, "envelope": s}` for each stored envelope after c, in cursor
   order, at most 32 frames beyond the last ack: `s` is a JSON string whose UTF-8 bytes are the exact bytes the
   relay stored, and `r` the second it stored them, in Unix seconds (changed 2026-10-25; was:
   `{"t": "env", "cursor": n, "envelope": ...}`, the envelope embedded as its exact stored JSON text, which a client
   that keeps exact bytes had to cut out of the frame). A client verifies the bytes of `s` as they are and never
   re-serializes an envelope to read it: a frame whose `envelope` is not a string is `bad-shape`, and a frame that a
   JSON library reads and writes again (pretty-printed, members reordered) still carries the same bytes in `s`. The
   name `received_at` is an implementation default, and a reader takes the members in any order;
5. client: `{"t": "ack", "cursor": n}`: delivered up to and including n (cumulative: implementation default). The relay
   stores the ack per mailbox and signer. An ack never deletes: a mailbox row lives until its `expires_at`.

Delivery is at least once (added 2026-10-25). An ack means delivered and deletes nothing. The
relay sends every unexpired row after the cursor a subscription resumes after (step 3), so a frame that was not acked,
or whose ack was lost with its connection, comes again, the same frame (cursor, `received_at` and `envelope`), to the
next subscription that resumes before it; and another signer of the mailbox, a delegate, reads every row from its own
cursor. The relay confirms no ack: a client that closes right after an ack can lose it unless it runs the WebSocket
closing handshake, after which the relay has read every frame sent before the close. So an edge drops by id what it
has already seen (§9 item 3); a frame whose `(relay, mailbox, cursor)` it already holds a row for is the same envelope
only when their ids match, since that triple can repeat across a relay restore, so the edge decides by id (§9 item 2,
Appendix B item 102).

A relay restored from an older copy of its store (Appendix B item 102) loses the mail it acknowledged after the copy's
time: the sender's edge marked that target `published` on the `200` and never publishes it again (`resend` reseals a
failed target only, §9 item 1), so the mail reaches the recipient only if the sender also published it to another of
the recipient's listed relays. This is inherent to at-least-once delivery, not a relay fault; the at-most-three relay
fan-out (K = 3, §9 item 1) is what bounds it (added 2026-10-31).

A failed handshake gets `{"t": "error", "error": code}` (`bad-auth`, `not-authorized` or a chain code, and `revoked`) and the connection is closed (implementation default).

Added 2026-10-25 (implementation defaults where not said otherwise):
6. the end of a chain: a subscription whose `auth` is not empty ends when the relay's clock passes the earliest `exp`
   of its hops (a chain is valid through its `exp`, §6.2 rule 8). The relay sends no `env` frame after that second; it
   sends `{"t": "error", "error": "hop-expired"}` and closes with 4001, within a second (the reference relay looks at its
   clock before each frame and every 500 ms). The mailbox key itself, with `auth` `[]`, has no such end;
7. silence: the relay pings every 30 s and closes with 4003 a subscriber it has heard nothing from for the idle timeout,
   60 s, at least twice the ping interval; every frame and every pong restarts the silence (a pong does so at
   once; the reference relay before it could close a subscriber that answered every ping at exactly the idle timeout). A connection that sends no auth frame within the idle timeout is closed 4003
   too. A subscriber that stops reading — its TCP window stays full, so a send would block — is also closed with 4003
   at the idle timeout, logged reason `stopped reading`, rather than holding the relay task open; and the relay checks a
   chain's `exp` (item 6) and the revoked list (item 8) before each frame, not once per batch, so no `env` frame goes
   out after `exp` or after a revoking record even when sends are slow (added 2026-11-01).

Added 2026-10-26 (implementation defaults in Appendix B 75):
8. the revoked list: a subscription whose `auth` is not empty ends once the relay stores a newer address record of the
   mailbox whose `revoked` list names a hop's `iss` or `sub`. The relay sends no `env` frame after that record is
   stored; it sends `{"t": "error", "error": "revoked"}` and closes with 4001, the close of item 6's end, for the same
   reason: the subscriber's credentials no longer hold (the reference relay reads the mailbox's kept list again before
   its next frame, and when the record's notification reaches the subscription, whenever an address record was stored
   since its last read). The mailbox key itself, with `auth` `[]`, has no chain to revoke. A relay that never receives
   the newer record keeps the subscription until one reaches it: each relay of a mailbox needs the mailbox's newest
   address record, which the edge leaves at its relays.

What a client does (the edge's is §9 item 10): a close with no error frame (4003 for silence,
1001 for a relay shutting down, 1011 for the relay's own failure, or a dropped socket) is transient, so it reconnects
with backoff and resumes with `cursor: null`, so the relay resumes from the ack it stores for this mailbox and signer
(step 3, §9 item 10), not from a cursor the client remembers. An error frame names the reason: `bad-shape` (4002) is the
client's own protocol error; `bad-auth`, `not-authorized` and the chain codes (4001) refuse its credentials, which every
new handshake meets again until they change, so a client stops after a few such refusals in a row (§9 item 10: three),
and so does `revoked` (4001), at a handshake or ending an open subscription;
and `hop-expired` on a subscription that was open means that its chain has run out, so the client renews the chain (a
new hop from its principal) and subscribes again with it.

**8.6 health: `GET /v0/health`.** Returns 200 `{"ok": true}` (implementation default). The reference relay also
answers `version` and `now` (Appendix B 28) and, since 2026-10-25, `url`, the URL it announces (§8.1),
`null` when it has none.

**8.7 Expiry.** Every 60 seconds the relay deletes expired mailbox rows, then the envelopes no mailbox row references. Changed 2026-10-25 (implementation defaults where not said
otherwise): for each envelope it deletes whose `ts + TTL + skew` is not yet past, the relay keeps a tombstone, its id
and that second (`until`), which step 6a of §8.2 reads, so that a replay inside the ts window is a duplicate after the
sweep as before it (the dedup window); a tombstone is deleted once its `until` is past, when a replay of it is
`stale-ts` at step 6 anyway. The same sweep deletes the address records past `iat + ttl` and the key records past
`exp`. (Added 2026-10-26: the relay keeps, for each key, the `revoked`
list of the newest address record of that key it has stored, after the sweep deletes the record, until an address
record of that key with a newer `iat` replaces it; the list is read at subscribe for the mailbox, at fetch for the
chain's root and at publish for a root an address admits (§8.2 step 7, §8.3, §8.5 items 2 and 8). So a record's
revocations outlive its expiry, an older record published later does not shorten them, and a fetch of the expired
record is still 404. Implementation defaults: Appendix B 75.) Because that list is per relay, a revoking edge reports a
revocation as incomplete while any listed relay has not taken the newer record — the revoked key is still honoured
there — rather than as done (Appendix B 110). The reference relay finds every row the sweep deletes
through an index on its expiry, so a sweep with nothing
expired reads no row, and keeps the store's schema version, refusing to open a database whose version is newer than
its own. (Added 2026-10-25: the sweep also deletes the pending rows past their `until`, §8.2 step 9; an
envelope with a pending row is kept as long, and after the sweep the pending rows are judged again.)

**8.8 Domain roots.** A relay resolves the domain roots of the accept-from records it holds as
an edge resolves an org's root (§9 item 4), with these rules; the defaults are marked:
1. **The fetch.** `GET https://<host>/.well-known/bag/address.json` with `accept: application/json`, over HTTPS
   only, following no redirect (a 3xx is a failure, as any status but 200), through no proxy, within a timeout over
   the whole resolution (10 s by default, at most 60: implementation default) and reading at most 65,536 bytes
   (implementation default). (Changed 2026-10-25: at most 262,144 bytes, the
   edge's cap, Appendix B 41 and 49, one cap for both; at 65,536 an org record with more than about 880 revoked keys
   resolved at an edge and not at a relay.) (Changed 2026-10-26: a relay that
   implements §12 finds the URL by §12.2. It first asks for the TXT records of `_bag.<host>`, asking nothing
   for a name §12.2 item 4 does not ask; with no bag record it fetches the well-known URL above, and with one it
   fetches `/.well-known/bag/address.json` at the origin the record names, `https://bag.<host>` for
   `host=bag`, else `https://<host>`, under the same rules, the guard of item 2 applied to the origin's host;
   two records, a malformed one or a failed lookup fail the resolution as item 6 says, logged `txt-ambiguous`,
   `txt-malformed` or `txt-lookup-failed`. The timeout covers the lookup and the fetch together. The reference relay
   implements §12 and asks with a stub resolver of its own, Appendix B 73.)
2. **The guard.** Before connecting, the relay resolves the host once and refuses it when any resulting address is not
   public: unspecified, loopback, link-local, private (RFC 1918), shared (RFC 6598), unique local (RFC 4193),
   multicast, documentation, benchmarking, an IETF protocol assignment, or reserved (outside `2000::/3` for IPv6), an
   IPv4-mapped or NAT64 address taking the category of the IPv4 address it carries (the full list beyond the brief's
   six is an implementation default; `packages/core/src/net.ts` and `crates/ac-core/src/net.rs` hold it). It then
   connects only to those addresses, presenting the host for SNI and certificate validation, and never resolves the
   host again in between. A host that is an IP literal never gets this far: §7.4 refuses it.
3. **The record.** It must be an address record that verifies at the relay's clock with its skew (§7.5: form,
   signature, `iat`, expiry; `ttl` is at most 86,400 by its form). (Added 2026-10-26:
   when the TXT names a key, the record must agree with it by §12.2 item 5, by that key or by one rotation the key
   countersigned; a record that agrees in neither way fails the resolution before any pin is read, logged
   `txt-key-mismatch` with both keys, and item 6 applies.)
4. **The cache.** A record is used until `iat + ttl`, for 60 s at least and the relay's own ceiling at most (86,400 s
   by default), the ceiling winning over the floor (implementation default). A domain is resolved at most once at a
   time; concurrent publishes wait for that resolution. (Added 2026-10-25: a
   chain whose root is not the key of a domain's cached record, in a publish that did not just resolve that domain,
   fetches the record once more, at most once a minute per domain by the relay's clock and never while a failed
   resolution of it is remembered (item 6), so that a countersigned rotation to that root moves the pin by item 5 and
   admits the chain in the same publish; the rotated-away key is refused from then on. Implementation defaults: the
   bound's key, the domain; its clock, the relay's; a publish that makes no network call never refreshes.) (Added
   2026-10-26: one publish sends at most 8 domains to the network, first contacts, expired caches and the
   refresh above alike, the domains whose pinned key is the chain's root first and then in the order the recipients
   name them; a domain past the cap counts from the cache alone, as in a publish that makes no network call, so its
   recipient is held pending (§8.2 step 9) or the publish is 503 `resolve-failed` with `Retry-After`, and a later try
   reads the next ones while the failures of the first are remembered (item 6). One publish to a mailbox whose roots
   name 1,024 domains fetched all of them before; it fetches 8. Implementation default: the cap, Appendix B 67.)
   A pending-row retry (§8.2 step 9) follows the same per-row cap of 8 domains, pinned roots first and the rest from the
   cache, and a whole retry pass reads at most 64 domains across all rows (`MAX_FETCHES_PER_RETRY`); a row past the pass
   budget counts from the cache alone until the next pass. The retries run on their own task beside the 60 s sweep tick,
   so a slow retry no longer holds the sweep (added 2026-11-01).
5. **The pin.** The relay pins each domain's key in its store at first contact. A record of the pinned key refreshes
   the pin (the newer record by `iat` is kept); a record of another key is accepted only as a rotation of the pinned
   record (§7.3, by the pinned key or its rotation key), which moves the pin; anything else keeps the pin and is logged
   `pin-mismatch` with the offered key (implementation default: the relay's log, not its answer). A mismatch does not
   take the pinned key out of service: it stays the domain's current key while its stored record is valid (item 6),
   so a bare record planted at the well-known path refuses only its own key (403 `root-not-accepted`).
6. **Failure.** A failed resolution, the fetch, the guard, the record or a pin mismatch, is remembered for 60 s, during
   which the domain is not fetched again (implementation default). Meanwhile the pinned key stays the domain's current
   key for as long as its stored record is valid (`now <= iat + ttl`; implementation default), and the one log line of the failure names it (`kept`, `valid_until`); a domain with no valid pinned
   record grants nothing: fail closed, 503 `resolve-failed`
   with `Retry-After: 60` when no other recipient admits the envelope (step 7). The reason goes to the relay's log
   only, never into the answer beyond the code.
7. **What the relay judges.** Only whether the chain's root is the domain's current key, and whether that record's
   `revoked` list names a key of the chain; it still evaluates no caveat.

The reference relay's test-only flags `--well-known-insecure-http` (http, and no guard) and `--well-known-resolve`
(a fixed address for a host) are refused unless it listens on a loopback address, and log a warning; a relay that
others use never sets them. Its operator's `--pin-reset <domain>` deletes one pin while the relay is stopped, for an
org that lost its key and its rotation key: trust on first use again, by a logged decision. (Added 2026-10-26:
the test-only `--dns-resolve <name>=<txt>`, repeatable, gives the TXT record `<txt>`, written in §12.2 item 7's text
form, at `<name>`; it is refused unless the relay listens on a loopback address, and logged as a warning. With it,
`--well-known-insecure-http` or `--well-known-resolve`, the relay asks no DNS server: a name it was not given has no
TXT record, so a test never reaches real DNS.)

**8.9 The network front (added 2026-10-25).** How the
reference relay finds and logs the client of a request, and checks itself; implementation defaults where not said
otherwise, none of them visible on the wire but the record answer (§8.2) and health's `url` (§8.6):
1. **Trusted proxies.** `--trust-proxy <cidr>`, repeatable, names the networks of proxies the relay trusts (an address
   alone is its /32 or /128; a network with bits set past its length, or anything else, is a flag error).
   `--client-ip-header <name>` names the header in which a trusted proxy names the client, `cf-connecting-ip` by
   default (cloudflared's, the proxy of the `usuals.now` stack), and is a flag error without `--trust-proxy`. For a
   request whose TCP peer is inside a trusted network, the header's values, all its lines joined by commas, are read
   from the right: trusted addresses are skipped and the first other address is the client (so `x-forwarded-for`
   gives the right-most address that is not a trusted proxy's); a value met before the client that is not an address,
   a port or brackets included, voids the header, and so do a header line that is not visible ASCII and a list of
   trusted addresses only: the request is then the proxy's own, never a third address. Values left of the client are
   not read, since a client may write them. (Corrected 2026-10-25 before merge, to the rule built and measured.) A peer outside every trusted network is its own client, whatever it sends; with no
   `--trust-proxy` no header is read.
2. **Buckets.** A client counts as its IPv4 address, or as its IPv6 address's /56 in the per-address rate
   limits (§8.2 step 3a and the fetch window of §8.3), the record signers' quota and the daily stored-byte quota (§8.2
   step 8), and as its IPv6 address's /64 in the connection and subscription caps; the pairing per-address counts
   (§8.10) stay at /64, as this item's words leave them; an IPv4-mapped IPv6 address is the IPv4 address. (Changed 2026-11-01: a single /64 let one routed /48 hold 65,536 rate buckets and void the per-address
   caps; a /56 maps to roughly one end site, so the rate, signer and byte caps again bound one actor, while the
   connection and subscription caps, already held by the proxy's global connection limit, stay at the finer /64.)
3. **The connection cap behind a proxy.** A connection whose TCP peer is a trusted proxy carries many clients'
   requests, so it is not counted at accept; a WebSocket upgraded through it takes a place under its client's bucket
   for the socket's life, and one over the cap is admitted at the upgrade and then sent `{"t": "error", "error":
   "rate-limited"}` and closed 1013, logged `connection-refused` with reason `connections-per-ip` (corrected 2026-11-01, where this read `subscriptions-per-ip`): the frame and 1013 close are the same as a direct
   client over its subscription reserve (§8.1), but the logged reason differs — the direct reserve refusal logs
   `subscriptions-per-ip`, the proxied over-cap refusal `connections-per-ip`. Both were changed 2026-10-31 from closing the socket at once with nothing written. The proxy's own connections are bounded by the header and body timeouts (§8.1).
4. **Log lines** (set on 2026-10-25). Every line that names a client, `publish`, `publish-record`,
   `publish-refused`, `rate-limited`, `subscribe`, `subscribe-refused` and `connection-refused`, names it in its
   `ip` field as `--log-ip` says: `prefix` (the default) its /24 or /48 network, `203.0.113.0/24`, `2001:db8:1::/48`;
   `full` the whole address, whose logs are deleted 7 days after capture; `none` `-`.
   Nothing else in a line depends on the mode.
5. **The probe.** `ac-relay probe <url> --key <file>` checks a relay from outside, as a healthcheck in a
   container with no shell can: health (200, `ok`); the probe key's accept-from record (roots the key itself, 4,096
   bytes, `ttl` 60), published only when the relay holds none for it; an envelope from the key to itself, empty
   chain, `ts` now, its sealed part 16 random bytes sealed to no one (it has no type), which must be 200 with its id,
   `duplicate` false and `delivered` 1; and a fetch of it by id, signed by the key, which must answer its exact bytes.
   It prints `probe ok <id>` and exits 0, or prints `probe: <step>: <what>` to stderr and exits 1, the step one of
   `health`, `key`, `record`, `publish` and `fetch`; a usage error exits 2. Each call has 5 s. The key's seed, 64 hex
   characters in `<file>`, is made with 32 random bytes and mode 0600 when the file is missing, and never printed. A
   run stores its one envelope, which expires 60 s after it is stored and is swept, its tombstone after it (§8.7).

**8.10 Pairing rendezvous: `pair/open`, `pair/claim` (pairing by a short code; added 2026-10-30).** Two people pair from a short **pairing code** instead of the
~300-character invite string. The code is `<nameplate>-<word>-<word>-<word>`: a relay-allocated numeric nameplate (a
locator, not a secret) and three words of the pairing wordlist (`packages/edge/src/wordlist.json`, the EFF Short
Wordlist #1; `spec/vectors/pair-code.json` pins the codec and the key derivation). The words seed the invitation MAC
key `S = HKDF-SHA256(utf8(NFKC(lower(words joined by one space))), salt = utf8(nameplate + "|" + invitation), info =
"ac/peer-code/1", 16 bytes)`; the lowercasing is applied first and NFKC to its result, as written, and both the key
derivation and the code parse MUST apply the two in this order, so a future non-ASCII wordlist cannot split `S` (latent
for ASCII words, where the two commute; added 2026-11-01). The request to the invitation identity is MAC'd under `S` as the `peer` ceremony. Integrity rests on the six **check digits** compared out of band, never on the code
(threat-model R19): whoever reaches the invitation with a guessed or intercepted code still shows different check
digits and the person declines. The six check digits are the first 4 bytes of `sha256(canonical(["ac/peer-code/1",
inviter, invitation, requester, sealing, S]))`, read as a big-endian unsigned integer modulo 10^6 and shown as six
decimal digits (added 2026-11-01; `packages/edge/src/pairing.ts`). A man-in-the-middle who substitutes
its own invitation identity or inviter address changes `inviter` or `invitation` in that preimage and so shows
different digits, which the out-of-band compare catches; its one-shot success is about 1 in 10^6 per pairing,
independent of the N = 20 MAC-guess bound. The three typed tries are the human re-reading the same digits, not guesses
at `S`, and do not materially raise that chance; the residual is whether a person performs a genuine out-of-band read
rather than glancing at a screen (§8.10). The check digits are compared by one side only. The acceptor (the display side) shows
its six digits once and reads them aloud over the human channel before it confirms the send, asserting no match of its
own; the inviter (the admitting side) types the six digits it was read, and the inviter edge compares them against its
own locally computed digits — the typing side never displays the digits it checks against, so the compare is a real
out-of-band step and not a copy from one screen into a box. A match admits the peer and lets the request go; a typed
mismatch is `digits-mismatch`, raised locally at the inviter (the relay never sees check digits), allowed at most three
typed attempts in the one dialog, never consuming the invitation and never counted in R19's N = 20 MAC-guess bound;
after the third mismatch the inviter abandons the attempt and tells the acceptor nothing, so a refusal is
indistinguishable from no-answer and a man-in-the-middle gets no oracle. The dialog never shows the expected digits and
offers no show-and-confirm fallback. For parity the CLI admitting side (`ac peer invite`) types the digits too, with no
plain yes/no confirm. The two calls are OPTIONAL; a relay may omit them, and an edge whose relay lacks them
falls back to the invite string. A relay that serves them is a *rendezvous*; the two sides configure which rendezvous
to use (`--rendezvous`, default the identity's first relay; a `code@host` form overrides it).

**The address-bound path is the default when the peer's address is known (2026-11-01).** Pairing's whole secrecy is the out-of-band digit comparison above: a man-in-the-middle on the human transfer channel, who edits the string or code in flight and substitutes their own invitation identity and inviter address, is caught only by that comparison, and only if a person truly reads the digits from the other channel rather than glancing at a screen (an attacker who can edit the string in transit controls both ends, and only the code comparison catches it). So when the inviting or accepting side already knows the other's address, the invitation is bound to it, and the open, unbound invitation is the fallback used only at genuine first contact, not the default. The admitting side names the peer (`--for <address>`) so only that address's request is admitted; the accepting side names the expected inviter (`--for <address>`) so a string naming any other inviter is refused `not-for` before the check digits are shown and without consuming the invitation. The bound address is one the side already holds out of band, never one read from the string or code being paired, so an attacker who substitutes an address in transit is refused before any prompt. Binding narrows who can answer; it does **not** replace the digit comparison, which is still performed on the bound path, since an attacker who controls both the address channel and the string channel would be bound to an address they chose. Inside an agent host, the bound path is offered in the host's own pairing dialog — a field for the peer's address, or the peer's pasted address — and the terminal invite is never offered as the default or as a workaround (the MCP `pair_invite`/`pair_accept` tools). The ceremony renders the check digits on one side only and never on the side that types them (the paragraph above), so no dialog invites a glance-and-confirm.

- `POST /v0/pair/open`. Body `{inviter, invitation, relays, ttl}` and `sig`, an Ed25519 signature by the key in
  `invitation` over `canonical(["ac/pair-open/1", inviter, invitation, relays, ttl])`: `inviter` and `invitation` are
  addresses, `relays` is a list of 1 to 64 relay URLs (§7.2's form and cap), each listed once and signed in the order
  listed, and `ttl` an integer; a body with any other member, or with one of these missing or malformed, is 400
  `bad-shape`, and a `sig` string that is not 128 hex characters 400 `bad-hex` (clarified 2026-11-03, from `crates/ac-relay/src/pair.rs`; the reference edge opens with one relay, the
  rendezvous itself). The relay verifies `sig`
  against `invitation` before allocating, else 422 `bad-sig`; so only the holder of the one-time invitation identity's
  key may open a nameplate for it, and an open naming a victim's mailbox is refused. `ttl` is required, 1 to 600 — a
  missing, `0` or over-600 `ttl` is 400 `bad-shape`, there is no default (corrected 2026-11-01, where this read "`ttl` ≤ 600 (default 600)"); the
  open's body is at most 768 bytes, 512 for the reach and 256 more for its signature (else 413 `body-too-large`;
  clarified 2026-11-03: the relay bounds the body it reads, where this read "the stored reach blob ... ≤ 512 bytes"),
  and the relay stores the reach `{inviter, invitation, relays, exp}`, with `exp = now + ttl`. The relay allocates the shortest free numeric nameplate (more digits only when the space fills) and returns
  200 `{nameplate}`, the `nameplate` a decimal string of 3 to 9 digits with no leading zero (not a number): the relay allocates from 100, and a claim of any other string is 404 `no-nameplate` (clarified 2026-11-03, from `crates/ac-relay/src/pair.rs`, where this read "1 to 9 digits"). A second open of an invitation that already holds an open nameplate is 409 `stale-record`. Caps:
  at most 16 open nameplates per client address (429 `rate-limited`) and at most 10,000 open in all (503
  `store-full`); an open also draws the client's publish allowance (§8.9).
- `GET /v0/pair/claim/{nameplate}`. Returns 200 `{inviter, invitation, relays, exp}`, or 404 `no-nameplate` when the
  nameplate is absent or expired; a claim does not consume it (retries are allowed). A per-client-address token bucket
  limits claims to 5 a second, burst 10. The relay stores and returns **reach metadata only** — the invitation
  identity, the inviter's address, the relays and the times — never the words, `S` or the check digits.
- The pairing request is an ordinary `publish` (§8.2) of an envelope to the invitation identity at the blob's
  `relays` — in the reference the blob's `relays` are the rendezvous itself, so the request goes there (corrected
  2026-11-01: the 2026-10-31 ruling moved the invitation identity and its mailbox to the
  rendezvous, Appendix B 110, and the earlier "not to the rendezvous" described the pre-ruling design; a rendezvous
  must therefore host the invitation mailbox at the relays its `pair/open` lists). A relay rate-limits requests delivered to an open invitation: a token bucket on the
  invitation across all client addresses, 1 a second, burst 5, and at most 10 per (invitation, client address),
  charged after the envelope verifies (§8.2) for a publish delivered to that invitation; a refused request draws no
  count. The invitation is consumed only by a request the inviter accepts; the inviter (edge, §9) refuses a bad MAC
  `bad-code` **without** consuming the invitation and ends it after 20 such misses — the guess bound, enforced at the
  edge so it holds whatever relays are used, cross-relay included (≈ 20 / 2^31; threat-model R19). A later request to a
  consumed invitation is `leaked`. A frame that is not a well-formed request under `S` — unparseable, the wrong type, a
  bad record, or a valid-form request that fails any check other than the MAC — is dropped silently: it neither
  consumes nor ends the invitation and is **not** counted toward the 20, on both the word-code and the paste-string
  paths (added 2026-11-01). Under a word code a bad
  MAC (`bad-code`) and a `not-for` each still print a `refused` line on the person's own side only — the one visible
  sign of an edited string, bounded by the code's own guess bound — while every other failure prints nothing and
  charges nothing; in Appendix A that local line is `bad-code` or `not-for`, and a silent drop carries no code. Only a structurally valid request whose sole failure is the
  MAC is one of the 20 "such misses", so the bound stays 20 guesses at `S` and a stranger cannot end an open pairing
  with junk envelopes. `leaked` is raised only when a second request that passes the MAC check arrives from a different
  requester (a different `from` key) — the true double-claim condition, two parties each producing a valid MAC under
  `S`, so `S` reached a third party; a retry from the same requester (for example after a lost publish answer, even
  rebuilt with a fresh `ts` and so a different envelope id) is not a leak, and a frame whose envelope id was already
  checked is dropped. The pairing request is exempt from §9 item 1's persist-before-publish rule: the acceptor's edge
  keeps no outbox for it, since a same-requester retry is no longer a leak and the person simply retries.
- **Private-address guard.** A rendezvous host — a pasted `code@host`, and the blob's `relays` read from an untrusted
  rendezvous — is subject to §9 item 11: a loopback, link-local, RFC 1918, unique-local or unspecified host (or a name
  resolving only to such) that is not a configured relay is `resolve-failed` before any request, unless the operator
  allows private relays (`--allow-private-relays`). This closes an SSRF from a hostile peer's code or invite, and the
  same guard now covers the long invite string's relay field.

**The invite string and the pairing request** (clarified 2026-11-03, from `packages/edge/src/pairing.ts` and
`pair-code.ts`; `pair-code.json` pins each construction, §11). The preimages' encodings are §2.4's.
1. **The invitation.** The inviter makes a fresh invitation identity I, a signing key and a sealing key (§3.3), and
   chooses the invitation's `ttl`, 1 to 600 s. At the rendezvous it publishes I's address record (`key` I,
   `sealing_key` I's X25519 public key, `relays` the rendezvous alone, no rotation key, nothing revoked, `ttl` the
   invitation's, `iat` now) and I's accept-from record (`roots` `["*"]`, `max_bytes` 8,192, the same `ttl` and
   `iat`), and subscribes to I's mailbox there. The invitation's end, `exp`, is that address record's `iat + ttl`.
2. **S.** With a word code, `S` is derived from the words as above, the salt naming the nameplate the rendezvous
   returned and I's address as `invitation`; when the rendezvous offers no pair call, `S` is 16 bytes from a CSPRNG and
   the inviter gives out the invite string instead.
3. **The invite string** is `ac-peer1:` followed by base64url without padding (RFC 4648 §5) of
   `utf8(canonical(["ac/peer-invite/1", inviter, invitation, relay, S]))`, `inviter` the inviter's address,
   `invitation` I's and `relay` the rendezvous where I is reached. A reader drops white space from a pasted string and
   refuses it unless the prefix and the tag are these, `inviter` and `invitation` are addresses, `relay` is `http://` or
   `https://` and one or more characters that are not white space, and `S` is 32 lowercase hex characters. Under a word
   code the acceptor instead claims the nameplate and takes `inviter`, `invitation`, the first of `relays` as `relay`,
   and `S` from the words.
4. **The acceptor's digits.** The acceptor reads I's address record at `relay` and stops, sending nothing, unless the
   record carries a sealing key and its clock is at most `iat + ttl` plus the skew; `exp` is that record's
   `iat + ttl`. `requester` is the acceptor's own address, and `sealing` its current key record's `sealing_key` (§7.4)
   when it has a key record, else its own X25519 public key, the one its address record names. It shows the check
   digits of `(inviter, invitation, requester, sealing, S)`, three digits, a space and three digits.
5. **The request.** On the person's yes the acceptor publishes to `relay` an envelope (§5) whose `from` is its own
   signing key, `auth` `[]` and `to` `[invitation]`, sealed (§4.3) to the `sealing_key` of I's address record, with a
   fresh `thread`, the sealed `type` `peer.request.v1` and the `body` `{"record": R, "key": K, "mac": M}`: R is the
   acceptor's current address record as its JSON text (§7), a string; K, present only when the acceptor has a key
   record, is that record's JSON text, a string; and M is the request MAC of `(inviter, invitation, requester,
   sealing, exp)` under `S`, 64 lowercase hex characters.
6. **The inviter's check.** The inviter parses and verifies the envelope (§5.4, §5.5) at its own clock, opens it with
   I's sealing key (§4.4), and takes it as a request only when `auth` is `[]`, the `type` is `peer.request.v1`, R is an
   address record that verifies (§7.5) and whose `key` is `from`, K, when present, is a key record that verifies and
   whose `key` is `from`, and `sealing`, K's `sealing_key` when K is present and else R's, is not `null`; anything else
   is the silent drop above. It then computes M with `requester` = `from` and compares it with the request's in constant
   time; a mismatch is the bad MAC above. A request that passes is checked against `--for` (`not-for`), and the check
   digits the inviter's person types are compared against the digits of these same fields.

Person-facing text (dialogs, the CLI, this spec, the Internet-Draft) calls the words the **pairing code** and the six
digits the **check digits**.

## 9. Edge requirements

The edge is the agent-side library: `packages/edge`, in TypeScript, with no native module. An
edge MUST:
1. **Keep an outbox of exact bytes.** Persist an envelope's bytes before the first publish and publish them to
   at most K = 3 of each recipient's relays, in the record's listed order, promoting the next listed relay when a target
   is given up and keeping at most K live targets per recipient; publish is idempotent by id. Per target relay:
   sealed, publishing, then published, or retry, kept so that `resend` sends the same bytes. A target is
   retried until the relay TTL has passed since the envelope's `ts` (the horizon), with a wait of 1 s × 2^n up to 1 hour
   less a jitter of up to 10%, never past the horizon, where a last try is made; it fails only at the horizon, as
   `publish-failed`, or at once on a refusal the same bytes would meet again (a 4xx other than 408 and 429), with the
   relay's code; a 429 waits for its `Retry-After` when that is longer (the 2026-10-24 rule of 20 tries it
   replaced is in Appendix B item 33).
2. **Keep an inbox.** Each envelope moves from received to verified or rejected (with its code), then to routed or
   queued, then acked. It acks only once the envelope is durable at the edge. The envelope id is the unit of
   idempotency (§5.5): an edge MAY key inbox rows by the relay's `(relay, mailbox, cursor)` position as a fast path, but
   that position is relay-local and not monotonic across a relay restore (Appendix B item 102), so it MUST NOT by itself
   decide delivery — a frame whose cursor matches a stored row but whose envelope id differs is a new envelope and MUST
   be stored and run through the id dedup of item 3, never dropped or acked on the cursor match alone (added 2026-10-31;
   traced from code, no run yet).
   (Normative since 2026-10-25: a check that ends in `resolve-failed` (a record that could not be read yet) or
   `future-ts` (a `ts` ahead of the edge's clock by more than the skew) is transient: the envelope stays received, is
   checked again after the backoff of item 1 until `ts` + TTL, and only then is rejected with that code. It may be acked
   to the relay meanwhile, since it is durable at the edge. Every other code rejects at first sight.)
3. **Verify.** §5.4, §5.5 and §6.2; then deduplicate with a set of seen ids whose entries expire at max(first sight,
   `ts`) + TTL + skew, counted through that second, the window of the stale-ts check; each later copy of an
   id already in the set is dropped, not silently but with its own audited `dedup` line (decision `reject`, reason
   `duplicate`), whatever relay the copy arrived on, so a recipient subscribed at several of a sender's relays records
   one `reject duplicate` per extra copy; then unseal (§4.4)
   and evaluate the caveats with the sealed part (§6.3). (The 2026-10-24 rule of first sight + TTL + skew it replaced
   is in Appendix B item 34.)
   (Normative since 2026-10-25: the receipt bound of §6.2's note. After §6.2, a chain is refused
   `hop-expired` when the frame's `received_at` (§8.5 step 4), or the edge's own first sight of the frame when the
   relay sent none, is past the earliest `exp` of the chain's hops plus the edge's skew; an empty chain meets no bound.
   The edge keeps that second as the inbox row's `received_at`, so a row checked again after a transient rejection
   (item 2) or after a restart meets the same bound: mail a relay received in time is not refused for being read late.
   The audit's `verify` line names `received_at` in its detail, and a refusal by the bound names `received_at` and
   `until`, the bound's last second. Implementation defaults: the column, and those two detail members.)
4. **Resolve and pin.** Read an org's record at `https://<domain>/.well-known/bag/address.json`
   and key records through relays. A record is read at the hint relays and then the edge's own relays, each
   asked once in that order — never at the relays the record itself lists, which are not known until the record is
   read (those are where the sender then publishes, Appendix B 40, §4.3) — one after another. From each relay that answers within its timeout the edge takes the record that verifies (its
   signature and form, §7; for a key record also that its `key` is the address asked for), and across the relays that
   answered it keeps the one with the greatest `iat` — it no longer stops at the first that verifies when more than one
   relay is available (changed 2026-11-01). The old first-verifying rule let an
   earlier relay serve a verifying but older epoch key, or an address record whose `revoked` list predates a
   revocation, over a newer one a later relay held, so the sender sealed to the superseded epoch or accepted the
   revoked key; §7.4's greatest-`iat` rule, which chose among the records one relay holds, now also chooses across the
   relays that answered, and the revoked list and epoch key the edge acts on are those of the greatest-`iat` record
   seen. The resolver never regresses: once it has seen an `iat` verify for a signer and kind — within a resolution or
   from its cache — it never uses a lower one, and if the relay that served the greatest `iat` becomes unreachable and
   only older records remain it fails `resolve-failed` rather than fall back to the older, the same fail-closed spirit
   as the guard below. **A relay that does not answer is never a disagreement and never blocks resolution** (the
   point of a two-relay install): the resolver resolves from the newest among the relays that answered, so one listed
   relay being down never turns into `resolve-failed` while another answered with a usable record, and fail-closed
   applies only to a disagreement between relays that answered, never to an unreachable one. The residual, as item 110
   named it for the publisher: a revocation — or a newer epoch key — held only by a relay the reader did not reach this
   resolution is not seen until that relay answers, so the reader may still accept a key that relay would show revoked,
   or seal to an epoch it would show superseded; this is surfaced (the resolution records which relays answered), not
   failed closed, since failing closed on an unreachable relay would let one down relay deny every read, and the
   publisher-side `incomplete` (item 110, §8.7) bounds how long a revocation stays withheld. A relay restored from an
   older copy (item 102) that rolled its `revoked` lists back heals the same way — a reader that also queries a relay
   holding the newer record takes it; when every queried relay lags or is restored the residual stands until the
   owner's keep-alive republishes (item 110), which a restore cannot re-assert on its own. The resolver MAY query the
   relays concurrently to hear from more than one without added latency. Each request is bounded by a timeout (default 10 s) but the number of relays tried and the total time
   are left unbounded, so a resolve against 64 unreachable relays can take 64 × 10 s = 640 s before it fails
   `resolve-failed`; this worst case is a known limit, left unbounded on purpose, since a total deadline could turn one
   slow but live relay into a false `resolve-failed` and no measure yet shows a bound is needed. Cache a record no
   longer than its TTL, and a key record no longer than
   `min(exp, now + skew)` (the skew, default 300 s), so a sender picks up a restored or rotated peer's fresh epoch key
   within the skew rather than sealing to one already deleted (changed 2026-10-25; key-record
   cache narrowed from a day to the skew 2026-10-29); pin a root's key at first contact
   and accept another key only through §7.3 (`pin-mismatch` otherwise); reject a chain in which any hop's `sub` is in
   the root's `revoked` list (`revoked`). To seal to a recipient, take its current key record's sealing key (§4.3,
   §7.4) if it has one; else a non-`null` address-record `sealing_key` if present; else fail `resolve-failed`. An edge
   that has already seen a recipient resolve a key record does not take that address-record fallback for it: it fails
   `resolve-failed` instead, so a withheld or faulting key record cannot downgrade a known forward-secret identity to
   a long-lived address key (added 2026-10-29). A recipient that publishes a `null` address-record `sealing_key`
   and a key record is therefore sealed only to its
   short-lived key record, and, when its key record is unavailable, the seal fails `resolve-failed` rather than
   downgrading: its signed address record carries a `null` sealing key, so an attacker can withhold the key record but
   cannot forge a non-`null` one, and there is no silent downgrade to a long-lived key. An edge publishes, for its own
   identity, a `null` address-record `sealing_key` and a current key record, rotating the record and deleting its old
   epoch private key after the deletion horizon (§7.4). The meaning of a non-`null` address-record sealing key, the
   fallback, is left to higher layers outside this core. (Added 2026-10-28.) (Added 2026-10-26: an edge that implements §12
   finds an org's record by §12.2, its TXT record first and the well-known URL without one, and resolves a handle by
   §12.4 item 4; the edge's half is deferred.)
5. **Apply its policy.** Trust roots explicitly, by domain with an optional pinned key, or by key, an address
   (`untrusted-root` otherwise; trust by key added 2026-10-25: the edge has done it,
   Appendix B 38). A root trusted by key that delegates, so that its chains are not empty, keeps its address record,
   with its `revoked` list, at the relays of the recipients it writes to, where their edges read it (Appendix B 38); a
   recipient without it refuses the chain `resolve-failed`, and a root that only signs for itself needs none;
   evaluate caveats with its configured evaluators, failing closed on any caveat they do not know (§6.3); accept only
   configured types (`type-not-accepted`). An optional spawn hook may start an agent for a root message, only for roots
   allowed by the mailbox's accept-from record and with tool permissions derived from the caveats. v0 has no
   spawn hook: it queues, and spawns nothing.
6. **Route by `thread.id`.** To a registered handler, else to the default handler or the spawn hook for a root message.
   It keeps (thread id, session) so that replies reach the session that opened the thread; `from` is the session key,
   the chain names the principal, and replies address the principal.
7. **Publish outbound through the retrying outbox** of item 1; the org relay's smarthost role is deferred.
8. **Audit every step** in a hash-chained JSONL log, each line `{seq, prev, ts, event, decision, reason, id, from, root,
   detail, hash}`, where `hash = sha256hex(utf8(canonical(audit line preimage)))` (§2.4), `detail` enters the preimage
   as JSON text, and `prev` is the previous line's `hash`, 64 zeros for the first line. Events: verify, policy, dedup,
   unseal, route, publish, resolve, pin, rotate, rate-limit. `reason` is a code from Appendix A, or `"ok"`
   (implementation default). Recomputing the chain finds any edited line. No line holds key material. (Changed
   2026-10-25: recomputing the chain finds an edited line, a reordering and a line deleted inside the log,
   not a cut tail or a log rewritten from some line on; only the anchor of the note below finds those, and no claim calls
   the log tamper-evident beyond that anchor until an outside witness exists. `decision` is one of `accept`,
   `reject`, `retry`, `route` and `queue`, and nothing else; Appendix B 35.)
   (Normative since 2026-10-25: the event `subscribe` is added, for a subscription the relay ended: decision
   `retry` when the edge subscribes again, `reject` when it gives up (item 10). The edge keeps the `seq` and `hash` of
   the last line it wrote outside the log, its anchor, updated after each append; a verifier given the anchor reports a
   log with fewer lines than the anchor's `seq` as truncated, and one whose line at that `seq` has another `hash` as
   diverged, which recomputing the chain cannot find; an edge does not continue such a log. Exactly one live process
   writes a given audit file: the edge holds a lock on its state while it may write its own `audit.jsonl`, and a tool
   that must audit while another process holds that chain writes its own file (a sidecar `cli-audit.jsonl`) rather than
   appending to the held one — two live writers of one file reuse a `seq` and fork the chain (measured, a
   `record keep` rotation run beside a live server). Each audit file is its own hash chain from genesis, independently
   verifiable, and independently anchored by its own row in the edge store; `audit verify` and start read the
   enumerable set of anchored files and fail closed on an anchored-but-missing file, so a dropped or rewritten file is
   caught as `truncated` or `diverged` across the whole set. A non-edge rotation's sidecar anchor is written lock-free
   — one disjoint-row upsert that must never block the MCP open path — and the sidecar may take an exclusive lock only
   on itself; the server MAY reconcile a sidecar into the single chain on its next start. There is no cross-chain total
   order between files: each is independently complete and tamper-evident, and `ts` gives the approximate interleaving.)
   (Editorial, 2026-10-29: the audit validator's accepted event set (`AUDIT_EVENTS`, packages/edge/src/audit.ts) is
   authoritative and, beyond those above and `subscribe`, also names `moderate` and `release` (a moderation module's
   verdict and an explicit release or drop of a quarantined message or held send), `onboard` and `restore`
   (a person's `ac init` and `ac restore`, in the identity's own log), and `pair`
   (each step of a pairing the MCP server's pair tools drive; §13.11).
   `decision` stays the five values above and `reason` a code or `"ok"`.)
   (Added 2026-11-12: a line the bag service writes carries a twelfth member, `connection`, inside its preimage; section
   9.1 item 3. A verifier accepts both forms.)
9. **Guard its keys.** Private keys are files of mode 0600 in a directory of mode 0700, never logged; the CLI prints
   addresses only.
10. **Subscribe at its configured relays, and subscribe again (normative since 2026-10-25).** An edge subscribes,
    one independent loop per relay, to the relays it is configured with (how many is the configuration's: the MCP
    server passes its whole `--relay` set, the reference CLI passes the one `--relay` it is given — a description of the
    reference, not a normative cap, since an edge may be configured with one relay or with many); it does not subscribe
    at an identity's address-record relays of its own accord. An identity's
    configured relays should therefore be exactly the relays its address record lists, because mail a sender publishes to
    a listed relay the identity does not subscribe to goes unread until a fetch by cursor finds it. When a relay ends a
    subscription with an error frame, the
    edge subscribes again with `cursor: null`, waiting 250 ms × 2^n, at most 30 s, between attempts; three
    permanent handshake refusals in a row (`bad-auth`, `not-authorized` or a chain code) end that relay's loop — the
    other relays' loops run on and `start` does not throw — and the
    edge audits and reports it. A closed connection is reconnected the same way. The edge
     MUST resume with `cursor: null`, never a cursor it remembers, so the relay resumes from the ack it stores for this
     mailbox and signer (§8.5 step 3): a remembered cursor is in the relay's pre-restore numbering, and after a restore
     the relay re-issues rows at lower cursors (item 29, item 102) which it never frames to a client resuming above them
     (the relay resumes after the client's cursor, clamped to its own last, so a row at or below that is skipped), and
     the id check of item 2 acts only on a frame that arrives. Resuming from the relay's ack keeps the resume point in
     the relay's current numbering, so every row after it is framed and genuine repeats are dropped by id; an unacked
     frame coming again is the only cost, already part of at-least-once delivery (added 2026-10-31; traced from code, no run yet).
11. **Refuse private relays it was not given (normative since 2026-10-25).** An edge does not publish to, fetch
    from or subscribe to a relay URL whose host is a loopback, link-local, private (RFC 1918), unique-local, multicast
    or unspecified address, IPv4 or IPv6 (an IPv4-mapped address read as its IPv4), or a name that resolves only to such
    addresses, unless the URL is one of the edge's own configured relays or its operator allows private relays; such a
    URL is `resolve-failed`, refused before any request (a recipient's record names the relays a sender
    publishes to). The relay's own guard for domain roots is §8.8's.
12. **Follow a raw-address root only on its rotation key (added 2026-10-28).** For a pinned `address:` root, one named by its raw key address and not by a domain, an
    edge moves the pin only to a rotation countersigned by the pinned record's `rotation_key`: a record whose
    `rotated_from` is the pinned key and whose `rotation_sig` verifies under `rotation_key`, §7.3's other accepted
    countersigner, the previous key itself, being refused for this subject. A pinned record with no `rotation_key`, or a
    pin held with no record, is not followed: the new key is `pin-mismatch`. A `domain:`
    root is unchanged: it follows its well-known record's rotations, countersigned by the previous key or its rotation
    key (§7.3, §9 item 4). §7.3 itself does not change, since relays still accept either countersigner, and no vector
    moves. `packages/edge/src/pins.ts` lines 75 and 76 split the path: every subject meets `verifyRotation`, and only an `address:`
    subject also meets `underRotationKey`.

(Items 1, 3 and 10 supersede Appendix B items 33 (the 20th failure), 34 (stated here as normative) and 42 (an error
frame was fatal), which Appendix B keeps as written, for history; the clean-up of 2026-10-30 adds Appendix B items 89
and 90 for the pairing rendezvous and the sender fan-out.)

### 9.1 The bag service: one process as the owner of many mailboxes (added 2026-11-12, bag 0.4.0)

This section is local, outside the frozen core: no wire format, preimage or relay call changes, and no vector moves. It
says what an edge that holds many identities in one long-lived process, the reference's bag service, keeps of items 1
to 12. The service's own socket, launch token and methods are the reference's local contract (`docs/bag-service.md` of
the source repository, contract 1), not part of this specification.

1. **One owner per mailbox, unchanged.** Exactly one live process fetches, acknowledges and advances the cursor of a
   given identity's mailbox at a time, as items 2 and 10 require of an edge. The service is that process for every
   identity it holds: it takes each identity's own state lock (the lock item 8 names) for as long as it owns the
   identity, so a per-identity server or a tool of the same home never owns one mailbox together with it. An identity
   another process holds is not owned by the service until that process releases it. One service runs per home; a
   second exits without opening any identity.
2. **Many readers, one cursor.** Several local connections (host sessions) may use one identity through the service.
   They share that identity's one inbox and its one subscription per relay: the service subscribes, acknowledges
   (section 8.5 step 5, `{"t": "ack", "cursor": n}`, cumulative) and deduplicates (item 3) once per identity, however
   many connections use it. An envelope is acknowledged once, after it is durable at the edge (item 2), and the at-least-once delivery of section 8.2 and the id
   dedup of item 3 are unchanged; acknowledgements are serialised per identity, so no two connections race one ack.
   Which connection a message is shown to is local behaviour (the reference returns it once, to the first connection
   that reads it), not a delivery rule.
3. **The audit line's connection (normative for the service's own lines).** A line the service writes in an
   identity's log for an act that arrived on a local connection carries a twelfth member, `connection`: an opaque
   local id of that connection (1 to 64 of `A-Za-z0-9._:-`), or `null` for an act no connection started (a delivery,
   a keep-alive republish). It names, and never authorises: it is not a key, a token or a capability, and nothing is
   looked up by it. The preimage of such a line is item 8's ten fields with `connection` appended,
   `[seq, prev, ts, event, decision, reason, id or null, from or null, root or null, detail or null, connection or
   null]`, so the connection is covered by the line's `hash` and by the chain. A line with no `connection` member keeps
   item 8's ten-field preimage. A verifier MUST accept both forms in one log, MUST compute each line's preimage by its
   own form, and MUST refuse a line whose `connection` member is present but neither `null` nor a string of that form.
   A per-identity server over stdio writes the ten-field form, as before. (Implementation default: the member's name
   and the id's form.)
4. **Keys stay in the edge.** The service reads each identity's keys from its custody (a key file of item 9, or a
   platform keychain item) when it opens the identity, holds them in that identity's edge, and never sends them to a
   connection; a restart reads them again from custody and never receives them from the process before it. Item 9's
   file modes hold for any key that is a file.
5. **Handover.** A service that stops for an upgrade first refuses new work, ends every pairing in progress (section 8.10:
   the invitation secret and the check digits die with it, never persisted), flushes each identity's store, cursor
   and acknowledgements, then releases each identity's lock before the next process can take it. There is no moment
   with two owners. A fetched envelope that was not yet acknowledged stays durable and is acknowledged by the next
   owner, which item 3's dedup makes safe.

### 9.2 Delivery between identities of one home (added 2026-11-13, bag 0.4.1)

This section is local, outside the frozen core: no wire format, preimage, record or relay call changes, and no vector
moves. Two identities of one person must stay unlinkable to relays and wire peers, so an edge that holds several
identities refuses an act from one to another (the reference's `to-own-identity`). This section says how such an edge
MAY still deliver mail between two of its own identities without that link ever reaching the wire.

1. **A home-wide word, and one Allow per pair.** A home-wide word turns local delivery on or off (the reference:
   `<home>/run/local.json`, version 2 `{"local_delivery": "on" | "off", "hidden": [label]}`, read only as a 0600
   regular file of the user; with no file it is on, one constant; `bag local-delivery off` turns it off at once and
   `on` asks a terminal y). An identity may be hidden: it sees none of the others and none reaches it. The edge MAY
   list the visible identities to each other (the reference: `status.home`). Each pair is then the person's own yes,
   asked once, on the first message from one to the other, in the recipient's window, in words built from the two
   labels only, never the message; the message waits until then, and a no refuses the pair for a cooling period (the
   reference: 10 held at most, 24 hours, re-asks bounded, 7 days to answer). Only the person's own no declines; no
   answer leaves the request waiting (a dialog closed or timed out, a cancelled call, an aborted confirm), and it is
   asked again later. While the word is off or either side is hidden the request is neither asked nor answered. No
   code, check digits or relay call is involved: there is no party between the two sides.
2. **A local record, never wire trust.** A pair's state is kept in a record of the edge's own (the reference:
   `<home>/run/local-peers.json`, 0600: requested, allowed, declined), never in the trust list item 6 reads for wire
   mail, never in an accept-from or any published record. So an envelope between the two that arrives from a relay is
   judged by the wire rules alone, and refused. A change the edge did not write is recorded and shown to the person,
   and a pair it did not write, whatever its state, is asked again; one naming no identity of the edge is dropped.
3. **The same envelope, a local origin.** A local send builds the envelope a wire send would (section 5: signed by the
   sender's key, sealed to the recipient's newest epoch key the edge holds, else the sealing key of its own copy of the
   recipient's address record, never one read from a relay) and hands its bytes to the recipient's receive path with an
   origin the edge itself sets: no relay URL can be that origin (the reference: the relay value `local:`, which no
   `http` or `https` URL is). The receive path runs as for a frame (items 1 to 7: verify, policy, dedup, one unseal,
   route); the recipient's local roots are added to its policy only for an envelope of that origin. Nothing is written
   to the outbox and no relay is called; a read receipt, when the reader's own setting allows it, goes back the same
   way.
4. **What stays refused.** A send whose recipients mix own identities and wire peers is refused: an envelope's `to` is
   seen by every recipient. Delegation, and any hop issued from one own identity to another, stays refused, since a
   chain travels in envelopes. An identity whose keys an agent holds, or whose authority is a grant, is never paired
   locally.
5. **Not open yet.** A recipient whose keys are not open (a keychain item read only when a person binds it) is never
   opened by a send: the sealed bytes wait in its own state (the reference: `<home>/state/<name>/local-spool/`) and are
   handed to its receive path when it opens. One that no longer unseals there (its key rotated since) is kept (the
   reference: `<id>.env.failed` in the spool) and logged, never dropped silently, and every refused drain is reported
   to the sender's own record. Unpairing drops the pair (the next message asks again); removing an identity drops its
   pairs and its waiting mail.

## 10. Security considerations

- **Metadata.** Relays see `v`, `id`, `to`, `from`, `auth` (every hop's keys, caveats and expiry), `suite`, `ts`, sizes,
  timing and the client's IP address; never `type`, `thread` or `body`. `auth` stays
  outer so that the recipient's relay can enforce accept-from. Sealing the caveats while keeping the chain's keys
  outer, and hiding `from`, are for later suites. The relay's optional metrics derive only from what it already sees: a
  count-only distinct-networks gauge — a set under a per-process, in-memory salt, dropped daily, from which only the
  bare count is exported and no network is stored — adds nothing. The new-signers-a-day metric is the delta of a counter
  (`ac_relay_new_signers_total`), not a per-record first-seen store, so it adds no per-identity metadata.
- **Local pairs join contexts (section 9.2).** Delivery between two identities of one home never reaches a relay,
  so no relay or wire peer can link them; but a local pair joins two contexts the person may have kept apart. A
  message from one identity reaches the other's host session as mail from a trusted sender: still data, never an
  instruction, yet a model misled in one session can now reach the other. Allow a pair only for identities that are
  meant to talk to each other, and hide one that must stay apart; a sender's local sends are bounded (the reference:
  20 a minute, 200 a day). The same user is not a boundary either way: a process of that user could already act as
  either identity, write the edge's local files, or take a host's consent link by registering first.
- **Root compromise** is unsolved, for everyone. It is bounded by short-lived principal and
  session keys, by revocation in address records that live a day at most, and by countersigned rotation against
  pinned keys. A rotation key kept offline lets an org recover a lost or compromised root.
  Forbidding an individual's long-lived sealing key (§7.2, §9) removes the pre-forward-secrecy exposure in which a
  single stolen long-term sealing key read a mailbox's whole mail, past and future.
  Short-lived keys bound a compromise against relays and the network, not against the key's holder: a hop
  is judged at the envelope's `ts`, which its signer picks, so the holder of an expired session or principal key can
  still sign mail dated inside the hop's life, which verifies for up to TTL + skew after `exp`. Judging live delivery
  at the relay's clock as well closes that for mail a relay receives after
  `exp` + skew; a relay that lies about when it received mail can still revive an expired key until relays sign their
  receipts. (§8.2 step 6 at the relay, §9 item 3 at the edge,
  which takes the relay's `received_at` or, when there is none, its own first sight.)
- **Revocation after expiry.** A `revoked` entry that dropped out at its hop's `exp`
  let a recipient that verifies after `exp`, an offline mailbox among them, accept mail its root had revoked
  while the hop was live; §7.2 now keeps the entry until `exp` + TTL + skew, the last second such mail passes the
  stale-ts check. An explicit `ac logout` additionally
  revokes every subject the agent granted in the window whose `exp + TTL + skew >= now`, closing the back-dating hole
  for hops that expired inside the window (§13.3).
- **Forward secrecy (individuals).** An individual's content is sealed only to its current, short-lived key-record
  sealing key (§4.3, §7.4), never to a long-lived key. The recipient rotates the epoch key and deletes the old private
  key after `exp` + TTL + skew, so a compromise of a sealing key exposes only mail within that horizon, about the key
  lifetime plus retention, and never older mail. The bound is inherent to asynchronous delivery, where a sender seals
  before the recipient is reached: MLS carries the same retention-plus-key-lifetime bound. One-time per-message
  prekeys, which would tighten the horizon toward a single message, are a deferred tier. (Added 2026-10-28.)
- **Offline reachability.** The key-record 24-hour cap (`exp` at most `iat + 86,400`, §7.4) is kept as a security
  bound, not widened for availability. An identity offline past that cap with no renewal lapses: the relay sweeps its
  key record and a new sender gets `resolve-failed` — unreachable, fail-closed, never a downgrade to a stale or expired
  record or an unauthenticated path. `record keep`, which re-signs a fresh short-lived record before the old lapses, is
  an opt-in, off-by-default availability mechanism that keeps a live record fresh within the cap and weakens no secrecy
  or integrity property; run unattended it needs the identity's signing key usable by a person-absent process, which is
  a new unattended use of a key already readable by every process of the uid (see "What a session reads"), not a new
  exposure. After a sweep, reachability is restored by the continue-from-copy heal, which re-signs from the last-written
  local record (the `ac onboard` pattern): `record keep --once` performs it unattended wherever a local copy survives, as
  does reopening a server, so `record keep` both prevents a lapse and cures one from the copy; `record keep --once` exits
  `not-found` only for an identity that never published (publish one first with `record address`). Heal keeps the
  identity's signing key and address — never a new identity — while publishing a fresh
  epoch sealing key, as any rotation does, since the key record itself may be gone; it advances `iat` and carries the
  full `revoked` list and the `rotation_key` forward — never an empty `revoked` list, which would be a revocation
  rollback that re-admits a previously revoked key, and never a bare first publish, which drops the rotation-continuity
  countersignature a sweep removes. The same continue-from-copy heal runs on `record keep`, `keys rotate`, `ac onboard`
  and `ac login` (and the MCP keep-alive), and pairing's own-address publish, which had the identical wipe, is fixed the
  same way; heal continues from whichever is newer, the last-written local copy or the record a relay answers, so a
  relay replaying an older own record cannot roll the list back, and a newer local copy is never replaced by an older
  one. Heal re-signs and re-publishes the address record on every reopen, even when the local copy is still within its
  life, since what matters is whether the relay still holds it — a sweep, a replayed older record, or a wiped relay.
  When the last-written local copy is
  missing or does not verify, heal fails closed with `no-held-record` for any identity that has ever published from this
  home — it does not publish `revoked = []`, since with the copy gone nothing local can prove the list was empty — and
  directs the owner to the offline backup or an explicit, acknowledged rotation (`keys
  rotate --accept-loss`, which publishes `rotation_key` null and `revoked []`); only an identity that never published
  starts empty. `keys rotate`'s first-publish branch carries `revoked` and `rotation_key` forward for the same reason. The
  residual is cross-device revocation drift: re-signing preserves the revocations the healing device last wrote, and
  later revocations from another device are surfaced through `stale_since`, not hidden. A durable waiting send (a
  `resolve-failed` send held until its `until`) belongs to a fixed `--as` identity, is written under that identity's
  home at 0700/0600, and holds the message plaintext on the sender's own disk — the send is unsealed precisely because
  the recipient's key did not resolve — so it adds strictly-local durability across a sender restart and no network
  exposure, while a `--session` server keeps its waiting sends in memory only. (Added 2026-10-30; cross-reference Forward secrecy.)
- **Read receipts (optional profile).** A receipt lets a sender learn its message reached the reader. It is an optional
  profile above the core — a sealed, signed envelope of a distinct content type (`ac.receipt`, the §5.2 `type`) that the
  relay and core need no knowledge of, inheriting the core's binding and replay properties — off by default and
  controlled by the reader, never the sender. The receipt's body carries only the acknowledged envelope `id`, in a
  reserved member `ac.ack`, and nothing else: the body holds `ac.` members only — a member outside `ac.` is refused and
  an unknown `ac.*` ignored, so only `ac.ack` is read — no quote or hash of the message beyond its id, no reader
  location, network or device metadata, no other reader state, no free-text. There is no inner signature by default: authenticity is the envelope's own signature (Binding
  above — no one can forge an envelope from another sender), and the acked id is already bound by the envelope (the id
  commits to the sealed content and to the original envelope's `from` and `to`), so a separate inner signature would add
  only transferability, which the default omits. A sender may request a receipt with a sealed body member `ac.receipt:
  true` (which requires an object body); the relay never sees it and can neither add nor strip it. Member names
  beginning `ac.` are reserved for the protocol and an unknown `ac.*` member is ignored, and the absence of `ac.receipt`
  is no request. The reader may ignore the request and can never be compelled; declining is indistinguishable from
  receipts being unsupported and from the message being unread — a declining reader emits nothing — so the absence of a
  receipt reveals nothing, the central privacy property. Time is a stated limit, not removed: the receipt payload
  carries no time, but a receipt is an ordinary envelope whose outer `ts` is mandatory and in clear, and the relay sees
  reader-to-sender traffic right after delivery, so the relay and the sender learn approximately when the reader read;
  the reader SHOULD apply the system's timing jitter — the reference waits up to 20 s — and MAY delay or coarsen the
  receipt to loosen that correlation, which widens the window without removing it. Residual non-repudiation: full deniability is not achievable in a
  signed-envelope system — the reader did send a signed envelope — but the default mints no portable token; to prove
  reading to a third party the sender must reveal and open the whole sealed receipt envelope, higher friction and more
  self-disclosure than a one-line token. A reader who wants provable, transferable acknowledgement MAY opt in, per
  message or peer, to a transferable receipt carrying a detached reader signature; that tier is not built here, is never
  the default, and its transferability is stated at the point of opt-in. A receipt is terminal: an `ac.receipt`
  envelope never carries `ac.receipt: true` and never triggers a receipt, so there is no amplification. Enabling
  receipts is the reader's informed trade: a receipt reveals that the reader's identity processed that specific message,
  bound to its signing key, and approximately when. (Added 2026-10-30; design only, above
  the core; the `ac.` body-member reservation lives in this profile, not in §5.2, which stays type/thread/body.)
- **Replay and the dedup window.** A receiver drops an id seen within TTL + skew and rejects a `ts` outside that window,
  so neither a relay nor the network can replay an envelope after it; within it, replays are absorbed by
  deduplication. An address record is valid only until `iat + ttl`, so an old record with a shorter revocation list
  cannot be replayed after a day. An accept-from record does not expire, so an old one can be published to a relay that
  lacks the newer; it costs that relay storage and its owner the newer policy there until the owner republishes it.
- **Binding.** The id commits to every outer member and, through the sealed hash, to every wrap and the ciphertext; the
  signature commits to the id; the content AAD binds the ciphertext to `[v, to, from]`, and each wrap's AAD binds it to
  its recipient. A relay therefore cannot add, drop or reorder recipients, move a wrap, strip or append a caveat,
  extend an expiry, change `ts` or re-attribute an envelope without breaking the id or a signature. Every recipient
  holds the content key and can read the content, but none can forge an envelope from another sender, whose key it
  does not hold. One content key for every recipient holds for an honest sender: a
  sender can give a listed recipient a wrap that does not open, or opens to another key, and no other recipient can
  tell (§4.3). Suite 1 has no key commitment; a ciphertext made to open under two keys opens to pseudorandom bytes
  under one of them, which do not read as the content of §5.2, so the strict JSON of the content stands in for a
  commitment, and a profile whose plaintext is not JSON would need one.
- **What a session reads.** Caveats bound what a session may send, not
  what it may read. A session that holds its principal's sealing key (Appendix B 44) reads the principal's whole
  mailbox, whatever its caveats, for as long as it holds the key, and a copied session key file reads it too; the key
  leaves sessions with the opening agent. (A principal that revokes a session in its address record cuts that session's reading of
  the mailbox at every relay that holds the record, at once: the relay refuses its subscribe and fetch and ends its
  open subscription, §8.5 item 8. A relay that holds only an older record keeps serving the session until the newer
  record reaches it, and revocation never reaches what the session already read.) The limit of
  the opening agent (§13): it pays this debt for an identity in `agent` custody only. A session of an identity in file
  custody still holds the principal's sealing key and reads the whole mailbox, whatever its caveats; the same uid can
  read the key files, so neither the agent's socket nor its audit changes what such a session can read.
- **The agent's custody and its limit (§13).** The agent holds the principal's keys in its own
  memory for a window of at most 8 hours and answers one uid over `<home>/agent.sock`, kept to that uid by the socket
  file's owner and mode (0600 in a 0700 directory), not by peer credentials. That is a floor, not a boundary: every
  process of the uid, and root, can connect, and a session key file and chain are readable by every process of the uid.
  The seat is no isolation between two sessions of one user. A copied session key reads exactly what its grant reads, on
  the machine, until its `exp`. A principal in file custody gets none of this. `ac logout` revokes every subject granted
  in the window whose `exp + TTL + skew` is still ahead; a window that ends by its time signs nothing, so
  its just-expired hops stay unrevoked for up to about 7 days and a stolen session key can back-date mail over that span.
- **Malleability.** Ed25519 is verified strictly: a signature with a non-canonical S is rejected. The id excludes `sig`,
  so a malleated signature neither verifies nor changes an id. Every implementation
  refuses, before any library sees them, a public key `A` or a signature's `R` that is of small order (one of the
  eight torsion points, the sign bit aside) or non-canonically encoded (y >= p once the sign bit is cleared), and an
  S at or above L, so `R` = the identity and S = 0 under the identity key verifies nowhere. §2.3 states the rule, the
  cofactorless equation included, and the vectors pin it: a verifier that
  skips these checks fails 45 vector cases, so conformance (the opening of this document) now includes
  the strict refusals.
- **Fail closed.** An unknown caveat rejects the envelope (§6.3). Profile authors write predicates, never grants, or the
  conjunction stops narrowing.
- **Denial of service.** The caps bound every list and string a relay or edge reads. A relay stores nothing
  for an envelope without a hosted recipient, applies the owner's roots and size limit before storing, and
  limits rates per sender, root and IP. v0's counters are in memory, and a restart resets them. A domain root
  makes the relay fetch at most once per domain per cache period, or per 60 s after a failure, whatever the traffic
  (§8.8). (One publish fetches at most 8 domains, where an accept-from record naming
  1,024 made one publish an amplifier of 1,024 outbound requests toward hosts of the publisher's choosing, §8.8 item
  4.) A relay MAY also bound the bytes its store holds: once the store passes the bound it refuses a publish
  `store-full` while reads, fetches and the sweep continue, so the store drains as mail expires without dropping
  delivery (the reference relay's `--max-store-bytes`; added 2026-10-29). At the bound the relay also refuses a new
  signer's records `store-full`, while a known signer's update — a rotation, a revocation, a re-sign — is still taken,
  so revocation and rotation survive a full store (§8.2); and a per-client-address daily quota on stored
  envelope bytes (§8.2 step 8, the reference default 100 MB a UTC day) keeps one address from filling the
  store before the sweep drains it, since the byte bound alone refuses every tenant alike and has no per-address purge.
  (Adding the `store-full` refusal code is
  a class-A change before a partner is live and a class-D change after, per the change policy.)
- **Domain roots: the private-address guard.** A mailbox owner chooses the hosts its relay fetches, so
  a domain root could aim the relay at its own network (server-side request forgery). The relay fetches only a fixed
  path with GET, over HTTPS, and refuses a host any of whose addresses is not public, connecting only to the addresses
  it checked, so a second DNS answer cannot redirect it (§8.8 item 2); an IP literal is no domain root at all (§7.4).
  What remains is a GET of the well-known path of a public host, bounded by the cache.
- **Domain roots: the trust assumption.** A relay that resolves a domain root trusts the HTTPS PKI for
  the domains the mailbox owner named: the assumption an edge already makes for `--trust-root <domain>` (§9 item 4).
  The pin bounds it: a compromised web host or certificate authority can mint the key of a first contact, for
  a relay that has not pinned the domain yet, and cannot move an existing pin. A bad record at the well-known path
  cannot take the pinned key out of service while the pinned record is valid (a bare rotation refuses only its own
  key); after that, with no valid record served, the domain fails closed until one is. An operator's pin reset (§8.8)
  is the one way to accept a key no rotation links, and it is logged.
- **Discovery by DNS: a hint, not an authority.** The TXT record of §12.2 is read without DNSSEC, so anyone on a
  reader's DNS path can forge or remove it,
  and its answer is a hint. What it is worth: a second channel at first contact against a compromise of the org's web
  host alone, since a served record must still carry the key the TXT names or be countersigned
  by it; and nothing against whoever controls the org's DNS, who can also obtain certificates for its hosts. Forged, the
  TXT can only fail a resolution: it names no URL, the origin is the domain or `bag.<domain>`, whose
  certificates the forger cannot hold (§12.2 item 6), and the record must agree with its key (§12.2 item 5). Removed
  or stripped, it leaves the reader at the well-known URL, without the TXT's second check of the key.
  DNS never moves a pin: the signature, by a pinned key, is the authority, and a pin moves only by §7.3. The reference
  relay's stub resolver reads every answer as untrusted input: each query leaves on a fresh socket, on a port the
  system chooses, connected to its server; the id and the question must be its query's; a compression pointer must
  point backward; and an answer that is truncated or longer than it asked for fails. So a resolver fault can fail or
  misdirect a resolution and never forge an identity, the record having still to verify.
- **Handles: a name, never authority.** A handle record is an
  org's word that a handle names an address, signed by the domain's current, pinned key and valid a day at most:
  whoever holds the org key can point any of its handles at any key, as whoever holds a domain's DKIM key can sign any
  of its mail, which the org's rotation and revocation bound (§7.2, §7.3). A handle finds an address and admits no one
  (§12.3 item 2). An edge shows a handle for a sender only from a binding its user's own names hold, or from an
  unexpired handle record it resolved itself whose `address` is the envelope's principal and whose `org` is the
  chain's root, never from what a message says. A sender checks a handle's address against the `revoked` list of the
  freshest org record it holds at every send, not only when it resolved the handle (§12.4 item 4), so a revoked address
  stops receiving within one org record's ttl. Who learns what: the TXT lookup tells the reader's resolver the org and
  never the person, since the local part never enters DNS; the org's origin learns who asks for which handle; one
  record per handle and no list keep a domain's directory unpublished, but anyone who guesses a local part learns its
  address, as with email addresses, so an org that keeps its members private publishes no handle records. What a lying
  party can do: a resolver can deny a resolution or strip the TXT back to first contact by the well-known URL, and
  never moves a pin or binds a name; the origin's host can withhold a handle record or serve a stale one for up to its
  ttl, and never forges one, but on a domain without a TXT it can substitute the org's key at first contact;
  a relay can serve a stale address record of a handle's address for up to its ttl; and the org itself can sign
  two bindings for one name and show each to different askers, which only a log of records would show.
  A directory, registry or index is not an authority: its answer is a hint, and an edge uses
  a handle only after verifying its handle record at the org's origin under the domain's current key.
- **Parsing.** Implementations in different languages read the same bytes, and the canonical form and the vectors pin
  every value they hash. JSON readers differ on duplicate member names; a signature covers one reading, so two readers
  that disagree reject in at least one place, and the worst case is a dropped envelope (§2.5). (That held for the outer
  members, which the id covers, and not for the sealed content, which is parsed
  and never canonicalized: two readers keeping different members of one name would both accept one envelope and read
  different types, threads or bodies, and the coding profile's `repo=` caveat reads the body. Every reader now refuses
  a member name given twice in every text, the sealed content included (§2.5), and a `body` keeps its value across
  languages only within I-JSON (§4.2).)
- **Randomness.** The content key, the nonce and every ephemeral key MUST come from a CSPRNG and MUST NOT be reused; a
  content key encrypts one plaintext.
- **Keys and logs.** Private keys never appear in logs, audit lines, vectors or command output (§9). The seeds in
  `spec/vectors` are public test data by construction and protect nothing. Nor does key material go in a process's
  argument list, an environment
  variable, a log line or an audit line's detail, and a custody adapter is held to the same rule: the macOS Keychain
  adapter writes an item through the stdin of `security -i` and reads it into memory (Appendix B 58).
- **Host notices.** A notice that wakes or tells a
  host that mail arrived carries only fixed-grammar fields, an id, a sender and a type of bounded shape, and never peer
  text, a thread or a body: what a peer chose to say reaches the model only through a tool read, where it is marked
  data from another party. A `type` that is not a short token is not shown. Appendix B 76 names the grammar the
  reference tools use (`packages/mcp/src/push.ts`, `notice`).

## 11. Test vectors

`spec/vectors/` holds nine JSON files (seven at first; `discovery.json` since 2026-10-26; `pair-code.json` since
the pairing-code work, 2026-10-30 — the only one maintained by hand, not regenerated, so the byte-identical check below
does not cover it; corrected 2026-11-01, from "seven JSON files"), written by
`packages/core/scripts/gen-vectors.ts` from fixed seeds (one byte
repeated 32 times), fixed timestamps (from 1,800,000,000, which is 2027-01-15 08:00 UTC), a seeded xorshift128+ and
injected ephemeral keys. Each file opens with `description`, `generated_by`, `suite`, `suite_parameters`, `test_data`
and `notes`, then lists its cases. A case's verdict is its member `result`: `"ok"` or a code from Appendix A. Each case
states its expected values explicitly (canonical strings, digests, ids, signatures, ciphertexts), so a consumer in any
language needs no other source.

| file | holds |
|---|---|
| `canonical.json` | `cases`: values with their canonical strings and SHA-256; `invalid`: values the form rejects, a string given as `utf16_hex` (UTF-16 code units) when it holds a lone surrogate, which JSON cannot carry portably; `preimages`: a worked example of every row of §2.4 but the handle record's, whose examples are `discovery.json`'s, with its canonical string, SHA-256, and signer and signature where signed (corrected 2026-10-28) |
| `envelope.json` | `cases`: envelopes with every input (seeds, content, the injected content key, nonce and ephemeral keys) and every intermediate value (plaintext, content AAD, hop canonical strings, sealed hash, id, signature, chain, coding-profile result, exact bytes); `parse`: bytes (or `bytes_hex`, or bytes followed by `pad_with_spaces` spaces) and their §5.4 result, member names given twice and numbers that are not plain integers among them; `verify`: bytes, `now`, TTL and skew, and the §5.5 result, the strict rule of §2.3 among them; `open`: a sealed part (`to`, `from`, `sealed`), the recipient's address and sealing seed, and the result of §4.4 and §5.2, with the `content` when it opens; `seal`: a seal to a recipient key that is malformed or of small order, with its inputs, and its result (§4.1, §4.3); `key_record_seal`: a seal to a recipient's current key record, with the key record and the sealed result (§4.3, §7.4); `stolen_key`: an epoch key stolen past its deletion horizon that opens no mail (forward secrecy, §7.4) |
| `sealed-multi.json` | envelopes to 2, 3 and 16 recipients, laid out as `envelope.json` `cases` |
| `chain-valid.json` | chains that verify, with each hop's canonical string and digest, and the chain's root, principal and caveats; `caveats`: effective caveats, a sealed content and the coding profile's verdict on them (§6.3, §6.4), `ok` or the code with the `caveat` that decided |
| `chain-invalid.json` | chains that fail, each naming its rule; the "order" cases pin the rule order |
| `records.json` | `cases`: signed records with their canonical strings, digests and results at several times; `invalid`: form and cap failures; `rotations`: pairs (prev, next) and their §7.3 result; `parse`: bytes (or `bytes_hex`) read as a record (§2.5, §7.1); `rotation_claims`: a record and the result of checking its claim without the previous record (§7.3) |
| `hpke-rfc9180-subset.json` | the cases of the CFRG HPKE test-vector file for mode 0, kem 0x0020, kdf 0x0001 and aead 0x0002, every field kept, with the upstream URL, its sha256 and the download date |
| `discovery.json` | (added 2026-10-26; §12, L2) `presentation`: TXT records written as text (§12.2 item 7) and their character-strings as `strings_hex`, or `resolve-failed`; `txt`: a domain, its `txt_name` (`null` when none is asked), the TXT records its lookup gave (each a list of strings) and where they lead (§12.2 items 1 to 4): the `key` the record must agree with (`null` without an bag record), the address record's `url` and the org's `origin`, or `resolve-failed`; `agreement`: the key a TXT names (`txt_key`, `null` for none), an org record, the record a reader had `pinned` (`null` at first contact), the verdict of the record's agreement with the TXT (§12.2 item 5) and the key `pin`ned after the reading (§7.3); `handles`: strings read as handles (§12.3 item 1) with their local part, domain and record path, or `bad-address`; `cases`: signed handle records with their canonical strings, digests and signers, and their verdict for a reader that expects an org key and a handle and holds the org's revoked list, at several times (§12.4 item 3); `invalid`: handle records that break their form; `parse`: bytes read as a handle record |
| `pair-code.json` | (added 2026-10-30 with the pairing code, §8.10; **maintained by hand, not produced by `gen-vectors.ts`**, so the byte-identical check below does not cover it) pins the pairing-code codec and the key derivation: the wordlist encoding of the nameplate and three words, the MAC key `S = HKDF-SHA256(...)` (§8.10), and the check-digit construction, with worked inputs and expected outputs so a second implementation reproduces a code's `S` and digits byte for byte. (Clarified 2026-11-03: until then the file held only the codec and `S`. Its members `codec` and `s_derivation` stay maintained by hand; `check_digits` (a case with a leading zero among them), `request_mac`, `invite_string` and `pair_open` are written from the edge's own code by `packages/edge/scripts/gen-pair-code-vectors.ts`, whose `--check` fails when the code no longer reproduces them. The edge's tests and `scripts/verify_vectors.py` reproduce all six, and the Rust relay's tests reproduce `pair_open`.) |

- **Regenerate**: `node packages/core/scripts/gen-vectors.ts`. The RFC subset is rebuilt from its own inputs;
  `--upstream <test-vectors.json>` filters a fresh download, whose sha256 must equal the recorded one.
- **Check**: `npm run vectors:check -w packages/core` regenerates every file into a temporary directory and fails unless
  each is byte-identical to the committed one. Because the subset is rebuilt by the core's own HPKE, the check also
  fails if the implementation stops reproducing RFC 9180. It prints the number of cases (the entries of every case
  list) and how many codes of Appendix A some case gives as its `result`, the unit of a claim about the vectors (added
  2026-10-25): 376 cases and 37 of 55 codes, against 183 and 29 of 53 before it.
  The other 18 are relay and edge codes, which only §8's vectors could give a verdict (deferred). (Changed
  2026-10-26: 515 cases and 39 of 55 codes, `discovery.json`'s 139 cases
  adding `resolve-failed` and `revoked`; the seven files before it are byte for byte as they were. Changed 2026-10-27
  by the content.type control-character rule: five cases added to `envelope.json`'s open list (escaped C0, C1 U+009B,
  line separator U+2028, DEL U+007F, paragraph separator U+2029), 520 cases, the codes unchanged since each gives
  `bad-content`, which is already counted.) (As of 2026-11-01 Appendix A has 60 rows; as of 2026-11-02
  the gate prints the code count as 41 of 60 — the fetch-proof vectors add verdicts for `bad-auth` and
  `not-authorized`, raising it from 39; the per-commit figures above are as they stood on their dates, when
  Appendix A was smaller, and `pair-code.json`, being hand-maintained, is outside this regenerate-and-diff count.)
- **Verify independently**: `.venv/bin/python -I scripts/verify_vectors.py spec/vectors` recomputes every canonical
  string with `json.dumps(value, separators=(',', ':'), ensure_ascii=False)` and every sealed hash and id with hashlib;
  re-implements the parse, outer, chain and record rules; verifies every signature; and opens every wrap with its own
  RFC 9180 over the `cryptography` package. It exits 1 on a mismatch, and 2 when it had to skip a check. Since
  2026-10-25 it also gives its own verdict on every `open`, `seal`, `caveats`, record `parse` and
  `rotation_claims` case, refuses member names given twice through `object_pairs_hook`, and prints the count of
  Appendix A codes with a verdict, read from this document's table.
- The TypeScript tests (`packages/core/test/vectors.test.ts`, `hpke.test.ts`), the Rust core's conformance tests
  (`crates/ac-core/tests/conformance.rs`: every list but `open`, `seal` and `caveats`, since the crate never seals,
  opens or evaluates a caveat) and the relay's (`crates/ac-relay/tests/conformance.rs`, every parse, verify, chain and
  record case through publish) read the same files. RFC 9180 Appendix A prints no vector for suite 1's AEAD (A.1 is
  AES-128-GCM), which is why the subset comes from the CFRG file. (Added 2026-10-26: the three readers read
  every list of `discovery.json`, and the relay's conformance tests publish each of its handle records, which the relay
  refuses `bad-record`, §8.2.)

## 12. Naming (L2)

*(Added 2026-10-26, first as §7.6 and §7.7; moved out of §7 into this section. Its defaults are provisional.)* This section is L2, names over the frozen core: how a reader finds an org's records through DNS, and what a handle is. An
implementation of §2 to §9 conforms without it (§1); one that implements it also reproduces `discovery.json` (§11). It
changes no rule of §2 to §9: an envelope carries addresses only (§5); authority is the chain's (§6); a record verifies
by §7.5 and a pin moves only as §7.3 lets it, never by DNS; and a reader that does not implement this section reads an
org's address record at the well-known URL of §7.2.

**12.1 One origin per org.** An org serves its records at one origin: `https://bag.<domain>` when its
TXT record says `host=bag` (§12.2), else `https://<domain>`. Under that origin's `/.well-known/bag/`
are `address.json`, the org's address record (§7.2); `policy.json`, its served policy record (a draft, read at this origin); and `handles/<local>.json`, one handle record per handle (§12.4); and, for an org that offers the A2A extension,
`a2a.json` at `/.well-known/bag/a2a.json`, that extension's file: the agent-card binding it carries is
defined outside this core (the A2A extension, 2026-10-28), and a reader that does not implement the
extension ignores the file. The members' half of the org's policy is never served. A reader fetches each as a well-known record: HTTPS only, no redirect, the caps and
timeout of §8.8 items 1 and 2 at a relay and of §9 item 4 at an edge, and the private-address guard on the origin's
host, connecting only to the address it checked. Readers that do not implement this section read only
`https://<domain>` (§7.2), so an org that sets `host=bag` is found only by readers that do: no org sets it
until the reference edge reads the TXT record.

**12.2 Discovery by DNS.** An org MAY publish one TXT record at `_bag.<domain>`, for a `<domain>` that is a
host as §7.4 defines one. It names the key that signs the org's address record and, at most, that the org's origin is
`bag.<domain>`; it names no URL:

```
_bag.acme.example.  IN  TXT  "v=ac1; key=ed25519:<64 hex>; host=bag"
```

DNS is a hint and the signature is the authority. Without DNSSEC anyone who can answer a reader's DNS queries can
forge or remove the record, so the record at the origin must still verify and agree with the key the TXT names (item
5), and a reader's pin moves only as §7.3 lets it (item 6; §10).

1. **The text.** A TXT record's character-strings (RFC 1035 §3.3.14) are joined in order with nothing between them, as
   SPF joins them (RFC 7208 §3.3). The joined text is a list of fields separated by `;`. Spaces and tabs around a
   field, around its `=` and at the ends of the text are ignored, and an empty field (`;;`, or a trailing `;`) is
   skipped. A field is `name=value`: the name is 1 to 32 ASCII letters, digits, `-` and `_`, starting with a letter,
   compared case-sensitively; the value is one or more characters from `!` to `~` other than `;`, with no space or tab
   inside it.
2. **Ours.** A TXT record is an bag record when its first field is `v=ac1`. A reader finds that first field
   without validating the whole record: it splits the joined text leniently on `;`, trims the fields and drops the
   empty ones (item 1), tests whether the first is exactly `v=ac1`, and only then validates the record in full as ours
   (item 3's malformed cases). Every other TXT record at the name
   is not ours and is ignored, so that the name can hold other records and a later version (`v=ac2`) can stand beside
   this one.
3. **The fields.** `key`, required: an address (§3.2), the key the org's address record must agree with (item 5).
   `host`, optional: exactly `bag`, which puts the org's origin at `https://bag.<domain>` (§12.1);
   without it the origin is `https://<domain>`. A field named `rec` is refused: the TXT names no URL (changed: a URL in DNS, even one under the domain, lets whoever answers a reader's DNS and holds a certificate for
   any name under the domain pin its own key at first contact). A field of any other name is ignored. An bag
   record is malformed when it names a field twice, has no `key`, has a `rec`, has a field that breaks item 1, a `key`
   that is not an address or a `host` that is not `bag`, holds a byte other than tab and ` ` to `~`, or is over
   1,024 bytes once joined (implementation default).
4. **The lookup.** A reader asks for the TXT records of `_bag.<domain>`, and asks nothing when that name is
   over 253 characters (no such name exists) or when `<domain>`'s last label is one of the special-use names of §12.3
   item 1, which RFC 6761, 6762, 7686 and 9476 keep off the public DNS (implementation default); then:
   - with no bag record (the name does not exist, holds no TXT record or only records that are not ours, or
     was not asked), the origin is `https://<domain>` and the address record is at the well-known URL of §7.2, as
     without discovery;
   - with exactly one, well formed, the origin is the one item 3 names;
   - with two or more, or a malformed one, the resolution fails, `resolve-failed`, and the reader does not fall back to
     the well-known URL (as SPF's permerror for two records, RFC 7208 §4.5);
   - a lookup that fails (no answer, a server failure, an answer truncated or unreadable) is `resolve-failed`.
5. **The record's agreement.** The reader fetches the address record at the origin (§12.1) and verifies it by
   §7.5. When the TXT names a key `k`, the record agrees with it when its `key` is `k`, or when its `rotated_from` is
   `k` and its `rotation_sig` verifies under `k` over the record's preimage (§7.3's check of a rotation's claim: one
   step, countersigned by the key DNS names). This agreement test is form and signature only and reads no `now`: it is
   the agreement verdict alone, separate from pin trust, so a record the TXT agrees with but that no rotation links to
   the reader's pin agrees here and the pin is kept, and §9 item 4 is where a key that does not move the pin is reported
   `pin-mismatch`. Anything else is `resolve-failed` before any pin is read, and no pin is
   written or moved. (Changed: until then a record had to carry the TXT's own key, so every rotation of
   an org with a TXT failed first contacts until resolvers dropped the old TXT.) Then the pin, the cache, rotations and
   the memory of failures are a well-known record's (§7.3; §8.8 items 4 to 6 at a relay, §9 item 4 at an edge): a first
   contact pins the record's key, the new key when the second clause holds; a reader that pinned `k` moves its pin only
   by §7.3 against the record it holds; and a pinned key stays current while its stored record is valid. A rotation
   countersigned by the previous record's `rotation_key` does not agree with a TXT that still names the previous key,
   since a reader that holds only the TXT cannot check it (§7.3): an org that recovers with its rotation key changes the
   TXT's `key` with its record, and a reader that still holds the old TXT fails closed until its DNS cache lets it go.
6. **What DNS can and cannot do.** At first contact a reader binds a key to a domain through the HTTPS certificate of
   the origin's host (§10, "Domain roots: the trust assumption"). With the origin fixed at the domain or at
   `bag.<domain>`, as MTA-STS fixes `mta-sts.<domain>` (RFC 8461 §3.1 to §3.3), a forged TXT names a key that
   no record served at those two hosts carries or countersigns, or a host whose certificate the forger cannot hold: it
   can fail a resolution, which anyone on the DNS path can do already, or strip the TXT back to first contact by the
   well-known URL alone; it cannot choose the key a reader pins, and it never moves a pin. A reader does not require
   DNSSEC and treats a validated answer no differently (implementation default). An org that wants its records served
   from another host points a CNAME at it from `bag.<domain>`, and deletes that CNAME when it stops using the
   host: a dangling `bag.` name hands the org's origin to whoever claims the host it names.
7. **Text forms.** Where a TXT record is written as text (a zone file, a DNS-over-HTTPS JSON answer, the reference
   relay's test flag of §8.8), it is in RFC 1035 §5.1's presentation form: one or more character-strings separated by
   spaces or tabs, each a quoted string (`"..."`) or a bare word, in which `\` and three decimal digits stand for the
   byte of that value (at most 255) and `\` and any other character for that character; each string at most 255
   bytes; nothing but tab and ` ` to `~` in the text; no comment and no parentheses (implementation default). Anything
   else cannot be read, `resolve-failed`.
8. **A rotation.** An org that rotates its key publishes the new record, countersigned by the old key, first;
   then changes the TXT's `key` in place; and never publishes a second `v=ac1` record, since item 4 fails two. Until the
   TXT moves, the countersigned record agrees with the old TXT by item 5's second clause; after it, by its key.

§11's `discovery.json` pins items 1 to 5 and 7.

**12.3 Handles.** A handle names an address under an org's domain, as an email address names a mailbox:
`jane@acme.example`. It is a name, never an identity and never authority: an envelope carries addresses only (§5), and
an edge judges mail to or from a handle's address as any other (§6, §9 item 5).

1. **The form.** `<local>@<domain>`: the local part is 1 to 64 characters of `a` to `z`, `0` to `9`, `.`, `-` and `_`,
   its first and last a letter or a digit (implementation default: so that no handle maps to a dot file, which web
   servers often refuse to serve), and `<domain>` is a host as §7.4 defines one, so no port and no IP literal, whose
   last label is none of the special-use names `alt`, `arpa`, `internal`, `invalid`, `local`, `localhost` and `onion`,
   which name no org on the public DNS (added 2026-10-26). Anything else, an upper-case letter included, is not a handle; where a handle or an address may stand, a
   string that is neither is `bad-address`. A record holds a handle in this one spelling only. A client SHOULD fold `A`
   to `Z` to `a` to `z` in what a person typed before it reads a handle, and folds nothing else: `xn--` labels
   pass as written and are never decoded.
2. **What a handle does not do.** A handle finds an address and admits no one. Delivery still needs the
   recipient's accept-from roots to admit the sender's chain at the relay (§8.2 step 7) and the recipient's edge to
   trust its root (§9 item 5): a partner's domain entry, or a pairing. (Corrected: an earlier draft wrongly said a first contact needs only the handle.)
3. **Why.** An edge finds an address's record only at a relay it was hinted or at its own (Appendix B 40), so on
   2026-10-26 two first contacts across relays failed `resolve-failed` until their records were republished by hand
   a handle names the org's relays through the org's own record, so a sender who knows the
   handle finds the address and the relays at which to deliver.

§11's `discovery.json` pins item 1.

**12.4 The handle record.**

1. **The record.** A record of `kind` `"handle"` with exactly these members: `org`, the address of the org key that
   signs it; `handle`, a handle; `address`, the address the handle names; `iat`; `ttl`, 1 to 86,400 seconds, as an
   address record's; and `sig`, `org`'s signature over `["ac/handle/1", org, handle, address, iat, ttl]` (§2.4).
   Anything else is `bad-record`. It is valid from `iat - skew` to `iat + ttl`. Relays do not store handle records: a
   relay refuses kind `handle` at publish, `bad-record`, and a fetch of it is 404 (§7.1, §8.2).
2. **Where it is.** At `<origin>/.well-known/bag/handles/<local>.json`, under the org's one origin (§12.1), one
   record per handle and never a list (implementation default: a domain publishes no directory of its handles). It is
   fetched as the org's address record is (§12.1).
3. **Verification.** A reader resolving the handle `h` of a domain whose current key is `k` checks the handle record at
   `now`, with its skew, in this order: its form (`bad-record`); its signature under its own `org`
   (`bad-record-sig`); `iat <= now + skew` (`future-iat`); `now <= iat + ttl` (`record-expired`); that `org` is `k`
   and that `handle` is `h`, its local part and its domain both (`resolve-failed`: a reader cannot tell a stale record
   from a forged one, and neither resolves); and that the org's record does not list `address` in its `revoked`
   (`revoked`).
4. **Resolution** (an edge's, §9 item 4; a relay resolves no handle). To send to `jane@acme.example`, a reader:
   1. resolves the org's record of `acme.example` by §12.2, verified, pinned and cached as §9 item 4 says
      (`resolve-failed`, `pin-mismatch`);
   2. fetches the handle record at item 2's URL, a 404 meaning that the domain has no such handle (`resolve-failed`),
      and verifies it by item 3, `k` being the key of step 1's record;
   3. reads the address record of its `address` from the relays of the org's record, in their order (§8.4), then where
      it reads any address's record (Appendix B 40), and verifies it by §7.5; its `key` must be that `address`;
   4. seals to its current key record's sealing key (§4.3), and publishes to its relays, as for any address (§9
      item 1), the recipient's accept-from record and edge deciding whether it is delivered and accepted (§12.3 item
      2);
   5. caches the handle's binding no longer than the handle record's `iat + ttl`, and each record as §9 item 4 says,
      and checks the handle's address against the `revoked` list of the freshest org record it holds at every send,
      not only when it resolved the handle. The handle's address is not pinned on its own (implementation
      default): the org's signature is its authority, and the org's key is pinned.

§11's `discovery.json` pins items 1 and 3.

## 13. The agent seat (local)

*Added 2026-10-28. This section is outside the frozen
core, as §12 is: an implementation of §2 to §9 conforms without §13. It defines a local interface between an agent
process and the sessions of one user on one machine. Nothing in it is sent on the wire or read by a relay.*

### 13.0 Scope: the session half only

The **agent** is a long-lived local process that holds a **principal**'s signing and sealing keys (on a device, the
device's own keys, §13.1) for the length of an `ac login` **window** and answers **sessions** over a Unix-domain socket (`<home>/agent.sock`). A session holds its own
short-lived signing key and no principal key. This section defines how a session proves itself (§13.1), how the agent
judges its authority (§13.2, §13.3), the one thing it signs for a session (§13.4), how a first grant and renewals enter
that authority (§13.5), the many things it never signs (§13.6), the keep-alive seam for a non-session client (§13.7),
what it opens and releases (§13.8), its caps (§13.9), its result codes (§13.10) and its audit (§13.11). It pays the debt for
an identity in `agent` custody: the principal's sealing key never enters a session's process or files, a session key
copied off the machine opens nothing, every opening is audited, and `ac logout` ends every session's use.

**What the agent seat does not buy.** The socket proves a uid, not a session. A session's key file and chain are
readable by every process of that uid (Appendix B 43), so the seat is no boundary between two sessions of one user, and
"session isolation" MUST NOT be claimed. A copied session key reads exactly what its grant reads, on the machine, until
its `exp`; the gain is that it reads nothing off the machine. An identity in file custody gets none of this (§10).

**Brought into line with the implementation (2026-10-28).** The `device` grant (§13.1, §13.3) and a group's
generation unwrapping (§13.1, §13.2, §13.8) are built and specified below; the term table's held key is the principal,
or D's own key on a device.

**Held for a later section, not specified here:** the `member` grant; any org mode; the work-escrow wiring; and the
recovery wrap and its restore command. Recovery here is a format field only (not yet built).

| term | meaning |
|---|---|
| agent | the process that holds a principal's keys for a login window and answers sessions on `<home>/agent.sock` |
| principal | the identity P the agent answers for: the root (or a hop's `iss`) a session's chain names (§1). The held key is P's own, or on a device D's own key, whose agent answers for P (`Agent.held`: the device hop's `sub`, else the principal) |
| device | a key D that P signed a hop to (`device-grant`, §13.1); D's agent holds D's key, signs for sessions and opens nothing (§13.1, §13.8) |
| held group | a group G whose `group-key.v1` generation the agent took in this window (`group-key`, §13.1); at most 32 (Appendix B 87), dropped at logout |
| session | a short-lived key that asks the agent to sign or open; it signs envelopes, fetch and subscribe proofs itself |
| window | the span of one `ac login`: at most 8 hours, ended by `ac logout`, SIGINT, SIGHUP or SIGTERM, the window's end, or the process dying (§13.3) |
| grant | a hop the agent signed under the principal key for a session in the current window: a first grant (§13.5) or a derived hop (§13.4) |
| grant-set | the per-window, in-memory set of the grants the agent signed this window, by digest, that §13.2 tests the chain's held-key hop against; dropped at `ac logout`. A device hop never enters it (§13.1) |
| connection ledger | the per-connection, in-memory record of the connection nonce and the highest `seq` accepted; dropped when the connection ends |
| registered threads | the per-window, in-memory set of thread ids a session named for reads (§13.8, the `register` op); dropped at `ac logout` |

The key words of §1 apply.

### 13.1 The agent request and its preimage

**The peer check.** The floor under every request is the agent's own uid. The agent enforces it by the socket file's
owner and mode: `<home>/agent.sock` is created 0600 in a 0700 directory, so only the agent's uid can connect. It does
not read SO_PEERCRED, which Node does not expose. The residual gap: a process of the same uid, or of root, connects;
and where the file's owner and mode cannot be made to hold (a directory another uid can write, a file system that
ignores modes) there is no floor. Another uid cannot connect while the modes hold; while the socket's or its
directory's owner is not the agent's uid, or either is open to group or other, every connection is refused
`not-authorized`. The uid is not a session; it is only the floor below which nothing is served.

A session request carries a signature by the session key over this fixed-position preimage (§2). The preimage is
local: it is never on the wire, and the table is §13's own, not a row of §2.4.

| object | preimage | signed by |
|---|---|---|
| agent request | `["ac/agent/1", nonce, seq, session, op, argsHash]` | `session` |

- **`nonce`**: 64 hex, the 32 random bytes the agent sends when the connection opens (an implementation default). A
  request on another connection, or after an agent restart, meets a different nonce, so a captured request cannot be
  replayed.
- **`seq`**: a canonical integer, 0 for the first request on the connection and rising by exactly 1 for each request on
  it. The agent MUST refuse a `seq` it has already accepted or that does not rise by one (`bad-shape`).
- **`session`**: the session's address (§3.2). The signature verifies under this key (§2.3), and it MUST equal the last
  hop's `sub` of the chain the connection presented (§13.2); otherwise a session that is not the chain's last `sub` is
  `chain-not-to-sender` when the request carries the chain (the chain check, §13.2) and `not-authorized` on a later
  request without one. The agent parses a requested
  `sub` as an address (§3.2) before it signs anything for it.
- **`op`**: a non-empty string naming the operation: `sign` (§13.4), `open` or `register` (§13.8). An op outside this
  set is refused `bad-shape`; the agent never treats an unknown op as a request to sign (§13.6), and a session frame
  naming a non-session op is `bad-shape` too (`server.ts`: the two newest ops are taken only from a frame with no
  `session`). `resign` (§13.7), `grant` (§13.5), `logout` (§13.3), `device-grant` and `group-key` (both below) are
  **not** session requests: each is a non-session client's, authenticated by the uid floor alone and carrying no
  `ac/agent/1` signature.
- **`argsHash`**: `sha256hex(utf8(canonical(args)))` (§2.3) of the operation's canonical argument list. For `sign`,
  `args` is `[sub, caveats, exp]`; for `open`, `[mailbox, id]`, with the exact envelope bytes sent beside the request;
  for `register`, `[thread]`. The byte framing of a request is an implementation default (Appendix B 83). The agent
  bounds the envelope bytes of an `open` at parse to the envelope cap, 196,608 UTF-8 bytes (`envelope-too-large`,
  Appendix A; changed 2026-11-11 from 65,536).

**`device-grant`.** A uid-only op that signs the **device hop** `["ac/hop/1", principal, D, caveats, exp]` (§6.1)
under the principal key, for another machine's key D, after one `y` typed at the agent's terminal (the prompt of
§13.5, with the lines `device grant to <D>`, the caveats, or `unrestricted` for none, and `until <exp>`). Its refusals
are, in order, `bad-address` (D is not an address, or is the principal), `bad-shape` (the caveats or `exp` break §6.1's
bounds), `exp-not-monotone` (an `exp` past `now` + 30 days, Appendix B 86), then `agent-locked` with no open window and
`not-authorized` on a device's agent (a device pairs no other device); and `declined` for an `n` or no answer, as for
`grant`. A device hop is exempt from the at-least-one-caveat rule of `grant` and may carry zero caveats (shown `unrestricted` at the prompt); it keeps whatever caveats the ask gives, up to §6.1's bounds. **The device hop never enters the grant-set or the dated map of subjects
that §13.3's logout revokes** (`agent.ts`, `DeviceReply`): the grant-set tests hops signed for this window's sessions,
and entering D there would make P's `ac logout` revoke D, which is not what a logout is for. A device hop outlives
the window, to its own `exp`. It adds no session op, so §13.6's closed set is unchanged.

**`group-key`.** A uid-only op that takes a generation of a group G's key into the window: the args are one envelope's
exact JSON text, or a stored `group-key.v1` body replayed at login (`bad-shape` otherwise). It answers `agent-locked`
with no open window and `not-authorized` on a device's agent. For an envelope it parses it, checks its id and signature,
and opens the wrap addressed to the principal, **as the principal and outside the session read rule of §13.8**: this is
the one **named exception** to that rule. The exception is gated to the sealed `type` `group-key.v1` before the body is
used (any other type is refused `type-not-accepted`), and the op releases only `{group, generation, body}` to its
caller: no bypass exists for any other type, and no session reaches the op. The body then passes `openGroupKey`'s
checks -- the `group-key.v1` body's membership hop, signed by the group's signing key and binding this holder, verifies,
and the sealed generation key opens to the holder -- and the keep rule: another key at a held generation is `bad-key`, the later membership-hop
`exp` and the newest two generations of a group are kept, a group's own copy (no membership hop) is `not-authorized`,
and a window holds at most 32 groups (`rate-limited`; Appendix B 87). **Two residuals, both inside §13.1's uid floor:**
(a) a one-bit side channel: `type-not-accepted` tells a caller of the same uid that an envelope addressed to the
principal opened and is not `group-key.v1`, which a `bad-sig` or `open-failed` does not; (b) no rate cap on the
principal's `group-key` frames, each of which writes one audit line (§13.11). The cap of 32 is a cap on groups held,
refused `rate-limited` only when a frame would add a thirty-third group; it is not a cap on frames.

Position 0 is the string tag `ac/agent/1`, so a session-key signature made for the agent can never stand as an envelope
id, a hop, a fetch proof (`ac/fetch/1`) or a subscribe proof (`ac/sub/1`); §2.4 points here for the tag. A session's
envelope ids, fetch proofs and subscribe proofs stay the session's own signatures (§13.6).

**The `seq` high-water.** The connection's `seq` high-water advances the instant the request's signature verifies, after
the window check, the `seq` cap and the `seq`-order check. A refusal up to and including the signature check spends no
`seq`: a malformed frame (`bad-shape`), no open window (`agent-locked`), the `seq` cap (`rate-limited`), an out-of-order
`seq` (`bad-shape`), or a bad signature (`bad-sig`). In particular a frame refused `bad-sig` does not advance the
connection's `seq`, so a forged or malformed frame cannot burn the sequence. A refusal after it spends the `seq`: the
chain and authority checks (`not-authorized`, `hop-expired`, `not-in-grant`), the per-session and per-minute caps
(`rate-limited`), and an op's own refusal (`exp-not-monotone`, a withheld read). `bad-shape` and `rate-limited` occur on
both sides of the signature check, so a client cannot place a refusal by its code: it reconnects after any refusal. A
fresh connection starts at `seq 0` and presents its chain again; because the per-session caps and the registered threads
live in the window, a reconnect resets nothing.

The chain (0 to 8 hops, §6) is sent with the first request on the connection and verified with the first request, and with any later request that
replaces it.

### 13.2 Authority is judged at the agent's clock

The agent MUST judge a session's chain by chain rules 1 to 9 of §6.2 with `ts` set to the agent's own clock `now`, never
the session's and never a relay's. Every hop must be live at `now` (rule 8, `hop-expired`), the chain must be unbroken
and its caveats monotone (rules 5 and 7), and the last hop's `sub` must be the `session` of §13.1 (rule 6,
`chain-not-to-sender`). The chain's root MUST be one of the following (`rootRule`); otherwise `not-authorized`:

- **(a) the principal P.** `chain[0]` is a hop with `iss` P. On a device, `chain[0]` MUST be the device hop the agent
  holds, equal by digest (`hopDigest`), and the hop the agent signed is then `chain[1]`; a different hop of P's, or
  any other `chain[0]` on a device, is `not-authorized`.
- **(b) a held group G, never on a device.** `chain[0]` is a hop with `iss` G, a group the agent holds a generation of
  in this window (§13.1, `group-key`), with `sub` the principal and `group=<G>` among its caveats (the membership hop
  the group signs for the principal); the hop the agent signed is then `chain[1]`. A **`sign` request rooted at a group is refused
  `not-authorized`**: the agent signs a derived hop only for a chain rooted at P.

This is stricter than the live-delivery bound of §6.2's note and §5.5 step 4, where a chain is judged at the envelope's
`ts`, which its signer picks. The agent holds the principal key and signs under it, so it reads no `ts` from a requester:
a hop that has expired by the agent's clock is refused even if a requester offers an earlier one.

**And the held key's hop must be one this agent signed in the current window.** The agent keeps in memory, for the
length of the window, the **grant-set**: the grants it signed this window, by digest, the first grants of §13.5 and the
derived hops of §13.4. A chain is admitted only when the held key's hop in it, the first hop from the held key (`chain[0]`
under root (a) on P, `chain[1]` on a device or under root (b)), is in that set. A hop the principal signed
in an earlier window, or that a valid signature alone would carry across a logout, is refused `not-in-grant`. This is
what makes `ac logout` end every session's use of the agent. A session's first request is admitted because `ac grant`
has put its first grant in the set (§13.5).

### 13.3 The two memories, the window's end and logout

The agent keeps two in-memory records with different lifetimes. Neither holds key material or thread content. The
connection authority does cache the chain's effective caveats, which are public, because §13.1 sends the chain once.

**Per connection, the connection ledger:** the connection **nonce** and the **seq high-water**, the highest `seq`
accepted. The ledger holds the accepted range, not every value. It is dropped when the connection ends.

**Per window, the window state:** the **grant-set** (§13.2), the **registered thread ids** each session has named
(§13.8) and the **held generations** of each held group (§13.1, `group-key`; at most 32 groups, the newest two
generations of each). It is dropped at `ac logout`. Because all three live with the window and not the connection, a session whose socket
drops and reconnects keeps its threads and its grants.

**The window's end.** The window ends at the end of its span (at most 8 hours, Appendix B 77), at SIGINT, SIGHUP or
SIGTERM, and when the agent process dies. The window-end timer and the three signals all run the same window-end path,
which re-signs the principal's address record to revoke the subjects of the grants still live at that instant, and zeroes
the held key on every path. **At a clean window's end the timer signs nothing**: no grant is still live then (a grant's
`exp` is at most the window's end), so the set is empty and no record is signed; the same holds for a signal arriving at
or after the end. A signal arriving while the window is still open revokes the grants then live. The expired-but-still-
acceptable subjects are added only at an explicit `ac logout` (below), never by a signal or the timer. After the window
the agent holds no principal key and every request is refused `agent-locked`: the person's next step is `ac login`.

**`ac logout`.** `ac logout` runs the same path with the explicit-logout flag: it re-signs the principal's address record with `revoked`
(§7.2) extended by the grants still live and, additionally, by every subject the agent granted this window whose
`exp + TTL + skew >= now`, not only the grants still live. Within one window
(at most 8 hours) that is in effect all of the window's grant subjects: each expired at most 8 hours ago, and TTL + skew
(about 7 days) is still ahead. This is symmetric with the drop rule of §7.2, which keeps an entry until its hop's
`exp + TTL + skew`: logout revokes exactly the hops whose mail a reader would still accept. The re-sign applies that
drop rule — every carried `revoked` entry past its hop's `exp + TTL + skew`, which no longer protects any mail, is
dropped — **before** it tests the 1,024-entry cap, so a logout revocation is never blocked by dead entries (added
2026-11-01): the whole re-sign would otherwise fail `too-many-revoked` and revoke nothing
when the carried list plus the new subjects crossed the cap, even though the carried list held entries §7.2 would
drop. An entry whose hop expiry the edge cannot determine is kept, and the re-sign fails `too-many-revoked` only when
the still-live carried entries plus the new subjects exceed the cap. A hop that expired inside the
window is otherwise never revoked, yet its session key, readable by any process of the same uid, can be used to back-date
mail (a `ts` just before the hop's `exp`) that readers accept until `exp + TTL + skew`. Sending under the revoked
subjects then ends at the relays at once; a relay still holding an older address record delays the cut-off by up to that
record's `ttl`, a day at most (§7.2, §8.7). **The residual gap:** a window that ends without a later `ac logout` leaves
its just-expired hops unrevoked until each hop's `exp + TTL + skew`, about 7 days, and no tool revokes them afterwards,
because the agent closes at its window's end, so `ac logout` then finds no agent (`agent-locked`); and an agent still
listening with no open window revokes nothing at a logout frame, answering `{ok: true, record: null}` while `ac logout`
prints nothing-to-revoke and exits 0. The re-sign is the principal's, at logout, not a session
request (§13.6, §13.7).

**The logout frame.** `ac logout` sends a uid-only `{"op":"logout"}` frame: no `args`, no nonce, `seq`, session or
signature. It is admitted by the uid floor of §13.1, exactly like `grant` and `resign`; it is not a session request and
never reaches the session handler, so §13.6's closed set is unaffected. The agent re-signs the address record as above,
moves `iat`, zeroes the keys and closes. It replies with one JSON line: on success `{"ok": true, "record": <the address
record, or null when nothing was revoked>}`; on any failure to re-sign (no address record held, a rotation record, or
the revoked list passing its cap, 1,024, §7.2),
`{"ok": false, "code": "bad-record", "detail": <message>, "unrevoked": [<subjects left unrevoked>]}`
and no record is signed. `unrevoked` lists the subjects left unrevoked: at the cap, the whole revoked list the record
would carry; on another failure (no address record held, or a rotation record) the subjects this logout would have
added. On success `ac logout` publishes the returned record through its relays unless it is `null`; on a refusal it reports the
`code` and the `unrevoked` subjects.

**On a device (`Agent.device`, `server.ts` `#end`).** When the held key is a device's D (§13.0), D is not the
key of the address record that names P's sessions, so the end path of this section, at a logout, a signal or the
window's end, **signs nothing**: no record is re-signed or published, and the reply is `{"ok": true, "record": null,
"unrevoked": [{sub, until}, ...]}`. `unrevoked` lists every session subject the agent granted that a reader would still
accept, each with `until = exp + TTL + skew` of its hop (§7.2), the instant the last back-dated mail under it passes the
stale-`ts` check; a live subject whose `exp` the server did not see has `until` = the device hop's `exp` + TTL + skew, which every
chain on D carries. `ac logout` prints `unrevoked <address> until <time>` for each and the step that cuts them. **A device
is revoked by `ac record address --revoke <D>` on P's machine, after P's own `ac logout`**: not by an in-window
agent re-sign, and not by any message from D to P's machine (D cannot sign P's record). **The residual:**
an expired device-session hop's key, readable by any process of the same uid on D, can back-date mail that readers accept
until `exp + TTL + skew` (about 7 days), and no logout on D closes it; the person's `ac record address --revoke` on P's
machine does, and until then the window of exposure is that span, not the hop's `exp`. That revoke is complete only
once the newer address record reaches every listed relay: it publishes offer-to-all / succeeds-on-one (Appendix B
110), so a relay that has not yet taken it keeps admitting D's chains until it does, and an incident response to a lost
or compromised device watches for item 110's `incomplete` and the per-relay cut-off of §8.7 (added 2026-11-01, by design — this is the propagation side of the best-effort revocation).

**Generation keys.** Each held generation's private key is a seed of the agent's own (`Agent.#keep`), zeroed with
`fill(0)` at `ac logout`, at the window's end and when the generation is dropped or replaced, together with the
principal's held keys. **A core debt remains:** the core's `SealingKey` that `openGroupKey` returns keeps its own copy of
the key, and `openGroupKey`'s intermediate seed is not zeroed; neither is reachable from the agent (a comment in
`agent.ts`, `#keep`; the core is at its ceiling), so the agent zeroes its copies and not those.

### 13.4 The one derived hop: attenuation by exact string prefix

At a session's `sign` request the agent signs, under the principal key, exactly one object and no other: a derived hop

| object | preimage | signed by |
|---|---|---|
| hop | `["ac/hop/1", principal, sub, caveats, exp]` (§6.1) | `principal` (the held key) |

where `principal` is the agent's principal, `sub` the `sub` of the request's `args`, and the agent MUST check all of:

1. **`caveats` begins with the session's effective caveats as an exact string prefix.** The session's effective caveats
   are its chain's hops' caveats concatenated in chain order (§6.2). The derived hop's `caveats` MUST begin with that
   list verbatim, string for string in order, and MAY then append further caveat strings. The test is byte-level, never
   semantic: `type=coding.task.v1` is not judged narrower than `type=coding.*`, and the agent neither reorders, drops nor
   rewrites a session caveat. A `caveats` that does is refused `not-in-grant`. Since a later hop can only append (§6.2),
   an appended caveat can only narrow authority.
2. **At least one caveat.** `caveats` is non-empty. A session's effective caveats are themselves non-empty (every first
   grant carries at least one), so an empty requested `caveats` fails item 1 and is refused `not-in-grant`; no
   empty-caveats code exists. (For `grant`, where there is no chain to prefix against, empty `caveats` is `bad-shape`,
   §13.5.)
3. **`exp` is at most the session chain's earliest `exp`**, and at most the window's end and at most `now` + 8 hours. A
   derived hop whose `exp` exceeds the chain's earliest is refused `exp-not-monotone` (§6.2 rule 7). An `exp` past the
   window is caught by the same rule, since the chain's earliest `exp` is already at most the window's end. The one
   exception is a session's own renewal (§13.5).

The checks run in a fixed order so each refusal carries one code: §6.2 rules 2 to 4 on the requested hop (`bad-hop`,
`too-many-caveats`, `caveat-too-long`), then the prefix test (item 1), then `exp` (item 3). A hop a session signed with
its own key would make the session the delegate's principal and replies would address a key with no mailbox (Appendix B
9), which is why the agent signs it. Nothing else is signed for a session. The agent returns the signed hop and records
it in the grant-set and the audit (§13.11).

### 13.5 The first grant and renewals

§13.2 admits a chain only when the principal's hop in it is in the grant-set. A session's first request would be refused
`not-in-grant`, and a `sign` that advanced a grant's `exp` would be refused `exp-not-monotone` by §13.4 item 3. Two paths
put a hop in the grant-set and close both refusals.

**The first grant (`ac grant`).** `grant` is a non-session operation, authenticated by the uid floor alone, carrying no
`ac/agent/1` signature: a session cannot send it for itself, because it names a `session` other than the caller and
carries a human confirmation the socket cannot supply. `ac grant` passes the session's address, the `caveats` and an
`exp`. The agent prints that session, those caveats and that `exp` on its own terminal and, only after a `y` is typed
there, signs exactly one hop

| object | preimage | signed by |
|---|---|---|
| first grant | `["ac/hop/1", principal, session, caveats, exp]` (§6.1) | `principal` (the held key) |

and records its digest in the grant-set and the audit. The printed line escapes the control and separator classes and
also `\p{Cf}` and `\p{Cn}`, so a caveat cannot rewrite the line a person reads. A first grant stays renewable when
another session signs the same preimage. The `grant` request's refusals: empty `caveats` is `bad-shape`; an `exp` past
the window's end is `exp-not-monotone`; no open window is `agent-locked`; a `session` in the principal's held
address-record `revoked` list (§7.2) is `revoked`, returned before the terminal prints (the re-grant ruling below); and
an `n`, or no answer, at the terminal is
`declined`, reported by `ac` on the grant reply and never a socket code (§13.10, §13.11). There is no code for "needs
confirmation": the socket cannot ask a human, and a session with no grant is told `not-in-grant`.

`ac grant --exp` bounds **the first hop, not the session**. A renewal's `exp` is at most the window's end and at most
`now` + 8 hours, whatever the first grant's life; a process of the uid holding the session key can ask for more than the
first grant's life and the agent signs it.

**Renewals are silent.** Within the window a session keeps its grant alive without a new terminal `y`. A **renewal** is a
`sign` request whose `sub` is the requesting session itself and whose presented chain is **any single-hop first-kind
grant-set entry** of that session: the original first grant or a prior renewal. The agent re-signs a derived hop whose
`caveats` begin with the presented entry's `caveats` as an exact string prefix (equal, or narrower by appending: monotone
narrowing) and whose `exp` is at most the window's end, advancing `exp` beyond the presented entry's. Authority only
narrows, the first grant is the ceiling, nothing widens, and the chain stays one hop. It is signed with one printed line
and no `y`, and its digest enters the grant-set and is itself a first-kind entry. (The client's renewal cadence is an implementation default, Appendix B 85.) Because a renewal is bounded by the
window's end rather than the chain's earliest `exp`, it does not trip §13.4 item 3, and since the window is at most 8
hours no grant outlives it. (As built, a renewal narrows from the presented entry and does not re-widen to the first
grant's ceiling.)

Anything **wider** gets no silent treatment: a `sign` whose `sub` is not the requesting session, whose presented chain
is not a single-hop first-kind entry of that session, whose `caveats` are not an exact prefix of the presented entry's,
or whose `exp` is past the window's end, is judged as an ordinary derived hop under §13.4 and refused there
(`not-in-grant` for caveats that are not a prefix, `exp-not-monotone` for an `exp` past the chain's earliest).

**Many first grants at once.** A principal may have many first grants live in one window, one per session, each its own
single-hop entry in the grant-set and each gated by its own `y`; no session inherits a standing grant. An `ac grant` a
client asks for the session key it just made (an MCP server starting its own session) is consistent with this section:
it is still the uid-only `grant` client of §13.1, not a session acting for itself, and the terminal `y` is the gate.

**Re-grant after a revocation (the re-login case; ruled 2026-11-02).** `ac logout` revokes the session subjects it
granted (§13.3), and revocation is monotone: a later `ac login` does not reinstate them (§7.2). A session key named in
the principal's `revoked` list signs nothing a reader accepts — its chains are refused `revoked` at every relay and edge
(Appendix A) until the last back-dated mail under its hop passes the stale-`ts` check, about `exp + TTL + skew`.
Therefore **the agent MUST NOT sign a first grant or a derived hop whose `sub` is in the principal's held address-record
`revoked` list**; it refuses `revoked` on the socket (§13.10), before the `ac grant` terminal prints, so no person
approves a grant that readers would silently refuse. (As built before this ruling the agent did not read the held
record's `revoked`: a plugin or Codex `--session` server that re-granted its kept key after a logout-then-login signed a
dead chain the person had just approved with a fresh `y`, and the session could not subscribe or send for about seven
days.)

A long-lived `--session` client that outlives the window — the Claude Code plugin's `--session auto`, Codex `--mode
mcp` — therefore does not reuse its key across a logout. At the next window it **mints a fresh session key, takes one
new first grant** (one terminal `y`) **and re-registers its open thread ids** at the agent (the `register` op,
§13.8 (a)). Thread continuity holds across the re-key, because the mailbox is the principal's and not the session key's
(§13.8): replies on the old threads arrive at the principal, and the agent releases each to whichever live session
registered its thread id — the bearer-capability handover §13.8 (a) already defines for a front-desk takeover. The fresh
key is absent from `revoked`, so its chains send and subscribe at once. Reusing the kept key, or minting a new key
without re-registering the threads, loses the re-login continuity scenario 47 pins. This key lifecycle is an
implementation default of the MCP `--session` client, not a rule of this section; only the agent's `revoked` refusal
above is a rule here.

### 13.6 What a session may never sign

A session's request MUST NOT cause the agent to sign, under the principal key, anything but the derived hop of §13.4.
This holds by the closed op set of §13.1: the only session ops are `sign`, `open` and `register`, and `sign` signs
exactly one object. The non-session ops are `resign`, `grant`, `logout`, `device-grant` and `group-key` (§13.1): the
first four sign only what §13.7, §13.5, §13.3 and §13.1 name (a re-signed record, a first grant, the logout record, the
device hop), and `group-key` signs nothing. No session op can name any of the following, so none is expressible as a session request; an op
outside the set is refused `bad-shape`, never signed:

- a **record** (`ac/addr/1`, `ac/accept/1`, `ac/key/1`; §7);
- a **rotation** countersignature (§7.3);
- a **handle** record (`ac/handle/1`; §12.4);
- a **policy** statement (`ac/policy/1`, `ac/policy-members/1`; org mode, held back);
- a **group key** statement (`ac/gkey/1`; the group admin's, not the agent's: the agent takes a generation in with
  `group-key` and signs no statement about it).

These are the principal's own. The org tags are loaded only by an org-mode agent in its own home and process; a personal
agent does not load them.

### 13.7 `resign`: the keep-alive seam

`--keep-alive-records` keeps a principal's current records alive without a login dialog per cycle. It is not a session
capability. It is a non-session client, authenticated by the uid floor alone, with exactly one operation and no content:
**`resign <kind>`**, `kind` one of `address`, `accept-from`, `key`. The agent re-signs its own last record of that kind,
the one the principal's dialog last approved, under the principal key, with every member equal and only `iat` moved to
`max(now, last iat + 1)`. It needs no grant and carries no caveats: its only power is to keep the current state alive a
`ttl` longer (§7.2, §7.5). It is bounded: at most once per half `ttl` per kind (Appendix B 80), and only inside an open
window (outside one, `agent-locked`). A **changed** member (`relays`, `revoked`, `sealing_key`, `rotation_key`, `ttl`) and
any rotation are not `resign`: they are the principal's own `ac` dialog. The logout re-sign of §13.3 changes `revoked`,
so it too is the principal's, not `resign`.

### 13.8 The read rule: what the agent opens and releases

On an `open` request the agent MUST:

1. parse the envelope bytes itself (§5.4), recompute the id and verify `sig` under `from` (§5.5 steps 1 to 3); the
   stale/future-ts check (§5.5 step 4) is the edge's, since an inbox row may be retried late (§9 item 3);
2. judge the chain at its own clock (§13.2) and confirm the request's `session` is the chain's last `sub`;
3. take the wrap whose `to` is the mailbox's address, open it and the content in the agent's own memory (§4.4), and
   decode the plaintext, applying the control-character rule of §5.2. The mailbox is the principal's, or for a chain
   rooted at a held group (§13.2 (b)) that group's; any other `mailbox` is `not-authorized`, and so is every `open` on a
   device's agent, which opens nothing (D holds no key that opens P's mail). A group's wrap is opened with the group's
   newest held generation, then the one before it; if neither opens it, the first failure is raised, and the
   generation that opened it is written in the `open` audit line's `detail` (§13.11);
4. release the content to the session only when the read rule holds. Otherwise nothing leaves the agent: not the body,
   not the thread, not even the `type`.

**The read rule.** The agent releases an opened content to a session when either:

- **(a) registered thread.** The envelope's `thread.id` is one the session registered at the agent (the `register` op).
  A thread id is 32 random bytes, sealed, known only to the parties of the thread (§5.2); naming it is the capability.
  The window's registered-thread set holds it, so it survives a reconnect. Because naming it is the whole capability, a
  thread id is a bearer capability across the sessions of one principal: any session that holds the id may register and
  read its thread. This is how a session that takes over as the front desk (the MCP-server routing layer of §13.11)
  registers an earlier session's threads at the handover.
- **(b) admitted root.** The envelope is a root message (`thread.prev` is `[]`, §5.2) and every caveat of the session's
  effective caveats holds for the content under the evaluators the agent has (§6.3, §6.4). A caveat no evaluator knows
  fails closed; a caveat that does not hold fails too.

A read admitted by neither is refused with exactly one code, `not-in-grant`, whichever limb failed. Returning a second
code would tell the session whether the envelope is a root, which `thread.prev` holds sealed. The precise reason
(`caveat-failed`, `unknown-caveat`, or an unregistered thread) is kept in the agent's own audit and never leaves on the
socket. Envelope-level failures that precede the read rule (`bad-content`, `open-failed`, `not-recipient`) release no
content and any recipient of a message learns them. Rule (a) exists because caveats bound what a session may send, not
what it may read (§10): a client MUST register a thread at send or its replies are refused `not-in-grant`.

### 13.9 Caps

The agent's caps are implementation defaults, listed in Appendix B 77 onward, not rules of this section and not
configuration. A busy session a cap turns away is refused the local `rate-limited`, never a wire error.

### 13.10 Result codes

The agent reuses the closed set of Appendix A and adds two local codes of its own. A local code is raised on the socket
only, never sent on the wire, and a relay never sends it; the two local codes are written in the agent's audit (§13.11).
They are not rows of Appendix A, whose table is unchanged.

| code | raised by | meaning | relay status |
|---|---|---|---|
| `agent-locked` | agent | no login window is open: the agent holds no principal key, so it will sign nothing; the person's next step is `ac login`. It has one meaning: it is not raised for a kind a session may never sign (§13.6), and an op outside §13.1's set is `bad-shape` | — |
| `not-in-grant` | agent | an action outside the session's effective caveats or the read rule: a chain whose principal hop is not in the grant-set (§13.2), a derived hop that drops or reorders a session caveat or whose caveats are not the presented entry's prefix (§13.4, §13.5), or a read admitted by neither a registered thread nor the caveats (§13.8) | — |

Reused from Appendix A: `bad-sig` (the outer signature does not verify) is **not** a local code; the agent returns it for
a request frame whose `sig` does not verify under the session key the frame names (§13.1). Also reused: `not-authorized`,
the chain codes of §6.2, `exp-not-monotone`, `revoked` (a `grant` or a `sign` whose `sub` is in the principal's held
address-record `revoked` list, §13.5), `rate-limited`, `bad-content`, `not-recipient`, `open-failed`,
`envelope-too-large`, `bad-address` and `bad-shape`; and, for `device-grant` and `group-key` (§13.1), `bad-key` and
`type-not-accepted`, each an existing Appendix A row used here without a new one; `caveat-failed` and `unknown-caveat` appear only in the agent's audit
for a withheld root read. `declined` (an `n` or no answer at the `ac grant` terminal) travels on the grant reply to the
uid-only `ac` client; it is `ac`'s report, not an agent result code and never a socket code.

### 13.11 Audit

The agent keeps its own hash-chained JSONL log in the format of §9 item 8: each line
`{seq, prev, ts, event, decision, reason, id, from, root, detail, hash}` over the preimage
`[seq, prev, ts, event, decision, reason, id or null, from or null, root or null, detail or null]` (§2.4), with
`hash = sha256hex(utf8(canonical(preimage)))`, `prev` the previous line's `hash` (64 zeros for the first), `decision` one
of `accept`, `reject`, `retry`, `route`, `queue`, and `reason` a code or `"ok"`. No line holds key material. The line's
`seq` is the audit line's, not the request's. The agent audits a session request only after its signature verifies: a
request refused before that writes no audit line.

| event | decision | id | from | root | detail |
|---|---|---|---|---|---|
| `sign` | `accept` / `reject` | the derived hop's digest | the requester (`session`) | the principal | `{tag: "ac/hop/1", sub, exp, caveats: <count>}` |
| `open` | `accept` / `reject` | the envelope id | the requester (`session`) | the principal | `{mailbox, rule: "thread" \| "root"}`, and at a group mailbox `generation: <the generation that opened it>` |
| `declined` | `reject` | null | null | the principal | implementation-defined |
| `device` | `accept` / `reject` | the device hop's digest | null | the principal | `{tag: "ac/hop/1", sub: <D>, exp, caveats: <count>}` |
| `rotate` | `accept` / `reject` | the envelope id, or null for a replayed body | the envelope's `from`, or null | the principal | on `accept` `{group, generation, sealing_key, hop_exp, kept: "new" \| "renewed" \| "held" \| "dropped"}` (the public key, never the private one); on `reject` empty |
| `pair` | `accept` / `reject` / `queue` | null | the peer, or null | null | `{step, name}` or `{step, code}`; never S, the six digits or a key |

`reason` is the refusing code; on an `accept`, `"ok"`; on a `declined` event, `"declined"`. The `detail`
never names key material, the sealed `type`, or a thread id.

**`device` and `rotate`.** The agent's own events are now `sign`, `open`, `declined`, `device` and `rotate`
(`AgentAuditEvent`). `device` is written by `device-grant`: `accept` once the `y` signs the hop, `reject` for
`exp-not-monotone`, `agent-locked`, `not-authorized` or `declined` (a malformed ask, `bad-address` or `bad-shape`, names
nothing and writes no line). `rotate` is written by `group-key`, `accept` or `reject <code>`; it is also the edge's own
event name (§9 item 8). Both are uid-only frames with no signature, so, like `declined`, they are written without the
signature check that gates a session request's line. **The codes each event may carry, as the line parser holds them:**
`not-in-grant` on `sign` and `open`; `agent-locked` on `sign`, `open`, `device` and `rotate`; `declined` on `declined`
and `device`; a `declined` event's `reason` is `declined`. Every Appendix A code parses on any event; this list restricts
only the two agent-local codes and `declined`. **What the agent writes is narrower than what parses:** it writes
`agent-locked` only on a `device` or `rotate` line. A `sign` or `open` refused `agent-locked` writes **no** line,
because the window check precedes the signature check and the agent audits a session request only after that check
(`handle` audits only after `#verify`). **The residual:** `agent-locked` still parses on **any**
`rotate` line, because `rotate` is also the edge's event and nothing in a line tells the agent's from the edge's, so a
line the edge wrote with that code would not be refused by the parser.

**`declined`.** The agent writes a `declined` line when a `grant` prompt is refused at the terminal (a non-`y` answer, or
no answer), including when the requester has left before the answer (and a `device` line with `declined` for a refused `device-grant` prompt); the one exception is a window that ends before the
answer, where there is no agent to record and the window's end is its own record. (A `y` typed after the requester left
signs nothing and writes nothing.) It is an exception to "a request refused before its signature verifies writes no audit line", with `device` and
`rotate` above: a `grant` frame is uid-only and carries no signature (§13.1), so a declined grant is still logged. The agent logs `declined`; `ac`
reports it; it is never a socket code.

**`pair` (pairing in Claude Code, 2026-10-29).** The MCP server's `pair_invite` and `pair_accept` tools write a `pair`
line at each step of a pairing driven from inside Claude Code through elicitation: `queue` for `invite-open` (the inviter's string is shown; `from` null) and `request` (a request arrived under the
invitation secret); `accept` for `admit`/`accept` (the peer is admitted to the accept-from and written to the name book);
`reject` for a bad or `leaked` `request`, a `refuse` (the inviter ended it) or a `decline` (the acceptor said no).
`reason` is always `"ok"`; `detail` is `{step, name}` or `{step, code}` and never carries the invitation secret S, the
six-digit comparison code or any key. Like `rotate`, `pair` is written through the edge's audit log, so it is also an edge
event name (§9 item 8); it carries no envelope, so `id` and `root` are null. The person's keystroke that completes a
pairing is the model-cannot-answer invariant, not a session-request signature, so no signature gate
applies and `pair` lines are written for every step above.

**Agreement check.** For each session, the set of envelope ids in its edge `unseal accept` lines equals the set in the
agent's `open accept` lines naming that session: the agent opens exactly what the session's own receive path would have.

**Many sessions on one principal.** When several of a principal's sessions run behind a front desk (the MCP-server
routing layer that admits root messages to one session at a time, above the seat and not a read boundary: §13.8 (b)
still releases every root to every session whose caveats hold, so each session still receives each root), this agreement
holds as a subset, not an equality, for a session that is not the desk. Its edge `unseal accept` ids are the agent's
`open accept` ids naming it less (a) the roots it held back for the desk (`desk-held`) and (b) the roots an earlier desk
already took (`desk-answered`). The per-principal ledger `<home>/state/<principal>/desk-handled` lists the taken roots,
so the held set is auditable. `desk-held` and `desk-answered` are the front desk's own reasons, raised above the seat;
they are neither codes of this section (§13.10) nor rows of Appendix A.

## Appendix A. Error codes

The closed set (one set for relay responses and audit reasons). "core" codes are raised by the core
libraries; "core, edge" codes only arise where the sealed part is read, which is never at a relay. The relay status is
the HTTP status of §8; "—" means the relay never sends that code. A wrong HTTP method on a path the relay serves is 405
with no code in its body (Appendix B 99), the one relay response outside this set.
The agent seat's two local codes, `agent-locked` and `not-in-grant`, are §13's; they are raised on the socket, never by a relay; `not-in-grant` is written in the agent's audit, while `agent-locked` is raised before any session request's audit (the window check precedes the signature) and is written only on a `device` or `rotate` line (§13.11), and §13 reuses `bad-sig` from this table.

| code | raised by | meaning | relay status |
|---|---|---|---|
| `bad-canonical` | core | a value with no canonical form (§2.1) | — |
| `bad-hex` | core | a byte field that is not lowercase hex of its length | 400 |
| `bad-address` | core | a string that is not an address (§3.2); where a handle may stand too, one that is neither (§12.3; added 2026-10-26) | 400 |
| `bad-key` | core | key material of the wrong length, or a small-order X25519 key | — |
| `bad-json` | core | not UTF-8 JSON text, or an object that names a member twice (§2.5; the second since 2026-10-25) | 400 |
| `bad-shape` | core | a member missing, extra or of the wrong type (§5.4) | 400 |
| `bad-version` | core | `v` is not 1 | 400 |
| `bad-suite` | core | `suite` is not 1 | 400 |
| `envelope-too-large` | core | an envelope over 196,608 bytes (65,536 before 2026-11-11) | 413 |
| `too-many-recipients` | core | over 16 recipients | 422 |
| `bad-id` | core | the id does not recompute | 422 |
| `bad-sig` | core | the outer signature does not verify | 422 |
| `stale-ts` | core | `ts` before `now - (ttl + skew)` | 422; 401 at fetch |
| `future-ts` | core | `ts` after `now + skew` | 422; 401 at fetch |
| `too-many-hops` | core | chain rule 1 | 422 |
| `bad-hop` | core | chain rule 2 | 422 |
| `too-many-caveats` | core | chain rule 3 | 422 |
| `caveat-too-long` | core | chain rule 4 | 422 |
| `chain-broken` | core | chain rule 5 | 422 |
| `chain-not-to-sender` | core | chain rule 6 | 422 |
| `exp-not-monotone` | core | chain rule 7 | 422 |
| `hop-expired` | core | chain rule 8; at a relay also a chained envelope received past its chain's earliest `exp` + skew, and at an edge one whose `received_at` is past it (§8.2 step 6, §9 item 3; added 2026-10-25) | 422 |
| `bad-hop-sig` | core | chain rule 9 | 422 |
| `unknown-caveat` | core, edge | a caveat no evaluator knows (§6.3) | — |
| `caveat-failed` | core, edge | a caveat that does not hold (§6.3) | — |
| `not-recipient` | core, edge | no wrap names this address (§4.4) | — |
| `open-failed` | core, edge | a wrap or the content does not open (§4.4) | — |
| `bad-content` | core, edge | the plaintext is not `{type, thread, body}` (§5.2), or is not JSON a reader takes, a member named twice included (§2.5) | — |
| `bad-thread` | core, edge | a malformed thread (§5.2) | — |
| `too-many-prev` | core, edge | over 64 parents (§5.2) | — |
| `bad-record` | core | a record that breaks its form (§7) | 400 |
| `too-many-relays` | core | over 64 relays | 422 |
| `too-many-revoked` | core | over 1,024 revoked keys | 422 |
| `bad-record-sig` | core | a record's signature does not verify | 422 |
| `future-iat` | core | `iat` after `now + skew` | 422 |
| `record-expired` | core | past `iat + ttl`, or past `exp` | 422 |
| `bad-rotation` | core | not a valid rotation (§7.3) | 422 |
| `body-too-large` | relay | a request body over 262,144 bytes, or a record body over 131,072 (§8.2 step 1; the second added 2026-10-25) | 413 |
| `not-hosted` | relay | no recipient has an accept-from record at this relay | 403 |
| `root-not-accepted` | relay | the chain's root is not in the recipient's `roots`, nor the current key of a domain they name (§8.8) | 403 |
| `too-large-for-mailbox` | relay | the envelope is over the recipient's `max_bytes` | 403 |
| `rate-limited` | relay | over a rate limit, the client address's quota of new record signers a UTC day included (§8.2; the quota added 2026-10-25) | 429, with `Retry-After` |
| `store-full` | relay | a publish refused because the relay's store is at its byte bound (§10, `--max-store-bytes`); reads, fetches and the sweep continue (added 2026-10-29) | 503, with `Retry-After` |
| `bad-auth` | relay | a fetch or subscribe proof that is missing, malformed or does not verify | 401; an error frame at subscribe |
| `not-authorized` | relay | a proven signer who may not read this | 403; an error frame at subscribe |
| `not-found` | relay | no such envelope or record | 404 |
| `stale-record` | relay | a record not newer than the stored one | 409 |
| `internal` | relay | the relay's own failure (its store, say): a failed try, which the client repeats (§8.1); added 2026-10-25 | 500 |
| `untrusted-root` | edge | the chain's root is not trusted (§9) | — |
| `type-not-accepted` | edge | the sealed type is not accepted (§9) | — |
| `revoked` | edge, relay | a hop's `sub` is in the root's `revoked` list (§9); at a relay, a hop's `iss` or `sub` is in the `revoked` list of the domain record that admits the root (§8.2 step 7); a handle whose address the org's record revokes (§12.4; added 2026-10-26); at a relay since 2026-10-26, a hop's `iss` or `sub` in the revoked list the relay keeps (§8.7) for the mailbox at subscribe, for the chain's root at fetch, or for a root an address admits at publish, and the end of an open subscription that a newer record revokes (§8.2 step 7, §8.3, §8.5 items 2 and 8) | 403; an error frame at subscribe, closed 4001 |
| `pin-mismatch` | edge; relay log | a key that differs from the pinned key, without a valid rotation (§9); a relay logs it for a domain root and keeps the pinned key while its record is valid (§8.8) | — |
| `duplicate` | edge | an id already seen (§9; a relay answers a duplicate with 200 and `"duplicate": true`) | — |
| `resolve-failed` | edge, relay | a record could not be fetched or did not verify (§9); at a relay, a domain root that did not resolve (§8.8); since 2026-10-26 also a TXT record at `_bag.<domain>` that is malformed or one of two, a TXT lookup that failed, or a record that agrees with its TXT's key neither by that key nor by one rotation it countersigned (§12.2), and a handle that does not resolve (§12.4) | 503, with `Retry-After` |
| `publish-failed` | edge | the outbox gave up after its tries (§9) | — |
| `unreachable` | edge | one try that got no answer from the relay: no connection, or no response (§9 item 1); added 2026-10-25 | — |
| `bad-code` | edge | a pairing request whose MAC under the code's `S` does not verify, in the word-code ceremony or the paste dialog (§8.10; added 2026-10-30) | — |
| `digits-mismatch` | edge | the six check digits typed at the inviter do not match the inviter's own locally computed digits; a local inviter event (the relay never sees check digits), not counted in R19's N = 20 MAC-guess bound and not consuming the invitation (§8.10; added 2026-10-30) | — |
| `leaked` | edge | a pairing request to an invitation a valid request already consumed (§8.10; added 2026-10-30) | — |
| `no-nameplate` | relay | a `pair/claim` for a nameplate the relay does not hold or that has expired (§8.10; added 2026-10-30) | 404 |

## Appendix B. Implementation defaults

Each point below is a choice this document makes where it was otherwise silent. Each
is marked where it appears.
1. The canonical form's caps count UTF-8 bytes (§6.1), and a caveat is a non-empty, well-formed string (§6.1).
2. JSON reading rejects a byte-order mark and an escaped lone surrogate (`bad-json`); duplicate member names are
   discouraged, and the TypeScript reader keeps the last (§2.5). Changed 2026-10-25: every reader
   (TypeScript, Rust, the Python verifier) takes a number where a canonical integer is expected only when it is
   written `0` or `[1-9][0-9]*` and is at most 2^53 - 1, refuses any other with the code of that place, and calls a
   number past a double's range `bad-json`; the sealed `body` keeps any JSON number (§2.5, §4.2). Changed 2026-10-25: duplicate member names are no longer only discouraged; every reader refuses an object that names a
   member twice, `bad-json`, and `bad-content` in the sealed content, and no reader keeps the last (§2.5).
3. Writers emit the envelope's members in the order of §5.1 with no white space; readers reject unknown members (§5.1).
4. The parse order of §5.4, with `v` and `suite` checked first, and the outer-check order of §5.5.
5. Wraps follow the order of `to`, one per recipient; each wrap's `ct` is exactly 48 bytes, and `sealed.ct` at least 16
   (§4.3, §5.4).
6. The sealed content has exactly `type`, `thread` and `body`; `type` is non-empty and holds no Unicode control
   character (`Cc`) nor U+2028 or U+2029 (added 2026-10-27, §5.2); a reply names 1 to 64 distinct parents (§5.2).
7. A builder does not judge the chain (§5.6).
8. The rule "each hop well-formed" is chain rules 2 to 4, one code each; every rule runs over all hops before the
   next (§6.2).
9. The principal is the last hop's `iss`, or `from` (§1, §6.2). Note of 2026-10-25:
   the MCP server's `delegate` tool could let a session delegate on, against the convention that sessions sign and
   principals receive; the principal of a chain extended that way is the session, which has no mailbox, so replies to
   its delegate reach none. The tool refuses unless the server runs with `--allow-session-delegation`.
10. Combining evaluators: a caveat holds with at least one `hold` and no `fail` or `needs-sealed`; `needs-sealed` and a
    throwing evaluator give `caveat-failed` (§6.3).
11. The coding grammar's edges: `*` only as a trailing `.*`; malformed `type=` and `repo=` caveats are unknown (§6.4).
12. Record kinds `address`, `accept-from` and `key`; unknown record members rejected (§7.1).
13. Relay URLs: distinct, `http` or `https`, a non-empty host, no space or control character; `relays` may be empty
    (§7.2; the `relays` row there is the one statement of the form, clarified 2026-11-03). Added 2026-10-25: a relay URL is a base,
    and a client drops all its trailing slashes before it appends the API path (§7.2).
14. An address record is valid from `iat - skew` to `iat + ttl`; a key record to `exp`; `rotation_sig` only with
    `rotated_from` (§7.2, §7.5). Changed 2026-10-25: a key record's `exp` is at most `iat` + 86,400
    (§7.4).
15. An accept-from record does not expire, and its `ttl` (retention) has no 24-hour ceiling; `"*"` stands alone in
    `roots`; `max_bytes` and `ttl` are positive (§7.4). Changed 2026-10-25: `roots` holds at most 1,024
    entries.
16. Publish dispatches records by a top-level `kind` member; an envelope over 196,608 bytes (65,536 before 2026-11-11) is 413; success bodies as in
    §8.2; delivery to the recipients that admit the envelope, 403 only when none does; a rotation is checked when the
    relay holds the previous record (§8.2). Changed 2026-10-25: when it holds none, its claim is
    checked alone, under `rotated_from` (§7.3), so a bare or wrongly countersigned rotation is 422 `bad-rotation`
    rather than stored; a rotation by the previous record's rotation key needs a relay that holds that record.
17. Fetch: `AC-Ts` within the skew; `AC-Auth` as base64url JSON; the proof's `audience` (§8.3) one of the relay's configured accepted base URLs — the advertised URL (`--advertise` / `config.url`) and each `--accept-base` — compared byte for byte, never against a `Host` or forwarded header, with no normalization of the audience (a trailing slash, a written `:443` or an upper-case host is `bad-auth`); an `--accept-base` value has a single trailing slash dropped at read and is otherwise refused at start unless in §7.2's relay base form (clarified 2026-11-03; was "the §7.1 `relays`-entry form"); 401 for a failed proof (§8.3).
18. Subscribe: a 32-byte nonce; resume after the cursor or the stored ack (else 0); envelopes embedded as their stored
    JSON text; cumulative acks; an error frame and a close on a failed handshake (§8.5). Changed 2026-10-25: the envelope is a JSON string of its stored bytes, beside `received_at`, the second the relay stored it
    (§8.5 step 4), and delivery is at least once, an unacked frame coming again to the next subscription (§8.5).
19. Health returns `{"ok": true}` (§8.6).
20. An audit line's `reason` is a code or `"ok"` (§9).
21. The relay and edge codes of Appendix A beyond the base set: `bad-auth`, `not-authorized`, `not-found`, `stale-record`,
    `untrusted-root`, `type-not-accepted`, `revoked`, `pin-mismatch`, `duplicate`, `resolve-failed`, `publish-failed`.
    Since 2026-10-25 also `internal` (relay) and `unreachable` (edge); the relay answers `revoked`
    and `resolve-failed` too (§8.2 step 7).

**Added 2026-10-24: the defaults the relay and the edge chose where this document is silent.** They are listed here, not marked in the sections above. Choices that no peer can observe (the relay's storage and locking, the edge's ports) are omitted here.

The relay:

22. Publish: a body is a record when its top-level object has a `kind` member, whatever its value; a body over the
    envelope cap that is not a record is refused as `envelope-too-large` before it is read (implementation default).
    Changed 2026-10-25: a record body over 131,072 bytes is 413 `body-too-large`,
    checked once the body is known to be a record, before its form is read further.
23. `delivered` counts the mailbox rows written; a duplicate writes none, even if a recipient became hosted since
    (implementation default). Changed 2026-10-25: dedup runs before hosting (§8.2 step 6a),
    so a duplicate of an envelope whose recipients are no longer hosted is 200 `duplicate`, not 403.
24. Rate limits: records are limited per signer and per source address, like envelopes; the windows are aligned to
    multiples of 60 s; the limits are checked in the order from, root, address; a refused publish counts nowhere; the
    source address is the TCP peer, and no proxy header is read (implementation default). Changed 2026-10-25: the client address is counted at step 3a by every publish that reaches it, whatever happens
    next, before any signature is verified; `from` and root at step 8, by a publish that passes both; "a refused
    publish counts nowhere" now holds for those two, and for a publish refused at steps 1 to 3. Changed 2026-10-25: "the source address is the TCP peer, and no proxy header is read" holds without
    `--trust-proxy`; behind a trusted proxy the client is the address its header names (§8.9 item 1), and a client
    counts by its bucket, an IPv4 address or an IPv6 /64 (§8.9 item 2), which for an IPv6 peer is the one change
    without the flag.
25. Fetch checks, in order: the id (400 `bad-hex`), the headers and `AC-Auth` (401 `bad-auth`), the signature (401
    `bad-auth`), `AC-Ts` (401 `stale-ts`, `future-ts`), the chain at `AC-Ts` (403 `not-authorized`), the lookup (404
    `not-found`), the party check (403 `not-authorized`). So any key holder learns whether an id exists (404 against
    403); ids are 256-bit hashes. `AC-Auth` is read with or without base64 padding. A record fetch of an unknown kind is
    404 (implementation default). Changed 2026-10-25: the party check admits the envelope's
    principal, the last hop's `iss`, beside `from` and the `to`, and a chain from any of them; a 200 carries
    `AC-Received-At` (§8.3).
26. Subscribe: the auth frame has exactly `t`, `mailbox`, `signer`, `auth`, `cursor` (`null` allowed) and `sig`;
    anything else, a binary frame or a bad signature is `bad-auth`; a chain failure reports its own code; the close
    code is 4001. A resume cursor past the mailbox's last is clamped to it (implementation default).
27. Subscribe, after the handshake: an ack is cumulative and stored as the maximum per mailbox and signer; an ack past
    the last cursor sent, or any frame but an ack, gets `{"t": "error", "error": "bad-shape"}` and close 4002; the relay
    pings every 30 s; silence (pongs count as activity), or no auth frame within 60 s, closes 4003; a shutdown closes
    1001; a store failure closes 1011 with no frame; frames are at most 262,144 bytes (implementation default).
    Changed 2026-10-25: the ping interval and the idle timeout are flags (`--ping-interval`, `--idle-timeout`,
    the second at least twice the first), a pong restarts the silence at once, and a subscription under a
    chain closes at its chain's earliest `exp` with `hop-expired` and 4001 (§8.5 item 6).
28. Health returns `{"ok": true, "version": "0.0.0", "now": <seconds>}` (implementation default; §8.6 names `ok`).
    Changed 2026-10-25: it also answers `url`, the URL the relay announces (§8.1), `null` in a relay
    that has none (an in-process test relay).
29. Cursors start at 1 and never go back, even after a sweep or a restart (item 102); an envelope expires with the last
    of its mailbox rows, and fetch answers 404 after that (implementation default). Changed 2026-10-25: a
    swept id stays a duplicate, from its tombstone, until `ts` + TTL + skew (§8.7). A restore of the store from an older
    copy is the one case where a mailbox's next cursor goes back to the copy's value (added 2026-10-31): the per-mailbox cursor is monotonic across a sweep and a restart only, so `(relay, mailbox,
    cursor)` is not a stable envelope identity and a conforming edge decides delivery by id, not cursor (§9 item 2, item
    3; item 102).
30. The reference relay listens on 127.0.0.1 only; `--db` is required; a flag error exits 2; a database, port or
    stdout it cannot use exits 1; SIGTERM or SIGINT exits 0 after closing subscribers, waiting up to 5 s
    (implementation default). Changed 2026-10-25: each count and duration flag it added is at least 1, else
    exit 2, as is an `--idle-timeout` under twice `--ping-interval`; a database whose schema version is newer than the
    relay's exits 1. "Listens on 127.0.0.1 only" is item 46's `--bind`.
31. JSON readers: the reference relay refuses `1.0`, `1e0` and `-0` as integers, calls `1e400` and nesting over 128
    `bad-json`, and keeps the last value of a member given twice, as `JSON.parse` does, so the relay and the edge read
    the same envelope (implementation default). Changed 2026-10-25: §2.5 now requires the refusal of
    every number not written as a plain decimal integer, and the TypeScript reader and the Python verifier refuse the
    same spellings with the same codes, `1e400` included (was: §2.5 allows both readings). Changed 2026-10-25: the reference relay refuses a member name given twice as `bad-json`, through `ac-core`'s reader, and so do
    the TypeScript reader and the Python verifier, so the relay and the edge still read one envelope alike (was: it
    keeps the last value).
32. Ed25519 verification also refuses a small-order R or public key (implementation default; §10 names a non-canonical
    S). (added 2026-10-25) No longer a Rust-only default: §10 now requires it of every implementation,
    and the TypeScript core (`verifySig`) and the Python verifier (`scripts/verify_vectors.py`) refuse a small-order
    or non-canonical `A` or `R` and an S at or above L before OpenSSL sees them, as the Rust core does. Since 2026-10-25 §2.3 states the rule, the cofactorless equation included, and the vectors pin it (§11).

The edge:

33. Outbox: one target per relay URL across all recipients (the relay fans out); a failed try's reason is the relay's
    code when its body named one, else `publish-failed`, and the 20th failure is `publish-failed`; a 4xx other than
    408 and 429 fails its target at once with the relay's code, kept for resend; a 429 waits for its `Retry-After` when
    that is longer than the backoff (implementation default). Superseded 2026-10-25: §9 item 1's normative
    text replaces the 20 tries with a horizon of `ts` + TTL; `unreachable` is now the reason of a try that got no
    answer (Appendix A). Added 2026-10-25: the writer is built, behind
    `EdgeOptions.unreachableReason`, which the CLI turns on and the MCP server; the library's
    default stays off. A relay that answers with a redirect (3xx), which no edge follows
    (item 41), has answered: the try fails with that status, not `unreachable`. (Corrected 2026-10-25: "the library's default stays off" no longer holds; a later change turned `unreachableReason` on by default and removed the CLI's line that turned it on.)
34. The seen-set entry of an id lives until max(first sight, ts) + TTL + skew, through that second (implementation
    default; §9 item 3 says first sight + TTL + skew, which lets a replay through for up to the skew). Superseded
    2026-10-25: §9 item 3 states this window as normative; it is no longer a default.
35. Audit: `decision` is one of `accept`, `reject`, `retry`, `route` and `queue`; `seq` starts at 1; `detail` is carried
    in the line as the JSON text that entered the preimage; a last line that does not parse stops the edge from
    starting (implementation default). Changed 2026-10-25: `decision` is closed to these five
    values (§9 item 8), the events include `subscribe` (§9 item 8's note), and a try that got no answer from the
    relay has the reason `unreachable` (Appendix A).
36. Inbox: rows are keyed by (relay, mailbox, cursor) as a fast path, but the envelope id decides delivery (§9 item 2,
    items 29 and 102), one row per frame, unparseable ones included; an acked row keeps its reason and session; the edge
    resumes a subscription with `cursor: null`, so the relay resumes after the highest ack it stores for the mailbox and
    signer (§8.5 step 3, §9 item 10) — restore-safe — not after a cursor the edge remembers; a rejected row's `id` is
    the id its bytes claim, or null when they do not parse (implementation default).
37. Routing: a handler that throws leaves the message queued; a spawn hook that throws counts as none; the default
    handler is asked before the spawn hook; a reply on an unknown thread is queued (implementation default).
38. Trust: a root may be trusted by key as well as by domain; a key-trusted root with a non-empty chain needs its
    address record, read from the edge's relays, for its revoked list, else `resolve-failed`; an empty chain needs
    none; a domain root's configured key is a pin before first contact (implementation default).
39. Caching and pins: an address record is cached until min(now, iat) + ttl, a key record until min(exp, now +
    skew) (the skew, default 300 s; the cap was a day, narrowed 2026-10-29, so a sender picks up a
    restored or rotated peer's fresh key within the skew); a pin keeps the newest record (by `iat`) of the pinned key;
    an address subject's first pin is the address
    itself, and a relay-served rotation countersigned by it moves the recipient to the new key (implementation
    default).
40. A recipient's relays are its address record's, else the hint relays, else the edge's own; none at all is
    `resolve-failed`, before anything is persisted (implementation default).
41. HTTP: well-known and relay calls follow no redirects (as MTA-STS, RFC 8461, does not), read at most 262,144 bytes
    and time out after 10 s; a domain is a lowercase host name with an optional port (implementation default). Changed
    2026-10-25: a relay's 3xx is still not followed, and is read as the relay's answer
    with its status (item 33); a well-known fetch still fails on one. Since 2026-10-25 a relay reads a
    well-known record up to the same 262,144 bytes (item 49): one cap.
42. WebSocket: a reconnect after 250 ms × 2^n (at most 30 s), forever by default; an error frame, and any frame its
    stage does not take, is fatal; the embedded envelope's exact text is kept, and a JSON-string envelope is accepted
    too (implementation default). Changed 2026-10-25: an error frame ends the subscription, and the receiver
    subscribes again (§9 item 10); and the edge takes the envelope only as a JSON string, whose UTF-8
    bytes it verifies (§8.5 step 4), a frame whose envelope is anything else, the raw embedding included, being
    `bad-shape`, and it keeps the frame's `received_at`, or its own first sight, as the inbox row's (§9 item 3).
43. Key files: names `[a-z0-9][a-z0-9._-]{0,63}`, written with an exclusive create (never overwritten), `fchmod` 0600
    and `fsync`; a symlink, a non-regular file, or a group- or world-accessible file or directory is refused
    (implementation default).
44. A session that signs for its principal holds the session's signing key and the principal's sealing key, receives
    at the principal's mailbox, and presents at subscribe and fetch the suffix of its chain that starts at the mailbox
    (implementation default). Note of 2026-10-25: caveats bound what such a session sends,
    not what it reads; it reads the principal's whole mailbox for as long as it holds the sealing key, which the
    convention (sessions sign, principals receive) does not intend, and a copied session key file reads it too. The
    debt is paid when the opening agent opens for a session within its grant and the key leaves sessions (§10, "What a session reads"). Closed 2026-10-28 with its limit: the debt is paid for an identity in `agent`
    custody only (§13); a session of an identity in file custody still holds the sealing key and reads the whole
    mailbox.
45. On start, an edge finishes the inbox rows a crash left received or verified before it subscribes at its relays; a
    timer (1 s by default) publishes due outbox targets and prunes expired seen ids (implementation default).

**Added 2026-10-24: the reference relay on a network.**

46. Item 30's "listens on 127.0.0.1 only" becomes the default of `--bind`: the reference relay listens on one address,
    IPv4 or IPv6, 127.0.0.1 unless `--bind` names another (0.0.0.0 or `::` for every interface). The line of §8.1 is
    `AC_RELAY_URL=<url>`: the scheme and host of `--advertise` when given, else `http://` and the bound address, or
    the loopback address of its family when that is unspecified; the port is always the one it listens on, and a port
    written in `--advertise` is replaced. An unreadable `--bind` or `--advertise` exits 2. Its first log line names
    the bind address and that URL (implementation default). Changed 2026-10-25: a port written in
    `--advertise` is kept; without one, `https` is announced with no port and `http` with the listening one, so a
    relay behind a TLS proxy announces `https://relay-acme.usuals.now`, not `...:7701`; health answers the same URL
    (item 28).
47. The client address that item 24's per-address rate limit counts, and that the logs name, is the TCP peer's, with
    an IPv4-mapped IPv6 address read as the IPv4 address it maps; every publish, publish-record and subscribe log line
    names it (implementation default). Changed 2026-10-25: without `--trust-proxy` it is
    still the TCP peer's; behind a trusted proxy it is the address the proxy's header names (§8.9 item 1); the lines
    name it by its /24 or /48 unless `--log-ip` says `full` or `none` (§8.9 item 4).

**Added 2026-10-25: trust at the relay by domain.**

48. A domain root's host: at most 253 characters, two or more labels of 1 to 63 of `a`-`z`, `0`-`9` and `-`, no hyphen
    at either end of a label, no trailing dot, and not an IP literal by the WHATWG rule (the last label is not all
    digits and not `0x` with hex digits); `bad-record` otherwise, as any malformed root (§7.4) (implementation default).
49. The fetch: `accept: application/json`, `user-agent: ac-relay/<version>` (the reference relay), no proxy, no redirect
    (any status but 200 fails), a timeout of 10 s over DNS, connection, TLS and body (1 to 60 s), and at most 65,536
    bytes, where the edge reads 262,144 (item 41), so an org record over 65,536 bytes, about 880 revoked keys, resolves
    at an edge and not at a relay (implementation default). Changed 2026-10-25: at most
    262,144 bytes, the edge's cap of item 41, so a record resolves at a relay wherever it resolves at an edge.
50. The guard's categories (§8.8 item 2) beyond the six: shared, documentation, benchmarking, IETF protocol
    assignments (`192.0.0.0/24`, `2001::/23`, `2002::/16`) and reserved (`240.0.0.0/4` with the broadcast address,
    `192.88.99.0/24`, IPv6 outside `2000::/3`); IPv4-mapped and NAT64 addresses classified by the IPv4 address they
    carry; one shared table of 76 cases tests both cores (implementation default).
51. The cache: until `min(max(iat + ttl, now + 60), now + ceiling)`, so a short record is used up to 60 s past its
    `iat + ttl`, and a ceiling under 60 s wins (implementation default).
52. A failed resolution, a pin mismatch included, is remembered for 60 s; meanwhile the pinned key stays current
    while its record is valid, and a 503, when nothing is valid, carries `Retry-After: 60` (implementation default).
53. Step 7's order when no recipient remains: `resolve-failed`, then `revoked`, then `root-not-accepted`, then
    `too-large-for-mailbox`; a publish that admits some recipient is 200 and skips the others, an unresolved one
    included, which does not get the envelope (a later publish of the same id is a duplicate), and is logged
    (implementation default). Changed 2026-10-25: an unresolved recipient is no longer
    skipped but held in a pending row and delivered when its domain resolves within the relay TTL (§8.2 step 9; item
    63); a refused one is still skipped.
54. Revocation at the relay: the `iss` and `sub` of every hop are checked against the `revoked` lists of every domain
    record that admits the root; a root admitted by its address or by `"*"` is checked against no record (the edge
    still checks it) (implementation default). (Changed 2026-10-26: a
    root admitted by its address is checked against the revoked list the relay keeps for it (§8.7), the mailbox's kept
    list at subscribe (§8.5 items 2 and 8) and the chain's root's at fetch (§8.3), each against the `iss` and `sub` of
    every hop; `"*"` still reads no list, and a domain root's list is still its cached record's; item 75.)
55. The pin: a domain's first verified record pins its key, even a record that names `rotated_from`; a record of the
    pinned key replaces the stored one when its `iat` is not older; the pin is kept on a mismatch, and the pinned key
    stays the domain's current key, on a mismatch or any other failure, while its stored record is valid (`now <= iat +
    ttl`), so a chain under the pinned key is admitted and one under the offered key refused 403 `root-not-accepted`
    (implementation default; corrected before merge).
56. The relay's log lines for domains, one per resolution: `well-known` (`pinned`, `refreshed`, `rotated`) or
    `well-known-refused` (the reason, its fields, and `kept` with `valid_until` when the pinned key stays current),
    and `domain-roots` for a recipient that domains refused; never record bytes (implementation default).
57. The reference relay's flags: `--well-known-timeout` (default 10), `--well-known-cache-max` (default 86,400), the
    test-only `--well-known-insecure-http` and `--well-known-resolve <host>=<ip>:<port>`, refused (exit 2) unless the
    bind address is loopback and logged as a warning after `listening`, and the operator's `--pin-reset <domain>`, run
    while the relay is stopped (implementation default).

**Added 2026-10-25: key custody.**

58. The macOS Keychain custody of the edge: one generic password item per identity, its service `bag:<name>`
    and its account the identity's address, so that no attribute holds a seed; written by one command line on the stdin
    of `/usr/bin/security -i` and read by `find-generic-password -w`, whose output is parsed in the edge's process and
    not kept; a dialog at every read by default, unless the item trusts `/usr/bin/security` (implementation default).

**Added 2026-10-25: the relay's network front.**

59. Trusted proxies: `--trust-proxy <cidr>`, repeatable (an address alone is its /32 or /128; bits set past the length
    a flag error); `--client-ip-header`, `cf-connecting-ip` by default, a flag error without `--trust-proxy`; the
    header's lines joined by commas and read from the right, trusted addresses skipped, the first other address the
    client; a value met before it that is not an address, a line that is not visible ASCII, or a list of trusted
    addresses only, leaves the TCP peer: never a third address; values left of the client are not read (§8.9 item 1;
    implementation default; corrected 2026-10-25 before merge).
60. A client's bucket is its IPv4 address or its IPv6 /64, for step 3a, the record signers' quota and the connection
    cap (§8.9 item 2).
61. The connection cap behind a proxy: a trusted proxy's connections are not counted at accept; a WebSocket through
    one counts under its client's bucket for its life, and over the cap it is admitted at the upgrade and then sent
    `{"t": "error", "error": "rate-limited"}` and closed 1013, logged `connection-refused` with the client and reason
    `connections-per-ip` (§8.9 item 3; implementation default; corrected 2026-11-01, from
    `subscriptions-per-ip` — which is the direct reserve refusal's reason, §8.1 — to `connections-per-ip`, the reason
    the code logs for the proxied over-cap refusal; changed 2026-10-31, from
    closing it with nothing written). `--connections-per-ip`
    keeps its default of 79 (raised 2026-10-31 from 72, 2026-10-30 from 68), a client's, behind the tunnel too. Because the cap there counts a
    client address's WebSockets only, people behind one shared address share it: one subscription per identity per relay,
    and at the cap the next subscription is refused and retried while that address's sends still work (e2e scenario 54).
    Reached directly, where the cap counts every connection, an address's calls are kept getting in not by this count
    but by the subscriptions-per-ip reserve of §8 (slow clients).
62. Log modes: `--log-ip prefix` (the default), `full` or `none`, the `ip` field of the seven client lines a /24
    or /48 in CIDR notation, the whole address, or `-`, nothing else changed; the `listening` line names `log_ip`,
    `trust_proxy` and `client_ip_header`; a later `--log-ip` overrides an earlier one (§8.9 item 4; implementation
    default but the prefix lengths).
63. Pending rows: a table `pending(id, addr, until)`, schema version 4 (version 3 gains it as it opens), `until` =
    `received_at` + the relay TTL; written with the envelope in one transaction; the envelope kept while one lives;
    retried after each sweep, at most 256 rows a sweep, the earliest `until` first; a delivered row expires at
    `received_at` + min(relay TTL, the recipient's ttl); a row whose envelope is gone or does not parse, whose
    recipient is no longer hosted, or whose step 7 now refuses it (the root, a revoked key, the size, or that expiry
    already past) is dropped; logged `pending`, `pending-delivered` and `pending-dropped` with a reason (§8.2 step 9;
    implementation default).
64. The refresh on a root mismatch: only in a publish that may use the network and did not just resolve that
    domain; at most once in 60 s of the relay's clock per domain; never while a failed resolution of the domain is
    remembered (§8.8 item 6); the record read moves the pin by §8.8 item 5 (§8.8 item 4; implementation default).
65. The record answer's `valid_until`: `iat + ttl`, `exp`, or `null` for an accept-from record, beside `ok`, `kind`,
    `signer` and `iat` (§8.2; the record-answer shape, with `valid_until` added here).
66. The probe: `ac-relay probe <url> --key <file>`, a key file of 64 hex characters made 0600 when missing; the
    probe's accept-from record published only when the relay holds none; an envelope to itself with a sealed part of
    16 random bytes sealed to no one; 5 s a call; `probe ok <id>` and exit 0, `probe: <step>: <what>` and exit 1, a
    usage error exit 2 (§8.9 item 5; implementation default). (Changed 2026-10-26: each call runs on a
    thread of its own, given its 5 s, and the HTTP client has no timeout of its own, so that it never sets a socket
    timeout, which macOS refuses with EINVAL on a socket the peer reset though the answer had arrived; a call past its
    5 s fails `<step>: no answer within 5 s`.)

**Added 2026-10-26: the cap on domain resolutions in one publish.**

67. The cap on domain resolutions in one publish: 8, `MAX_FETCHES_PER_PUBLISH` in `crates/ac-relay/src/resolver.rs`,
    counting every domain the cache does not answer (no record, an expired cache, or a cached key that is not the
    chain's root, whether or not the refresh is due); the domains whose stored pin names the chain's root first;
    past the cap, the cache's answer or nothing, as in the relay's publish with no network; one log line
    `resolutions-capped` with the id, the cap and the number deferred (§8.8 item 4). Why 8: a mailbox names few
    domains, and the common first contact needs one (the sender's org, read first when pinned); 8 keeps one publish's
    outbound fetches within 8 of its one inbound request, and a mailbox with more domains resolves over a few tries,
    8 a try: a domain that resolved stays cached, and one that failed is remembered 60 s, so a mailbox naming more
    than 8 failing domains ahead of the root's needs its tries within that minute (an edge's backoff makes about six).

**Added 2026-10-26: discovery by DNS and handles.** They follow item 67, which reached
main first.

68. The TXT record (§12.2): at `_bag.<domain>`; `v=ac1` its first field; the grammar of §12.2 item 1 (names of
    1 to 32 letters, digits, `-` and `_` from a letter, case-sensitive; values of `!` to `~` but `;`, no inner space;
    spaces and tabs around ignored; empty fields skipped); a name given twice refused, `rec` refused, any other
    unknown name ignored; at most 1,024 bytes joined, tab and ` ` to `~` only; two bag records or a malformed
    one `resolve-failed` with no fallback, none at all the well-known URL; no TXT asked for a name over 253 characters
    or for a domain under a special-use name of item 71; a record that agrees with the TXT's key neither by that key
    nor by one rotation the key countersigned `resolve-failed` before any pin is read.
69. The origin (§12.1; §12.2 items 3 and 6): `host` exactly `bag`, putting the org's one origin
    at `https://bag.<domain>`, else `https://<domain>`; the address record, the served policy record and the
    handle records at `/.well-known/bag/address.json`, `policy.json` and `handles/<local>.json` under it; no URL
    in DNS; no DNSSEC required, and a validated answer treated as any other.
70. The text form of a TXT record: RFC 1035 §5.1's character-strings, quoted or bare, `\DDD` (at most 255) and `\X`
    escapes, 255 bytes a string, tab and ` ` to `~` only, no comment and no parentheses (§12.2 item 7).
71. Handles: a local part of 1 to 64 of `a`-`z`, `0`-`9`, `.`, `-` and `_`, from and to a letter or a digit; a domain
    under none of the special-use names `alt`, `arpa`, `internal`, `invalid`, `local`, `localhost` and `onion` (the
    list fixed here; `test` and `example` stay allowed); a string that
    is neither an address nor a handle `bad-address`; one spelling in records; a client SHOULD fold typed `A` to `Z` to
    `a` to `z` and folds nothing else (§12.3 item 1).
72. The handle record: `kind` `"handle"`, the members `org`, `handle`, `address`, `iat`, `ttl` (1 to 86,400) and
    `sig`, the tag `ac/handle/1`; served at `<origin>/.well-known/bag/handles/<local>.json`, one per handle and
    no list, `<origin>` the org's one origin; checked in §12.4 item 3's order, a binding to another key or handle
    `resolve-failed` and a revoked address `revoked`; the address record read through the org record's relays first;
    the handle's address not pinned on its own, and checked against the freshest org record's `revoked` list at every
    send; relays store no handle record (§7.1, §8.2, §12.4).
73. The reference relay's stub resolver (`crates/ac-relay/src/dns.rs`): TXT over UDP only, recursion desired, EDNS(0)
    with a 1,232-byte payload, asked again without it after FORMERR; a fresh socket for each query, on a port the system
    chooses, connected to its server, so that a datagram from any other address is never read; a 16-bit id from
    the system's random source; the answer's id and question (the name, compared without case, type TXT, class IN)
    checked, a datagram that does not match discarded while the try lasts; a truncated answer, a datagram over 1,232
    bytes, a compression pointer that does not point backward, a name over 255 bytes, TXT strings that do not fill their
    record, and a CNAME chain over 8 fail; NXDOMAIN and an empty answer are no records; SERVFAIL, REFUSED and the like
    move to the next server; at most 3 nameservers from `/etc/resolv.conf`, read at each lookup (127.0.0.1 and ::1 when
    it names none), 2 s a try; no TCP, no DNSSEC and no cache of its own (the records are cached, §8.8 item 4); the
    lookup and the fetch together within `--well-known-timeout` (§8.8 item 1).
74. The reference relay's lines and flag: a `txt` line for each lookup (`domain`, `name`, `source`, `dns` or `fixed`,
    and `records`); the `well-known` line gains `source` (`txt` or `well-known`) and `url`; `well-known-refused` gains
    the reasons `txt-lookup-failed` (with `detail`), `txt-malformed` (with `detail`), `txt-ambiguous` (with `records`)
    and `txt-key-mismatch` (with `txt` and `offered`); the test-only `--dns-resolve <name>=<txt>`, repeatable, refused
    (exit 2) unless the bind is loopback and logged `dns-resolve` after `listening`; with any test-only flag no DNS
    server is asked, and a name with no `--dns-resolve` has no TXT record (§8.8).

**Added 2026-10-26: the revoked lists a relay keeps.**

75. The revoked lists a relay keeps (§8.2 step 7, §8.3, §8.5 items 2 and 8, §8.7): in the reference relay a table
    `revoked(addr, iat, keys)`, schema version 5 (a version 1 to 4 database gains it as it opens, filled from its
    stored address records), one row per key that has stored an address record, written in the transaction that
    stores the record as the newest of its key, replaced only by a record with a newer `iat`, never swept; the `iss`
    and `sub` of every hop checked; at subscribe after the chain and the root check, at fetch after the party check,
    at publish for a recipient whose roots list the root by its address, before its size check; a store that cannot
    read a list closes a subscriber 1011 with no frame and answers a fetch or a publish 500; an open subscription reads
    its mailbox's list again, before its next frame and when notified for its mailbox, once the relay's count of
    stored address records has moved since its last read, so with no address record stored it reads none; logged
    `subscribe-refused` and `fetch-refused` with the code, `subscribe-closed` with the reason `revoked`, and
    `revoked-hop` (the mailbox and the root) for a recipient refused at publish (implementation default).
76. A host notice (§10, "Host notices"): a notice an edge or an MCP server
    sends a host to say a message was delivered has fixed-grammar fields only, never peer text, thread or body. In the
    reference MCP server (`packages/mcp/src/push.ts` lines 13 to 18) it is `message <id> from <from>, type <type>: read
    it with the inbox tool`, with `meta` `{id, from, type}`; `type` is shown only when it matches `^[\w.+*-]{1,64}$`, else
    `(not shown)`. The cli's wake hook writes one fixed line naming the identity and asking only for a read
    (`packages/cli/src/commands/wake-hook.ts` line 134) (implementation default).

**Added 2026-10-28: the agent seat** (§13). Each is an implementation default; the numbers marked "no basis" are to be confirmed by measurement.

77. The window: 8 hours by default and at most 8 hours (`ac login --window <seconds>`, capped at 8 hours), so no grant
    outlives it (§13.3).
78. A grant's `exp`: at most `now` + 8 hours and at most the window's end; for an ordinary derived hop also at most the
    session chain's earliest `exp`; a silent renewal is bounded by the window's end instead (§13.4, §13.5). `ac grant
    --exp` bounds the first hop only.
79. Caveats per derived hop: at least 1 and at most 32, each at most 256 UTF-8 bytes (§6.2); hops per chain at most 8;
    envelope on `open` at most 196,608 UTF-8 bytes (65,536 before 2026-11-11), checked at parse (`envelope-too-large`); the request frame at most
    1 MiB (§13.1).
80. `resign`: for a record with a `ttl`, at most once per half its `ttl`; for a key record, which has none, at most once
    per half its lifetime (`exp - iat`); per kind, only inside an open window (§13.7).
81. Per-session caps: 600 openings and 60 signatures a minute, 4,096 registered thread ids (no basis); over a per-minute
    cap the agent answers the reused local `rate-limited`.
82. `seq` per connection: at most 1,000,000 requests before the connection is recycled (no basis); the connection ledger
    keeps the accepted range, not every value (§13.3).
83. The request framing: one JSON line per frame in each direction on `<home>/agent.sock`, the 64-hex nonce sent first by
    the agent when a connection opens; the argument tuples of `sign`, `open` and `register` are those of §13.1. The
    socket is created 0600 in a 0700 directory (§13.1).
84. The printed grant line escapes the control and separator classes and also `\p{Cf}` and `\p{Cn}`; a first grant stays
    renewable when another session signs the same preimage; the agent writes its audit only after a request's signature
    verifies, apart from the `declined` line, which is built (§13.5, §13.11).
85. An MCP client's renewal pace (the client's, not the agent's; §13.5 is agnostic to when a client renews): the least time
    between two renewals of a session's grant is `min(300, floor(life / 2))` seconds, where `life` is the first grant's
    remaining life when the client starts (at least 1): 300 s (5 minutes) for a grant with 10 minutes or more left at
    start, half that life for a shorter one, so a grant does not lapse mid-window and does not churn. Source:
    `packages/mcp/src/agent.ts` (`RENEW_MIN_S = 300`; `pace = Math.min(RENEW_MIN_S, Math.floor(life / 2))`)
    (implementation default).

**Added 2026-10-28: the device grant and groups in the agent** (§13.1). Each is an implementation default
(`packages/edge/src/agent/model.ts`), with no basis recorded beyond the choice.

86. `DEVICE_MAX`: a device hop's `exp` is at most `now` + 30 days (2,592,000 s); a later `exp` is `exp-not-monotone`
    (`device-grant`, §13.1).
87. `GROUPS_MAX`: a window holds generations of at most 32 groups, the newest two of each; a frame that would add a
    thirty-third group is `rate-limited` (`group-key`, §13.1). It is a cap on groups held, not on frames.
88. `CHAIN_EXP`: the org-to-principal delegation chain that `ac onboard` builds lives 7 days (604,800 s) by default,
    set by `ac onboard --chain-exp <seconds>`, and at most §6.1's 30-day SHOULD ceiling (`MAX_CHAIN_EXP` = 2,592,000 s);
    a longer `--chain-exp` is refused (`packages/cli/src/commands/onboard.ts`).

**Added 2026-10-30: the pairing rendezvous (§8.10) and the sender fan-out (§4.3, §9 item
1).** Each is an implementation default.

89. The pairing rendezvous (§8.10): a nameplate `ttl` required, 1 to 600 s, with no default (a missing, `0` or
    over-600 `ttl` is `bad-shape`); the open's body at most 768 bytes, 512 for the reach and 256 for its signature (else
    `body-too-large`) (clarified 2026-11-03, from `crates/ac-relay/src/pair.rs`, where this item read "a nameplate
    `ttl` of at most 600 s, default 600; the stored reach blob at most 512 bytes"); the shortest free numeric nameplate allocated, more digits only as the space fills;
    at most 16 open nameplates per client address (`rate-limited`) and 10,000 open in all (`store-full`); `pair/claim`
    limited to 5 a second, burst 10, per client address; a pairing request delivered to an open invitation limited to
    1 a second, burst 5, across all client addresses, and 10 per (invitation, client address), charged only after the
    envelope verifies; the inviter ending an invitation after 20 bad-MAC misses (the guess bound, threat-model R19),
    none of which consumes it; `pair/open` signed by the invitation key over `ac/pair-open/1`. Sources: §8.10,
    `crates/ac-relay` and `packages/edge`.
90. The sender fan-out (§4.3, §9 item 1): K = 3 relays published to at once per recipient, in the record's listed
    order; a target given up at once on a permanent refusal (a 4xx other than 408 and 429) or after RETIRE_TRIES = 3
    unanswered attempts, otherwise retried to the horizon; the next listed relay promoted only on a give-up, while a
    relay the edge's policy refuses fails at once with no promotion; the failover plan persisted beside the envelope in
    the edge's outbox (routing fields only — the listed relays and which are counted — never a key or unsealed content,
    and never pooled across identities), so a later process of the same identity promotes an untried listed relay, and
    an outbox row written before plans were persisted carries none
    (`packages/edge/src/sender.ts`: `K`, `RETIRE_TRIES`).

Relay builder's choices (added 2026-10-31). A clean-room relay built from this spec alone (`clean-room/go`) met fifteen
places the text did not settle for a relay; each is settled below, in that builder's order, as what the reference relay
(`crates/ac-relay`) does, so a relay builder need not read the reference. Three say where the reference leaves a point
open or a rule changes behaviour (items 98, 103, 104).
91. A request body over the envelope cap that is not a record is `envelope-too-large` (413), not `bad-json`. The relay
    parses the body as JSON, then if the value is an object with a `kind` member it is a record and the record body cap
    (131,072) applies, else it checks the envelope cap (196,608; 65,536 before 2026-11-11) before the structured envelope
    parse. So a non-record over the envelope cap — a body that names a member twice among them, since the strict reader (§2.5) refuses it as a record —
    is `envelope-too-large`, decided before the parse error surfaces (§8.2 step 1; `crates/ac-relay/src/policy.rs:182`-
    `199`).
92. A record publish's checks run in this order: §7.5 (`record.verify`), then the rotation check (`bad-rotation`, 422),
    then the new-signer and sender-domain limits, then `stale-record` (409, the stored record not older). The stale
    check and the rotation check read different stored records (the signer's own, and `rotated_from`'s), so both can
    fire on one record; when they do, the relay answers `bad-rotation`, not `stale-record`. The new-signer and
    sender-domain limits at that step are optional rate limits (`--record-signers-per-day`, `--domain-publishes-per-day`);
    a relay without them has nothing there and the step is a no-op — the load-bearing order is §7.5, then the rotation
    check, then stale (§8.2; `crates/ac-relay/src/policy.rs:401`-`439`).
93. The subscribe auth frame (§8.5 step 2) is checked in order: the frame is JSON; it has exactly `t, mailbox, signer,
    auth, cursor, sig`; `t` is `auth`; `mailbox` and `signer` are addresses, `cursor` null or a canonical integer, `sig`
    64-byte hex; the `auth` member is a JSON array; the signature verifies over the subscribe preimage; then chain shape
    and chain rules 1 to 9 at the challenge's `ts` (each its own code); then the root equals the mailbox
    (`not-authorized`); then the kept revoked list (`revoked`). An `auth` member that is not an array is the frame's
    shape error, `bad-auth`, checked before the signature and the chain, never a chain code (clarifies item 26;
    `crates/ac-relay/src/auth.rs:173`-`213`).
94. A fetch (`GET /v0/fetch`) whose `AC-Auth` chain fails any chain rule is `not-authorized` (403); the failing rule's
    own code is logged (event `fetch-chain-refused`), not returned. An `AC-Auth` header that is not base64url of a JSON
    array is `bad-auth` (401) (clarifies item 25; §8.3; `crates/ac-relay/src/auth.rs:126`, `:132`-`135`, `:83`-`87`).
95. The fetch revoked-list read turns on whether a chain is present, not on whether the signer is a party: an empty
    `AC-Auth` (a bare `to`/`from` party) reads no revoked list; a non-empty chain reads the kept list for the chain's
    root and checks every hop, even when the signer is itself a party. The fetch party check — the chain's root must be a
    `to`/`from` party of the envelope (or the principal) — runs before this read, so a chain whose root is not a party
    is `not-authorized` and the kept list is never reached (§8.3; `crates/ac-relay/src/auth.rs:103`-`109`, `:142`-`149`).
96. When a recipient's accept-from admits the chain's root by an address entry (or `"*"`) and also lists domain roots,
    the address entry decides that recipient: if the kept revoked list names a hop key the recipient is `revoked` and
    the domain entries are not tried. Domains are read only when no address or `"*"` entry admits the root; `"*"` reads
    no revoked list (§8.2 step 7; `crates/ac-relay/src/policy.rs:226`-`234`, `:251`-`265`).
97. The 32-frame unacked window (§8.5 step 4) is this connection's: the room to push is `max_unacked` (32) minus the
    frames this connection has sent and not had acked, counted from the cursor it resumed after, never from the stored
    ack (clarifies item 29; `crates/ac-relay/src/ws.rs:309`, `:228`, `:200`).
98. The expiry boundary second is not uniform, by design. A stored envelope and a mailbox row are delivered while
    `now < expires_at` and swept at `now >= expires_at` (exclusive): the boundary second is neither delivered nor kept.
    A record and a tombstone are kept while `now <= expires_at` and `now <= until` (inclusive), matching §7.5's
    `now <= iat + ttl`, and swept the next second; a pending row is retried while `until > now` (exclusive). A builder
    matches each operator, not one rule: a single inclusive rule delivers an envelope or mailbox row one second past the
    reference. A mailbox row's `expires_at` is set at publish to `received_at` + min(the relay's `--ttl`, the
    recipient's accept-from `ttl`); a stored envelope's is the greatest `expires_at` of its mailbox and pending rows
    (else `received_at`), so the envelope outlives its rows and is swept once past it (§8.7, §8.2 step 9;
    `crates/ac-relay/src/policy.rs:269`, `crates/ac-relay/src/store/sqlite.rs:320`, `:360`, `:381`, `:436`, `:453`,
    `:439`, `:437`).
99. An HTTP path the relay does not serve is `not-found` (404, `{"error": "not-found"}`). A wrong method on a path it
    does serve is 405 with an `Allow` header naming that path's methods, as RFC 9110 §15.5.6 requires, and no error-code
    body (the relay's only response outside Appendix A). A HEAD on a path the relay serves with GET is served by the GET
    handler, headers only, not a wrong method (RFC 9110 §9.3.2). A `GET /v0/subscribe` with no WebSocket upgrade is
    `bad-shape` (400), item 100. The reference takes HEAD and the 405's `Allow` from its HTTP framework, not from relay
    code (§8.1; `crates/ac-relay/src/http.rs:45`-`59`, `:213`-`215`; `crates/ac-relay/tests/http_publish.rs:202`-`208`).
100. A `/v0/subscribe` request that is not a WebSocket upgrade — wrong method, a missing or bad upgrade header, or an
     unsupported `Sec-WebSocket-Version` alike — is `bad-shape` (400); the reference sends no 426 and no
     `Sec-WebSocket-Version` header. After the upgrade, an RFC 6455 violation or a frame over the 262,144-byte cap ends
     the connection with the WebSocket library's own protocol close (1002, 1007 or 1009) and no application error frame
     first; the relay fixes only that there is no error frame before the close, not the close code (clarifies item 27;
     §8.5; `crates/ac-relay/src/http.rs:185`-`189`, `:200`; `crates/ac-relay/src/ws.rs:92`).
101. A subscribe ack frame has exactly `t` and `cursor`; an ack with any other member, or missing one, is not an ack —
     a protocol break, closed `bad-shape` / 4002 — as is an ack `cursor` past the last frame sent (clarifies item 27;
     §8.5 step 4; `crates/ac-relay/src/ws.rs:64`-`69`, `:356`-`378`).
102. A restart keeps everything in the store — envelopes, mailbox rows, cursors, acks, records, tombstones, pending
     rows, kept revoked lists and domain pins — and loses only in-memory state: the fixed-window rate counters (§10),
     the change-detector that re-reads a kept revoked list, the pairing nameplates and the event channel. None of the
     lost state can make a resumed client's cursor go back or skip mail (clarifies item 29; §8.2 step 9, §8.5 step 5,
     §8.7; `crates/ac-relay/src/store/sqlite.rs:28`-`86`; `crates/ac-relay/src/config.rs:110`). A restore of the store
     from an older copy (a Litestream stream or a Fly snapshot) is not a restart: it replaces the store with the copy,
     so a mailbox's `cursors.next` returns to the copy's value and the relay re-issues cursor numbers it had already
     issued, raising no alarm (it clamps a resuming client to its own last cursor, `crates/ac-relay/src/ws.rs:223`-`231`).
     Cursor monotonicity therefore holds across a sweep (item 29) and a restart, never across a restore: the mail
     reaching a mailbox after the copy's time collides on `(relay, mailbox, cursor)` with rows the edge already took, and
     a conforming edge survives this by id, not cursor (§9 item 2, item 3; traced from code, no run yet). The reference relay detects a restore on its own — it keeps an empty marker file beside the database
     (`<db>.volume`) and checks it for existence; a database found with its marker absent has reached a new volume and
     is treated as a restore — and on that boot alone raises every mailbox's `cursors.next` by 2^20, past any such gap,
     keeping cursors effectively monotonic across a restore; there is no operator flag, since a fresh-volume restore
     starts with no one present to set one, no schema change is made, and a rollback still opens the file
     (2026-10-31, unrun; corrected 2026-11-01, from a wording that had the
     relay compare the database's `application_id` against the marker). A snapshot that carries both the database and
     its marker reads as a restart, so only a database-only restore onto a fresh volume is detected. That guard is
     defence-in-depth and efficiency, not the correctness guarantee, which is the edge's.
103. Domain-root resolution (§8.8) is not optional in the reference: it always resolves and has no mode that turns it
     off. A relay that does not resolve a recipient's domain root MUST fail closed as a relay whose resolution fails —
     `resolve-failed` (503) with `Retry-After: 60`, so a sender retries to its seven-day horizon — and never admits a
     domain root it did not resolve and pin. This newly allows a relay that serves only address and `"*"` roots; the
     reference has no such mode and §8.8 did not mark domain roots optional (§7.4, §8.8; `crates/ac-relay/src/policy.rs:
     300`-`311`; `crates/ac-relay/src/resolver.rs:51`, `:53`).
104. The reference relay's command line, beyond the flags §8.1 names, accepts `--rate-per-ip` (default 600),
     `--record-signers-per-day` (100), `--domain-publishes-per-day` (10,000; `0` off), `--blocklist <file>`,
     `--abuse-contact <uri>` (served at `GET /v0/abuse`) and `--exit-on-stdin-eof`, all of which the shared-relay e2e
     runner passes; a harness that starts any relay with them needs a relay that takes them. The relay prints exactly
     one stdout line, `AC_RELAY_URL=<url>` (the `url` is the bound address or `--advertise`), when the listener is
     bound, every other line going to stderr as JSON. These six flags and the stdout contract are documented here
     because no §8 text named them; they are not newly required of every relay. The conformance run (2026-10-31) surfaced
     seven more the shared-relay runner passes that §8 names only as values or not at all — `--sweep-interval`,
     `--rate-per-from`, `--rate-per-root`, `--ping-interval`, `--idle-timeout`, `--header-timeout` and `--body-timeout` —
     so a harness that starts any relay needs one that takes all thirteen (clarifies item 30; §8.1;
     `crates/ac-relay/src/main.rs:62`-`200`, `:436`-`440`). Added 2026-11-01: `--fetch-per-ip` (default 6,000) and `--bytes-per-ip-per-day` (default 100,000,000; `0` off),
     the per-address fetch-rate window of §8.3 and §8.4 and the per-address daily stored-envelope-byte quota of §8.2
     step 8. Added the same day: `--fetch-global-per-minute` (default 30,000; `0`
     off), a fixed 60-second window whatever `--rate-window` says, charged before the signature verify; an address over
     its own `--fetch-per-ip` window is refused first and spends none of the ceiling, and a ceiling refusal charges the
     address nothing (log limit `fetch-global`). These bring the set a harness must accept to sixteen.
105. Smaller relay choices the text did not settle. `GET /v0/health` is 200 with a JSON object `{ok, version, now,
     url}`; `version` is the relay's build version (the reference's is `0.0.0`) and no client reads it, so its value is
     unconstrained; `url` is the announced URL — §8.1's `--advertise` rule (the value with any port it names kept, else the listening port
     for `http`), not the raw flag string — and is the only member a client reads. A duplicate publish
     answers `"delivered": 0`. A record fetch for a malformed address is `bad-address` (400), not `not-found`. A record
     past its validity but not yet swept is still served (200) at fetch and still refuses an older publish as
     `stale-record`; it is `not-found` only once the sweep removes it. A subscribe to a mailbox with no accept-from
     record at this relay is accepted and reads nothing (accept-from gates publishing, not subscribing). A handshake
     that sends no auth frame is closed 4003 with no error frame (§8.1, §8.5, §8.6; `crates/ac-relay/src/http.rs:168`-
     `172`; `crates/ac-relay/src/auth.rs:158`-`163`; `crates/ac-relay/src/ws.rs:158`-`168`).

The conformance run of 2026-10-31 (the reference e2e suite against the clean-room Go relay) settled three more.
106. The WebSocket handshake follows RFC 6455 (§8.5). A relay MAY apply its handshake rules strictly — RFC 6455 §4.2.1's
     `Sec-WebSocket-Key` of 16 bytes of base64 among them — and refuse a bad handshake with 400; the reference is
     lenient and accepts a `Sec-WebSocket-Key` that is not 16 bytes, which a conformance test client must not rely on.
     The spec requires the handshake, not the reference's leniency (§8.5; RFC 6455 §4.2.1; the suite's raw WebSocket
     client is fixed separately).
107. The relay's log is the reference's operational format, not protocol. §8.9 item 4 fixes only the line kinds and the
     `ip` field; the JSON fields a reference relay emits — `event` (`subscribe`, `subscribe-closed`, `subscribe-refused`,
     `publish`, `publish-record`, among others), `signer`, `mailbox`, `reason`, `code`, `timestamp` — are the
     reference's, and a scenario that reads them (22b, 40 and 42 match the `subscribe-closed` line with `reason`
     `hop-expired` or `revoked`) is reference-specific, not a protocol check. The `sweep` event (with a `mailbox` count) is
     the reference's too: scenario 51's "past the relay TTL" and "past B's accept-from ttl" tests wait on it
     (`e.event === 'sweep' && e.mailbox > 0`), so a relay that sweeps on time but logs no such line times them out —
     reference oracles, not protocol checks. No operator log profile is defined at v0; partners do not need one here
     (§8.9; `crates/ac-relay`; `packages/e2e/test/scenarios/51-offline-lapse.test.ts`).
108. The store is the reference's. No section requires a store format; `--db` names a SQLite file in the reference
     (`cut/docs/partner-install.md`), and a scenario that opens it as SQLite (48) is reference-specific. A relay MAY use
     any store; the protocol constrains the wire, never the store (§8.1; `crates/ac-relay/src/store/sqlite.rs`).

The re-run of 2026-10-31 settled one more.
109. The WebSocket close reason strings are the reference's, not protocol. §8.5 item 7 and item 105 fix the close codes
     (4001, 4002, 4003, 1013, and the library's 1002, 1007, 1009); the human-readable reasons a reference relay sends
     with them (`"no auth"`, `"idle"`) are operational text a client does not key off, and a scenario that asserts them
     (H7a, H8) is reference-specific, like items 107 and 108 (§8.5; `crates/ac-relay/src/ws.rs`).

A found defect on the two-relay install, 2026-10-31 (read from code, unrun), settled one more.
110. Publishing a record to the relays an identity lists is offer-to-all, keep-until-each-holds, not all-or-nothing. An
     edge offers each record (address, accept-from, key) to every listed relay and keeps offering until each holds it:
     the keep-alive re-signs and republishes the address and accept-from records at every listed relay each run, and
     (added 2026-10-31) offers the current epoch's key record there too, the same bytes, a relay that already holds it
     answering `stale-record`, which counts as held (§7.2, §9 item 4). The keeper offers the key record only to a relay
     that does not read back as already holding it, because a `stale-record` publish still spends the address's publish
     allowance (§8.2 step 3a): re-offering on every run to a relay that already holds it rate-limited 344 renewals in
     one measured run, a cost that multiplies with many identities on one address; a
     `stale-record` answer to a race the read-back did not catch still counts as held (corrected 2026-11-01). Before this the keepers carried only the address
     and accept-from, and a key record went out only with a new epoch (up to 11 hours), so a relay that missed a
     rotation, or a listed relay down during a fresh install, served the old key or none and a sender reading only that
     relay could not seal. A pairing succeeds once
     the rendezvous relay that holds the invitation (§8.10) and at least one of the identity's listed relays hold its
     records; a demand key rotation (`ac keys rotate`) succeeds once at least one listed relay holds the new key and
     address records; in both the edge prints the relays that did not take them, and keep carries the rest. Before this
     (2026-10-31) a single down relay aborted a pairing or a rotation outright — an availability coupling with no safety
     gain: a relay that lacks an accept-from fails safe (`not-hosted`, §8.2) and a relay still serving the pre-rotation
     key record is delayed adoption of a forward-countersigned key (§7.3), never a downgrade. The one carve-out is a
     record that carries a `revoked` list: because a relay honours only the revoked list it has stored (§8.7, §8.5 item
     8), a revoked key is still accepted at a listed relay that has not taken the newer record, so
     the edge reports such a revocation as incomplete — a security-relevant gap naming each lagging relay, not a benign
     "not yet" — until every listed relay holds it (added 2026-10-31; traced from code, no run yet).

A decision of 2026-11-01 (telemetry throughout bag, behind a consent switch) added one.
111. Telemetry is outside the protocol. It adds no wire format, no envelope or record member, no header and no API
     call, and no conformance point turns on it: a relay or client that emits none is fully conformant. A client's
     optional report (opt-in, one a day to `telemetry.bag.dev`) and a relay's optional operational metrics (aggregate
     counts on a private listener with its own flag, scraped over the private network; `/metrics` on the public name is
     404 `not-found`, the item 105 fallback) are the reference's operational signals, like the relay's log (item 107),
     not protocol. The relay's metrics carry route, status, closed-set codes, limit names, reasons, counts, gauges,
     durations, the build revision (the `ac_relay_build_info{rev}` info metric) and the region (Fly's scrape label),
     and a count-only distinct-networks gauge exporting only a bare count (its set under a per-process, in-memory salt, dropped daily; §10), and
     never an address, id, root, domain, nameplate, IP or prefix as a
     label — the same addresses-never rule as the log (§8.9 item 4) — so they teach a reader nothing a relay does not
     already hold, and §10 "Metadata" is unchanged. A client report carries only a closed schema — a schema version,
     the UTC date (never a time), a random install id made at opt-in, one per machine and shared by every identity, the build as a
     published cut commit else `other`, OS family, arch and a supported `node`,
     host kind, the relays used as power-of-two buckets, and daily counts — power-of-two buckets over closed sets (CLI
     command verbs with exit and code, MCP tool/ok/code and sessions by host kind, the a2a surface and its bridge, audit
     triples, pairing outcome, relay error codes, durations by command and tool) — and never a
     message body, type or thread, a key or seed, a pairing digit, word, nameplate or invite string, an address or
     handle raw or hashed, a petname or session name, an IP, a file path, a hostname, user or machine id, a relay URL
     beyond the two public names, or a free-text error. Telemetry feeds no protocol or security decision. The schema,
     the opt-in consent model, the endpoint, the install id and the retention are defined outside this spec; the new observers are `docs/audit/threat-model.md` R25 and R26 (§8.9; §10;
     `telemetry.bag.dev`, the Grafana Cloud EU log copy).

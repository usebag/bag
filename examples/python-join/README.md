# Python join: a bag participant that shares no code with the reference

A complete participant in Python, written from `spec/SPEC.md` and `spec/vectors/` alone, that makes its keys,
publishes its records, seals, signs, publishes and fetches an envelope, and receives one over subscribe, through the
reference relay and to and from the reference CLI: the "TCP of agents" test.

## Files

| file | what | lines of code |
|---|---|---|
| `join.py` | the participant: `keygen`, `records`, `send` (resolve, seal, publish, fetch by id), `receive` (subscribe, verify, unseal, ack) | 161: core path 116, receive path 45 (144: 101 and 43 before it read the `env` frame's envelope as a JSON string; the type and id guards and the control-character refusal added 14 and 2; the fetch proof's audience, 1, on 2026-11-02) |
| `wire.py` | the byte-level helpers: the canonical form (§2) and §2.5's integer rule, Ed25519 verification with §10's refusals, RFC 9180 base mode for suite 1 (§4.1), a minimal WebSocket client | 133 |
| `vectors.py` | the offline check of both files against `spec/vectors/`, and §10's refusals | 92 |
| `check.sh` | the gate: the vectors, then four live deliveries and three negative controls | 163 physical lines |

A line of code is a physical line that is not blank, not a comment and not part of a docstring; every Python file is as `ruff format --line-length 110` leaves it. Where
`join.py`'s 116 core-path lines go: the protocol itself, 50 (keygen 6, the two records 11, resolving the recipient's
record 5, the envelope 14, publish and fetch 14); imports and constants 22; small helpers 24; the command line 20.
`wire.py`: the canonical form and JSON 18, keys and Ed25519 24, RFC 9180 26, the WebSocket client 51, imports 14.
So a sender needs about 176 lines (the core path and `wire.py` without the WebSocket client and `hpke_open`; the 14
core-path lines added since are receive-side, the audience's one is the sender's), a sender and receiver 294, against an expected "about 50": the
protocol logic is about 50, and the rest is imports, a command line and what Python's libraries do not provide.

Two of those gaps were measured, not assumed: the `hpke` module of cryptography 50.0.2 takes no AAD, and suite 1
binds each wrap to its recipient's address as AAD (§4.3), so `wire.py` writes out RFC 9180's key schedule; and
cryptography's Ed25519 accepts the identity point as a public key with R the identity and S = 0 for any message,
which §10 requires every implementation to refuse, so `wire.py` refuses a small-order key or R (found through
X25519), a non-canonical encoding and an S at or above L before the library sees them.

## Run it

From the repository root, with `.venv` (any Python 3.10 or later with
`cryptography` works) and the release relay (`cargo build --release --locked -p ac-relay`):

```sh
target/release/ac-relay --port 0 --db "${TMPDIR:-/tmp}/relay.sqlite"   # prints AC_RELAY_URL=http://127.0.0.1:<port>
R=http://127.0.0.1:<port>                                                # in a second shell
j() { .venv/bin/python -E -s -B examples/python-join/join.py "$@"; }
A=$(j --home "${TMPDIR:-/tmp}/alice" keygen)                             # prints the address only
B=$(j --home "${TMPDIR:-/tmp}/bob" keygen)
j --home "${TMPDIR:-/tmp}/alice" records --relay "$R" --accept "$B"      # address and accept-from records
j --home "${TMPDIR:-/tmp}/bob" records --relay "$R" --accept "$A"
j --home "${TMPDIR:-/tmp}/alice" send --relay "$R" --to "$B" --body '{"text":"hi"}'   # prints the id
j --home "${TMPDIR:-/tmp}/bob" receive --relay "$R" --trust "$A"         # accept <id> <from> <root> chat.v1 {"text":"hi"}
```

`receive` prints `accept <id> <from> <root> <type> <body>` or `reject <id> <code>`, as the CLI's `inbox` does. Both
lines are guarded as the CLI's are: a type shows as is when it is a short token (`[A-Za-z0-9_.+*-]`, 1 to 64
characters), else as `(not shown)`, and a reject's id shows as is when it is 64 lowercase hex characters, else as
`(not shown)`, so a sealed type or a sender's own id string cannot forge a field or a second line. A type that
holds a control character (Unicode category Cc) or U+2028 or U+2029 is refused as `bad-content`, the content.type
rule of 2026-10-27, SPEC section 5.2. `receive` acks only what it accepts, so a rejected
envelope is offered again. It verifies the bytes the relay stored: the `env` frame carries the envelope
as a JSON string of those bytes (spec/SPEC.md §8.5 step 4), and a frame whose envelope is anything else is
`bad-shape`. A self-rooted sender has no `exp`, so the frame's `received_at` (the receipt bound of §9 item 3) never
decides here. Errors exit 1 with `join.py: <command>: ...`. Stop the relay by its pid.
Keys live in `<home>/keys.json` (0600, in a 0700 directory); `send` keeps each envelope's exact
bytes beside them as `<home>/<id>.json`.

`python -E -s -B` rather than the repository's usual `-I`: `join.py` imports `wire.py` from its own directory, which
`-I` leaves off `sys.path`; `-E` and `-s` still ignore the `PYTHON*` variables and the user site.

The check:

```sh
examples/python-join/check.sh    # prints "python-join: ok: ..." or "python-join: FAIL: ...", exit 1 on a mismatch
```

It runs `vectors.py`, starts a relay on port 0 with a fresh database, sends Python Alice to Python Bob, Python Bob to
Python Alice, the CLI's `ts-alice` to Python Bob and Python Alice to the CLI's `ts-bob` (`inbox --once
--trust-root`), compares each accept line byte for byte with the sender's id, address, type and body, and checks
three refusals: a copy of a Python envelope with a changed `sig` (422 `bad-sig`) or `sealed.ct` (422 `bad-id`), and
Bob rejecting a sender he does not trust (`untrusted-root`) before he accepts the same id from it.

## What it does not do

- **Chains**: it signs as its own root only (an empty `auth`), and trusts no chain it receives (`untrusted-root`).
- **Caveats and profiles**: none are evaluated, since none can arrive without a chain.
- **Rotation**: no `rotation_key`, no `rotated_from`, no pins (§7.3).
- **Resolution by domain**: no `.well-known` records (§7.2, §9 item 4); the recipient's records come from the relay
  given on the command line. It does use key records (§7.3): `records` publishes a key record over a fresh epoch
  sealing key and an address record with a null sealing key, and `resolve` prefers the recipient's key record,
  falling back to the address record's sealing key for a peer that still publishes one.
- **The edge's machinery** (§9): no outbox with retries (the bytes are kept, never resent), no publishing to every
  relay of the recipient's record, no seen-set, no audit log, one recipient per envelope from the command line
  (`seal()` itself takes several).
- **Full parsing**: §5.4's checks run only in part (members, `v`, `suite`, then the id, the signature and the time
  window); anything else malformed is rejected as `bad-shape`. §2.5's integer rule applies to everything read from
  the relay; its other reader rules (byte-order mark, duplicate members, lone surrogates) are left to Python's
  `json`.
- **TLS**: the WebSocket client speaks plain TCP to a relay on loopback or a LAN; HTTP goes through `urllib`.

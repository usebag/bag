# spec/adversarial: the differential cases

*This file is the contract every reader of these cases follows: the TypeScript check
(`packages/core/test/adversarial/differential.test.ts`), the Rust reader (`crates/ac-core/tests/adversarial_differential.rs`)
and the Python checker (`scripts/verify_adversarial.py`). It also covers the `round2-*.json` files, the
`rotation-claim` kind and "Round 2" below.*

Every `*.json` file here except `rng-expected.json` is written by `packages/core/scripts/gen-adversarial.ts` from the one
seed 20261025. Do not edit them by hand: `npm run adversarial:check -w packages/core` regenerates them into a temporary
directory and fails unless each is byte-identical (line G2).

## The files

| file | lines | kinds |
|---|---|---|
| `canonical-fuzz.json` | P1 | `canonical` |
| `envelope-mutations.json` | F1, F2, F8, F9, D6 (envelopes), P2 (`ts`, `suite`, `v`, hop `exp`), R2, P3 | `parse`, `outer`, `json` |
| `chain-mutations.json` | F3, F4, F5, F6, F7 (hops, and the envelope's `sig` and `from`) | `chain`, `outer` |
| `record-mutations.json` | D1, D3, D4, D5 (form), D6 (records), P2 (`iat`, `ttl`, `exp`), F7(b) (`key`) | `record`, `rotation` |
| `open-cases.json` | P4 (a) to (e), F2 and F8 (the open half), D6 (a sealed content with two `type`) | `open` |
| `round2-domains.json` | W7 | `record` |
| `round2-records.json` | T1, T2, T3 | `rotation-claim`, `rotation`, `record` |
| `round2-keys.json` | T4 | `record`, `chain`, `outer` |
| `round2-duplicates.json` | T5, T6 | `parse`, `outer`, `record`, `rotation-claim`, `json`, `open` |
| `round2-numbers.json` | T7 | `open`, `json`, `parse`, `record` |
| `rng-expected.json` | G2 | none: see below |

F1 sweeps over 1.8 million mutations (every byte of 200 envelopes flipped at bit position mod 8, and every hex character
of their hex fields replaced by the next hex digit). The file keeps, for each (pass, region of the envelope, verdict),
the first three mutations met in order of envelope size, smallest first, and every mutation that verified `ok` (none
did at generation); the generator's summary prints the verdict counts of the whole sweep. Each kept case carries its
full bytes, which is why the file holds a sample: the whole sweep would be some 15 GB of hex.

## A case file

```
{
  "description": "...",
  "generated_by": "packages/core/scripts/gen-adversarial.ts",
  "seed": 20261025,
  "test_data": "...",
  "cases": [ case, ... ]
}
```

Members appear in this order. `test_data` says, as the vectors' field does, that every seed and key in the file is
test data generated from the seed and protects nothing.

## A case

```
{
  "name": "<line>/<n>/<mutation>",
  "line": "F1",
  "kind": "parse" | "outer" | "chain" | "record" | "rotation" | "rotation-claim" | "canonical" | "json" | "open",
  "input": { ... },
  "expected": "ok" | "<code>",
  "allowed": { "rs": { "verdict": "<code>", "reason": "<spec sentence>" }, "py": { ... } }
}
```

- `name` is unique in its file: the line, a running number within that line, and a short mutation label
  (`F1/1234/flip-byte-87`).
- `expected` is the verdict of the TypeScript core at generation time: `"ok"` or a code of `spec/SPEC.md` Appendix A.
  It records what the code does, not what the spec requires; the TypeScript tests under
  `packages/core/test/adversarial/` assert the requirement.
- `allowed` is optional, and per reader (`rs`, `py`). A reader passes a case when its verdict equals `expected`, or
  equals its own `allowed.<reader>.verdict`. Any other verdict is an unexpected divergence and turns that reader red.
  `reason` quotes the spec text that sanctions the difference. Since §2.5 changed (2026-10-25: every reader
  refuses a number not written as a plain decimal integer), no case carries `allowed`; before it, the generator wrote
  `allowed` for the P2 readings `1.0`, `1e0`, `1E0` and `-0`.
- A reader ignores members it does not know.

## Inputs, and the verdict each kind asks for

All integers are JSON integers that fit 2^53 - 1. Hex is lowercase. `bytes_hex` carries raw bytes, so invalid UTF-8,
a byte-order mark, duplicate member names and non-integer number spellings are representable.

| kind | `input` | the verdict |
|---|---|---|
| `json` | `bytes_hex` | the JSON reader alone (§2.5): `"ok"` when the bytes are one UTF-8 JSON value with no BOM and no escaped lone surrogate, else `bad-json`. No shape check. |
| `parse` | `bytes_hex` | envelope parsing, §5.4 steps 1 to 13 in order. No signature, no clock. |
| `outer` | `bytes_hex`, `now`, `ttl`, `skew` | the relay's in-core order (§8.2 steps 2 to 6): §5.4; then §5.5 step 1 (recipients), step 2 (`bad-id`), step 3 (`bad-sig`); then chain rules 1 to 9 of §6.2 for `from` at the envelope's `ts`; then §5.5 step 4 (`stale-ts`, `future-ts`) against `now`, `ttl` and `skew`. The first failure is the verdict. |
| `chain` | `auth` (a JSON list of hop objects, as on the wire), `from`, `ts` | §6.2 rules 1 to 9 in order, for the sender `from` at `ts`. |
| `record` | `bytes_hex`, `now`, `skew` | the JSON reader (`bad-json`), then §7.5 in order: form and caps (§7.1 to §7.4: `bad-record`, `too-many-relays`, `too-many-revoked`), `bad-record-sig`, `future-iat`, `record-expired`. |
| `rotation` | `prev_bytes_hex`, `next_bytes_hex` | each read by the JSON reader (`bad-json`), then §7.3: both records' forms (`bad-record`; both must be address records), then `next.rotated_from == prev.key` and a `rotation_sig` that verifies over `next`'s preimage under `prev.key` or `prev.rotation_key` (`bad-rotation`). The records' own `sig` is not checked here; that is a `record` case. |
| `rotation-claim` | `bytes_hex`, `now`, `skew` | a record judged by a reader that holds no record of its `rotated_from` (§7.3): the `record` kind's verdict first (the JSON reader, then §7.5), then, for an address record that names `rotated_from`, a `rotation_sig` that verifies over the record's preimage under `rotated_from` itself (`bad-rotation`; none at all is `bad-rotation` too). A record that names no `rotated_from` claims nothing: `"ok"`. A record of another kind is `bad-record`. (`verifyRotationClaim`, `records::verify_rotation_claim`, `verify_rotation_claim`.) |
| `canonical` | `value` (any JSON value), or `utf16_hex` (UTF-16BE code units of a string that holds a lone surrogate, as `spec/vectors/canonical.json` does), or `sparse_list` (see below); and for a valid value `canonical` (the canonical string) and `sha256` (hex of the SHA-256 of its UTF-8) | `"ok"` when the value has a canonical form (§2.1) and the reader writes exactly `canonical`, whose SHA-256 is `sha256`; else `bad-canonical`. A reader that writes other bytes for a valid value fails the case. |
| `open` | `v` (1), `to`, `from`, `sealed` (the envelope's members as on the wire), `address` (the recipient's address), `seal_seed` (hex of the recipient's 32-byte X25519 private key: test data) | §4.4: the wrap whose `to` is `address` (`not-recipient`), opened with `seal_seed`, info `ac/seal/1` and `address` as AAD; then `sealed.ct` with the content key, `sealed.nonce` and utf8(canonical([v, to, from])) as AAD; any failure is `open-failed`; then the plaintext read as §5.2 (`bad-content`, `bad-thread`, `too-many-prev`). The Rust core has no HPKE (§1), so the Rust reader skips `open` cases and says so. |

`sparse_list` is `{"length": n, "items": [[index, value], ...]}`: a list of length `n` with holes at every index not
listed. Only ECMAScript can hold such a list; it exists to pin that the TypeScript writer refuses a hole (§2.1, "a list
of canonical values": a hole is not a value). Its `expected` is always `bad-canonical`, and a reader that cannot
represent holes reports `bad-canonical` for it without building it.

## Round 2

The `round2-*.json` files come from the same generator and the same seed, drawn from the stream after the five earlier
files' last draw, so those five files regenerate byte for byte (G2). Two things differ from the five:

- **`expected` is the pre-registered verdict**, the code written for the case's line before any of these cases
  existed (Appendix A), with an accepted positive control (`control-` in the label) beside each
  refusal. It is not the TypeScript core's verdict: the generator computes that beside it and, where the
  two differ, still writes the pre-registered one and names the case in its summary
  (`gen-adversarial: round 2: N case(s) whose pre-registered verdict is not the TypeScript core's`), so the
  TypeScript reader fails on it as any other reader would. No round-2 case carries `allowed`.
- **The kind `rotation-claim`** (above) is new. The TypeScript, Rust and Python readers all judge it. The Rust reader
  still skips `open` cases (no HPKE in Rust), so each `open` case of `round2-duplicates.json` has a `json` twin, the
  same plaintext through the JSON reader alone (label `...-plaintext`), which all three readers judge: `bad-json`
  where the open case is `bad-content`, else `"ok"`.

## rng-expected.json

`{"seeds": {"1": [hex, hex, hex], "2": [...], "20261025": [...]}}`: the first three 32-byte draws of
`xorshiftRng(seed)` (`packages/core/test/support/rng.ts`: splitmix64 seeding, xorshift128+ with shifts 23, 18 and 5,
each 64-bit output written little-endian) for seeds 1, 2 and 20261025. A twin generator in another language reproduces
these 96 bytes per seed (line G2). It is written once by hand from the TypeScript generator and checked by
`packages/core/test/adversarial/differential.test.ts`.

## The checkers

- TypeScript: `npm run adversarial:check -w packages/core` (byte-identical regeneration), and the Vitest files under
  `packages/core/test/adversarial/`.
- Python: `.venv/bin/python -I scripts/verify_adversarial.py spec/adversarial [--controls]`: exit 0 when every case
  agrees or diverges as allowed, 1 on any unexpected divergence, 2 when a check was skipped. `--controls` plants a
  one-byte change in cases' `expected` verdicts and must report each as caught (line G3). Its `FILES` list names the
  round-2 files too.
- Rust: `cargo test -p ac-core --test adversarial_differential --locked` (it reads every `*.json` here but
  `rng-expected.json`; `v4_a_planted_wrong_verdict_is_caught_in_round_2` plants a wrong verdict in each round-2 kind).

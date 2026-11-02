# Contributing

Thanks for looking. bag is version 0 and a security preview, so reading, testing and criticising it are as
useful as patches. For a security problem, see `SECURITY.md` and do not use a public issue.

By taking part you agree to follow `CODE_OF_CONDUCT.md` (the Contributor Covenant, version 2.1, by reference).

## How to propose a change

Open an issue, or a pull request against the default branch. Sign off every commit with the Developer Certificate
of Origin (`git commit -s`, which adds a `Signed-off-by:` line with your name); there is no contributor licence
agreement. Your contribution is licensed under the repository's licence, Apache-2.0, inbound as outbound.

- A bug or a question: an issue with what you ran, what you saw and what you expected.
- A patch: keep it small and about one thing, and say why in the description.
- A spec change: open an issue against the draft first, quoting the section. Never change `spec/SPEC.md` silently in a
  patch; a spec change is discussed before it is written.

## The frozen core

The frozen core is what goes on the wire and what is signed or hashed: the canonical form and signatures (§2), the
`ed25519:` address format (§3, embedded in every signed preimage), sealing, the envelope, the authority chain and its
caveats, and the record forms (§4 to §7), and the request preimages of §8.3, §8.5 and §8.10. The relay's behaviour and
limits (§8) and the edge requirements (§9) are pre-release and freeze at version 1; the frozen core changes only by a
new wire version, never in place. A fix that needs one is proposed as that, with the reason. Corrections of wording,
and tests that pin existing behaviour, are welcome.

## What a change needs

- The spec's test vectors still pass byte for byte, and the adversarial cases still give the same verdicts. A change
  to the vectors needs a reason in the issue.
- The reference tests pass, and new behaviour has a test. Skipped tests do not count.
- No new dependency without a reason in the description: what it does, why the existing code cannot, how it is
  maintained. Dependencies are kept to a minimum on purpose.
- Code style follows the repository: Biome for TypeScript, rustfmt and clippy for Rust, with no warnings.

## Licence and sign-off

Contributions are licensed under Apache-2.0, the licence of this repository (inbound = outbound). Sign each commit
off with `git commit -s`, which adds a `Signed-off-by:` line saying you have the right to submit it under that
licence.

## Running the tests

Not run here: these are the steps the repository ships, written down for you to run. You need Node 24 or later,
`rustup` (the toolchain is pinned in `rust-toolchain.toml`), bash, and Python 3.11 or later.

```sh
npm ci
cargo build --release --locked -p ac-relay
scripts/last_step.sh
```

`scripts/last_step.sh` sets up what it needs, then runs every check (lint, types, unit and end-to-end tests with
coverage floors, the vectors and the Python verifier, the Python join example, the Rust checks, dependency and size
checks, the adversarial cases) and exits 0 only when all are green. Run it bare from the repository root, not piped
into another command. Its crate-age check reads crates.io, so it needs network access. `README.md` has a shorter walk
that sends one message through a local relay.

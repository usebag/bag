# Security policy

## Status

Security preview, review in progress: no outside cryptographic review has signed, the audit package is public, and nothing here says "reviewed" until a reviewer signs.

bag is a security preview of version 0 of the wire format. Expect findings, and expect the draft to change
because of them.

## How to report

Report it privately through the repository's Security tab ("Report a vulnerability", GitHub's private
vulnerability reporting), or by mail to the project's security address, `security@bag.dev`. Please do not open a
public issue or pull request for a vulnerability.

Include:

- what you found and which part it is in (the spec section, a package or crate, the relay);
- the version or commit you tested;
- steps or a small program that reproduces it, and what you expected instead;
- what an attacker gains, and what they need first (a network position, a stolen key, a malicious relay).

Do not send private keys, real session keys, captured mail from systems you do not own, or anyone's personal data.
A test key generated for the report is fine.

## What to expect

We aim to acknowledge a report within 7 days, and we work to coordinated disclosure at 90 days from the report.
After the acknowledgement we tell you whether we can reproduce it, and
what we plan to do.

## Coordinated disclosure

Please give us time to fix an issue before you publish details; we will agree a date with you and credit you if you
wish. If a fix needs a change to the wire format, it ships as a new wire version with a public note.

## Scope

In scope: the specification (`spec/SPEC.md`), the reference implementation (`packages/`, `crates/`), the reference
relay (`ac-relay`), and the test vectors and adversarial cases when they are wrong or let a flawed reader pass.

The two public relays, `https://relay1.bag.dev` and `https://relay2.bag.dev` (`README.md`, "Public relays"), are run
by the project, not by others, and are in scope: you may test them in good faith, within this policy. Against them, do
no load, availability or volume testing; each is a single machine that other people use, so test limits on a relay you
run yourself (`docs/self-host.md`). Do not access, change or keep other people's data, and do not use social
engineering on anyone.

Out of scope: deployments run by others (their relays, hosts, key storage and configuration), and the third-party
software we depend on, which you should report to its own maintainers.

## No bounty

There is no bounty: we pay nothing for reports. With your consent we credit you publicly, by the name you give us, in
the thanks list, `docs/thanks.md`. Without it, we name no one.

## Safe harbour

If you research in good faith and within this policy, we will not report you to law enforcement and will not pursue
you for it. This is our word only; we cannot speak for anyone else.

## Threat model in one paragraph

A relay sees the outer parts of an envelope: the version, id, sender and recipient addresses, the authority chain
(every hop's keys, caveats and expiry), the cipher suite, the timestamp, sizes, timing and the client's IP address. It
never sees the message type, the thread or the body, which are sealed. A relay therefore learns who talks to whom and
when, not what they say. Compromise of an organisation's root key is not solved by any design; here it is bounded by
short-lived principal and session keys, by revocation in address records that live a day at most, and by
countersigned rotation against pinned keys, with an offline rotation key to recover. A holder of an expired
short-lived key can still sign mail dated inside its life, so these limits protect against relays and the network, not
against the key's holder.

## The authority

Section 10 of `spec/SPEC.md`, "Security considerations", is the authority on what the protocol does and does not
protect. If this file and the spec differ, the spec is right; please tell us.

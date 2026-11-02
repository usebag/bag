//! The closed set of error codes (spec/SPEC.md, Appendix A).
//!
//! One vocabulary for every part of the system, in any language: the same strings, in the same order, as
//! `packages/core/src/errors.ts` (`AC_ERROR_CODES`): the core's codes first, then the relay's, then the edge's. A
//! conformance test compares this list with that file. A relay answers `{"error": "<code>"}`; Rust raises the core
//! and relay codes, and carries the edge's so that a tool can read any audit line. The relay also answers two codes of
//! the edge group, `resolve-failed` (503, with `Retry-After: 60`) and `revoked` (403), for a root it admits by domain
//! (spec/SPEC.md §8.8 and Appendix A); they stay in the edge group, so the order holds.
//! (Corrected 2026-10-25: this said that Rust raises only the core and relay codes.)

use std::fmt;

/// The part of the system that raises a code (spec/SPEC.md, Appendix A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Group {
    /// Raised by the core libraries.
    Core,
    /// Answered by a relay.
    Relay,
    /// Written by an edge into its audit lines.
    Edge,
}

/// Defines [`Code`], the list of every variant, the wire strings and the groups in one place, so that they cannot
/// drift apart.
macro_rules! codes {
    ($( $(#[$doc:meta])* $variant:ident => $text:literal ($group:ident), )*) => {
        /// An error code. Closed: every failure in `ac-core` and `ac-relay` is one of these.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Code {
            $( $(#[$doc])* $variant, )*
        }

        impl Code {
            /// Every code, in the order of `AC_ERROR_CODES`.
            pub const ALL: &'static [Code] = &[ $( Code::$variant, )* ];

            /// The code's wire form, for example `"bad-id"`.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Code::$variant => $text, )*
                }
            }

            /// The part of the system that raises it.
            #[must_use]
            pub const fn group(self) -> Group {
                match self {
                    $( Code::$variant => codes!(@group $group), )*
                }
            }
        }
    };
    (@group core) => { Group::Core };
    (@group relay) => { Group::Relay };
    (@group edge) => { Group::Edge };
}

codes! {
    // --- raised by the core libraries (spec/SPEC.md, Appendix A, "core" and "core, edge") ------------------------
    /// A value with no canonical form (§2.1).
    BadCanonical => "bad-canonical" (core),
    /// A byte field that is not lowercase hex of its length.
    BadHex => "bad-hex" (core),
    /// A string that is not an address (§3.2).
    BadAddress => "bad-address" (core),
    /// Key material of the wrong length, or a record signed by a key not its own.
    BadKey => "bad-key" (core),
    /// Not UTF-8 JSON text (§2.5).
    BadJson => "bad-json" (core),
    /// A member missing, extra or of the wrong type (§5.4).
    BadShape => "bad-shape" (core),
    /// `v` is not 1.
    BadVersion => "bad-version" (core),
    /// `suite` is not 1.
    BadSuite => "bad-suite" (core),
    /// An envelope over 65,536 bytes.
    EnvelopeTooLarge => "envelope-too-large" (core),
    /// Over 16 recipients.
    TooManyRecipients => "too-many-recipients" (core),
    /// The id does not recompute.
    BadId => "bad-id" (core),
    /// The outer signature does not verify.
    BadSig => "bad-sig" (core),
    /// `ts` before `now - (ttl + skew)`.
    StaleTs => "stale-ts" (core),
    /// `ts` after `now + skew`.
    FutureTs => "future-ts" (core),
    /// Chain rule 1: over 8 hops.
    TooManyHops => "too-many-hops" (core),
    /// Chain rule 2: a hop that is not well formed.
    BadHop => "bad-hop" (core),
    /// Chain rule 3: over 32 caveats in a hop.
    TooManyCaveats => "too-many-caveats" (core),
    /// Chain rule 4: a caveat over 256 UTF-8 bytes.
    CaveatTooLong => "caveat-too-long" (core),
    /// Chain rule 5: a hop's `sub` is not the next hop's `iss`.
    ChainBroken => "chain-broken" (core),
    /// Chain rule 6: the last hop's `sub` is not the sender.
    ChainNotToSender => "chain-not-to-sender" (core),
    /// Chain rule 7: a hop outlives the hop before it.
    ExpNotMonotone => "exp-not-monotone" (core),
    /// Chain rule 8: a hop expired before the time it is judged at.
    HopExpired => "hop-expired" (core),
    /// Chain rule 9: a hop's signature does not verify under its `iss`.
    BadHopSig => "bad-hop-sig" (core),
    /// A caveat no evaluator knows (§6.3); the edge's, never the relay's.
    UnknownCaveat => "unknown-caveat" (core),
    /// A caveat that does not hold (§6.3); the edge's.
    CaveatFailed => "caveat-failed" (core),
    /// No wrap names this address (§4.4); the edge's.
    NotRecipient => "not-recipient" (core),
    /// A wrap or the content does not open (§4.4); the edge's.
    OpenFailed => "open-failed" (core),
    /// The plaintext is not `{type, thread, body}` (§5.2); the edge's.
    BadContent => "bad-content" (core),
    /// A malformed thread (§5.2); the edge's.
    BadThread => "bad-thread" (core),
    /// Over 64 parents (§5.2); the edge's.
    TooManyPrev => "too-many-prev" (core),
    /// A record that breaks its form (§7).
    BadRecord => "bad-record" (core),
    /// Over 64 relays.
    TooManyRelays => "too-many-relays" (core),
    /// Over 1,024 revoked keys.
    TooManyRevoked => "too-many-revoked" (core),
    /// A record's signature does not verify.
    BadRecordSig => "bad-record-sig" (core),
    /// `iat` after `now + skew`.
    FutureIat => "future-iat" (core),
    /// Past `iat + ttl`, or past `exp`.
    RecordExpired => "record-expired" (core),
    /// Not a valid rotation (§7.3).
    BadRotation => "bad-rotation" (core),
    // --- answered by a relay (§8) --------------------------------------------------------------------------------
    /// A request body over 262,144 bytes.
    BodyTooLarge => "body-too-large" (relay),
    /// No recipient has an accept-from record at this relay.
    NotHosted => "not-hosted" (relay),
    /// The chain's root is not in the recipient's `roots`.
    RootNotAccepted => "root-not-accepted" (relay),
    /// The envelope is over the recipient's `max_bytes`.
    TooLargeForMailbox => "too-large-for-mailbox" (relay),
    /// Over a rate limit.
    RateLimited => "rate-limited" (relay),
    /// A fetch or subscribe proof that is missing, malformed or does not verify.
    BadAuth => "bad-auth" (relay),
    /// A proven signer who may not read this.
    NotAuthorized => "not-authorized" (relay),
    /// No such envelope or record.
    NotFound => "not-found" (relay),
    /// A record not newer than the stored one.
    StaleRecord => "stale-record" (relay),
    /// The relay's own failure (its store, say), answered 500: a failed try that the client repeats (§8.1; added
    /// 2026-10-25). The reference relay sends it without a [`Code`] of its own (`Rejection::code`
    /// is `None`), so no relay path raises this variant.
    Internal => "internal" (relay),
    /// The relay's store is over its bound (`--max-store-bytes`): a publish is refused, a try to repeat once a sweep has
    /// freed space, answered 503 with `Retry-After`; fetch, subscribe and the sweep go on (added 2026-10-29).
    StoreFull => "store-full" (relay),
    /// A `pair/claim` for a nameplate the relay does not hold or that has expired, answered 404 (§8.10; added
    /// 2026-10-30, pairing by a short code); the relay's.
    NoNameplate => "no-nameplate" (relay),
    // --- written by an edge into its audit lines (§9) ------------------------------------------------------------
    /// The chain's root is not trusted (§9); the edge's.
    UntrustedRoot => "untrusted-root" (edge),
    /// The sealed type is not accepted (§9); the edge's.
    TypeNotAccepted => "type-not-accepted" (edge),
    /// A hop's `sub` is in the root's `revoked` list (§9); the edge's.
    Revoked => "revoked" (edge),
    /// A key that differs from the pinned key, without a valid rotation (§9); the edge's.
    PinMismatch => "pin-mismatch" (edge),
    /// An id already seen (§9); the edge's.
    Duplicate => "duplicate" (edge),
    /// A record could not be fetched or did not verify (§9); the edge's.
    ResolveFailed => "resolve-failed" (edge),
    /// The outbox gave up after its tries (§9); the edge's.
    PublishFailed => "publish-failed" (edge),
    /// One try that got no answer from the relay: no connection, or no response (§9 item 1;
    /// added 2026-10-25); the edge's.
    Unreachable => "unreachable" (edge),
    /// A pairing request whose MAC under the short code does not verify (§8.10; added 2026-10-30); the edge's.
    BadCode => "bad-code" (edge),
    /// A pairing request to an invitation a valid request already consumed (§8.10; added 2026-10-30); the edge's.
    Leaked => "leaked" (edge),
    /// Check digits typed at the inviter that do not match its own (§8.10; added 2026-10-30); the edge's, and local.
    DigitsMismatch => "digits-mismatch" (edge),
}

impl Code {
    /// The code whose wire form is `text`, if there is one.
    #[must_use]
    pub fn from_wire(text: &str) -> Option<Code> {
        Code::ALL.iter().copied().find(|c| c.as_str() == text)
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for Code {}

/// The result of every fallible operation in this crate.
pub type Result<T> = std::result::Result<T, Code>;

#[cfg(test)]
mod tests;

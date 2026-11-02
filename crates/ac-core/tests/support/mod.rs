//! Support for the adversarial tests: the seeded twin of the TypeScript test generator, the
//! builders of valid envelopes from seeded keys, the one-byte mutation helpers, and the verdicts each step of the
//! spec gives. Every key here comes from a seed written in a test: test data by construction, never a real key.
#![allow(dead_code, reason = "each test binary uses its own subset of this module")]

use ac_core::chain::{self, Hop};
use ac_core::envelope::{Envelope, Sealed, Wrap};
use ac_core::keys::SigningKey;
use ac_core::{Address, Code, hex};

/// A fixed time, 2027-01-15 08:00 UTC, so no test depends on the clock (the same `NOW` as the unit tests).
pub const NOW: u64 = 1_800_000_000;

/// The seed every adversarial generator starts from.
pub const STUDY_SEED: u64 = 20_261_025;

const MIX: u64 = 0x9e37_79b9_7f4a_7c15;
const MUL_1: u64 = 0xbf58_476d_1ce4_e5b9;
const MUL_2: u64 = 0x94d0_49bb_1331_11eb;

/// splitmix64: the next state and its output, as `packages/core/test/support/rng.ts` computes them.
fn splitmix64(state: u64) -> (u64, u64) {
    let next = state.wrapping_add(MIX);
    let mut z = next;
    z = (z ^ (z >> 30)).wrapping_mul(MUL_1);
    z = (z ^ (z >> 27)).wrapping_mul(MUL_2);
    (next, z ^ (z >> 31))
}

/// xorshift128+ (Vigna; shifts 23, 18 and 5), seeded through splitmix64: the twin of the TypeScript
/// `xorshiftRng`, bit for bit (line G2).
#[derive(Debug, Clone)]
pub struct Rng {
    s0: u64,
    s1: u64,
}

impl Rng {
    /// The generator of `seed`.
    pub fn new(seed: u64) -> Rng {
        let (next, s0) = splitmix64(seed);
        let (_, s1) = splitmix64(next);
        Rng { s0, s1 }
    }

    /// The next 64-bit output.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.s0;
        let y = self.s1;
        self.s0 = y;
        x ^= x << 23;
        self.s1 = x ^ y ^ (x >> 18) ^ (y >> 5);
        self.s1.wrapping_add(y)
    }

    /// `n` bytes: `ceil(n / 8)` outputs, each written little-endian, the bytes past `n` dropped.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let word = self.next_u64().to_le_bytes();
            let take = (n - out.len()).min(8);
            out.extend_from_slice(&word[..take]);
        }
        out
    }

    /// 32 bytes, as a seed or a key.
    pub fn seed32(&mut self) -> [u8; 32] {
        self.bytes(32).try_into().unwrap()
    }

    /// A number in `0..n` (`n > 0`); the modulo bias does not matter to a test generator.
    pub fn below(&mut self, n: usize) -> usize {
        let n64 = u64::try_from(n).unwrap();
        usize::try_from(self.next_u64() % n64).unwrap()
    }

    /// Hex of `n` random bytes.
    pub fn hex(&mut self, n: usize) -> String {
        hex::encode(&self.bytes(n))
    }
}

/// The generator as a byte source: `rng(n)` returns the next `n` bytes, as the TypeScript `Rng` type does.
pub fn xorshift_rng(seed: u64) -> impl FnMut(usize) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    move |n| rng.bytes(n)
}

/// The signing key of a 32-byte seed.
pub fn key(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_seed(seed)
}

/// The key of a one-byte seed (`[n; 32]`), as `testkit::key(n)` makes it.
pub fn fixed_key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}

/// Caveats the generator draws from: the coding grammar, every escape class of §2.2, and non-ASCII.
const CAVEATS: [&str; 8] = [
    "type=coding.task.v1",
    "repo=bag",
    "role=session",
    "tab\there",
    "quote\"and\\backslash",
    "caf\u{e9} \u{2713} \u{1f600}",
    "ctl\u{1f}\u{7f}\u{2028}",
    "slash/kept",
];

/// A valid envelope built from seeded keys, with the seeds that sign it.
pub struct Fixture {
    /// The envelope, signed and valid at [`NOW`].
    pub env: Envelope,
    /// The seed of `from`, the session key.
    pub sender: [u8; 32],
    /// The seed of each hop's `iss`, root first.
    pub issuers: Vec<[u8; 32]>,
}

impl Fixture {
    /// The sender's key.
    pub fn sender_key(&self) -> SigningKey {
        key(&self.sender)
    }

    /// The wire bytes.
    pub fn bytes(&self) -> Vec<u8> {
        self.env.to_bytes()
    }

    /// The envelope re-signed by its own sender with another chain (a malicious session, or a forger's check of
    /// the chain alone): the id and `sig` recomputed, so only the chain can fail.
    pub fn resigned(&self, auth: Vec<Hop>) -> Envelope {
        Envelope::sign(&self.sender_key(), self.env.to.clone(), auth, self.env.ts, self.env.sealed.clone())
            .unwrap()
    }
}

fn caveat(rng: &mut Rng) -> String {
    if rng.below(4) == 0 {
        // Printable ASCII, 1 to 40 characters.
        let len = 1 + rng.below(40);
        rng.bytes(len).iter().map(|b| char::from(0x20 + b % 0x5f)).collect()
    } else {
        CAVEATS[rng.below(CAVEATS.len())].to_owned()
    }
}

/// A chain of `n` hops from fresh seeded roots to `sender`, with non-increasing `exp` (equal neighbours
/// included) all after [`NOW`].
pub fn chain_to(rng: &mut Rng, sender: &Address, n: usize) -> (Vec<Hop>, Vec<[u8; 32]>) {
    let issuers: Vec<[u8; 32]> = (0..n).map(|_| rng.seed32()).collect();
    let mut exp = NOW + 86_400 * (2 + u64::try_from(rng.below(30)).unwrap());
    let mut hops = Vec::with_capacity(n);
    for (i, seed) in issuers.iter().enumerate() {
        let sub = issuers.get(i + 1).map_or_else(|| sender.clone(), |next| key(next).address());
        let caveats = (0..rng.below(5)).map(|_| caveat(rng)).collect();
        hops.push(Hop::sign(&key(seed), &sub, caveats, exp).unwrap());
        exp -= 3_600 * u64::try_from(rng.below(3)).unwrap();
    }
    (hops, issuers)
}

/// An opaque sealed part with one wrap per recipient, every byte field drawn from `rng`.
pub fn sealed(rng: &mut Rng, to: &[Address]) -> Sealed {
    let wraps = to.iter().map(|a| Wrap { to: a.clone(), enc: rng.hex(32), ct: rng.hex(48) }).collect();
    let ct_len = 16 + rng.below(100);
    Sealed { wraps, nonce: rng.hex(12), ct: rng.hex(ct_len) }
}

/// A valid envelope with `n_to` recipients and `n_hops` hops, at [`NOW`].
pub fn build(rng: &mut Rng, n_to: usize, n_hops: usize) -> Fixture {
    let sender = rng.seed32();
    let from = key(&sender).address();
    // Recipients are never verified as curve points, so random bytes do.
    let to: Vec<Address> = (0..n_to).map(|_| Address::from_key(rng.seed32())).collect();
    let (auth, issuers) = chain_to(rng, &from, n_hops);
    let sealed = sealed(rng, &to);
    let env = Envelope::sign(&key(&sender), to, auth, NOW, sealed).unwrap();
    Fixture { env, sender, issuers }
}

/// A valid envelope with 1 to 16 recipients and 0 to 8 hops ("F").
pub fn envelope(rng: &mut Rng) -> Fixture {
    let n_to = 1 + rng.below(16);
    let n_hops = rng.below(9);
    build(rng, n_to, n_hops)
}

/// `bytes` with the byte at `pos` exclusive-or'd with `mask`; panics unless the bytes changed.
pub fn flipped(bytes: &[u8], pos: usize, mask: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[pos] ^= mask;
    assert_ne!(out, bytes, "the mutation at {pos} changed nothing");
    out
}

/// `bytes` with the byte at `pos` replaced by `byte`; panics unless the bytes changed.
pub fn replaced(bytes: &[u8], pos: usize, byte: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[pos] = byte;
    assert_ne!(out, bytes, "the mutation at {pos} changed nothing");
    out
}

/// Which part of verification gave a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    /// §5.4, parsing.
    Parse,
    /// §5.5 steps 1 to 3: the recipients, the id, the signature.
    Outer,
    /// §6.2, the chain rules at the envelope's `ts`.
    Chain,
    /// §5.5 step 4, the `ts` window.
    Window,
}

impl Step {
    /// The codes the spec allows this step to give.
    pub fn allowed(self) -> &'static [Code] {
        match self {
            Step::Parse => &[
                Code::EnvelopeTooLarge,
                Code::BadJson,
                Code::BadShape,
                Code::BadVersion,
                Code::BadSuite,
                Code::BadHex,
                Code::TooManyRecipients,
                Code::BadAddress,
                Code::TooManyHops,
                Code::BadHop,
                Code::TooManyCaveats,
                Code::CaveatTooLong,
            ],
            Step::Outer => &[Code::BadShape, Code::TooManyRecipients, Code::BadId, Code::BadSig],
            Step::Chain => &[
                Code::TooManyHops,
                Code::BadHop,
                Code::TooManyCaveats,
                Code::CaveatTooLong,
                Code::ChainBroken,
                Code::ChainNotToSender,
                Code::ExpNotMonotone,
                Code::HopExpired,
                Code::BadHopSig,
            ],
            Step::Window => &[Code::StaleTs, Code::FutureTs],
        }
    }
}

/// The relay's in-core order (§8.2 steps 2 to 6, the `outer` kind of `spec/adversarial/README.md`): parse, the
/// recipients, the id, the signature, the chain at `ts`, the window. The first failure, with its step.
///
/// # Errors
///
/// The step and code of the first check that fails.
pub fn outer_verdict(bytes: &[u8], now: u64, ttl: u64, skew: u64) -> Result<Envelope, (Step, Code)> {
    let env = Envelope::parse(bytes).map_err(|c| (Step::Parse, c))?;
    env.check_recipients().map_err(|c| (Step::Outer, c))?;
    env.check_id().map_err(|c| (Step::Outer, c))?;
    env.check_sig().map_err(|c| (Step::Outer, c))?;
    chain::verify(&env.from, env.ts, &env.auth).map_err(|c| (Step::Chain, c))?;
    env.check_ts(now, ttl, skew).map_err(|c| (Step::Window, c))?;
    Ok(env)
}

/// [`outer_verdict`] at [`NOW`] with the default TTL and skew, as a code.
pub fn verdict(bytes: &[u8]) -> Option<Code> {
    use ac_core::envelope::{DEFAULT_SKEW, DEFAULT_TTL};
    outer_verdict(bytes, NOW, DEFAULT_TTL, DEFAULT_SKEW).err().map(|(_, c)| c)
}

/// The JSON value of wire text, to change before writing it back.
pub fn wire(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

/// The path of a file in the repository.
pub fn repo(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(path)
}

/// The bytes of a case's hex member.
fn case_bytes(input: &serde_json::Value, member: &str) -> Vec<u8> {
    hex::decode(input[member].as_str().unwrap_or_else(|| panic!("no {member}"))).unwrap()
}

fn case_u64(input: &serde_json::Value, member: &str) -> u64 {
    input[member].as_u64().unwrap_or_else(|| panic!("no integer {member}"))
}

/// A verdict as the case files write it: `"ok"` or a code.
fn wire_verdict<T>(result: Result<T, Code>) -> String {
    result.map_or_else(|c| c.as_str().to_owned(), |_| "ok".to_owned())
}

/// The `canonical` kind of `spec/adversarial/README.md`: `"ok"` when the value has a canonical form and Rust writes
/// exactly the case's `canonical` with its `sha256`; `bad-canonical` when it has none; otherwise a sentence that is
/// no verdict, so the case fails.
pub fn canonical_verdict(input: &serde_json::Value) -> String {
    if input.get("utf16_hex").is_some() || input.get("sparse_list").is_some() {
        // A lone surrogate cannot become a Rust string, and a list with holes cannot be built: neither has a
        // canonical form (§2.1). A Rust list cannot hold a hole, so the case is read without building it.
        if let Some(units) = input["utf16_hex"].as_str() {
            let units: Vec<u16> = units
                .as_bytes()
                .chunks(4)
                .map(|c| u16::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
                .collect();
            if String::from_utf16(&units).is_ok() {
                return "a utf16_hex string that is valid UTF-16".to_owned();
            }
        }
        return Code::BadCanonical.as_str().to_owned();
    }
    let written =
        ac_core::canonical::from_json(&input["value"]).and_then(|v| ac_core::canonical::to_string(&v));
    match written {
        Err(c) => c.as_str().to_owned(),
        Ok(text) if Some(text.as_str()) != input["canonical"].as_str() => {
            format!("wrote other bytes: {text}")
        }
        Ok(text) if Some(ac_core::hash::sha256_hex(text.as_bytes()).as_str()) != input["sha256"].as_str() => {
            "another sha256".to_owned()
        }
        Ok(_) => "ok".to_owned(),
    }
}

/// The Rust verdict of one case of `spec/adversarial/` by its `kind` (`spec/adversarial/README.md`), or `None`
/// for a kind the Rust core cannot judge (`open`: no HPKE here) or does not know.
pub fn case_verdict(kind: &str, input: &serde_json::Value) -> Option<String> {
    use ac_core::records::{self, Record};
    let verdict = match kind {
        "json" => wire_verdict(ac_core::json::parse(&case_bytes(input, "bytes_hex"))),
        "parse" => wire_verdict(Envelope::parse(&case_bytes(input, "bytes_hex"))),
        "outer" => {
            let n = |m| case_u64(input, m);
            wire_verdict(
                outer_verdict(&case_bytes(input, "bytes_hex"), n("now"), n("ttl"), n("skew"))
                    .map_err(|e| e.1),
            )
        }
        "chain" => wire_verdict(chain::check_shape(Some(&input["auth"])).and_then(|hops| {
            let from = Address::parse(input["from"].as_str().ok_or(Code::BadShape)?)?;
            chain::verify(&from, case_u64(input, "ts"), &hops)
        })),
        "record" => wire_verdict(
            Record::parse(&case_bytes(input, "bytes_hex"))
                .and_then(|r| r.verify(case_u64(input, "now"), case_u64(input, "skew"))),
        ),
        "rotation" => {
            let read = |m: &str| -> Result<records::AddressRecord, Code> {
                match Record::parse(&case_bytes(input, m))? {
                    Record::Address(a) => Ok(a),
                    _ => Err(Code::BadRecord),
                }
            };
            wire_verdict(read("prev_bytes_hex").and_then(|prev| {
                let next = read("next_bytes_hex")?;
                records::verify_rotation(&prev, &next)
            }))
        }
        "rotation-claim" => wire_verdict(Record::parse(&case_bytes(input, "bytes_hex")).and_then(|record| {
            // §7.5 at the case's clock, then the claim of §7.3 for a reader that holds no record of rotated_from
            // (T1, T2): only an address record carries one.
            record.verify(case_u64(input, "now"), case_u64(input, "skew"))?;
            match record {
                Record::Address(next) => records::verify_rotation_claim(&next),
                _ => Err(Code::BadRecord),
            }
        })),
        "canonical" => canonical_verdict(input),
        _ => return None,
    };
    Some(verdict)
}

/// Fixtures with at least `min_hops` hops, and 1 to 16 recipients.
pub fn fixtures_with_hops(seed: u64, count: usize, min_hops: usize) -> Vec<Fixture> {
    let mut rng = Rng::new(seed);
    (0..count)
        .map(|_| {
            let n_to = 1 + rng.below(16);
            let n_hops = min_hops + rng.below(9 - min_hops);
            build(&mut rng, n_to, n_hops)
        })
        .collect()
}

/// The positive control: the unmutated envelope verifies.
pub fn control(f: &Fixture) {
    assert_eq!(verdict(&f.bytes()), None, "positive control {}", f.env.id_hex());
}

/// The chain verdict of `hops` for the fixture's sender, directly and through the envelope re-signed by the
/// sender; the two must agree.
pub fn chain_code(f: &Fixture, hops: &[Hop]) -> Option<Code> {
    assert_ne!(hops, f.env.auth.as_slice(), "the mutation changed nothing");
    let direct = chain::verify(&f.env.from, f.env.ts, hops).err();
    assert_eq!(
        verdict(&f.resigned(hops.to_vec()).to_bytes()),
        direct,
        "direct and enveloped verdicts differ"
    );
    direct
}

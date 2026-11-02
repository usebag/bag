//! Envelope and chain forgery in the Rust core: lines F1, F3, F4, F5, F6 (b) and (c), F9 and P6
//! (F7 is in `adversarial_malleability.rs`). Every envelope is built correctly from seeded keys first and verifies
//! before it is mutated, and every mutation is checked to change the bytes. The seeds are written
//! here; the generator is the twin of the TypeScript one (`support::Rng`, proven by line G2).

mod support;

use ac_core::canonical::{self, MAX_SAFE_INTEGER, Value};
use ac_core::chain::{self, Hop};
use ac_core::envelope::Envelope;
use ac_core::records::{AcceptFromRecord, AddressRecord, KeyRecord, Record, Roots};
use ac_core::requests::{fetch_preimage, subscribe_preimage};
use ac_core::{Address, Code, hash};
use std::collections::BTreeMap;
use support::{
    Fixture, NOW, Rng, STUDY_SEED, Step, build, chain_code, control, fixed_key, fixtures_with_hops, flipped,
    replaced, verdict, wire,
};

/// One test's tally: how many cases ended at each (step, code).
type Tally = BTreeMap<(Step, Code), usize>;

/// The code a substitution inside a hex field must give, by the member and its depth in the wire object: first
/// for another lower-case hex digit, then for the upper-case letter.
fn hex_field_codes(member: &str, depth: usize) -> Option<(Code, Code)> {
    match (member, depth) {
        ("sig", 1) => Some((Code::BadSig, Code::BadHex)),
        ("from", 1) => Some((Code::BadId, Code::BadAddress)),
        ("to", 2) => Some((Code::BadShape, Code::BadAddress)),
        ("to", 4) => Some((Code::BadShape, Code::BadShape)),
        ("iss" | "sub" | "sig", 3) => Some((Code::BadId, Code::BadHop)),
        ("id", 1) | ("nonce" | "ct", 2) | ("enc" | "ct", 4) => Some((Code::BadId, Code::BadHex)),
        _ => None,
    }
}

/// Every hex character inside a hex field of wire bytes written with no white space, with the codes of
/// [`hex_field_codes`]. A small scanner: strings, member names and nesting depth.
fn hex_positions(bytes: &[u8]) -> Vec<(usize, (Code, Code))> {
    let (mut out, mut depth, mut member, mut i) = (Vec::new(), 0usize, String::new(), 0);
    while i < bytes.len() {
        match bytes[i] {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth -= 1,
            b'"' => {
                let start = i + 1;
                let mut end = start;
                while bytes[end] != b'"' {
                    end += if bytes[end] == b'\\' { 2 } else { 1 };
                }
                let text = &bytes[start..end];
                if bytes.get(end + 1) == Some(&b':') {
                    member = String::from_utf8_lossy(text).into_owned();
                } else if let Some(codes) = hex_field_codes(&member, depth) {
                    let skip = if text.starts_with(b"ed25519:") { 8 } else { 0 };
                    out.extend((start + skip..end).map(|p| (p, codes)));
                }
                i = end;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

fn other_hex_digit(c: u8) -> u8 {
    let v = if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 };
    b"0123456789abcdef"[usize::from((v + 8) % 16)]
}

/// F1 for a slice of envelopes: XOR 0x01 at every byte, and inside every hex field each character replaced by
/// another hex digit and, for a letter, by its upper case.
fn f1_tally(fixtures: &[Fixture]) -> Tally {
    let mut tally = Tally::new();
    for f in fixtures {
        let bytes = f.bytes();
        for pos in 0..bytes.len() {
            let case = flipped(&bytes, pos, 0x01);
            let Err((step, code)) = support::outer_verdict(&case, NOW, 604_800, 300) else {
                panic!("F1: a flip at byte {pos} of {} verified", f.env.id_hex());
            };
            assert!(step.allowed().contains(&code), "F1: {code} is not a code of {step:?} (byte {pos})");
            *tally.entry((step, code)).or_default() += 1;
        }
        for (pos, (digit_code, upper_code)) in hex_positions(&bytes) {
            let c = bytes[pos];
            let mut cases = vec![(replaced(&bytes, pos, other_hex_digit(c)), digit_code)];
            if c.is_ascii_lowercase() {
                cases.push((replaced(&bytes, pos, c.to_ascii_uppercase()), upper_code));
            }
            for (case, want) in cases {
                let got = support::outer_verdict(&case, NOW, 604_800, 300).err();
                assert_eq!(got.map(|g| g.1), Some(want), "F1 hex field at byte {pos}");
                *tally.entry(got.unwrap()).or_default() += 1;
            }
        }
    }
    tally
}

fn print_tally(line: &str, tally: &Tally) {
    let total: usize = tally.values().sum();
    eprintln!("{line}: {total} cases, 0 accepted");
    for ((step, code), n) in tally {
        eprintln!("{line}:   {step:?} {code}: {n}");
    }
}

#[test]
fn f1_single_byte_flips_never_verify() {
    // Seed: STUDY_SEED + 0xF1. 20 envelopes, 1 to 16 recipients, 0 to 8 hops (reduced from the pre-registered 200
    // to keep the gate usable under coverage).
    let mut rng = Rng::new(STUDY_SEED + 0xF1);
    let fixtures: Vec<Fixture> = (0..20).map(|_| support::envelope(&mut rng)).collect();
    fixtures.iter().for_each(control);
    let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    let tallies: Vec<Tally> = std::thread::scope(|s| {
        let handles: Vec<_> =
            fixtures.chunks(fixtures.len().div_ceil(threads)).map(|c| s.spawn(move || f1_tally(c))).collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut tally = Tally::new();
    for t in tallies {
        for (k, n) in t {
            *tally.entry(k).or_default() += n;
        }
    }
    let bytes: usize = fixtures.iter().map(|f| f.bytes().len()).sum();
    eprintln!("F1: {} envelopes, {bytes} bytes", fixtures.len());
    print_tally("F1", &tally);
}

#[test]
fn f3_reordered_hops_break_the_chain() {
    let mut tally = Tally::new();
    let mut rng = Rng::new(STUDY_SEED + 0xF3);
    for f in fixtures_with_hops(STUDY_SEED + 0xF3, 30, 2) {
        control(&f);
        let hops = &f.env.auth;
        let (i, j) = (rng.below(hops.len() - 1), hops.len() - 1);
        let mut swapped = hops.clone();
        swapped.swap(i, j);
        let reversed: Vec<Hop> = hops.iter().rev().cloned().collect();
        let mut left = hops.clone();
        left.rotate_left(1);
        let mut right = hops.clone();
        right.rotate_right(1);
        for m in [swapped, reversed, left, right] {
            let code = chain_code(&f, &m).expect("F3: a reordered chain verified");
            assert!(matches!(code, Code::ChainBroken | Code::ChainNotToSender), "F3: {code}");
            *tally.entry((Step::Chain, code)).or_default() += 1;
            // The same reordering on the wire, the id and sig kept (a relay's forgery): the id breaks.
            let mut j = wire(&f.env.to_json_text());
            j["auth"] = m.iter().map(|h| wire(&h.to_json_text())).collect();
            assert_eq!(verdict(j.to_string().as_bytes()), Some(Code::BadId));
        }
    }
    print_tally("F3", &tally);
}

#[test]
fn f4_a_changed_caveat_breaks_its_hop_signature() {
    let mut rng = Rng::new(STUDY_SEED + 0xF4);
    let mut cases = 0;
    for f in fixtures_with_hops(STUDY_SEED + 0xF4, 30, 1) {
        control(&f);
        let k = rng.below(f.env.auth.len());
        let hop = &f.env.auth[k];
        let mut mutations = Vec::new();
        if !hop.caveats.is_empty() {
            let c = rng.below(hop.caveats.len());
            let mut dropped = hop.clone();
            dropped.caveats.remove(c);
            mutations.push(dropped);
            let mut edited = hop.clone();
            let ascii: Vec<usize> = (0..edited.caveats[c].len())
                .filter(|i| (0x20..0x7f).contains(&edited.caveats[c].as_bytes()[*i]))
                .collect();
            if let Some(&at) = ascii.get(rng.below(ascii.len().max(1))) {
                let mut raw = edited.caveats[c].clone().into_bytes();
                raw[at] = 0x20 + (raw[at] - 0x20 + 1) % 0x5f;
                edited.caveats[c] = String::from_utf8(raw).unwrap();
                mutations.push(edited);
            }
        }
        let mut appended = hop.clone();
        appended.caveats.push("type=coding.task.v1".into());
        mutations.push(appended);
        for m in mutations {
            let mut hops = f.env.auth.clone();
            hops[k] = m;
            assert_eq!(chain_code(&f, &hops), Some(Code::BadHopSig), "F4 hop {k}");
            cases += 1;
        }
    }
    eprintln!("F4: {cases} cases, every one bad-hop-sig");
}

#[test]
fn f5_a_raised_expiry_is_refused() {
    let mut tally = Tally::new();
    for f in fixtures_with_hops(STUDY_SEED + 0xF5, 20, 1) {
        control(&f);
        for k in 0..f.env.auth.len() {
            let exp = f.env.auth[k].exp;
            for raised in [exp + 1, exp + 86_400, MAX_SAFE_INTEGER] {
                let mut hops = f.env.auth.clone();
                hops[k].exp = raised;
                let monotone_break = k > 0 && raised > hops[k - 1].exp;
                let want = if monotone_break { Code::ExpNotMonotone } else { Code::BadHopSig };
                assert_eq!(chain_code(&f, &hops), Some(want), "F5 hop {k} exp {raised}");
                *tally.entry((Step::Chain, want)).or_default() += 1;
            }
        }
    }
    print_tally("F5", &tally);
}

#[test]
fn f6_a_self_rooted_attacker_cannot_pose_as_a_principal() {
    let (root, attacker) = (fixed_key(60), fixed_key(61));
    let to = vec![fixed_key(62).address()];
    let caveats = vec!["type=coding.task.v1".to_owned()];
    // (b) iss = the org root, sub = the attacker, signed by the attacker.
    let preimage = chain::hop_preimage(&root.address(), &attacker.address(), &caveats, NOW + 3_600);
    let forged = Hop {
        iss: root.address(),
        sub: attacker.address(),
        caveats: caveats.clone(),
        exp: NOW + 3_600,
        sig: attacker.sign_preimage(&preimage).unwrap(),
    };
    let genuine = Hop::sign(&root, &attacker.address(), caveats, NOW + 3_600).unwrap();
    let sealed = support::sealed(&mut Rng::new(STUDY_SEED + 0xF6), &to);
    let send = |auth: Vec<Hop>| Envelope::sign(&attacker, to.clone(), auth, NOW, sealed.clone()).unwrap();
    assert_eq!(verdict(&send(vec![genuine]).to_bytes()), None, "positive control");
    assert_eq!(verdict(&send(vec![forged]).to_bytes()), Some(Code::BadHopSig), "F6(b)");
    // (c) a genuine first hop copied from another chain, then principal -> attacker signed by the attacker.
    for f in fixtures_with_hops(STUDY_SEED + 0xF6, 20, 1) {
        control(&f);
        let copied = f.env.auth[0].clone();
        let principal = copied.sub.clone();
        let pre = chain::hop_preimage(&principal, &attacker.address(), &[], copied.exp);
        let tail =
            Hop { iss: principal, sub: attacker.address(), caveats: vec![], exp: copied.exp, sig: [0; 64] };
        let tail = Hop { sig: attacker.sign_preimage(&pre).unwrap(), ..tail };
        let env = send(vec![copied, tail]);
        assert_eq!(verdict(&env.to_bytes()), Some(Code::BadHopSig), "F6(c)");
    }
}

#[test]
fn f9_a_changed_recipient_list_never_verifies() {
    let mut rng = Rng::new(STUDY_SEED + 0xF9);
    let mut cases = 0;
    for _ in 0..20 {
        let n_to = 2 + rng.below(14);
        let n_hops = rng.below(9);
        let f = build(&mut rng, n_to, n_hops);
        control(&f);
        let extra = Address::from_key(rng.seed32());
        for matched in [false, true] {
            let edit = |change: &dyn Fn(&mut Vec<serde_json::Value>, bool)| {
                let mut j = wire(&f.env.to_json_text());
                change(j["to"].as_array_mut().unwrap(), false);
                if matched {
                    change(j["sealed"]["wraps"].as_array_mut().unwrap(), true);
                }
                let bytes = j.to_string().into_bytes();
                assert_ne!(bytes, f.bytes());
                verdict(&bytes)
            };
            let new_item = |wrap: bool| -> serde_json::Value {
                if wrap {
                    serde_json::json!({"to": extra.as_str(), "enc": "ab".repeat(32), "ct": "cd".repeat(48)})
                } else {
                    extra.as_str().into()
                }
            };
            let pad_17 = |l: &mut Vec<serde_json::Value>, wrap: bool| {
                while l.len() < 17 {
                    let a = Address::from_key([u8::try_from(l.len()).unwrap(); 32]);
                    l.push(if wrap {
                        serde_json::json!({"to": a.as_str(), "enc": "ab".repeat(32), "ct": "cd".repeat(48)})
                    } else {
                        a.as_str().into()
                    });
                }
            };
            let id_or_shape = if matched { Code::BadId } else { Code::BadShape };
            let results = [
                (edit(&|l, w| l.push(new_item(w))), id_or_shape),
                (edit(&|l, _| l.truncate(l.len() - 1)), id_or_shape),
                (edit(&|l, _| l.swap(0, 1)), id_or_shape),
                (edit(&|l, _| l[1] = l[0].clone()), Code::BadShape),
                (edit(&pad_17), Code::TooManyRecipients),
            ];
            for (got, want) in results {
                assert_eq!(got, Some(want), "F9 matched={matched}");
                cases += 1;
            }
        }
    }
    eprintln!("F9: {cases} cases, none accepted");
}

/// The canonical text of each preimage kind, built from real objects, with the prefix it must start with.
fn preimages() -> Vec<(&'static str, String)> {
    let f = build(&mut Rng::new(STUDY_SEED + 0x96), 2, 1);
    let k = fixed_key(80);
    let text = |v: &Value| canonical::to_string(v).unwrap();
    let address = AddressRecord {
        key: k.address(),
        sealing_key: None,
        relays: vec![],
        rotation_key: None,
        revoked: vec![],
        ttl: 3_600,
        iat: NOW,
        rotated_from: None,
        rotation_sig: None,
        sig: [0; 64],
    };
    let accept = AcceptFromRecord {
        owner: k.address(),
        roots: Roots::Any,
        max_bytes: 1,
        ttl: 1,
        iat: NOW,
        sig: [0; 64],
    };
    let key_record =
        KeyRecord { key: k.address(), sealing_key: "aa".repeat(32), iat: NOW, exp: NOW, sig: [0; 64] };
    // An audit line whose fields imitate the envelope's: seq 1, prev, ts, event, decision, reason, id, from, root.
    let audit = Value::Array(vec![
        Value::Int(1),
        Value::from(f.env.id_hex()),
        Value::Int(NOW),
        Value::from("receive"),
        Value::from("accept"),
        Value::from("ok"),
        Value::from(f.env.id_hex()),
        Value::from(f.env.from.as_str()),
        Value::from(f.env.from.as_str()),
        Value::Null,
    ]);
    vec![
        ("[1,[", text(&f.env.id_preimage())),
        ("[\"ac/hop/1\",", text(&f.env.auth[0].preimage())),
        ("[\"ac/addr/1\",", text(&address.preimage())),
        ("[\"ac/accept/1\",", text(&accept.preimage())),
        ("[\"ac/key/1\",", text(&key_record.preimage())),
        ("[\"ac/sub/1\",", text(&subscribe_preimage(&"00".repeat(32), &k.address(), &k.address(), None))),
        (
            "[\"ac/fetch/1\",",
            text(&fetch_preimage(&k.address(), &f.env.id_hex(), NOW, "https://relay.example")),
        ),
        ("[1,\"", text(&audit)),
    ]
}

#[test]
fn p6_preimage_kinds_have_distinct_prefixes_and_signatures_do_not_cross() {
    let kinds = preimages();
    for (i, (prefix, text)) in kinds.iter().enumerate() {
        assert!(text.starts_with(prefix), "{text} starts with {prefix}");
        for (j, (other, _)) in kinds.iter().enumerate() {
            assert!(i == j || !text.starts_with(other), "{text} also starts with {other}");
        }
    }
    let audit = &kinds[7].1;
    assert_eq!(audit.as_bytes()[4 + 64], b'"', "the audit line: an integer, then a 64-hex string");
    // A hop's sig presented as an envelope's sig, over an id set to the hop's digest: the id does not recompute.
    let (k, sub) = (fixed_key(81), fixed_key(82).address());
    let hop = Hop::sign(&k, &sub, vec!["role=session".into()], NOW + 60).unwrap();
    assert!(chain::verify(&sub, NOW, std::slice::from_ref(&hop)).is_ok(), "positive control");
    let to = vec![sub.clone()];
    let sealed = support::sealed(&mut Rng::new(STUDY_SEED + 0x97), &to);
    let base = Envelope::sign(&k, to, vec![], NOW, sealed).unwrap();
    let replayed = Envelope { id: hash::digest(&hop.preimage()).unwrap(), sig: hop.sig, ..base };
    let parsed = Envelope::parse(&replayed.to_bytes()).unwrap();
    assert!(parsed.check_sig().is_ok(), "the signature is valid over those 32 bytes: only the id stops it");
    assert_eq!(verdict(&replayed.to_bytes()), Some(Code::BadId));
    // A record's sig as a hop's, and a hop's sig as a record's.
    let mut record = Record::Key(KeyRecord {
        key: k.address(),
        sealing_key: "aa".repeat(32),
        iat: NOW,
        exp: NOW + 60,
        sig: [0; 64],
    });
    record.sign(&k).unwrap();
    assert_eq!(record.verify(NOW, 300), Ok(()), "positive control");
    let Record::Key(kr) = &record else { unreachable!() };
    let crossed = Hop { sig: kr.sig, ..hop.clone() };
    assert_eq!(chain::verify(&sub, NOW, &[crossed]).err(), Some(Code::BadHopSig));
    let crossed_record = Record::Key(KeyRecord { sig: hop.sig, ..kr.clone() });
    assert_eq!(crossed_record.verify(NOW, 300).err(), Some(Code::BadRecordSig));
    // The audit line hashes to another digest than the envelope id it imitates.
    assert_ne!(hash::sha256(audit.as_bytes()), hash::sha256(kinds[0].1.as_bytes()));
}

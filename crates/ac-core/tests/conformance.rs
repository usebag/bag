//! Conformance with the shared test vectors (spec/vectors/, spec/SPEC.md §11) and the TypeScript core's error
//! codes (packages/core/src/errors.ts). Every case of canonical, envelope, sealed-multi, chain-valid,
//! chain-invalid and records is checked here: canonical strings, digests, ids, signatures, parse, outer-check,
//! chain and record verdicts, record parsing and rotation claims. The HPKE subset, envelope.json's "open" and "seal"
//! and chain-valid.json's "caveats" are not: this crate never seals or opens, and never evaluates a caveat. Since
//! 2026-10-26 every list of discovery.json is: the TXT text form, the TXT records of a lookup, a record's
//! agreement with its TXT and the pin after it, handles, handle records, their form and their bytes (§12, L2).

use ac_core::canonical;
use ac_core::chain::{self, Hop};
use ac_core::discovery::{self, Discovery, RecordUrl};
use ac_core::envelope::{DEFAULT_SKEW, DEFAULT_TTL, Envelope};
use ac_core::error::Group;
use ac_core::handles::{Handle, HandleRecord};
use ac_core::keys::{self, SigningKey};
use ac_core::records::{self, Domain, Record};
use ac_core::requests::{fetch_preimage, subscribe_preimage};
use ac_core::{Address, Code, hash, hex};
use serde_json::Value;
use std::path::PathBuf;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn vectors(name: &str) -> Value {
    let path = repo().join("spec/vectors").join(format!("{name}.json"));
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
        .unwrap()
}

fn list<'a>(file: &'a Value, key: &str) -> &'a [Value] {
    file[key].as_array().unwrap_or_else(|| panic!("no list {key}"))
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("no string {key} in {}", v["name"]))
}

fn result(v: &Value) -> Option<Code> {
    match text(v, "result") {
        "ok" => None,
        other => Some(Code::from_wire(other).unwrap_or_else(|| panic!("{other} is not a code"))),
    }
}

fn verdict<T>(r: Result<T, Code>) -> Option<Code> {
    r.err()
}

fn addr(v: &Value) -> Address {
    Address::parse(v.as_str().unwrap()).unwrap()
}

#[test]
fn the_error_codes_are_the_typescript_set_in_order() {
    let ts = std::fs::read_to_string(repo().join("packages/core/src/errors.ts")).unwrap();
    let mut expected = Vec::new();
    for (group, name) in [(Group::Core, "CORE"), (Group::Relay, "RELAY"), (Group::Edge, "EDGE")] {
        let start = ts.find(&format!("export const {name}_ERROR_CODES = [")).unwrap();
        let body = &ts[start..start + ts[start..].find("] as const").unwrap()];
        for line in body.lines().skip(1) {
            let line = line.trim();
            if let Some(code) = line.strip_prefix('\'').and_then(|l| l.split('\'').next()) {
                expected.push((code.to_owned(), group));
            }
        }
    }
    let ours: Vec<(String, Group)> = Code::ALL.iter().map(|c| (c.as_str().to_owned(), c.group())).collect();
    assert_eq!(ours, expected);
    // 53 until 2026-10-25; then `internal` (relay) and `unreachable` (edge) were added, then `store-full`;
    // 2026-10-30 pairing by a short code added `no-nameplate` (relay) and `bad-code` and `leaked` (edge), then
    // typed digits `digits-mismatch` (edge).
    assert_eq!(ours.len(), 60);
}

#[test]
fn canonical_cases_write_the_expected_strings_and_digests() {
    let file = vectors("canonical");
    for case in list(&file, "cases") {
        let value = canonical::from_json(&case["value"]).unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        let written = canonical::to_string(&value).unwrap();
        assert_eq!(written, text(case, "canonical"), "{}", case["name"]);
        assert_eq!(hash::sha256_hex(written.as_bytes()), text(case, "sha256"), "{}", case["name"]);
    }
    assert_eq!(list(&file, "cases").len(), 16);
}

#[test]
fn canonical_invalid_values_have_no_canonical_form() {
    let file = vectors("canonical");
    for case in list(&file, "invalid") {
        assert_eq!(result(case), Some(Code::BadCanonical));
        if let Some(units) = case.get("utf16_hex").and_then(Value::as_str) {
            // A lone surrogate cannot become a Rust string at all: the type rules it out, which is this check.
            let units: Vec<u16> = units
                .as_bytes()
                .chunks(4)
                .map(|c| u16::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
                .collect();
            assert!(String::from_utf16(&units).is_err(), "{}", case["name"]);
        } else {
            assert_eq!(
                verdict(canonical::from_json(&case["value"])),
                Some(Code::BadCanonical),
                "{}",
                case["name"]
            );
        }
    }
    assert_eq!(list(&file, "invalid").len(), 12);
}

#[test]
fn every_preimage_table_hashes_and_verifies() {
    let file = vectors("canonical");
    for case in list(&file, "preimages") {
        let table = text(case, "table");
        let value = canonical::from_json(&case["preimage"]).unwrap();
        let written = canonical::to_string(&value).unwrap();
        assert_eq!(written, text(case, "canonical"), "{table}");
        let digest = hash::sha256(written.as_bytes());
        assert_eq!(hex::encode(&digest), text(case, "sha256"), "{table}");
        if let Some(sig) = case.get("sig").and_then(Value::as_str) {
            let signer = Address::parse(text(case, "signer")).unwrap();
            assert!(keys::verify(&signer, &digest, &hex::decode_array::<64>(sig).unwrap()), "{table}");
        }
        // The preimages this crate builds for the relay's proofs give the same strings.
        let p = case["preimage"].as_array().unwrap();
        if table.starts_with("subscribe response") {
            let cursor = p[4].as_u64();
            let built = subscribe_preimage(p[1].as_str().unwrap(), &addr(&p[2]), &addr(&p[3]), cursor);
            assert_eq!(canonical::to_string(&built).unwrap(), written, "{table}");
        }
        if table == "fetch auth" {
            // Five fields since 2026-11-02: the audience last (spec/SPEC.md §8.3).
            assert_eq!(p.len(), 5, "{table}: [tag, signer, id, ts, audience]");
            let audience = p[4].as_str().unwrap();
            let built =
                fetch_preimage(&addr(&p[1]), p[2].as_str().unwrap(), p[3].as_u64().unwrap(), audience);
            assert_eq!(canonical::to_string(&built).unwrap(), written, "{table}");
        }
        if table == "hop" {
            let caveats: Vec<String> =
                p[3].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_owned()).collect();
            let built = chain::hop_preimage(&addr(&p[1]), &addr(&p[2]), &caveats, p[4].as_u64().unwrap());
            assert_eq!(canonical::to_string(&built).unwrap(), written, "{table}");
        }
    }
    assert_eq!(list(&file, "preimages").len(), 11);
}

/// One envelope case of envelope.json or sealed-multi.json: everything a verifier can recompute.
fn check_envelope_case(case: &Value) {
    let name = &case["name"];
    let expected = &case["expected"];
    let bytes = text(expected, "bytes").as_bytes();
    assert_eq!(bytes.len() as u64, expected["size"].as_u64().unwrap(), "{name}");
    let env = Envelope::parse(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
    // This crate writes the same bytes as packages/core.
    assert_eq!(env.to_bytes(), bytes, "{name}");
    assert_eq!(
        canonical::to_string(&env.sealed.preimage()).unwrap(),
        text(expected, "sealed_hash_canonical"),
        "{name}"
    );
    assert_eq!(env.sealed.hash_hex(), text(expected, "sealed_hash"), "{name}");
    assert_eq!(canonical::to_string(&env.id_preimage()).unwrap(), text(expected, "id_canonical"), "{name}");
    assert_eq!(hex::encode(&env.compute_id().unwrap()), text(expected, "id"), "{name}");
    assert_eq!(env.id_hex(), text(expected, "id"), "{name}");
    assert_eq!(hex::encode(&env.sig), text(expected, "sig"), "{name}");
    env.check_id().unwrap();
    env.check_sig().unwrap();
    env.verify_outer(env.ts, DEFAULT_TTL, DEFAULT_SKEW).unwrap();
    // Ed25519 is deterministic: the sender's seed signs the id to the same signature.
    let seed = hex::decode_array::<32>(text(&case["inputs"], "from_seed")).unwrap();
    let sender = SigningKey::from_seed(&seed);
    assert_eq!(sender.address(), env.from, "{name}");
    assert_eq!(hex::encode(&sender.sign(&env.id)), text(expected, "sig"), "{name}");
    for (hop, want) in env.auth.iter().zip(list(expected, "hops")) {
        let written = canonical::to_string(&hop.preimage()).unwrap();
        assert_eq!(written, text(want, "canonical"), "{name}");
        assert_eq!(hash::sha256_hex(written.as_bytes()), text(want, "digest"), "{name}");
    }
    assert_eq!(env.auth.len(), list(expected, "hops").len(), "{name}");
    let verified = chain::verify(&env.from, env.ts, &env.auth).unwrap();
    let chain = &expected["chain"];
    assert_eq!(verified.root.as_str(), text(chain, "root"), "{name}");
    assert_eq!(verified.principal.as_str(), text(chain, "principal"), "{name}");
    let caveats: Vec<&str> = list(chain, "caveats").iter().map(|c| c.as_str().unwrap()).collect();
    assert_eq!(verified.caveats, caveats, "{name}");
    // The parsed envelope is the expected object, member for member.
    let parsed: Value = serde_json::from_slice(&env.to_bytes()).unwrap();
    assert_eq!(parsed, expected["envelope"], "{name}");
}

#[test]
fn envelope_cases_recompute_every_value() {
    let file = vectors("envelope");
    list(&file, "cases").iter().for_each(check_envelope_case);
    assert_eq!(list(&file, "cases").len(), 4);
}

#[test]
fn sealed_multi_cases_recompute_every_value() {
    let file = vectors("sealed-multi");
    list(&file, "cases").iter().for_each(check_envelope_case);
    assert_eq!(list(&file, "cases").len(), 3);
}

/// The bytes of a parse case: `bytes`, or `bytes_hex`, followed by `pad_with_spaces` spaces.
fn case_bytes(case: &Value) -> Vec<u8> {
    let mut bytes = match case.get("bytes_hex").and_then(Value::as_str) {
        Some(h) => hex::decode(h).unwrap(),
        None => text(case, "bytes").as_bytes().to_vec(),
    };
    let pad = case.get("pad_with_spaces").and_then(Value::as_u64).unwrap_or(0);
    bytes.resize(bytes.len() + usize::try_from(pad).unwrap(), b' ');
    bytes
}

#[test]
fn every_parse_case_gives_its_verdict() {
    let file = vectors("envelope");
    for case in list(&file, "parse") {
        let got = verdict(Envelope::parse(&case_bytes(case)));
        assert_eq!(got, result(case), "{}", case["name"]);
    }
    // 37 until 2026-10-25; then 18 more: member names given twice and numbers that are not plain integers;
    // then 1: per-wrap order, a bad-hex wrap[0] before a bad-shape wrap[1] (SPEC 5.4 step 12).
    assert_eq!(list(&file, "parse").len(), 56);
}

#[test]
fn every_outer_check_case_gives_its_verdict() {
    let file = vectors("envelope");
    for case in list(&file, "verify") {
        let env = Envelope::parse(text(case, "bytes").as_bytes())
            .unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        let n = |k: &str| case[k].as_u64().unwrap();
        let got = verdict(env.verify_outer(n("now"), n("ttl"), n("skew")));
        assert_eq!(got, result(case), "{}", case["name"]);
    }
    // 11 until 2026-10-25; then 67 more: the degenerate keys, S at or above L, R, the mixed orders.
    assert_eq!(list(&file, "verify").len(), 78);
}

fn chain_verdict(case: &Value) -> Result<chain::Verified, Code> {
    let hops: Vec<Hop> = chain::check_shape(Some(&case["auth"]))?;
    chain::verify(&addr(&case["from"]), case["ts"].as_u64().unwrap(), &hops)
}

#[test]
fn every_valid_chain_verifies_to_its_root_principal_and_caveats() {
    let file = vectors("chain-valid");
    for case in list(&file, "cases") {
        let name = &case["name"];
        assert_eq!(result(case), None);
        let v = chain_verdict(case).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(v.root.as_str(), text(&case["chain"], "root"), "{name}");
        assert_eq!(v.principal.as_str(), text(&case["chain"], "principal"), "{name}");
        let caveats: Vec<&str> =
            list(&case["chain"], "caveats").iter().map(|c| c.as_str().unwrap()).collect();
        assert_eq!(v.caveats, caveats, "{name}");
        let hops = chain::check_shape(Some(&case["auth"])).unwrap();
        for (hop, want) in hops.iter().zip(list(case, "hops")) {
            let written = canonical::to_string(&hop.preimage()).unwrap();
            assert_eq!(written, text(want, "canonical"), "{name}");
            assert_eq!(hash::sha256_hex(written.as_bytes()), text(want, "digest"), "{name}");
        }
    }
    // 11 until 2026-10-25; then a mixed-order iss whose k is 0 mod 8.
    assert_eq!(list(&file, "cases").len(), 12);
}

#[test]
fn every_invalid_chain_fails_its_rule() {
    let file = vectors("chain-invalid");
    let rule_code = [
        Code::TooManyHops,
        Code::BadHop,
        Code::TooManyCaveats,
        Code::CaveatTooLong,
        Code::ChainBroken,
        Code::ChainNotToSender,
        Code::ExpNotMonotone,
        Code::HopExpired,
        Code::BadHopSig,
    ];
    for case in list(&file, "cases") {
        let rule = usize::try_from(case["rule"].as_u64().unwrap()).unwrap();
        assert_eq!(result(case), Some(rule_code[rule - 1]), "{}: the rule and the code agree", case["name"]);
        assert_eq!(verdict(chain_verdict(case)), result(case), "{}", case["name"]);
    }
    // 32 until 2026-10-25; then 17 more: the degenerate keys, S + L, R the identity, a mixed-order iss.
    assert_eq!(list(&file, "cases").len(), 49);
}

#[test]
fn record_cases_hash_sign_and_verify_at_each_time() {
    let file = vectors("records");
    for case in list(&file, "cases") {
        let name = &case["name"];
        let record = Record::from_json(&case["record"]).unwrap_or_else(|e| panic!("{name}: {e}"));
        let written = canonical::to_string(&record.preimage()).unwrap();
        assert_eq!(written, text(case, "canonical"), "{name}");
        assert_eq!(record.digest_hex().unwrap(), text(case, "digest"), "{name}");
        assert_eq!(record.signer().as_str(), text(case, "signer"), "{name}");
        // Written back, it is the same object.
        assert_eq!(serde_json::from_slice::<Value>(&record.to_bytes()).unwrap(), case["record"], "{name}");
        for check in list(case, "checks") {
            let n = |k: &str| check[k].as_u64().unwrap();
            assert_eq!(
                verdict(record.verify(n("now"), n("skew"))),
                result(check),
                "{name} at {}",
                check["now"]
            );
        }
    }
    // 8 cases, then 2 with domain roots, then 16 more: 1,024 roots, the degenerate keys and R
    // the identity as a record's signer; then 1: a relay URL with a U+2028 line separator, accepted (SPEC 7.1).
    assert_eq!(list(&file, "cases").len(), 27);
}

#[test]
fn record_invalid_cases_break_their_form_or_caps() {
    let file = vectors("records");
    for case in list(&file, "invalid") {
        assert_eq!(verdict(Record::from_json(&case["record"])), result(case), "{}", case["name"]);
        // The same bytes through the parser give the same code.
        let bytes = serde_json::to_vec(&case["record"]).unwrap();
        assert_eq!(verdict(Record::parse(&bytes)), result(case), "{}", case["name"]);
    }
    // 18 cases, then 11 malformed domain roots, then 1,025 roots and a key record a
    // second over a day; then 1: a relay URL with a Cc control character, bad-record (SPEC 7.1).
    assert_eq!(list(&file, "invalid").len(), 32);
}

#[test]
fn every_rotation_case_gives_its_verdict() {
    let file = vectors("records");
    for case in list(&file, "rotations") {
        let read = |k: &str| match Record::from_json(&case[k]).unwrap() {
            Record::Address(a) => a,
            other => panic!("{}: {k} is a {:?} record", case["name"], other.kind()),
        };
        let (prev, next) = (read("prev"), read("next"));
        assert_eq!(verdict(records::verify_rotation(&prev, &next)), result(case), "{}", case["name"]);
    }
    assert_eq!(list(&file, "rotations").len(), 6);
}

#[test]
fn every_record_parse_case_gives_its_verdict() {
    // 2026-10-25: bytes read as a record, duplicate member names and non-plain numbers (§2.5).
    let file = vectors("records");
    for case in list(&file, "parse") {
        let bytes = case_bytes(case);
        assert_eq!(verdict(Record::parse(&bytes)), result(case), "{}", case["name"]);
        // A record that reads is written back to the same bytes as packages/core writes them.
        if let Ok(record) = Record::parse(&bytes) {
            assert_eq!(record.to_bytes(), bytes, "{}", case["name"]);
        }
    }
    assert_eq!(list(&file, "parse").len(), 13);
}

#[test]
fn every_rotation_claim_gives_its_verdict() {
    // 2026-10-25: what a reader that holds no record of rotated_from can check.
    let file = vectors("records");
    for case in list(&file, "rotation_claims") {
        let Record::Address(next) = Record::from_json(&case["next"]).unwrap() else {
            panic!("{}: not an address record", case["name"]);
        };
        assert_eq!(verdict(records::verify_rotation_claim(&next)), result(case), "{}", case["name"]);
    }
    assert_eq!(list(&file, "rotation_claims").len(), 5);
}

#[test]
fn every_presentation_case_gives_its_strings() {
    let file = vectors("discovery");
    for case in list(&file, "presentation") {
        let name = &case["name"];
        match discovery::parse_presentation(text(case, "text")) {
            Ok(strings) => {
                assert_eq!(result(case), None, "{name}");
                let hexes: Vec<String> = strings.iter().map(|s| hex::encode(s)).collect();
                let want: Vec<&str> = list(case, "strings_hex").iter().map(|v| v.as_str().unwrap()).collect();
                assert_eq!(hexes, want, "{name}");
            }
            Err(_) => assert_eq!(result(case), Some(Code::ResolveFailed), "{name}"),
        }
    }
    // 22, then 3: a parenthesis in a quoted string (accepted) and a bare `(` and `)` (refused), SPEC 12.2 item 7.
    assert_eq!(list(&file, "presentation").len(), 25);
}

#[test]
fn every_txt_case_leads_where_it_says() {
    let file = vectors("discovery");
    for case in list(&file, "txt") {
        let name = &case["name"];
        let domain = Domain::parse(text(case, "domain")).unwrap();
        assert_eq!(discovery::txt_name(&domain).as_deref(), case["txt_name"].as_str(), "{name}");
        let records: Vec<Vec<Vec<u8>>> = list(case, "records")
            .iter()
            .map(|r| r.as_array().unwrap().iter().map(|s| s.as_str().unwrap().as_bytes().to_vec()).collect())
            .collect();
        match discovery::discover(&records, &domain) {
            Ok(d) => {
                assert_eq!(result(case), None, "{name}");
                assert_eq!(d.key.as_ref().map(Address::as_str), case["key"].as_str(), "{name}");
                assert_eq!(d.url.to_string(), text(case, "url"), "{name}");
                assert_eq!(d.url.origin(), text(case, "origin"), "{name}");
            }
            Err(refusal) => assert_eq!(Some(refusal.code()), result(case), "{name}"),
        }
    }
    // 40 at first; 41 since the 13 cases of rec's URL grammar out, host and rec-refused in).
    assert_eq!(list(&file, "txt").len(), 41);
}

#[test]
fn every_agreement_case_gives_its_verdict_and_the_pin_after_it() {
    // A record agrees with its TXT by its key or by one rotation the TXT's key countersigned; the
    // pin then moves only by §7.3 (verify_rotation against the pinned record), so DNS moves no pin.
    let file = vectors("discovery");
    let domain = Domain::parse("acme.example").unwrap();
    let address_record = |v: &Value| match Record::from_json(v).unwrap() {
        Record::Address(a) => a,
        other => panic!("a {:?} record", other.kind()),
    };
    for case in list(&file, "agreement") {
        let name = &case["name"];
        let record = address_record(&case["record"]);
        let pinned = (!case["pinned"].is_null()).then(|| address_record(&case["pinned"]));
        let key = (!case["txt_key"].is_null()).then(|| addr(&case["txt_key"]));
        let found = Discovery { key, url: RecordUrl::well_known(&domain) };
        let agreed = found.check(&record);
        assert_eq!(verdict(agreed), result(case), "{name}");
        let pin = match (&agreed, &pinned) {
            (Err(_), p) => p.as_ref().map(|p| p.key.clone()),
            (Ok(()), None) => Some(record.key.clone()),
            (Ok(()), Some(p)) if p.key == record.key || records::verify_rotation(p, &record).is_ok() => {
                Some(record.key.clone())
            }
            (Ok(()), Some(p)) => Some(p.key.clone()),
        };
        assert_eq!(pin.as_ref().map(Address::as_str), case["pin"].as_str(), "{name}");
    }
    assert_eq!(list(&file, "agreement").len(), 14);
}

#[test]
fn every_handle_string_reads_as_it_says() {
    let file = vectors("discovery");
    for case in list(&file, "handles") {
        let name = &case["name"];
        match Handle::parse(text(case, "handle")) {
            Ok(h) => {
                assert_eq!(result(case), None, "{name}");
                assert_eq!(
                    (h.local(), h.domain().as_str()),
                    (text(case, "local"), text(case, "domain")),
                    "{name}"
                );
                assert_eq!(h.path(), text(case, "path"), "{name}");
                assert_eq!(h.to_string(), text(case, "handle"), "{name}");
            }
            Err(code) => assert_eq!(Some(code), result(case), "{name}"),
        }
    }
    // 20, then 12 added on 2026-10-26 (ports, IP literals and the special-use top-level names).
    assert_eq!(list(&file, "handles").len(), 32);
}

#[test]
fn every_handle_record_case_hashes_signs_and_verifies() {
    let file = vectors("discovery");
    for case in list(&file, "cases") {
        let name = &case["name"];
        let record = HandleRecord::from_json(&case["record"]).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(canonical::to_string(&record.preimage()).unwrap(), text(case, "canonical"), "{name}");
        assert_eq!(record.digest_hex().unwrap(), text(case, "digest"), "{name}");
        assert_eq!(record.org.as_str(), text(case, "signer"), "{name}");
        assert_eq!(serde_json::from_str::<Value>(&record.to_json_text()).unwrap(), case["record"], "{name}");
        for check in list(case, "checks") {
            let n = |k: &str| check[k].as_u64().unwrap();
            let handle = Handle::parse(text(check, "handle")).unwrap();
            let revoked: Vec<Address> = list(check, "revoked").iter().map(addr).collect();
            let got = record.verify(&addr(&check["org"]), &handle, &revoked, n("now"), n("skew"));
            assert_eq!(verdict(got), result(check), "{name} at {}", check["now"]);
        }
    }
    assert_eq!(list(&file, "cases").len(), 7);
}

#[test]
fn every_invalid_handle_record_breaks_its_form() {
    let file = vectors("discovery");
    for case in list(&file, "invalid") {
        assert_eq!(verdict(HandleRecord::from_json(&case["record"])), result(case), "{}", case["name"]);
        let bytes = serde_json::to_vec(&case["record"]).unwrap();
        assert_eq!(verdict(HandleRecord::parse(&bytes)), result(case), "{}", case["name"]);
    }
    assert_eq!(list(&file, "invalid").len(), 17);
}

#[test]
fn every_handle_record_parse_case_gives_its_verdict() {
    let file = vectors("discovery");
    for case in list(&file, "parse") {
        let bytes = text(case, "bytes").as_bytes();
        assert_eq!(verdict(HandleRecord::parse(bytes)), result(case), "{}", case["name"]);
        if let Ok(record) = HandleRecord::parse(bytes) {
            assert_eq!(record.to_json_text().as_bytes(), bytes, "{}", case["name"]);
        }
    }
    assert_eq!(list(&file, "parse").len(), 6);
}

#[test]
fn the_vectors_give_a_verdict_for_41_of_the_60_codes() {
    // 37 until 2026-10-26; then discovery.json added resolve-failed (§12.2, §12.4) and revoked (§12.4 item 3).
    // The 56th code, `store-full`, is a relay code with no core vector; 2026-10-30 pairing by a
    // short code added `no-nameplate` (relay) and `bad-code` and `leaked` (edge), 57 to 59, also with no core vector.
    // 2026-11-02: canonical.json's fetch_proofs (§8.3, the audience) added bad-auth and not-authorized, 40 and 41.
    // The vector claim's unit: a code of Appendix A that some case gives as
    // its `result`. The relay and edge codes but these have no core vector; §8's vectors are deferred.
    fn walk(v: &Value, found: &mut std::collections::BTreeSet<String>) {
        match v {
            Value::Object(m) => {
                if let Some(Value::String(r)) = m.get("result") {
                    found.insert(r.clone());
                }
                m.values().for_each(|x| walk(x, found));
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, found)),
            _ => {}
        }
    }
    let mut found = std::collections::BTreeSet::new();
    for name in [
        "canonical",
        "envelope",
        "sealed-multi",
        "chain-valid",
        "chain-invalid",
        "records",
        "hpke-rfc9180-subset",
        "discovery",
    ] {
        walk(&vectors(name), &mut found);
    }
    let with: Vec<&str> = Code::ALL.iter().map(|c| c.as_str()).filter(|c| found.contains(*c)).collect();
    assert_eq!((with.len(), Code::ALL.len()), (41, 60), "{with:?}");
    for code in [Code::BadAuth, Code::NotAuthorized] {
        assert!(with.contains(&code.as_str()), "{code:?}: a fetch_proofs verdict");
    }
}

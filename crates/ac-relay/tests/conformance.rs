//! The relay against the shared test vectors (spec/vectors/, spec/SPEC.md §8 and §11): every envelope parse and
//! outer-check case, every chain, every vector envelope and every record goes through publish (and fetch), with
//! the code and the status of Appendix A. `ac-core`'s own conformance test checks the values; this one checks that
//! the relay's policy composes them in the spec's order.

use ac_core::chain::{self, Hop};
use ac_core::envelope::{Envelope, Sealed, Wrap};
use ac_core::keys::SigningKey;
use ac_core::records::{AcceptFromRecord, Record, Roots};
use ac_core::requests::fetch_preimage;
use ac_core::{Address, Code, hex};
use ac_relay::auth::FetchHeaders;
use ac_relay::clock::{Clock, ManualClock};
use ac_relay::relay::status;
use ac_relay::store::memory::MemoryStore;
use ac_relay::{Config, Published, Relay};
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn vectors(name: &str) -> Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors").join(format!("{name}.json"));
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
        .unwrap()
}

fn cases<'a>(file: &'a Value, key: &str) -> &'a [Value] {
    file[key].as_array().unwrap()
}

fn expected(v: &Value) -> Option<Code> {
    match v["result"].as_str().unwrap() {
        "ok" => None,
        other => Some(Code::from_wire(other).unwrap()),
    }
}

/// The key of a vector address: every seed in the vectors is one byte repeated 32 times (spec/SPEC.md §11).
fn key_of(address: &Address) -> SigningKey {
    (0..=u8::MAX)
        .map(|n| SigningKey::from_seed(&[n; 32]))
        .find(|k| &k.address() == address)
        .unwrap_or_else(|| panic!("{address} has no one-byte seed"))
}

struct Fixture {
    relay: Relay,
    clock: Arc<ManualClock>,
}

/// The fixture relay's public base URL, the audience of its fetch proofs.
const BASE: &str = "https://relay.example";

fn relay_at(now: u64, config: Config) -> Fixture {
    let clock = Arc::new(ManualClock::new(now));
    let config = Config { url: Some(BASE.to_owned()), ..config };
    Fixture { relay: Relay::new(Arc::new(MemoryStore::new()), clock.clone(), config), clock }
}

impl Fixture {
    /// Hosts each address with an accept-from record for every root, signed with its seed.
    fn host(&self, to: &[Address]) {
        for a in to {
            let mut r = Record::AcceptFrom(AcceptFromRecord {
                owner: a.clone(),
                roots: Roots::Any,
                max_bytes: 65_536,
                ttl: 604_800,
                iat: self.clock.now(),
                sig: [0; 64],
            });
            r.sign(&key_of(a)).unwrap();
            assert!(matches!(self.relay.publish(&r.to_bytes(), IP), Ok(Published::Record { .. })));
        }
    }

    /// The verdict of a publish: `None` when accepted, else the code, after checking its status.
    fn verdict(&self, body: &[u8]) -> Option<Code> {
        match self.relay.publish(body, IP) {
            Ok(_) => None,
            Err(r) => {
                let code = r.code.expect("a code, not a 500");
                assert_eq!(r.status, status(code), "{code}");
                Some(code)
            }
        }
    }

    fn fetch(&self, id: &str, signer: &SigningKey) -> Result<Vec<u8>, ac_relay::Rejection> {
        let now = self.clock.now();
        let proof = fetch_preimage(&signer.address(), id, now, BASE);
        let sig = hex::encode(&signer.sign_preimage(&proof).unwrap());
        let (who, ts) = (signer.address().to_string(), now.to_string());
        let headers = FetchHeaders { signer: Some(&who), ts: Some(&ts), sig: Some(&sig), auth: None };
        self.relay.fetch(id, &headers).map(|stored| stored.bytes)
    }
}

fn parse_bytes(case: &Value) -> Vec<u8> {
    let mut bytes = match case.get("bytes_hex").and_then(Value::as_str) {
        Some(h) => hex::decode(h).unwrap(),
        None => case["bytes"].as_str().unwrap().as_bytes().to_vec(),
    };
    let pad = usize::try_from(case.get("pad_with_spaces").and_then(Value::as_u64).unwrap_or(0)).unwrap();
    bytes.resize(bytes.len() + pad, b' ');
    bytes
}

/// The valid single-recipient envelope the parse and verify cases are made from.
fn base_envelope() -> Envelope {
    let file = vectors("envelope");
    let valid = cases(&file, "parse").iter().find(|c| c["result"] == "ok").unwrap();
    Envelope::parse(&parse_bytes(valid)).unwrap()
}

#[test]
fn every_parse_case_through_publish() {
    let file = vectors("envelope");
    let base = base_envelope();
    let f = relay_at(base.ts, Config::default());
    f.host(&base.to);
    for case in cases(&file, "parse") {
        assert_eq!(f.verdict(&parse_bytes(case)), expected(case), "{}", case["name"]);
    }
}

#[test]
fn every_outer_check_case_through_publish() {
    let file = vectors("envelope");
    for case in cases(&file, "verify") {
        let n = |k: &str| case[k].as_u64().unwrap();
        let f = relay_at(n("now"), Config { ttl: n("ttl"), skew: n("skew"), ..Config::default() });
        let bytes = case["bytes"].as_str().unwrap().as_bytes();
        f.host(&Envelope::parse(bytes).unwrap().to);
        assert_eq!(f.verdict(bytes), expected(case), "{}", case["name"]);
    }
}

#[test]
fn every_vector_envelope_is_delivered_once_and_fetched_back_exactly() {
    for file in ["envelope", "sealed-multi"] {
        let file = vectors(file);
        for case in cases(&file, "cases") {
            let name = &case["name"];
            let bytes = case["expected"]["bytes"].as_str().unwrap().as_bytes();
            let env = Envelope::parse(bytes).unwrap();
            let f = relay_at(env.ts, Config::default());
            f.host(&env.to);
            match f.relay.publish(bytes, IP).unwrap() {
                Published::Envelope { id, duplicate, delivered, root, .. } => {
                    assert_eq!(
                        (id.as_str(), duplicate, delivered),
                        (env.id_hex().as_str(), false, env.to.len()),
                        "{name}"
                    );
                    assert_eq!(root, case["expected"]["chain"]["root"].as_str().unwrap(), "{name}");
                }
                record @ Published::Record { .. } => panic!("{name}: {record:?}"),
            }
            let sender = SigningKey::from_seed(
                &hex::decode_array::<32>(case["inputs"]["from_seed"].as_str().unwrap()).unwrap(),
            );
            assert_eq!(f.fetch(&env.id_hex(), &sender).unwrap(), bytes, "{name}");
            for to in &env.to {
                assert_eq!(f.fetch(&env.id_hex(), &key_of(to)).unwrap(), bytes, "{name}");
            }
            assert!(
                matches!(f.relay.publish(bytes, IP), Ok(Published::Envelope { duplicate: true, .. })),
                "{name}"
            );
        }
    }
}

/// An envelope from the chain case's sender to one recipient, carrying the case's chain at the case's `ts`.
fn chain_envelope(case: &Value, to: &Address) -> Vec<u8> {
    let from = Address::parse(case["from"].as_str().unwrap()).unwrap();
    let ts = case["ts"].as_u64().unwrap();
    let sealed = Sealed {
        wraps: vec![Wrap { to: to.clone(), enc: "ab".repeat(32), ct: "cd".repeat(48) }],
        nonce: "ef".repeat(12),
        ct: "01".repeat(32),
    };
    // Rules 5 to 9 need a signed envelope: the relay checks the id and the signature first.
    if let Ok(hops) = chain::check_shape(Some(&case["auth"])) {
        return Envelope::sign(&key_of(&from), vec![to.clone()], hops, ts, sealed).unwrap().to_bytes();
    }
    // Rules 1 to 4 fail at parsing, before any signature: the chain goes into a valid envelope as it is.
    let base = Envelope::sign(&key_of(&from), vec![to.clone()], Vec::<Hop>::new(), ts, sealed).unwrap();
    let mut json: Value = serde_json::from_str(&base.to_json_text()).unwrap();
    json["auth"] = case["auth"].clone();
    json.to_string().into_bytes()
}

#[test]
fn every_chain_case_through_publish() {
    let recipient = SigningKey::from_seed(&[0xee; 32]).address();
    for (file, ok) in [("chain-valid", true), ("chain-invalid", false)] {
        let file = vectors(file);
        for case in cases(&file, "cases") {
            let f = relay_at(case["ts"].as_u64().unwrap(), Config::default());
            f.host(std::slice::from_ref(&recipient));
            let verdict = f.verdict(&chain_envelope(case, &recipient));
            assert_eq!(verdict, expected(case), "{}", case["name"]);
            assert_eq!(verdict.is_none(), ok, "{}", case["name"]);
        }
    }
}

#[test]
fn every_record_case_through_publish_at_each_time() {
    let file = vectors("records");
    for case in cases(&file, "cases") {
        let bytes = serde_json::to_vec(&case["record"]).unwrap();
        for check in cases(case, "checks") {
            let f = relay_at(
                check["now"].as_u64().unwrap(),
                Config { skew: check["skew"].as_u64().unwrap(), ..Config::default() },
            );
            let verdict = f.verdict(&bytes);
            assert_eq!(verdict, expected(check), "{} at {}", case["name"], check["now"]);
            if verdict.is_none() {
                let kind = case["record"]["kind"].as_str().unwrap();
                assert_eq!(
                    f.relay.fetch_record(case["signer"].as_str().unwrap(), kind).unwrap(),
                    bytes,
                    "{}",
                    case["name"]
                );
                // The same record again is not newer: 409.
                assert_eq!(f.verdict(&bytes), Some(Code::StaleRecord), "{}", case["name"]);
            }
        }
    }
}

#[test]
fn every_invalid_record_through_publish() {
    let file = vectors("records");
    let f = relay_at(1_800_000_000, Config::default());
    for case in cases(&file, "invalid") {
        assert_eq!(
            f.verdict(&serde_json::to_vec(&case["record"]).unwrap()),
            expected(case),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn every_rotation_through_publish() {
    // The relay checks a rotation against the stored record of `rotated_from` when it holds one, and otherwise checks
    // the rotation's claim alone, under `rotated_from` (§7.3): the vector's verdict applies whenever the record names a
    // previous key, held or not, and a record that names none is stored. (Changed 2026-10-25; until then a record
    // naming a previous key the relay does not hold was stored.)
    let file = vectors("records");
    for case in cases(&file, "rotations") {
        let (prev, next) = (&case["prev"], &case["next"]);
        let f = relay_at(prev["iat"].as_u64().unwrap(), Config::default());
        assert_eq!(
            f.verdict(&serde_json::to_vec(prev).unwrap()),
            None,
            "{}: the previous record",
            case["name"]
        );
        f.clock.set(next["iat"].as_u64().unwrap());
        let held = next["rotated_from"] == prev["key"];
        let want = if held || !next["rotated_from"].is_null() { expected(case) } else { None };
        assert_eq!(f.verdict(&serde_json::to_vec(next).unwrap()), want, "{}", case["name"]);
    }
}

#[test]
fn every_record_parse_case_through_publish() {
    // Appended 2026-10-25: records.json "parse" holds bytes that no parsed object can carry, a
    // member name given twice and numbers not written as plain integers (§2.5), so they go through publish here.
    let file = vectors("records");
    for case in cases(&file, "parse") {
        let f = relay_at(1_800_000_000, Config::default());
        assert_eq!(f.verdict(&parse_bytes(case)), expected(case), "{}", case["name"]);
    }
}

#[test]
fn every_handle_record_through_publish_is_a_kind_the_relay_does_not_keep() {
    // 2026-10-26 (spec/SPEC.md §7.1, §8.2): a handle record is served by its domain and never
    // stored by a relay, so publish refuses each one of discovery.json, valid or not, 400 `bad-record`, as any kind the
    // relay does not know, and a fetch of the kind `handle` is 404.
    let file = vectors("discovery");
    let f = relay_at(1_800_000_000, Config::default());
    let mut refused = 0;
    for list in ["cases", "invalid"] {
        for case in cases(&file, list) {
            let body = serde_json::to_vec(&case["record"]).unwrap();
            assert_eq!(f.verdict(&body), Some(Code::BadRecord), "{list}: {}", case["name"]);
            refused += 1;
        }
    }
    assert_eq!(refused, 7 + 17);
    let org = cases(&file, "cases")[0]["record"]["org"].as_str().unwrap();
    let fetched = f.relay.fetch_record(org, "handle").expect_err("no handle record is held");
    assert_eq!((fetched.status, fetched.code), (404, Some(Code::NotFound)));
}

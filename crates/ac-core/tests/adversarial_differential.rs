//! The Rust reader of the differential cases and the proof of the seeded generator (G2).
//!
//! Every `spec/adversarial/*.json` file but `rng-expected.json` holds cases written by
//! `packages/core/scripts/gen-adversarial.ts`: an input, a `kind`, the TypeScript verdict (`expected`) and, for
//! a sanctioned difference, `allowed.rs`. For each case the Rust verdict of its kind
//! (`support::case_verdict`, the contract of `spec/adversarial/README.md`) must equal `expected` or
//! `allowed.rs.verdict`; anything else is an unexpected divergence and fails the test. `open` cases are skipped
//! and counted: the Rust core has no HPKE. With no case file at all the test passes with zero cases, so it is
//! never red for a file not yet generated. One summary line per file: cases, agreed, allowed divergences.
//!
//! Round 2 added the `round2-*.json` files and the `rotation-claim` kind (a record judged by a reader that
//! holds no record of its `rotated_from`, `records::verify_rotation_claim`). In those files `expected` is the
//! pre-registered verdict, so a Rust verdict that differs is reported here as an unexpected divergence.

mod support;

use support::{STUDY_SEED, xorshift_rng};

/// The first three 32-byte draws of the TypeScript `xorshiftRng` for seeds 1, 2 and 20261025, computed with
/// `packages/core/test/support/rng.ts` under Node 24 (test data: the output of a test generator).
const EXPECTED_DRAWS: [(u64, [&str; 3]); 3] = [
    (
        1,
        [
            "0c6a9f917ef23d9b5145dced970b3c913ce338b4985274b8a20c514d9633aaed",
            "a3ecf19f41655cea384d64a6329e4c367f8d6292a8953129eca2bed1757e2989",
            "cbdfb53c688f16b481c74362c04fb851b59422154c699e08c9b791e4da238edb",
        ],
    ),
    (
        2,
        [
            "dd14a67b50aa28826d64d997ce561f367f9698bfc27f33061e651ce3834ec234",
            "b6f9228a3956ae51575d0b59d01e545f7e870979e809e7200f94764c0e4f7ea0",
            "5421b2620103b58e0671fd869db7d85661d88f79463d324d994c80ad8bc00bca",
        ],
    ),
    (
        STUDY_SEED,
        [
            "f1e2e836dcc892878ceea762c61edc2da77cfd0f9009041a4e20a1e4066696d3",
            "bb1bd3b702f73e71bd99549912f7b49fab8c31be75e484b0726e8071084c708b",
            "9407ab063be8edd657933769e8767a48d8a80b8fe573b3cce3bf03174309c1f7",
        ],
    ),
];

#[test]
fn g2_the_rng_twin_reproduces_the_typescript_draws() {
    let file = std::fs::read(support::repo("spec/adversarial/rng-expected.json")).ok();
    let committed: Option<serde_json::Value> = file.map(|raw| serde_json::from_slice(&raw).unwrap());
    for (seed, draws) in EXPECTED_DRAWS {
        let mut rng = xorshift_rng(seed);
        for (i, want) in draws.iter().enumerate() {
            assert_eq!(ac_core::hex::encode(&rng(32)), *want, "seed {seed}, draw {i}");
            if let Some(file) = &committed {
                assert_eq!(
                    file["seeds"][seed.to_string()][i],
                    *want,
                    "rng-expected.json, seed {seed}, draw {i}"
                );
            }
        }
    }
    // Lengths that are not a multiple of 8 drop the bytes past n, word by word.
    let mut whole = xorshift_rng(1);
    let mut cut = xorshift_rng(1);
    assert_eq!(cut(5), whole(8)[..5]);
    assert_eq!(cut(3), whole(8)[..3]);
}

/// One file's count.
#[derive(Default)]
struct Count {
    cases: usize,
    agreed: usize,
    allowed: usize,
    skipped: usize,
    divergences: Vec<String>,
}

fn read_file(path: &std::path::Path) -> Count {
    let file: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap())
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut count = Count::default();
    for case in file["cases"].as_array().unwrap_or_else(|| panic!("{}: no cases", path.display())) {
        count.cases += 1;
        let kind = case["kind"].as_str().unwrap();
        let Some(got) = support::case_verdict(kind, &case["input"]) else {
            count.skipped += 1;
            continue;
        };
        let expected = case["expected"].as_str().unwrap();
        if got == expected {
            count.agreed += 1;
        } else if case["allowed"]["rs"]["verdict"].as_str() == Some(got.as_str()) {
            count.allowed += 1;
        } else {
            count.divergences.push(format!("{}: rust {got}, expected {expected}", case["name"]));
        }
    }
    count
}

#[test]
fn every_differential_case_gets_its_verdict_or_its_allowed_one() {
    let dir = support::repo("spec/adversarial");
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .map(|entries| entries.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default();
    files.retain(|p| {
        p.extension().is_some_and(|e| e == "json") && p.file_name().is_some_and(|n| n != "rng-expected.json")
    });
    files.sort();
    let mut divergences = Vec::new();
    let mut total = 0;
    for path in &files {
        let count = read_file(path);
        let name = path.file_name().unwrap().to_string_lossy();
        eprintln!(
            "diff rust {name}: {} cases, {} agreed, {} allowed divergences, {} skipped (open: no HPKE in Rust), {} \
             unexpected",
            count.cases,
            count.agreed,
            count.allowed,
            count.skipped,
            count.divergences.len()
        );
        total += count.cases;
        divergences.extend(count.divergences);
    }
    eprintln!("diff rust: {} files, {total} cases", files.len());
    assert!(
        divergences.is_empty(),
        "{} unexpected divergences, the first: {:#?}",
        divergences.len(),
        &divergences
    );
}

/// A one-byte change planted in the expected verdict of the first case of each kind in each round-2
/// file is caught, so the Rust reader judges every round-2 kind (the new `rotation-claim` included) instead of
/// passing it by default; `open` is the one kind it skips (no HPKE in Rust).
#[test]
fn v4_a_planted_wrong_verdict_is_caught_in_round_2() {
    let dir = support::repo("spec/adversarial");
    let mut judged = Vec::new();
    for name in [
        "round2-domains.json",
        "round2-records.json",
        "round2-keys.json",
        "round2-duplicates.json",
        "round2-numbers.json",
    ] {
        let raw = std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let file: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for case in file["cases"].as_array().unwrap() {
            let kind = case["kind"].as_str().unwrap();
            if !seen.insert(kind.to_owned()) {
                continue;
            }
            let Some(got) = support::case_verdict(kind, &case["input"]) else {
                assert_eq!(kind, "open", "{name}: the Rust reader skipped a {kind} case");
                continue;
            };
            let expected = case["expected"].as_str().unwrap();
            let last = if expected.ends_with('x') { "y" } else { "x" };
            let planted = format!("{}{last}", &expected[..expected.len() - 1]);
            assert_eq!(got, expected, "{name} {}", case["name"]);
            assert_ne!(got, planted, "{name} {}: a planted verdict was not caught", case["name"]);
            judged.push(format!("{name} {kind}"));
        }
    }
    eprintln!("round-2 rust: {} planted verdicts caught: {judged:?}", judged.len());
    // 12 kinds in the four files of the first read, and json, parse and record in round2-numbers.json (T7).
    assert_eq!(judged.len(), 15, "{judged:?}");
}

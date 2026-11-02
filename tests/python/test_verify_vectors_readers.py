"""scripts/verify_vectors.py on the reader rules of 2026-10-25: a member name given twice is refused
in every peer text, the sealed content included (spec/SPEC.md §2.5); accept-from roots hold at most 1,024 entries;
a key record lives a day at most; a rotation claim is checked under rotated_from by a reader that holds no
previous record (§7.3); and the count of Appendix A codes with a vector verdict is 37 of 55 (39 of 55 since
discovery.json, 2026-10-26, which adds resolve-failed and revoked; 41 of 60 since canonical.json's fetch_proofs,
2026-11-02, which adds bad-auth and not-authorized)."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("verify_vectors", ROOT / "scripts" / "verify_vectors.py")
assert _SPEC is not None and _SPEC.loader is not None
vv = importlib.util.module_from_spec(_SPEC)
sys.modules["verify_vectors"] = vv
_SPEC.loader.exec_module(vv)

if vv.CRYPTO is None:  # a missing package fails, never skips
    raise AssertionError("cryptography is not importable: the reader checks would not run")

VECTORS = ROOT / "spec" / "vectors"
RECORDS = json.loads((VECTORS / "records.json").read_text(encoding="utf-8"))


def record_of(kind: str) -> dict:
    return copy.deepcopy(next(c["record"] for c in RECORDS["cases"] if c["record"]["kind"] == kind))


def test_a_member_name_given_twice_is_refused_with_the_code_of_its_place() -> None:
    for text in ('{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '[{"x":{"b":1,"b":1}}]', '{"":1,"":1}'):
        assert vv.verdict(lambda t=text: vv.parse_json(t.encode())) == "bad-json", text
        assert vv.verdict(lambda t=text: vv.parse_json(t.encode(), "bad-content", strict_integers=False)) == "bad-content"
    for text in ('[{"a":1},{"a":1}]', '{"a":{"a":1}}', '{"a":"a","b":"a"}', '{"a\\\\":1,"a":2}'):
        assert vv.parse_json(text.encode()) == json.loads(text), text


def test_the_sealed_content_reads_numbers_freely_but_not_duplicates() -> None:
    thread = json.dumps({"id": "ab" * 32, "prev": []})
    body = f'{{"type":"t","thread":{thread},"body":{{"x":1.5,"y":[1e0]}}}}'.encode()
    assert vv.decode_content(body)["body"] == {"x": 1.5, "y": [1.0]}
    doubled = f'{{"type":"t","thread":{thread},"body":{{"repo":"a","repo":"b"}}}}'.encode()
    assert vv.verdict(lambda: vv.decode_content(doubled)) == "bad-content"


def test_accept_from_roots_are_capped_at_1024() -> None:
    r = record_of("accept-from")
    roots = [f"ed25519:{vv.sha256hex(f'root {i}')}" for i in range(1025)]
    assert vv.verdict(lambda: vv.check_record({**r, "roots": roots[:1024]})) == "ok"
    assert vv.verdict(lambda: vv.check_record({**r, "roots": roots})) == "bad-record"
    assert vv.verdict(lambda: vv.check_record({**r, "roots": [*roots[:1024], "domain:acme.example"]})) == "bad-record"


def test_a_key_record_lives_a_day_at_most() -> None:
    r = record_of("key")
    for span, want in ((0, "ok"), (86_400, "ok"), (86_401, "bad-record"), (-1, "bad-record")):
        assert vv.verdict(lambda s=span: vv.check_record({**r, "exp": r["iat"] + s})) == want, span


def test_a_rotation_claim_is_checked_under_rotated_from() -> None:
    claims = {c["name"]: c for c in RECORDS["rotation_claims"]}
    assert len(claims) == 5
    for c in claims.values():
        assert vv.verdict(lambda c=c: vv.verify_rotation_claim(c["next"])) == c["result"], c["name"]
    tampered = copy.deepcopy(next(c["next"] for c in claims.values() if c["result"] == "ok" and c["next"]["rotated_from"]))
    tampered["relays"] = ["https://elsewhere.example"]
    assert vv.verdict(lambda: vv.verify_rotation_claim(tampered)) == "bad-rotation"
    assert vv.verdict(lambda: vv.verify_rotation_claim(record_of("key"))) == "bad-record"


def test_the_vectors_give_a_verdict_for_41_of_the_60_codes() -> None:
    files = {name: json.loads((VECTORS / name).read_text(encoding="utf-8")) for name in vv.FILES}
    with_verdict, codes = vv.codes_with_a_verdict(files)
    assert (len(with_verdict), len(codes)) == (41, 60)
    assert "resolve-failed" in with_verdict and "revoked" in with_verdict
    assert "bad-auth" in with_verdict and "not-authorized" in with_verdict  # the fetch proofs' verdicts
    assert "internal" in codes and "unreachable" in codes and "store-full" in codes
    assert "bad-key" in with_verdict and "open-failed" in with_verdict and "caveat-failed" in with_verdict

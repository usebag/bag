"""scripts/verify_adversarial.py : the Python reader agrees with every committed case, or diverges
as the case allows, and a planted wrong verdict is caught (line G3)."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
_SPEC = importlib.util.spec_from_file_location("verify_adversarial", ROOT / "scripts" / "verify_adversarial.py")
va = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(va)
CASES = ROOT / "spec" / "adversarial"


def test_the_committed_cases_agree_and_the_controls_are_caught() -> None:
    assert va.main([str(CASES), "--controls"]) == 0


def test_a_planted_wrong_verdict_is_caught(tmp_path: Path) -> None:
    for name in va.FILES:
        shutil.copy(CASES / name, tmp_path / name)
    path = tmp_path / "chain-mutations.json"
    f = json.loads(path.read_text(encoding="utf-8"))
    case = next(c for c in f["cases"] if c["expected"] == "bad-hop-sig")
    case["expected"] = "bad-hop-siG"
    path.write_text(json.dumps(f), encoding="utf-8")
    tally = va.check_file("chain-mutations.json", f)
    assert [u.split(" ")[0] for u in tally["unexpected"]] == [case["name"]]
    assert va.main([str(tmp_path)]) == 1


ROUND2 = (
    "round2-domains.json",
    "round2-records.json",
    "round2-keys.json",
    "round2-duplicates.json",
    "round2-numbers.json",
)


def test_the_round_2_files_are_read() -> None:
    """The reader checks the round-2 files, every case judged and none skipped."""
    assert set(ROUND2) <= set(va.FILES)
    for name in ROUND2:
        f = json.loads((CASES / name).read_text(encoding="utf-8"))
        tally = va.check_file(name, f)
        assert tally["cases"] == len(f["cases"]) > 0
        assert tally["agreed"] == tally["cases"], tally["unexpected"][:3]
        assert tally["skipped"] == 0


def test_the_rotation_claim_kind_is_judged_and_a_planted_verdict_caught() -> None:
    """The rotation-claim kind runs verify_record, then verify_rotation_claim."""
    f = json.loads((CASES / "round2-records.json").read_text(encoding="utf-8"))
    claims = [c for c in f["cases"] if c["kind"] == "rotation-claim"]
    assert {va.verdict_of(c) for c in claims} == {"ok", "bad-rotation"}
    for c in claims:
        assert va.verdict_of(c) == c["expected"], c["name"]
        planted = dict(c, expected=va.one_byte(c["expected"]))
        assert va.check_file("round2-records.json", {"cases": [planted]})["unexpected"]
    # The claim is read after the record itself: a record whose own sig is broken is bad-record-sig, not a claim verdict.
    good = next(c for c in claims if c["expected"] == "ok" and "control-rotation-sig-by-rotated-from" in c["name"])
    record = json.loads(bytes.fromhex(good["input"]["bytes_hex"]))
    record["sig"] = ("0" if record["sig"][0] != "0" else "1") + record["sig"][1:]
    broken = dict(good, input=dict(good["input"], bytes_hex=json.dumps(record).encode().hex()))
    assert va.verdict_of(broken) == "bad-record-sig"


def test_t7_a_number_past_a_doubles_range_is_bad_content_in_the_seal_and_bad_json_outside() -> None:
    """The open cases past the range are bad-content, their json twins and the parse and
    record cases bad-json, the finite controls ok; and verify_vectors.decode_content, the oracle's own reader, agrees
    with check_content on each open case's plaintext."""
    f = json.loads((CASES / "round2-numbers.json").read_text(encoding="utf-8"))
    by_kind: dict[str, set[str]] = {}
    for c in f["cases"]:
        assert va.verdict_of(c) == c["expected"], c["name"]
        by_kind.setdefault(c["kind"], set()).add(c["expected"])
    assert by_kind == {
        "open": {"ok", "bad-content"},
        "json": {"ok", "bad-json"},
        "parse": {"ok", "bad-json"},
        "record": {"ok", "bad-json"},
    }
    for c in f["cases"]:
        if c["kind"] != "json":
            continue
        pt = bytes.fromhex(c["input"]["bytes_hex"])
        want = "bad-content" if c["expected"] == "bad-json" else "ok"
        assert va.vv.verdict(lambda pt=pt: va.vv.decode_content(pt)) == want, c["name"]
        assert va.vv.verdict(lambda pt=pt: va.check_content(pt)) == want, c["name"]


def content_of(type_json: str) -> bytes:
    return f'{{"type":{type_json},"thread":{{"id":"{"ab" * 32}","prev":[]}},"body":{{"n":1.5}}}}'.encode()


def test_check_content_is_the_oracles_one_predicate(monkeypatch) -> None:
    """examples/python-join-type-guard: check_content has no copy of §5.2, it calls verify_vectors.decode_content."""
    seen: list[bytes] = []
    monkeypatch.setattr(va.vv, "decode_content", seen.append)
    va.check_content(b"anything")
    assert seen == [b"anything"]


def test_a_type_that_is_not_a_non_empty_string_is_bad_content_and_a_string_is_not() -> None:
    """§5.2: a non-string or empty type is bad-content by the one predicate; a plain or a space-only string passes."""
    for bad in ('""', "1", "null", "true", "[]", '{"a":"b"}', '["chat.v1"]'):
        assert va.vv.verdict(lambda b=bad: va.check_content(content_of(b))) == "bad-content", bad
    for good in ('"chat.v1"', '" "'):
        assert va.vv.verdict(lambda g=good: va.check_content(content_of(g))) == "ok", good

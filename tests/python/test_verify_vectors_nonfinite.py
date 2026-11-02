"""scripts/verify_vectors.py refuses a number past a double's range inside the sealed content as bad-content
(changed 2026-10-25): the body is exempt from the integer rule only (spec/SPEC.md §4.2), not from §2.5's
range of a double, as the TypeScript core and scripts/verify_adversarial.py read it."""

from __future__ import annotations

import importlib.util
import json
import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("verify_vectors", ROOT / "scripts" / "verify_vectors.py")
vv = importlib.util.module_from_spec(_SPEC)
sys.modules["verify_vectors"] = vv
_SPEC.loader.exec_module(vv)

PAST = ["1e400", "-1e400", "1E400", "1.7976931348623159e308", "1" + "0" * 400, "-1" + "0" * 400]
CARRIED = [
    ("1e-400", 0.0),
    ("1e308", 1e308),
    ("1.5", 1.5),
    ("1.0", 1.0),
    ("1e+16", 1e16),
    ("9007199254740993", 2**53 + 1),
]
THREAD = json.dumps({"id": "ab" * 32, "prev": []}, separators=(",", ":"))


def content(body: str) -> bytes:
    return f'{{"type":"t","thread":{THREAD},"body":{body}}}'.encode()


@pytest.mark.parametrize("n", PAST)
def test_a_number_past_a_doubles_range_is_refused_with_strict_integers_off(n: str) -> None:
    assert vv.verdict(lambda: vv.parse_json(f"[{n}]".encode(), strict_integers=False)) == "bad-json"
    nested = f'{{"x":[1.5,{{"y":{n}}}]}}'.encode()
    assert vv.verdict(lambda: vv.parse_json(nested, "bad-content", strict_integers=False)) == "bad-content"
    assert vv.verdict(lambda: vv.parse_json(f"[{n}]".encode())) == "bad-json"


@pytest.mark.parametrize("n", PAST)
def test_decode_content_refuses_it_in_the_body_as_bad_content(n: str) -> None:
    assert vv.verdict(lambda: vv.decode_content(content(n))) == "bad-content"
    assert vv.verdict(lambda: vv.decode_content(content(f'{{"a":[0,{n}]}}'))) == "bad-content"


@pytest.mark.parametrize(("n", "value"), CARRIED)
def test_a_finite_body_number_is_carried(n: str, value: float) -> None:
    body = vv.decode_content(content(n))["body"]
    assert body == value and not math.isnan(body)
    assert vv.parse_json(n.encode(), strict_integers=False) == value


def test_the_largest_double_is_carried() -> None:
    assert vv.parse_json(b"1.7976931348623157e308", strict_integers=False) == sys.float_info.max

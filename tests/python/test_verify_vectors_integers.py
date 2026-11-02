"""scripts/verify_vectors.py reads a number only when it is written as a plain decimal integer of at most 2^53 - 1
(spec/SPEC.md §2.5, changed 2026-10-25), with the code of the place that reads it, as TypeScript and
Rust do."""

from __future__ import annotations

import importlib.util
import json
import math
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("verify_vectors", ROOT / "scripts" / "verify_vectors.py")
vv = importlib.util.module_from_spec(_SPEC)
sys.modules["verify_vectors"] = vv
_SPEC.loader.exec_module(vv)

NOT_PLAIN = ["1.0", "1e0", "1E0", "-0", "-1", "0.5", "1e-400", "9007199254740990.9", "9007199254740992"]
NOT_JSON = ["01", "1e400", "-1e400"]
PLAIN = [("0", 0), ("1", 1), ("9007199254740991", 2**53 - 1)]
ENVELOPE = json.loads((ROOT / "spec" / "vectors" / "envelope.json").read_text(encoding="utf-8"))["cases"][1]
TEXT = ENVELOPE["expected"]["bytes"]
CODES = {"v": "bad-version", "suite": "bad-suite", "ts": "bad-shape", "exp": "bad-hop"}


def respell(field: str, spelling: str) -> bytes:
    text, n = re.subn(f'"{field}":[0-9]+', f'"{field}":{spelling}', TEXT, count=1)
    assert n == 1
    return text.encode("utf-8")


def test_parse_json_keeps_plain_integers_and_reads_other_numbers_as_nan() -> None:
    for text, n in PLAIN:
        assert vv.parse_json(f"[{text}]".encode()) == [n]
    for text in NOT_PLAIN:
        assert math.isnan(vv.parse_json(f"[{text}]".encode())[0]), text
    for text in NOT_JSON:
        assert vv.verdict(lambda t=text: vv.parse_json(f"[{t}]".encode())) == "bad-json", text


@pytest.mark.parametrize("field", list(CODES))
def test_the_envelope_reader_refuses_each_spelling_with_its_code(field: str) -> None:
    for s in NOT_PLAIN:
        assert vv.verdict(lambda s=s: vv.parse_envelope(respell(field, s))) == CODES[field], s
    for s in NOT_JSON:
        assert vv.verdict(lambda s=s: vv.parse_envelope(respell(field, s))) == "bad-json", s


def test_v_and_suite_are_integers_and_plain_ts_and_exp_are_taken() -> None:
    e = vv.parse_envelope(TEXT.encode("utf-8"))
    assert type(e["v"]) is int and type(e["suite"]) is int
    for field in ("ts", "exp"):
        for s, _ in PLAIN:
            assert vv.verdict(lambda f=field, s=s: vv.parse_envelope(respell(f, s))) == "ok"

"""scripts/verify_vectors.py on discovery.json (2026-10-26; spec/SPEC.md §12):
the verifier reads the TXT text form, the TXT records of a lookup, a record's agreement with its TXT and
the pin after it, handles and handle records from the spec alone, and catches a changed verdict, a changed record URL,
a changed pin and a changed signature."""

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
    raise AssertionError("cryptography is not importable: the discovery checks would not run")

DISCOVERY = json.loads((ROOT / "spec" / "vectors" / "discovery.json").read_text(encoding="utf-8"))
ACME = "acme.example"
KEY = "ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"


def run(f: dict) -> vv.Tally:
    t = vv.Tally(quiet=True)
    vv.check_discovery(f, t)
    return t


def test_every_list_is_read_and_matches() -> None:
    t = run(DISCOVERY)
    assert t.mismatches == [] and t.skipped == []
    kinds = set(t.kinds)
    assert {"txt text verdict", "txt verdict", "txt discovery", "handle verdict", "handle record verdict"} <= kinds
    assert {"agreement verdict", "pin after"} <= kinds
    assert t.total(0) >= 200


def test_a_rec_any_host_but_bag_and_two_records_are_refused_and_none_falls_back() -> None:
    # DNS names no URL, under the domain or not; host is exactly bag or absent.
    refused = [
        [[f"v=ac1; key={KEY}; rec=https://agents.acme.example/org.json".encode()]],
        [[f"v=ac1; key={KEY}; rec=https://{ACME}/.well-known/bag/address.json".encode()]],
        [[f"v=ac1; key={KEY}; host=agents".encode()]],
        [[f"v=ac1; key={KEY}".encode()], [f"v=ac1; key={KEY}".encode()]],
        [[f"v=ac1; key={KEY}; key={KEY}".encode()]],
    ]
    for records in refused:
        assert vv.verdict(lambda r=records: vv.discover(r, ACME)) == "resolve-failed", records
    well_known = (None, f"https://{ACME}/.well-known/bag/address.json", f"https://{ACME}")
    assert vv.discover([], ACME) == well_known
    assert vv.discover([[b"v=spf1 -all"]], ACME) == well_known
    assert vv.discover([[b"v=ac1; ke", f"y={KEY}".encode()]], ACME) == (KEY, *well_known[1:])
    origin = f"https://bag.{ACME}"
    host = [[f"v=ac1; key={KEY}; host=bag".encode()]]
    assert vv.discover(host, ACME) == (KEY, f"{origin}/.well-known/bag/address.json", origin)
    assert vv.discover(host, "acme.local") == (None, "https://acme.local/.well-known/bag/address.json", "https://acme.local")


def test_a_record_agrees_with_its_txt_by_its_key_or_one_countersigned_rotation() -> None:
    # On the committed cases: the verdicts and the pins the three readers give.
    cases = {c["name"]: c for c in DISCOVERY["agreement"]}
    first = cases["k11 countersigned by the TXT's key k10, at first contact: k11 is pinned"]
    assert vv.agrees(first["txt_key"], first["record"]) and vv.pin_after(None, first["record"]) == first["record"]["key"]
    moved = cases["k11 countersigned by the TXT's key k10, k10 pinned: the pin moves to k11"]
    assert vv.pin_after(moved["pinned"], moved["record"]) == moved["record"]["key"]
    for name in ["k11 naming k10, countersigned by another key", "k11 naming k10 with no rotation_sig"]:
        assert not vv.agrees(cases[name]["txt_key"], cases[name]["record"]), name
    kept = cases["the TXT names k11, k10 pinned, a k11 that no rotation links: DNS moves no pin"]
    assert vv.agrees(kept["txt_key"], kept["record"]) and vv.pin_after(kept["pinned"], kept["record"]) == kept["pinned"]["key"]


def test_the_text_form_reads_escapes_and_refuses_the_rest() -> None:
    assert vv.parse_presentation('"a\\059b" c\\"d') == [b"a;b", b'c"d']
    for bad in ["", '"x', '"a\\256"', '"a\\05x"', "é"]:
        assert vv.verdict(lambda b=bad: vv.parse_presentation(b)) == "resolve-failed", bad


def test_a_handle_record_is_checked_in_order() -> None:
    case = DISCOVERY["cases"][0]
    r, first = case["record"], case["checks"][0]
    args = (first["org"], first["handle"], [], first["now"], first["skew"])
    assert vv.verdict(lambda: vv.verify_handle_record(r, *args)) == "ok"
    assert vv.verdict(lambda: vv.verify_handle_record({**r, "ttl": 0}, *args)) == "bad-record"
    assert vv.verdict(lambda: vv.verify_handle_record({**r, "address": KEY}, *args)) == "bad-record-sig"
    other = ("ed25519:" + "11" * 32, *args[1:])
    assert vv.verdict(lambda: vv.verify_handle_record(r, *other)) == "resolve-failed"
    revoked = (args[0], args[1], [r["address"]], *args[3:])
    assert vv.verdict(lambda: vv.verify_handle_record(r, *revoked)) == "revoked"
    assert vv.verdict(lambda: vv.parse_handle("Jane@acme.example")) == "bad-address"


def test_a_changed_url_verdict_or_signature_is_a_mismatch() -> None:
    changes = []
    url = copy.deepcopy(DISCOVERY)
    url["txt"][0]["url"] = "https://agents.acme.example/other.json"
    changes.append(url)
    result = copy.deepcopy(DISCOVERY)
    result["handles"][0]["result"] = "bad-address"
    changes.append(result)
    sig = copy.deepcopy(DISCOVERY)
    sig["cases"][0]["record"]["sig"] = vv.flip_hex(sig["cases"][0]["record"]["sig"])
    changes.append(sig)
    pin = copy.deepcopy(DISCOVERY)
    pin["agreement"][4]["pin"] = pin["agreement"][4]["pinned"]["key"]
    changes.append(pin)
    for f in changes:
        assert run(f).mismatches, "a one-place change went unreported"

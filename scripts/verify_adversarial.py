"""Check the differential cases in spec/adversarial/*.json, with the Python reader (README.md).

    .venv/bin/python -I scripts/verify_adversarial.py [spec/adversarial] [--controls]

The reader is scripts/verify_vectors.py, imported as a module: its JSON reader, canonical form, envelope parsing,
outer checks, chain rules, record checks, rotation check, RFC 9180 open and sealed content (§5.2, decode_content).
This script only composes them in the order each case kind asks for (the README's table). The round2-*.json files
use the rotation-claim kind (verify_record, then verify_rotation_claim). For every case it computes
the Python verdict and compares it with `expected` (the TypeScript core's; in round2-*.json a pre-registered
verdict) or the case's `allowed.py` verdict. It prints one line per file: cases, agreed, allowed divergences,
unexpected divergences, with the first ten unexpected named.

--controls plants a one-byte change in the `expected` verdict of chosen cases, one at a time, and
each must be reported as an unexpected divergence.

Exit 0 when every case agreed or diverged as allowed (and, with --controls, every control was caught); 1 on an
unexpected divergence or a missed control; 2 when nothing diverged but a check was skipped (cryptography missing),
because a skipped check is not run.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_vectors as vv  # noqa: E402  (the oracle: imported, never copied)

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "canonical-fuzz.json",
    "envelope-mutations.json",
    "chain-mutations.json",
    "record-mutations.json",
    "open-cases.json",
    # Round 2: their expected verdicts are pre-registered ones (spec/adversarial/README.md).
    "round2-domains.json",
    "round2-records.json",
    "round2-keys.json",
    "round2-duplicates.json",
    "round2-numbers.json",
)
Rejected = vv.Rejected


def outer(raw: bytes, now: int, ttl: int, skew: int) -> None:
    """§5.4, §5.5 steps 1 to 3, chain rules 1 to 9 at ts, §5.5 step 4: the relay's in-core order."""
    e = vv.parse_envelope(raw)
    vv.verify_outer(e, e["ts"], 0, 0)  # recipients, bad-id, bad-sig; a zero window around ts cannot fail
    vv.verify_chain(e["auth"], e["from"], e["ts"])
    vv.verify_outer(e, now, ttl, skew)  # the ts window (steps 1 to 3 pass again)


def rotation_claim(raw: bytes, now: int, skew: int) -> None:
    """The rotation-claim kind: the JSON reader, §7.5 at now and skew, then §7.3's claim for a reader
    that holds no record of rotated_from (verify_rotation_claim: rotation_sig must verify under rotated_from)."""
    r = vv.parse_json(raw)
    vv.verify_record(r, now, skew)
    vv.verify_rotation_claim(r)


def check_content(pt: bytes) -> None:
    """§5.2 by the oracle's one predicate, verify_vectors.decode_content."""
    vv.decode_content(pt)


def open_sealed(i: dict[str, Any]) -> None:
    """§4.4: the wrap named by the address, opened with the seed; the content under [v, to, from]; then §5.2."""
    vv.need_crypto()
    wrap = next((w for w in i["sealed"]["wraps"] if w["to"] == i["address"]), None)
    if wrap is None:
        raise Rejected("not-recipient")
    try:
        seed = bytes.fromhex(i["seal_seed"])
        key = vv.open_base(
            bytes.fromhex(wrap["enc"]), seed, vv.SEAL_INFO, i["address"].encode("utf-8"), bytes.fromhex(wrap["ct"])
        )
        if len(key) != 32:
            raise ValueError("a content key of another length")
        aad = vv.canonical([i["v"], i["to"], i["from"]]).encode("utf-8")
        pt = vv.aead_open(key, bytes.fromhex(i["sealed"]["nonce"]), aad, bytes.fromhex(i["sealed"]["ct"]))
    except vv.NeedCrypto:
        raise
    except Exception:  # a wrap or content that does not authenticate, a small-order enc, malformed hex
        raise Rejected("open-failed") from None
    check_content(pt)


def canonical_case(i: dict[str, Any]) -> None:
    if "sparse_list" in i:
        raise Rejected("bad-canonical")  # a list with holes: Python cannot hold one, and it has no canonical form
    value = vv.utf16(i["utf16_hex"]) if "utf16_hex" in i else i["value"]
    c = vv.canonical(value)
    if c != i.get("canonical") or vv.sha256hex(c) != i.get("sha256"):
        raise Rejected("wrote-other-bytes")


def run_case(c: dict[str, Any]) -> Callable[[], Any]:
    i, kind = c["input"], c["kind"]
    raw = (lambda k: bytes.fromhex(i[k]))  # noqa: E731
    if kind == "json":
        return lambda: vv.parse_json(raw("bytes_hex"))
    if kind == "parse":
        return lambda: vv.parse_envelope(raw("bytes_hex"))
    if kind == "outer":
        return lambda: outer(raw("bytes_hex"), i["now"], i["ttl"], i["skew"])
    if kind == "chain":
        return lambda: vv.verify_chain(i["auth"], i["from"], i["ts"])
    if kind == "record":
        return lambda: vv.verify_record(vv.parse_json(raw("bytes_hex")), i["now"], i["skew"])
    if kind == "rotation":
        return lambda: vv.verify_rotation(vv.parse_json(raw("prev_bytes_hex")), vv.parse_json(raw("next_bytes_hex")))
    if kind == "rotation-claim":
        return lambda: rotation_claim(raw("bytes_hex"), i["now"], i["skew"])
    if kind == "canonical":
        return lambda: canonical_case(i)
    if kind == "open":
        return lambda: open_sealed(i)
    raise ValueError(f"unknown kind {kind!r}")


def verdict_of(c: dict[str, Any]) -> str:
    """The Python verdict; 'skipped' without cryptography; 'error:<type>' for a crash, which never agrees."""
    try:
        return vv.verdict(run_case(c))
    except vv.NeedCrypto:
        return "skipped"
    except Exception as err:  # a crash is a divergence, never a pass
        return f"error:{type(err).__name__}"


def check_file(name: str, f: dict[str, Any]) -> dict[str, Any]:
    tally: dict[str, Any] = {"cases": 0, "agreed": 0, "allowed": 0, "skipped": 0, "unexpected": []}
    for c in f["cases"]:
        tally["cases"] += 1
        got = verdict_of(c)
        allowed = c.get("allowed", {}).get("py", {}).get("verdict")
        if got == "skipped":
            tally["skipped"] += 1
        elif got == c["expected"]:
            tally["agreed"] += 1
        elif got == allowed:
            tally["allowed"] += 1
        else:
            tally["unexpected"].append(f"{c['name']} (py {got}, ts {c['expected']})")
    return tally


def one_byte(code: str) -> str:
    return code[:-1] + ("x" if code[-1] != "x" else "y")


def run_controls(files: dict[str, dict[str, Any]]) -> tuple[int, int]:
    """(caught, missed): the first, middle and last case of each file, and the first case of each kind in it."""
    caught = missed = 0
    for name, f in files.items():
        cases = f["cases"]
        picks = {0, len(cases) // 2, len(cases) - 1}
        seen: set[str] = set()
        for n, c in enumerate(cases):
            if c["kind"] not in seen:
                seen.add(c["kind"])
                picks.add(n)
        for n in sorted(picks):
            planted = copy.deepcopy(cases[n])
            planted["expected"] = one_byte(planted["expected"])
            planted.pop("allowed", None)
            if check_file(name, {"cases": [planted]})["unexpected"]:
                caught += 1
            else:
                missed += 1
                print(f"  CONTROL MISSED: {name} {cases[n]['name']}: a changed expected verdict was not reported")
    return caught, missed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dir", nargs="?", type=Path, default=ROOT / "spec" / "adversarial")
    ap.add_argument("--controls", action="store_true", help="plant one-byte changes in expected verdicts (G3)")
    a = ap.parse_args(argv)
    print(f"verify_adversarial: {a.dir} (cryptography {vv.CRYPTO or 'missing'})")
    files: dict[str, dict[str, Any]] = {}
    unexpected = skipped = missing = 0
    for name in FILES:
        path = a.dir / name
        if not path.is_file():
            print(f"  {name}: MISSING")
            missing += 1
            continue
        files[name] = json.loads(path.read_text(encoding="utf-8"))
        t = check_file(name, files[name])
        unexpected += len(t["unexpected"])
        skipped += t["skipped"]
        first = "; ".join(t["unexpected"][:10])
        print(
            f"  {name}: {t['cases']} cases, {t['agreed']} agreed, {t['allowed']} allowed divergences, "
            f"{len(t['unexpected'])} unexpected divergences, {t['skipped']} skipped" + (f": {first}" if first else "")
        )
    caught = missed = 0
    if a.controls:
        caught, missed = run_controls(files)
        print(f"  controls: {caught} of {caught + missed} planted one-byte changes caught, {missed} missed")
    if unexpected or missed or missing:
        print(f"verify_adversarial: FAIL: {unexpected} unexpected divergences, {missed} controls missed, {missing} missing")
        return 1
    if skipped:
        print(f"verify_adversarial: NOT RUN IN FULL: {skipped} cases skipped; a skipped check is not a pass")
        return 2
    print("verify_adversarial: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

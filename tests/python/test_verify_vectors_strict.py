"""scripts/verify_vectors.py verify_sig is strict (spec/SPEC.md §10): a small-order or non-canonical key
or R, and S >= L, are refused before cryptography (OpenSSL) sees them; honest signatures still verify. And its fetch
auth check (spec/SPEC.md §8.3, added 2026-11-02): five fields, the audience last, a base with no path; and its reading
of canonical.json's fetch_proofs, the relay's verdict on a fetch proof, on cases made here in the generator's shape."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("verify_vectors", ROOT / "scripts" / "verify_vectors.py")
vv = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(vv)
if vv.CRYPTO is None:  # a missing package fails, never skips
    raise RuntimeError("the cryptography package is missing from .venv")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey  # noqa: E402

FORGED = vv.SMALL_ORDER_POINTS[0] + bytes(32)  # R = identity, S = 0
ALIASES = [bytes.fromhex(h) for h in ("01" + "00" * 30 + "80", "ec" + "ff" * 31)]  # x = 0 with the sign bit set
PLUS_P = [((vv.FIELD_P + y) | s).to_bytes(32, "little") for y in range(19) for s in (0, 1 << 255)]
DEGENERATE = [*vv.SMALL_ORDER_POINTS, *ALIASES, *PLUS_P]
DIGESTS = [hashlib.sha256(f"message {i}".encode()).digest() for i in range(64)]
HONEST = Ed25519PrivateKey.from_private_bytes(bytes([0x21]) * 32)  # test data by construction
PUB, SIG = HONEST.public_key().public_bytes_raw(), HONEST.sign(b"m")
ENV = json.loads((ROOT / "spec" / "vectors" / "envelope.json").read_text())["cases"][0]["expected"]["envelope"]


def test_openssl_alone_accepts_the_forgery_under_the_identity():
    for d in DIGESTS:
        Ed25519PublicKey.from_public_bytes(vv.SMALL_ORDER_POINTS[0]).verify(FORGED, d)  # raises if refused


@pytest.mark.parametrize("key", DEGENERATE, ids=lambda b: b.hex())
def test_a_degenerate_signer_or_r_is_refused_everywhere(key):
    a, ts, f = "ed25519:" + key.hex(), ENV["ts"], FORGED.hex()
    assert not any(vv.verify_sig(key, d, FORGED) for d in DIGESTS)
    assert not vv.verify_sig(PUB, b"m", key + SIG[32:])
    assert not vv.verify_preimage(a, ["ac/fetch/1", a, "ab", 1, "https://relay.example"], f)
    e = {**ENV, "from": a, "sig": f}
    e["id"] = vv.sha256hex(vv.canonical(vv.envelope_id_preimage(e)))
    hop = {"iss": a, "sub": ENV["from"], "caveats": [], "exp": ts + 60, "sig": f}
    rec = {"kind": "key", "key": a, "sealing_key": "00" * 32, "iat": ts, "exp": ts + 60, "sig": f}
    assert vv.verdict(lambda: vv.verify_outer(e, ts, vv.TTL, vv.SKEW)) == "bad-sig"
    assert vv.verdict(lambda: vv.verify_chain([hop], ENV["from"], ts)) == "bad-hop-sig"
    assert vv.verdict(lambda: vv.verify_record(rec, ts, vv.SKEW)) == "bad-record-sig"


def test_s_at_or_above_l_is_refused_and_honest_signatures_verify():
    assert vv.verify_sig(PUB, b"m", SIG)
    s = int.from_bytes(SIG[32:], "little")
    for bad in (vv.ORDER_L, s + vv.ORDER_L, 2**256 - 1):
        assert not vv.verify_sig(PUB, b"m", SIG[:32] + bad.to_bytes(32, "little"))


def test_a_fetch_proof_has_five_fields_and_its_audience_is_a_base_with_no_path():
    a, i, base = "ed25519:" + PUB.hex(), "ab" * 32, "https://relay.example"
    assert vv.fetch_auth_fields(["ac/fetch/1", a, i, 7, base])
    assert vv.fetch_auth_fields(["ac/fetch/1", a, i, 7, "http://127.0.0.1:7701"])
    for audience in [base + "/", base + "/bag", base + "?x", "relay.example", ""]:
        assert not vv.fetch_auth_fields(["ac/fetch/1", a, i, 7, audience]), audience
    for p in [["ac/fetch/1", a, i, 7], ["ac/sub/1", a, i, 7, base], ["ac/fetch/1", a, i.upper(), 7, base]]:
        assert not vv.fetch_auth_fields(p), p
    # The five fields sign and verify as any preimage does.
    p = ["ac/fetch/1", a, i, 7, base]
    assert vv.verify_preimage(a, p, HONEST.sign(vv.digest(p)).hex())


NOW, ID, BASE = 1_800_000_090, "ab" * 32, "https://relay.acme.example"
ME = "ed25519:" + PUB.hex()
SESSION = Ed25519PrivateKey.from_private_bytes(bytes([0x22]) * 32)  # test data by construction
SESSION_ADDR = "ed25519:" + SESSION.public_key().public_bytes_raw().hex()


def fetch_case(*, key=HONEST, signer=ME, accepted=(BASE,), audience=BASE, ts=NOW, path_id=ID, signed=None,
               parties=(ME,), auth=None):  # fmt: skip
    """A fetch_proofs case in canonical.json's shape, signed by `key` over `signed` (by default the five fields)."""
    signed = ["ac/fetch/1", signer, path_id, ts, audience] if signed is None else signed
    headers = {"ac-signer": signer, "ac-ts": str(ts), "ac-sig": key.sign(vv.digest(signed)).hex()}
    if auth is not None:
        headers["ac-auth"] = auth
    return {"name": "made here", "accepted": list(accepted), "now": NOW, "id": path_id, "headers": headers,
            "parties": list(parties), "signed": signed, "result": ""}  # fmt: skip


def test_the_fetch_proof_reader_gives_the_reference_relay_s_verdict_for_each_class():
    other, two = "https://relay.globex.example", "https://relay2.acme.example"
    hop = {"iss": ME, "sub": SESSION_ADDR, "caveats": [], "exp": NOW + 60}
    hop["sig"] = HONEST.sign(vv.digest(vv.hop_preimage(hop))).hex()
    chain = base64.urlsafe_b64encode(json.dumps([hop]).encode()).decode().rstrip("=")
    cases = [
        (fetch_case(), "ok"),
        (fetch_case(audience=other), "bad-auth"),
        (fetch_case(signed=["ac/fetch/1", ME, ID, NOW]), "bad-auth"),
        *((fetch_case(audience=a), "bad-auth") for a in (BASE + "/", BASE + "/bag", BASE + ":443", BASE.upper())),
        (fetch_case(accepted=(BASE, two), audience=two), "ok"),
        (fetch_case(ts=NOW - 301), "stale-ts"),
        (fetch_case(ts=NOW + 301), "future-ts"),
        (fetch_case(ts=NOW - 300), "ok"),
        (fetch_case(ts=NOW - 301, audience=other), "bad-auth"),
        (fetch_case(key=SESSION, signer=SESSION_ADDR, auth=chain), "ok"),
        (fetch_case(key=SESSION, signer=SESSION_ADDR), "not-authorized"),
        (fetch_case(key=SESSION, signer=SESSION_ADDR, auth="!!"), "bad-auth"),
        (fetch_case(signed=["ac/sub/1", "00" * 32, ME, ME, None]), "bad-auth"),
        (fetch_case(signed=["ac/fetch/2", ME, ID, NOW, BASE]), "bad-auth"),
        (fetch_case(path_id=ID.upper()), "bad-hex"),
        (fetch_case(path_id="00" + ID), "bad-hex"),
        (fetch_case(signer="ed25519:" + PUB.hex().upper()), "bad-auth"),
    ]
    for case, want in cases:
        assert vv.fetch_verdict(case) == want, (case["signed"], case["accepted"], case["headers"], want)


def test_canonical_json_s_fetch_proofs_are_read_and_their_absence_is_a_mismatch():
    assert "fetch_proofs" in vv.READ_LISTS["canonical.json"]
    good = {**fetch_case(), "result": "ok"}
    f = {"cases": [], "invalid": [], "preimages": [], "fetch_proofs": [good, {**good, "result": "bad-auth"}]}
    t = vv.Tally(quiet=True)
    vv.check_canonical(f, t)
    assert len(t.mismatches) == 1 and "fetch proof verdict" in t.mismatches[0], t.mismatches
    t = vv.Tally(quiet=True)
    vv.check_canonical({**f, "fetch_proofs": []}, t)
    assert any("fetch proofs present" in m for m in t.mismatches), t.mismatches


def test_the_eight_constants_are_the_typescript_ones():
    ts = (ROOT / "packages" / "core" / "src" / "keys.ts").read_text()
    assert all(f"'{e.hex()}'" in ts for e in vv.SMALL_ORDER_POINTS) and len(set(vv.SMALL_ORDER_POINTS)) == 8

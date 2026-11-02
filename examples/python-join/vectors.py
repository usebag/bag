"""Check join.py and wire.py against spec/vectors/ offline.

    python3 vectors.py [spec/vectors]

The canonical cases and rejections, the preimage examples and their signatures, the RFC 9180 subset's
single-shot seal and open, the exact bytes of every self-rooted envelope case rebuilt from its injected keys,
every wrap of every case opened by its recipient, the verdict of every verify case through the receiver's own
checks, and the digest and signature of every address and accept-from record case. Prints one line of counts;
exits 1 on any mismatch.
"""

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from join import ACCEPT, ADDRESS, Reject, open_envelope, seal
from wire import L, canonical, digest, hpke_open, hpke_seal, verified

VECTORS = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[2] / "spec" / "vectors"
counts, failures = {}, []


def expect(kind, what, ok):
    counts[kind] = counts.get(kind, 0) + 1
    if not ok:
        failures.append(f"{kind}: {what}")


def outcome(fn):  # fn's value, or the code it refused with
    try:
        return fn()
    except (Reject, ValueError) as err:
        return str(err)


def load(name):
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def x25519(seed_hex):
    return X25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


c = load("canonical.json")
for case in c["cases"]:
    expect("canonical", case["name"], canonical(case["value"]) == case["canonical"])
for case in c["invalid"]:
    utf16 = bytes.fromhex(case.get("utf16_hex", "")).decode("utf-16-be", "surrogatepass")
    value = utf16 if "utf16_hex" in case else case["value"]
    expect("canonical", case["name"], outcome(lambda v=value: canonical(v)) == case["result"])
for case in c["preimages"]:
    expect("canonical", case["table"], digest(case["preimage"]).hex() == case["sha256"])
    if "sig" in case:
        expect("signature", case["table"], verified(case["signer"], digest(case["preimage"]), case["sig"]))

# §10, not in spec/vectors: each of the eight small-order points (the encodings scripts/verify_vectors.py
# lists), as the key and as R with S = 0, the identity encoded with y = p + 1, and S + L in place of a good S.
# cryptography alone accepts the identity's for any message.
SMALL_ORDER = [
    "01" + "00" * 31,
    "ec" + "ff" * 30 + "7f",
    "00" * 32,
    "00" * 31 + "80",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
]
for point in [*SMALL_ORDER, "ee" + "ff" * 30 + "7f"]:
    expect("signature", f"§10 refuses {point}", not verified("ed25519:" + point, b"any", point + "00" * 32))
hop = c["preimages"][1]
big_s = int.from_bytes(bytes.fromhex(hop["sig"])[32:], "little") + L
malleated = hop["sig"][:64] + big_s.to_bytes(32, "little").hex()
expect("signature", "§10 refuses S + L", not verified(hop["signer"], digest(hop["preimage"]), malleated))

h = load("hpke-rfc9180-subset.json")["cases"][0]
x = h["encryptions"][0]
info, aad, pt = bytes.fromhex(h["info"]), bytes.fromhex(x["aad"]), bytes.fromhex(x["pt"])
enc, ct = hpke_seal(bytes.fromhex(h["pkRm"]), info, aad, pt, bytes.fromhex(h["skEm"]))
expect("rfc9180", "seal, encryption 0", (enc.hex(), ct.hex()) == (h["enc"], x["ct"]))
expect("rfc9180", "open, encryption 0", hpke_open(enc, x25519(h["skRm"]), info, aad, ct) == pt)

for name in ("envelope.json", "sealed-multi.json"):
    for case in load(name)["cases"]:
        inp, env = case["inputs"], case["expected"]["envelope"]
        where = f"{name} {case['name']}"
        if not inp["auth"]:  # join.py builds self-rooted envelopes only
            # The rng's draws, in seal()'s order: the content key, the nonce, one ephemeral key per recipient
            draws = (bytes.fromhex(v) for v in [inp["content_key"], inp["nonce"], *inp["ephemeral_seeds"]])
            sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(inp["from_seed"]))
            recipients = [(r["address"], bytes.fromhex(r["sealing_key"])) for r in inp["to"]]
            raw = seal(sk, inp["from"], recipients, inp["content"], inp["ts"], lambda n, d=draws: next(d))
            expect("envelope bytes", where, raw == case["expected"]["bytes"].encode())
        # Every recipient opens its wrap; join.py trusts no chain, so a chained case is untrusted-root
        expected = "untrusted-root" if inp["auth"] else inp["content"]
        for r in inp["to"]:
            args = (env, x25519(r["sealing_seed"]), r["address"], [inp["from"]], inp["ts"])
            got = outcome(lambda a=args: open_envelope(*a))
            expect("wrap opened", f"{where}, {r['address'][:16]}", got == expected)

f = load("envelope.json")
r0 = f["cases"][0]["inputs"]["to"][0]  # every verify case is addressed to the first case's recipient
for case in f["verify"]:
    e = json.loads(case["bytes"])
    args = (e, x25519(r0["sealing_seed"]), r0["address"], [e["from"]], case["now"], case["ttl"], case["skew"])
    got = outcome(lambda a=args: open_envelope(*a))
    expect("verify verdict", case["name"], (got if isinstance(got, str) else "ok") == case["result"])

tables = {"address": ("ac/addr/1", ADDRESS), "accept-from": ("ac/accept/1", ACCEPT)}
for case in load("records.json")["cases"]:
    record = case["record"]
    if record["kind"] in tables:
        tag, fields = tables[record["kind"]]
        preimage = [tag, *(record[k] for k in fields)]
        expect("record", case["name"], digest(preimage).hex() == case["digest"])
        signed = all(k["result"] != "bad-record-sig" for k in case["checks"])
        expect("record", case["name"], verified(case["signer"], digest(preimage), record["sig"]) == signed)

total = sum(counts.values())
parts = ", ".join(f"{k} {n}" for k, n in counts.items())
print(f"vectors: {total - len(failures)} of {total} checks match ({parts})")
for failure in failures:
    print(f"  MISMATCH {failure}")
sys.exit(1 if failures else 0)

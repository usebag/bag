"""Verify spec/vectors independently of the TypeScript core (spec/SPEC.md §11).

    .venv/bin/python -I scripts/verify_vectors.py [spec/vectors]

Stdlib, and the `cryptography` package for Ed25519, X25519 and AES-256-GCM when it imports. Shares no code with
packages/core. For the eight vector files (discovery.json since 2026-10-26) it recomputes:

* every canonical string with json.dumps(value, separators=(",", ":"), ensure_ascii=False), after its own check of
  the canonical form's value rules, and compares it with the string the TypeScript generator wrote;
* every SHA-256 with hashlib: digests, sealed hashes, envelope ids, and the exact bytes of every envelope;
* the verdict of every parse, outer, chain, record, record parse, rotation and rotation claim case, by its own
  implementation of spec/SPEC.md §5 to §7, and the coding profile's result for every envelope and every caveat case;
* for discovery.json, by its own reading of §12: the strings of every TXT text form,
  the TXT name of each domain and where its TXT records lead (the key, the record URL and its origin, or
  resolve-failed), every record's agreement with its TXT and the key pinned after it, every handle's parts and record
  path, and every handle record's canonical string, digest, signature and verdict;
* with cryptography: every Ed25519 signature, strictly (§2.3: no small-order or non-canonical A or R, no S at or above
  L, then the cofactorless equation); every address and sealing key from its seed; every HPKE wrap, opened and sealed
  again with its injected ephemeral key; every content ciphertext, opened and sealed again; the verdict of every open
  and seal case (§4.3, §4.4, §5.2); and every field of the RFC 9180 subset, with its own RFC 9180 on cryptography's
  primitives;
* forward secrecy (2026-10-28; §4.3 step 3, §7.4, §10), envelope.json's `key_record_seal` and
  `stolen_key`: a wrap sealed to the sealing key of the recipient's current key record (the valid one with the
  greatest iat), which the verifier checks, recomputes the wrap to and opens with the epoch key; and a wrap sealed to an
  epoch key, read after that key's deletion horizon (exp + TTL + skew), gives open-failed under the recipient's
  long-term signing key in three forms (the raw seed, the Ed25519-to-X25519 map, RFC 9180 DeriveKeyPair of the seed)
  and under its current, different epoch key, while only the deleted key opens it;
* for canonical.json's `fetch_proofs` (2026-11-02; §8.3): each relay verdict on a fetch proof, by its own reading in
  the reference relay's order, the signature over the five-field preimage for one of the accepted bases byte for
  byte, and the form of the `fetch auth` preimage (five fields, the audience a base with no path);
* how many codes of spec/SPEC.md Appendix A have a verdict in the vectors (a `result` member, in any list);
* that every case list of every file is one the verifier reads.

Without cryptography, each check that needs it prints as "skipped (cryptography missing)" and is counted. Then it runs
negative controls: each one-byte change to a loaded vector must be reported as a mismatch.

Exit 0 when every check matched, every control was caught and nothing was skipped; 1 on a mismatch or a missed
control; 2 when nothing mismatched but a check was skipped, because a skipped check is not run.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import json
import math
import re
import unicodedata
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    import cryptography
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    CRYPTO: str | None = cryptography.__version__
except ImportError:  # the checks that need it are reported as skipped
    CRYPTO = None

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec" / "SPEC.md"
FILES = (
    "canonical.json",
    "envelope.json",
    "sealed-multi.json",
    "chain-valid.json",
    "chain-invalid.json",
    "records.json",
    "hpke-rfc9180-subset.json",
    "discovery.json",
    "pair-code.json",
)
MAX_INT = 2**53 - 1
TTL, SKEW = 604_800, 300
MAX_ROOTS = 1_024  # an accept-from record's roots (changed 2026-10-25)
MAX_KEY_LIFETIME = 86_400  # a key record's exp - iat (changed 2026-10-25)
HEX = re.compile(r"(?:[0-9a-f]{2})*")
PLAIN_INTEGER = re.compile(r"0|[1-9][0-9]*")
ADDRESS = re.compile(r"ed25519:[0-9a-f]{64}")
# A fetch proof's audience (SPEC.md 8.3, added 2026-11-02): the relay's base URL as the relays entry the caller used,
# scheme and authority with no path, query, fragment or trailing slash.
AUDIENCE = re.compile(r"https?://[^/?#\s]+")
SURROGATE = re.compile("[\ud800-\udfff]")
# A forbidden character in content.type: a Unicode control character (Cc: U+0000 to U+001F, U+007F, U+0080 to U+009F)
# or a line/paragraph separator (U+2028, U+2029). The decoder refuses one (SPEC.md 5.2, added 2026-10-27).
TYPE_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
# http or https, a non-empty authority, and no space or control character (U+0000 to U+001F, U+007F to U+009F).
RELAY_URL = re.compile(r"https?://[^\x00-\x20\x7f-\x9f/?#]+[^\x00-\x20\x7f-\x9f]*")
ENVELOPE_KEYS = {"v", "id", "to", "from", "auth", "suite", "ts", "sealed", "sig"}
HOP_KEYS = {"iss", "sub", "caveats", "exp", "sig"}
ADDRESS_KEYS = {
    "kind",
    "key",
    "sealing_key",
    "relays",
    "rotation_key",
    "revoked",
    "ttl",
    "iat",
    "rotated_from",
    "rotation_sig",
    "sig",
}
ACCEPT_KEYS = {"kind", "owner", "roots", "max_bytes", "ttl", "iat", "sig"}
KEY_KEYS = {"kind", "key", "sealing_key", "iat", "exp", "sig"}
SEAL_INFO = b"ac/seal/1"
# Strict Ed25519 (spec/SPEC.md §10). p is the field prime, L the order of the prime subgroup.
FIELD_P = 2**255 - 19
ORDER_L = 2**252 + 27742317777372353535851937790883648493
Y_MASK = 2**255 - 1  # clears the sign bit of an encoded point
# The eight small-order points of edwards25519 (the torsion subgroup), canonically encoded: the identity, order 2, two
# of order 4, four of order 8. Public constants, derived from RFC 8032 section 6 (packages/core/test/keys-strict.test.ts).
SMALL_ORDER_POINTS = tuple(
    bytes.fromhex(h)
    for h in (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    )
)
# Their y values, sign bit aside: x = 0 with the sign bit set is no valid encoding, yet OpenSSL reads it as a point.
SMALL_ORDER_Y = frozenset(int.from_bytes(e, "little") & Y_MASK for e in SMALL_ORDER_POINTS)


class Rejected(Exception):
    """A verdict other than ok: the error code of spec/SPEC.md, Appendix A."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class NeedCrypto(Exception):
    """The check needs the cryptography package, which did not import."""


def need_crypto() -> None:
    if CRYPTO is None:
        raise NeedCrypto


# ---- the canonical form (spec/SPEC.md §2) --------------------------------------------------------------------------


def is_int(v: Any) -> bool:
    return type(v) is int and 0 <= v <= MAX_INT


def fetch_auth_fields(p: Any) -> bool:
    """A fetch proof's preimage, ["ac/fetch/1", signer, id, ts, audience] (SPEC.md 8.3): five fields since 2026-11-02,
    the audience last, so that a proof made for one relay is refused at another."""
    return (
        isinstance(p, list)
        and len(p) == 5
        and p[0] == "ac/fetch/1"
        and is_address(p[1])
        and is_hex(p[2], 32)
        and is_int(p[3])
        and isinstance(p[4], str)
        and AUDIENCE.fullmatch(p[4]) is not None
    )


def is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def has_canonical_form(v: Any) -> bool:
    if v is None:
        return True
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return 0 <= v <= MAX_INT
    if isinstance(v, str):
        return SURROGATE.search(v) is None
    if isinstance(v, list):
        return all(has_canonical_form(x) for x in v)
    return False


def canonical(v: Any) -> str:
    if not has_canonical_form(v):
        raise Rejected("bad-canonical")
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


def sha256hex(data: str | bytes) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def digest(preimage: Any) -> bytes:
    return hashlib.sha256(canonical(preimage).encode("utf-8")).digest()


def is_hex(v: Any, n: int | None = None) -> bool:
    return isinstance(v, str) and HEX.fullmatch(v) is not None and (n is None or len(v) == 2 * n)


def is_address(v: Any) -> bool:
    return isinstance(v, str) and ADDRESS.fullmatch(v) is not None


def well_formed(v: Any) -> bool:
    if isinstance(v, str):
        return SURROGATE.search(v) is None
    if isinstance(v, list):
        return all(well_formed(x) for x in v)
    if isinstance(v, dict):
        return all(well_formed(k) and well_formed(x) for k, x in v.items())
    return True


def reject_constant(name: str) -> None:
    raise ValueError(f"{name} is not JSON")


def finite(literal: str) -> float:
    number = float(literal)
    if math.isinf(number):
        raise ValueError(f"{literal} is past the range of a double")
    return number


def plain_int(literal: str) -> int | float:
    """An integer token: kept when written 0 or [1-9][0-9]* and at most 2^53 - 1 (spec/SPEC.md §2.5), else NaN."""
    finite(literal)
    return int(literal) if PLAIN_INTEGER.fullmatch(literal) and int(literal) <= MAX_INT else math.nan


def finite_int(literal: str) -> int:
    """An integer token in the sealed content (strict_integers off): kept exactly, unless past a double's range."""
    finite(literal)
    return int(literal)


def not_int(literal: str) -> float:
    """A token with a fraction or an exponent: never a canonical integer, so NaN, which equals nothing."""
    finite(literal)
    return math.nan


def distinct_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """object_pairs_hook: an object that names a member twice is not JSON a reader takes (spec/SPEC.md §2.5; changed
    2026-10-25). json.loads decodes the names first, so "a" and "\\u0061" are one name."""
    members = dict(pairs)
    if len(members) != len(pairs):
        raise ValueError("an object names a member twice")
    return members


def parse_json(raw: bytes, code: str = "bad-json", strict_integers: bool = True) -> Any:
    """UTF-8 JSON text (spec/SPEC.md §2.5). A number not written as a plain decimal integer of at most 2^53 - 1 is
    NaN, so the reader that expects an integer refuses it with its own code; one past a double's range is `code`;
    an object that names a member twice is `code`. With strict_integers off, numbers are read as json.loads reads
    them, for the sealed content, whose body is exempt from the integer rule (§4.2) but not from the range of a
    double, so one past it is still `code` (changed 2026-10-25)."""
    try:
        text = raw.decode("utf-8")
        if text.startswith("﻿"):
            raise ValueError("a byte-order mark")
        numbers = (
            {"parse_int": plain_int, "parse_float": not_int}
            if strict_integers
            else {"parse_int": finite_int, "parse_float": finite}
        )
        value = json.loads(text, parse_constant=reject_constant, object_pairs_hook=distinct_members, **numbers)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Rejected(code) from None
    if not well_formed(value):
        raise Rejected(code)
    return value


# ---- Ed25519, X25519, AES-256-GCM and RFC 9180 (spec/SPEC.md §3, §4) --------------------------------------------


def ed25519_public(seed: bytes) -> bytes:
    need_crypto()
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def strict_point(b: bytes) -> bool:
    """A canonical encoding (y < p) of a point that is not of small order."""
    y = int.from_bytes(b, "little") & Y_MASK
    return y < FIELD_P and y not in SMALL_ORDER_Y


def verify_sig(public: bytes, message: bytes, sig: bytes) -> bool:
    need_crypto()
    if len(public) != 32 or len(sig) != 64:
        return False
    # Before OpenSSL: refuse a small-order or non-canonical key or R, and S >= L.
    if not strict_point(public) or not strict_point(sig[:32]) or int.from_bytes(sig[32:], "little") >= ORDER_L:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(sig, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_preimage(address: Any, preimage: Any, sig: Any) -> bool:
    if not is_address(address) or not is_hex(sig, 64):
        return False
    try:
        d = digest(preimage)
    except Rejected:
        return False
    return verify_sig(bytes.fromhex(address[len("ed25519:") :]), d, bytes.fromhex(sig))


def x25519_public(sk: bytes) -> bytes:
    need_crypto()
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def x25519(sk: bytes, pk: bytes) -> bytes:
    need_crypto()
    shared = X25519PrivateKey.from_private_bytes(sk).exchange(X25519PublicKey.from_public_bytes(pk))
    if shared == bytes(32):
        raise ValueError("a small-order public key")
    return shared


def aead_seal(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
    need_crypto()
    return AESGCM(key).encrypt(nonce, pt, aad)


def aead_open(key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
    need_crypto()
    return AESGCM(key).decrypt(nonce, ct, aad)


def i2osp(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


KEM_SUITE = b"KEM" + i2osp(0x0020, 2)
HPKE_SUITE = b"HPKE" + i2osp(0x0020, 2) + i2osp(0x0001, 2) + i2osp(0x0002, 2)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(prk, i2osp(length, 2) + b"HPKE-v1" + suite + label + info, length)


def derive_key_pair(ikm: bytes) -> tuple[bytes, bytes]:
    prk = labeled_extract(KEM_SUITE, b"", b"dkp_prk", ikm)
    sk = labeled_expand(KEM_SUITE, prk, b"sk", b"", 32)
    return sk, x25519_public(sk)


def extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    prk = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh)
    return labeled_expand(KEM_SUITE, prk, b"shared_secret", kem_context, 32)


def encap(pk_r: bytes, sk_e: bytes) -> tuple[bytes, bytes]:
    enc = x25519_public(sk_e)
    return extract_and_expand(x25519(sk_e, pk_r), enc + pk_r), enc


def decap(enc: bytes, sk_r: bytes) -> bytes:
    return extract_and_expand(x25519(sk_r, enc), enc + x25519_public(sk_r))


def key_schedule(shared: bytes, info: bytes) -> dict[str, bytes]:
    psk_id_hash = labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(HPKE_SUITE, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = labeled_extract(HPKE_SUITE, shared, b"secret", b"")
    return {
        "key_schedule_context": context,
        "secret": secret,
        "key": labeled_expand(HPKE_SUITE, secret, b"key", context, 32),
        "base_nonce": labeled_expand(HPKE_SUITE, secret, b"base_nonce", context, 12),
        "exporter_secret": labeled_expand(HPKE_SUITE, secret, b"exp", context, 32),
    }


def nonce_for(base: bytes, seq: int) -> bytes:
    return bytes(a ^ b for a, b in zip(base, i2osp(seq, 12), strict=True))


def seal_base(pk_r: bytes, info: bytes, aad: bytes, pt: bytes, sk_e: bytes) -> tuple[bytes, bytes]:
    shared, enc = encap(pk_r, sk_e)
    ks = key_schedule(shared, info)
    return enc, aead_seal(ks["key"], ks["base_nonce"], aad, pt)


def open_base(enc: bytes, sk_r: bytes, info: bytes, aad: bytes, ct: bytes) -> bytes:
    ks = key_schedule(decap(enc, sk_r), info)
    return aead_open(ks["key"], ks["base_nonce"], aad, ct)


# ---- envelopes, chains, records (spec/SPEC.md §5 to §7) -----------------------------------------------------------


def hex_field(v: Any, n: int | None) -> None:
    if not isinstance(v, str):
        raise Rejected("bad-shape")
    if not is_hex(v, n):
        raise Rejected("bad-hex")


def check_recipients(to: Any) -> list[str]:
    if not isinstance(to, list) or len(to) == 0:
        raise Rejected("bad-shape")
    if len(to) > 16:
        raise Rejected("too-many-recipients")
    for a in to:
        if not isinstance(a, str):
            raise Rejected("bad-shape")
        if not is_address(a):
            raise Rejected("bad-address")
    if len(set(to)) != len(to):
        raise Rejected("bad-shape")
    return to


def well_formed_hop(h: Any) -> bool:
    return (
        isinstance(h, dict)
        and set(h) == HOP_KEYS
        and is_address(h["iss"])
        and is_address(h["sub"])
        and isinstance(h["caveats"], list)
        and all(isinstance(c, str) and c != "" and SURROGATE.search(c) is None for c in h["caveats"])
        and is_int(h["exp"])
        and is_hex(h["sig"], 64)
    )


def check_chain_shape(auth: Any) -> None:
    """Chain rules 1 to 4, each over every hop before the next."""
    if not isinstance(auth, list):
        raise Rejected("bad-shape")
    if len(auth) > 8:
        raise Rejected("too-many-hops")
    if not all(well_formed_hop(h) for h in auth):
        raise Rejected("bad-hop")
    if any(len(h["caveats"]) > 32 for h in auth):
        raise Rejected("too-many-caveats")
    if any(len(c.encode("utf-8")) > 256 for h in auth for c in h["caveats"]):
        raise Rejected("caveat-too-long")


def hop_preimage(h: dict[str, Any]) -> list[Any]:
    return ["ac/hop/1", h["iss"], h["sub"], h["caveats"], h["exp"]]


def verify_chain(auth: Any, frm: Any, ts: Any) -> dict[str, Any]:
    if not is_address(frm):
        raise Rejected("bad-address")
    if not is_int(ts):
        raise Rejected("bad-shape")
    check_chain_shape(auth)
    pairs = list(zip(auth, auth[1:], strict=False))
    if any(a["sub"] != b["iss"] for a, b in pairs):
        raise Rejected("chain-broken")
    if auth and auth[-1]["sub"] != frm:
        raise Rejected("chain-not-to-sender")
    if any(b["exp"] > a["exp"] for a, b in pairs):
        raise Rejected("exp-not-monotone")
    if any(ts > h["exp"] for h in auth):
        raise Rejected("hop-expired")
    for h in auth:
        if not verify_preimage(h["iss"], hop_preimage(h), h["sig"]):
            raise Rejected("bad-hop-sig")
    return {
        "root": auth[0]["iss"] if auth else frm,
        "principal": auth[-1]["iss"] if auth else frm,
        "caveats": [c for h in auth for c in h["caveats"]],
    }


def check_sealed(s: Any, to: list[str]) -> None:
    if not isinstance(s, dict) or set(s) != {"wraps", "nonce", "ct"}:
        raise Rejected("bad-shape")
    wraps = s["wraps"]
    if not isinstance(wraps, list) or len(wraps) != len(to):
        raise Rejected("bad-shape")
    for i, w in enumerate(wraps):
        if not isinstance(w, dict) or set(w) != {"to", "enc", "ct"}:
            raise Rejected("bad-shape")
        if w["to"] != to[i]:
            raise Rejected("bad-shape")
        hex_field(w["enc"], 32)
        hex_field(w["ct"], 48)
    hex_field(s["nonce"], 12)
    hex_field(s["ct"], None)
    if len(s["ct"]) < 32:
        raise Rejected("bad-hex")


def parse_envelope(raw: bytes) -> dict[str, Any]:
    """spec/SPEC.md §5.4, in order."""
    if len(raw) > 196_608:
        raise Rejected("envelope-too-large")
    e = parse_json(raw)
    if not isinstance(e, dict):
        raise Rejected("bad-shape")
    if not is_number(e.get("v")):
        raise Rejected("bad-shape")
    if e["v"] != 1:
        raise Rejected("bad-version")
    if not is_number(e.get("suite")):
        raise Rejected("bad-shape")
    if e["suite"] != 1:
        raise Rejected("bad-suite")
    if set(e) != ENVELOPE_KEYS:
        raise Rejected("bad-shape")
    hex_field(e["id"], 32)
    to = check_recipients(e["to"])
    if not isinstance(e["from"], str):
        raise Rejected("bad-shape")
    if not is_address(e["from"]):
        raise Rejected("bad-address")
    check_chain_shape(e["auth"])
    if not is_int(e["ts"]):
        raise Rejected("bad-shape")
    check_sealed(e["sealed"], to)
    hex_field(e["sig"], 64)
    return e


def sealed_hash_preimage(s: dict[str, Any]) -> list[Any]:
    return [[[w["to"], w["enc"], w["ct"]] for w in s["wraps"]], s["nonce"], s["ct"]]


def envelope_id_preimage(e: dict[str, Any]) -> list[Any]:
    auth = [[h["iss"], h["sub"], h["caveats"], h["exp"], h["sig"]] for h in e["auth"]]
    sealed_hash = sha256hex(canonical(sealed_hash_preimage(e["sealed"])))
    return [e["v"], e["to"], e["from"], auth, e["suite"], e["ts"], sealed_hash]


def verify_outer(e: dict[str, Any], now: int, ttl: int, skew: int) -> None:
    """spec/SPEC.md §5.5, in order."""
    check_recipients(e["to"])
    if sha256hex(canonical(envelope_id_preimage(e))) != e["id"]:
        raise Rejected("bad-id")
    if not verify_sig(bytes.fromhex(e["from"][8:]), bytes.fromhex(e["id"]), bytes.fromhex(e["sig"])):
        raise Rejected("bad-sig")
    if e["ts"] < now - (ttl + skew):
        raise Rejected("stale-ts")
    if e["ts"] > now + skew:
        raise Rejected("future-ts")


def coding_verdict(caveat: str, sealed: dict[str, Any] | None) -> str:
    """The coding profile (spec/SPEC.md §6.4)."""
    if caveat.startswith("type="):
        pattern = caveat[len("type=") :]
        prefix = pattern[:-2] if pattern.endswith(".*") else None
        name = pattern if prefix is None else prefix
        if name == "" or "*" in name:
            return "unknown"
        if sealed is None:
            return "needs-sealed"
        holds = sealed["type"] == pattern if prefix is None else sealed["type"].startswith(prefix + ".")
        return "hold" if holds else "fail"
    if caveat.startswith("repo="):
        name = caveat[len("repo=") :]
        if name == "":
            return "unknown"
        if sealed is None:
            return "needs-sealed"
        body = sealed["body"]
        return "hold" if isinstance(body, dict) and body.get("repo") == name else "fail"
    return "unknown"


def evaluate_coding(caveats: list[str], sealed: dict[str, Any]) -> dict[str, Any]:
    for c in caveats:
        v = coding_verdict(c, sealed)
        if v in ("fail", "needs-sealed"):
            return {"ok": False, "code": "caveat-failed", "caveat": c}
        if v != "hold":
            return {"ok": False, "code": "unknown-caveat", "caveat": c}
    return {"ok": True}


def null_or(v: Any, test: Callable[[Any], bool]) -> bool:
    return v is None or test(v)


# Domain roots: an accept-from root may be `domain:<host>` (spec/SPEC.md §7.4). The check is part of check_record
# itself (the same rules, the same verdicts as an earlier wrapper around it gave).
DOMAIN_ROOT_PREFIX = "domain:"
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
HOST_NUMBER = re.compile(r"[0-9]+|0x[0-9a-f]*", re.IGNORECASE)


def is_domain_host(host: Any) -> bool:
    """A domain root's host: at most 253 characters, two or more DNS labels, no trailing dot, and not an IP literal
    (its last label is not a number, the WHATWG rule), as packages/core/src/records.ts isDomainHost reads it."""
    if not isinstance(host, str) or len(host) > 253:
        return False
    labels = host.split(".")
    if len(labels) < 2 or not all(DNS_LABEL.fullmatch(label) for label in labels):
        return False
    return HOST_NUMBER.fullmatch(labels[-1]) is None


def is_accept_root(root: Any) -> bool:
    """One entry of an accept-from record's roots: "*", an address, or domain:<host>."""
    if root == "*" or is_address(root):
        return True
    prefixed = isinstance(root, str) and root.startswith(DOMAIN_ROOT_PREFIX)
    return prefixed and is_domain_host(root[len(DOMAIN_ROOT_PREFIX) :])


def check_record(r: Any) -> None:
    """spec/SPEC.md §7.1 to §7.4: the form and the caps, in the order of each kind's members."""
    if not isinstance(r, dict):
        raise Rejected("bad-record")
    kind = r.get("kind")
    if kind == "address":
        # A non-null sealing_key stays valid: the forward-secrecy KEEP-NULL rule binds an individual's publishing, not a
        # reader, and a group's address record carries its generation key here (ruled 2026-10-28).
        if set(r) != ADDRESS_KEYS or not is_address(r["key"]) or not null_or(r["sealing_key"], lambda x: is_hex(x, 32)):
            raise Rejected("bad-record")
        if not isinstance(r["relays"], list):
            raise Rejected("bad-record")
        if len(r["relays"]) > 64:
            raise Rejected("too-many-relays")
        relays_ok = all(isinstance(u, str) and RELAY_URL.fullmatch(u) is not None for u in r["relays"])
        if not relays_ok or len(set(r["relays"])) != len(r["relays"]):
            raise Rejected("bad-record")
        if not null_or(r["rotation_key"], is_address) or not isinstance(r["revoked"], list):
            raise Rejected("bad-record")
        if len(r["revoked"]) > 1024:
            raise Rejected("too-many-revoked")
        if not all(is_address(a) for a in r["revoked"]) or len(set(r["revoked"])) != len(r["revoked"]):
            raise Rejected("bad-record")
        if not is_int(r["ttl"]) or not 1 <= r["ttl"] <= 86_400 or not is_int(r["iat"]):
            raise Rejected("bad-record")
        if not null_or(r["rotated_from"], is_address) or not null_or(r["rotation_sig"], lambda x: is_hex(x, 64)):
            raise Rejected("bad-record")
        if (r["rotation_sig"] is not None and r["rotated_from"] is None) or not is_hex(r["sig"], 64):
            raise Rejected("bad-record")
    elif kind == "accept-from":
        if set(r) != ACCEPT_KEYS or not is_address(r["owner"]):
            raise Rejected("bad-record")
        roots = r["roots"]
        if not isinstance(roots, list) or len(roots) == 0 or len(roots) > MAX_ROOTS:
            raise Rejected("bad-record")
        if not all(is_accept_root(x) for x in roots) or len(set(roots)) != len(roots):
            raise Rejected("bad-record")
        if "*" in roots and len(roots) > 1:
            raise Rejected("bad-record")
        if not is_int(r["max_bytes"]) or r["max_bytes"] < 1 or not is_int(r["ttl"]) or r["ttl"] < 1:
            raise Rejected("bad-record")
        if not is_int(r["iat"]) or not is_hex(r["sig"], 64):
            raise Rejected("bad-record")
    elif kind == "key":
        if set(r) != KEY_KEYS or not is_address(r["key"]) or not is_hex(r["sealing_key"], 32):
            raise Rejected("bad-record")
        if not is_int(r["iat"]) or not is_int(r["exp"]) or not 0 <= r["exp"] - r["iat"] <= MAX_KEY_LIFETIME:
            raise Rejected("bad-record")
        if not is_hex(r["sig"], 64):
            raise Rejected("bad-record")
    else:
        raise Rejected("bad-record")


def record_preimage(r: dict[str, Any]) -> list[Any]:
    if r["kind"] == "address":
        return [
            "ac/addr/1",
            r["key"],
            r["sealing_key"],
            r["relays"],
            r["rotation_key"],
            r["revoked"],
            r["ttl"],
            r["iat"],
            r["rotated_from"],
        ]
    if r["kind"] == "accept-from":
        return ["ac/accept/1", r["owner"], r["roots"], r["max_bytes"], r["ttl"], r["iat"]]
    return ["ac/key/1", r["key"], r["sealing_key"], r["iat"], r["exp"]]


def record_signer(r: dict[str, Any]) -> str:
    return r["owner"] if r["kind"] == "accept-from" else r["key"]


def verify_record(r: dict[str, Any], now: int, skew: int) -> None:
    """spec/SPEC.md §7.5, in order."""
    check_record(r)
    if not verify_preimage(record_signer(r), record_preimage(r), r["sig"]):
        raise Rejected("bad-record-sig")
    if r["iat"] > now + skew:
        raise Rejected("future-iat")
    if (r["kind"] == "address" and now > r["iat"] + r["ttl"]) or (r["kind"] == "key" and now > r["exp"]):
        raise Rejected("record-expired")


def verify_rotation(prev: dict[str, Any], nxt: dict[str, Any]) -> None:
    """spec/SPEC.md §7.3."""
    check_record(prev)
    check_record(nxt)
    if prev["kind"] != "address" or nxt["kind"] != "address":
        raise Rejected("bad-record")
    if nxt["rotated_from"] != prev["key"] or nxt["rotation_sig"] is None:
        raise Rejected("bad-rotation")
    signers = [prev["key"]] + ([prev["rotation_key"]] if prev["rotation_key"] is not None else [])
    if not any(verify_preimage(s, record_preimage(nxt), nxt["rotation_sig"]) for s in signers):
        raise Rejected("bad-rotation")


def verify_rotation_claim(nxt: dict[str, Any]) -> None:
    """spec/SPEC.md §7.3, for a reader that holds no record of rotated_from (changed 2026-10-25):
    rotation_sig must verify under rotated_from; a record that names none claims nothing."""
    check_record(nxt)
    if nxt["kind"] != "address":
        raise Rejected("bad-record")
    if nxt["rotated_from"] is None:
        return
    if nxt["rotation_sig"] is None or not verify_preimage(nxt["rotated_from"], record_preimage(nxt), nxt["rotation_sig"]):
        raise Rejected("bad-rotation")


# Discovery by DNS and handles (spec/SPEC.md §12; added 2026-10-26), read from the spec
# alone: the TXT text form, the fields of a bag TXT record, where a lookup leads, a record's agreement with its
# TXT, handles and handle records.
DISCOVERY_PREFIX = "_bag."
WELL_KNOWN_RECORD_PATH = "/.well-known/bag/address.json"
BAG_HOST = "bag"
HANDLES_PATH = "/.well-known/bag/handles/"
MAX_TXT_BYTES = 1_024
MAX_TXT_STRING = 255
TXT_FIELD_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")
TXT_FIELD_VALUE = re.compile(r"[!-:<-~]+")
TXT_PRINTABLE = re.compile(r"[\t -~]*")
HANDLE_LOCAL = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?")
HANDLE_KEYS = {"kind", "org", "handle", "address", "iat", "ttl", "sig"}
# Special-use top-level names a handle's domain may not end in, and for which no TXT record is asked (added
# 2026-10-26; §12.2 item 4 and §12.3 item 1).
SPECIAL_USE_TLDS = {"alt", "arpa", "internal", "invalid", "local", "localhost", "onion"}


def txt_name(domain: Any) -> str | None:
    """§12.2 item 4: the name to look up; none over 253 characters or for a domain under a special-use name."""
    if not is_domain_host(domain):
        raise Rejected("resolve-failed")
    name = DISCOVERY_PREFIX + domain
    return None if len(name) > 253 or domain.rsplit(".", 1)[-1] in SPECIAL_USE_TLDS else name


def parse_presentation(text: str) -> list[bytes]:
    """§12.2 item 7: RFC 1035 §5.1's character-strings, quoted or bare, with \\DDD and \\X escapes."""
    if TXT_PRINTABLE.fullmatch(text) is None:
        raise Rejected("resolve-failed")
    b = text.encode("ascii")
    out: list[bytes] = []
    i = 0
    while True:
        while i < len(b) and b[i] in b" \t":
            i += 1
        if i >= len(b):
            break
        quoted = b[i] == ord('"')
        i += quoted
        s = bytearray()
        while True:
            if i >= len(b):
                if quoted:
                    raise Rejected("resolve-failed")
                break
            c = b[i]
            if quoted and c == ord('"'):
                i += 1
                if i < len(b) and b[i] not in b" \t":
                    raise Rejected("resolve-failed")
                break
            if not quoted and c in b" \t":
                break
            if not quoted and c == ord('"'):
                raise Rejected("resolve-failed")
            if not quoted and c in b"()":
                raise Rejected("resolve-failed")  # SPEC §12.2 item 7: the presentation text has no parentheses
            if c == ord("\\"):
                if i + 1 >= len(b):
                    raise Rejected("resolve-failed")
                if not b[i + 1 : i + 2].isdigit():
                    s.append(b[i + 1])
                    i += 2
                    continue
                digits = b[i + 1 : i + 4]
                if len(digits) != 3 or not digits.isdigit() or int(digits) > 255:
                    raise Rejected("resolve-failed")
                s.append(int(digits))
                i += 4
            else:
                s.append(c)
                i += 1
        if len(s) > MAX_TXT_STRING:
            raise Rejected("resolve-failed")
        out.append(bytes(s))
    if not out:
        raise Rejected("resolve-failed")
    return out


def txt_field(part: bytes) -> tuple[str, str] | None:
    """§12.2 item 1: name=value, spaces and tabs around ignored; none when it breaks the grammar."""
    at = part.find(b"=")
    if at == -1:
        return None
    name, value = part[:at].strip(b" \t"), part[at + 1 :].strip(b" \t")
    try:
        n, v = name.decode("ascii"), value.decode("ascii")
    except UnicodeDecodeError:
        return None
    if TXT_FIELD_NAME.fullmatch(n) is None or TXT_FIELD_VALUE.fullmatch(v) is None:
        return None
    return n, v


def parse_txt(text: bytes, domain: str) -> tuple[str, str | None] | None:
    """§12.2 items 1 to 3: (key, host) or none when the record is not ours; resolve-failed when it is ours and
    malformed, a rec field included (DNS names no URL) and a host other than bag."""
    parts = [p for p in (x.strip(b" \t") for x in text.split(b";")) if p]
    if not parts or txt_field(parts[0]) != ("v", "ac1"):
        return None
    if any(not (c == 9 or 32 <= c <= 126) for c in text) or len(text) > MAX_TXT_BYTES:
        raise Rejected("resolve-failed")
    fields: dict[str, str] = {}
    for part in parts:
        f = txt_field(part)
        if f is None or f[0] in fields:
            raise Rejected("resolve-failed")
        fields[f[0]] = f[1]
    key, host = fields.get("key"), fields.get("host")
    if "rec" in fields or key is None or not is_address(key) or host not in (None, BAG_HOST):
        raise Rejected("resolve-failed")
    return key, host


def discover(records: list[list[bytes]], domain: Any) -> tuple[str | None, str, str]:
    """§12.2 item 4: (the key the record must agree with or None, the record URL, the origin), or resolve-failed. A
    domain that is not asked has no bag record, whatever records are handed in."""
    asked = records if txt_name(domain) is not None else []
    ours = [t for t in [parse_txt(b"".join(r), domain) for r in asked] if t is not None]
    if len(ours) > 1:
        raise Rejected("resolve-failed")
    key, host = ours[0] if ours else (None, None)
    origin = f"https://{host}.{domain}" if host else f"https://{domain}"
    return key, origin + WELL_KNOWN_RECORD_PATH, origin


def agrees(txt_key: str | None, record: dict[str, Any]) -> bool:
    """§12.2 item 5: no TXT key, the TXT key itself, or one rotation the TXT key countersigned."""
    if txt_key is None or record["key"] == txt_key:
        return True
    return record["rotated_from"] == txt_key and verdict(lambda: verify_rotation_claim(record)) == "ok"


def pin_after(pinned: dict[str, Any] | None, record: dict[str, Any]) -> str:
    """§7.3: the key pinned after reading a record that agreed with its TXT; DNS moves no pin."""
    if pinned is None or pinned["key"] == record["key"]:
        return record["key"]
    return record["key"] if verdict(lambda: verify_rotation(pinned, record)) == "ok" else pinned["key"]


def parse_handle(value: Any) -> tuple[str, str]:
    """§12.3 item 1: (local part, domain), or bad-address."""
    if not isinstance(value, str) or value.count("@") != 1:
        raise Rejected("bad-address")
    local, domain = value.split("@")
    if HANDLE_LOCAL.fullmatch(local) is None or not is_domain_host(domain) or domain.rsplit(".", 1)[-1] in SPECIAL_USE_TLDS:
        raise Rejected("bad-address")
    return local, domain


def handle_path(value: str) -> str:
    return f"{HANDLES_PATH}{parse_handle(value)[0]}.json"


def check_handle_record(r: Any) -> None:
    """§12.4 item 1: the form of a handle record."""
    if not isinstance(r, dict) or r.get("kind") != "handle" or set(r) != HANDLE_KEYS:
        raise Rejected("bad-record")
    if not is_address(r["org"]) or not is_address(r["address"]) or not is_int(r["iat"]):
        raise Rejected("bad-record")
    if verdict(lambda: parse_handle(r["handle"])) != "ok":
        raise Rejected("bad-record")
    if not is_int(r["ttl"]) or not 1 <= r["ttl"] <= 86_400 or not is_hex(r["sig"], 64):
        raise Rejected("bad-record")


def handle_record_preimage(r: dict[str, Any]) -> list[Any]:
    return ["ac/handle/1", r["org"], r["handle"], r["address"], r["iat"], r["ttl"]]


def verify_handle_record(r: Any, org: str, handle: str, revoked: list[str], now: int, skew: int) -> None:
    """§12.4 item 3, in order: form, signature under its org, iat, expiry, the binding, the revoked list."""
    check_handle_record(r)
    if not verify_preimage(r["org"], handle_record_preimage(r), r["sig"]):
        raise Rejected("bad-record-sig")
    if r["iat"] > now + skew:
        raise Rejected("future-iat")
    if now > r["iat"] + r["ttl"]:
        raise Rejected("record-expired")
    if r["org"] != org or r["handle"] != handle:
        raise Rejected("resolve-failed")
    if r["address"] in revoked:
        raise Rejected("revoked")


def decode_content(pt: bytes) -> dict[str, Any]:
    """spec/SPEC.md §5.2, in packages/core's order: the object (bad-content), then the thread (bad-thread,
    too-many-prev). Numbers are read freely, since the body is exempt from the integer rule (§4.2), but one past a
    double's range is bad-content."""
    c = parse_json(pt, "bad-content", strict_integers=False)
    if not isinstance(c, dict) or set(c) != {"type", "thread", "body"}:
        raise Rejected("bad-content")
    if not isinstance(c["type"], str) or c["type"] == "" or TYPE_FORBIDDEN.search(c["type"]):
        raise Rejected("bad-content")
    t = c["thread"]
    if not isinstance(t, dict) or set(t) != {"id", "prev"} or not is_hex(t["id"], 32):
        raise Rejected("bad-thread")
    if not isinstance(t["prev"], list):
        raise Rejected("bad-thread")
    if len(t["prev"]) > 64:
        raise Rejected("too-many-prev")
    if not all(is_hex(x, 32) for x in t["prev"]) or len(set(t["prev"])) != len(t["prev"]):
        raise Rejected("bad-thread")
    return c


def open_sealed(c: dict[str, Any]) -> dict[str, Any]:
    """spec/SPEC.md §4.4, in order: the wrap named by the address (not-recipient); its hex, the HPKE open, a 32-byte
    content key and the content ciphertext under [v, to, from] (open-failed); then the content (§5.2)."""
    need_crypto()
    s = c["sealed"]
    wrap = next((w for w in s["wraps"] if w["to"] == c["address"]), None)
    if wrap is None:
        raise Rejected("not-recipient")
    if not (is_hex(wrap["enc"], 32) and is_hex(wrap["ct"]) and is_hex(s["nonce"], 12) and is_hex(s["ct"])):
        raise Rejected("open-failed")
    try:
        enc, seed, ct = bytes.fromhex(wrap["enc"]), bytes.fromhex(c["sealing_seed"]), bytes.fromhex(wrap["ct"])
        key = open_base(enc, seed, SEAL_INFO, c["address"].encode("utf-8"), ct)
        if len(key) != 32:
            raise ValueError("the wrapped content key is not 32 bytes")
        aad = canonical([1, c["to"], c["from"]]).encode("utf-8")
        pt = aead_open(key, bytes.fromhex(s["nonce"]), aad, bytes.fromhex(s["ct"]))
    except (InvalidTag, ValueError):
        raise Rejected("open-failed") from None
    return decode_content(pt)


def seal_to(c: dict[str, Any]) -> None:
    """spec/SPEC.md §4.1 and §4.3: each wrap sealed to its recipient's key; a key that is not 32 bytes, or a
    small-order one, whose X25519 output is all zeros, makes the KEM abort (bad-key)."""
    need_crypto()
    for r, sk_e in zip(c["to"], c["ephemeral_seeds"], strict=True):
        try:
            seal_base(bytes.fromhex(r["sealing_key"]), SEAL_INFO, r["address"].encode("utf-8"),
                      bytes.fromhex(c["content_key"]), bytes.fromhex(sk_e))
        except ValueError:
            raise Rejected("bad-key") from None


# ---- forward secrecy (2026-10-28; spec/SPEC.md §4.3 step 3, §7.4, §9, §10) ------------------------------------------
# An individual's wrap is sealed to its current key record's sealing key, a key of a day at most that the recipient
# deletes after its horizon, exp + TTL + skew, so a key stolen later opens nothing sealed before.


def key_record_verdict(address: str, record: Any, now: int, skew: int) -> str:
    """Whether `record` is a current valid key record of `address` at `now`: "ok", or the code that stops it. A record
    that is not a key record, or is the key record of another key, is bad-record; a key record of this key gives its
    own §7.5 verdict."""
    if not isinstance(record, dict) or record.get("kind") != "key" or record.get("key") != address:
        return "bad-record"
    return verdict(lambda: verify_record(record, now, skew))


def sealing_target(address: str, records: list[Any], now: int, skew: int) -> bytes | None:
    """§4.3 step 3: the X25519 public key a wrap to `address` is sealed to, the sealing key of its current key record:
    of the records held, the valid key record of `address` with the greatest iat (two are valid while one is re-signed),
    a tie broken by the greater exp, then by the greater sealing_key hex (ruled 2026-10-28). None
    when no record held is one, and the sender omits the recipient."""
    valid = [r for r in records if key_record_verdict(address, r, now, skew) == "ok"]
    if not valid:
        return None
    return bytes.fromhex(max(valid, key=lambda r: (r["iat"], r["exp"], r["sealing_key"]))["sealing_key"])


def deletion_horizon(record: dict[str, Any], ttl: int = TTL, skew: int = SKEW) -> int:
    """§7.4: the last second at which mail dated in the key record's life can still arrive and verify, exp + TTL + skew
    (the stale-ts bound of §5.5 at ts = exp). The recipient keeps the epoch's private key until then, and deletes it
    after."""
    return record["exp"] + ttl + skew


def ed25519_scalar(seed: bytes) -> bytes:
    """The 32 bytes RFC 8032 §5.1.5 takes as the Ed25519 secret scalar, the first half of SHA-512(seed); X25519 clamps it
    as RFC 7748 §5 does, which makes it the Ed25519-to-X25519 map of a signing key's private half."""
    return hashlib.sha512(seed).digest()[:32]


def open_wrap(address: str, enc: str, ct: str, sk: bytes) -> bytes:
    """§4.4's first half: the content key of a wrap to `address`, opened with the X25519 private key `sk`; any failure
    is open-failed (a wrap that does not authenticate, a small-order enc, malformed hex, a key of another length)."""
    need_crypto()
    if not (is_hex(enc, 32) and is_hex(ct)):
        raise Rejected("open-failed")
    try:
        key = open_base(bytes.fromhex(enc), sk, SEAL_INFO, address.encode("utf-8"), bytes.fromhex(ct))
    except (InvalidTag, ValueError):
        raise Rejected("open-failed") from None
    if len(key) != 32:
        raise Rejected("open-failed")
    return key


def stolen_key_opens(address: str, wrap: dict[str, str], long_term_seed: bytes, current_seed: bytes) -> dict[str, str]:
    """§10: the verdict of opening a wrap sealed to a deleted epoch key with each key a thief holds afterwards:
    the long-term signing key's seed used as an X25519 private key, the same key through the Ed25519-to-X25519 map,
    the X25519 key RFC 9180's DeriveKeyPair makes from that seed, and the current (different) epoch key. Forward secrecy
    needs open-failed for every one (ruled 2026-10-28: all three long-term forms)."""
    tries = {
        "long-term seed": long_term_seed,
        "long-term scalar": ed25519_scalar(long_term_seed),
        "long-term DeriveKeyPair": derive_key_pair(long_term_seed)[0],
        "current epoch key": current_seed,
    }
    return {k: verdict(lambda sk=sk: open_wrap(address, wrap["enc"], wrap["ct"], sk)) for k, sk in tries.items()}


def verdict(fn: Callable[[], Any]) -> str:
    try:
        fn()
    except Rejected as r:
        return r.code
    return "ok"


# ---- the checks ------------------------------------------------------------------------------------------------


class Tally:
    """Counts checks by kind: run, mismatched, skipped."""

    def __init__(self, quiet: bool = False) -> None:
        self.kinds: dict[str, list[int]] = {}
        self.mismatches: list[str] = []
        self.skipped: list[str] = []
        self.quiet = quiet

    def run(self, kind: str, where: str, fn: Callable[[], Any]) -> None:
        counts = self.kinds.setdefault(kind, [0, 0, 0])
        try:
            ok = bool(fn())
        except NeedCrypto:
            counts[2] += 1
            self.skipped.append(f"{where}: {kind}")
            if not self.quiet:
                print(f"  skipped (cryptography missing): {where}: {kind}")
            return
        except Exception as err:  # a malformed vector, a failed open: a mismatch, never a crash
            ok = False
            where = f"{where} ({type(err).__name__})"
        counts[0] += 1
        if not ok:
            counts[1] += 1
            self.mismatches.append(f"{where}: {kind}")
            if not self.quiet:
                print(f"  MISMATCH {where}: {kind}")

    def total(self, index: int) -> int:
        return sum(c[index] for c in self.kinds.values())


def utf16(code_units_hex: str) -> str:
    return bytes.fromhex(code_units_hex).decode("utf-16-be", "surrogatepass")


def dumps(v: Any) -> str:
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


# A fetch_proofs case's members, in the generator's order (added 2026-11-02).
FETCH_PROOF_MEMBERS = ["name", "accepted", "now", "id", "headers", "parties", "signed", "result"]


def fetch_verdict(c: dict[str, Any]) -> str:
    """A relay's verdict on a canonical.json fetch_proofs case (SPEC.md 8.3, added 2026-11-02), in the reference
    relay's order (crates/ac-relay/src/auth.rs): the id; the headers, AC-Auth's hops shaped as a chain; the signature
    over ["ac/fetch/1", signer, id, ts, base] for one of the accepted bases, byte for byte; the skew; the chain at ts;
    then whether its root is a party of the held envelope. "signed" is never read."""
    h, now = c["headers"], c["now"]
    if not is_hex(c["id"], 32):
        return "bad-hex"
    signer, ts_text, sig = h.get("ac-signer"), h.get("ac-ts"), h.get("ac-sig")
    if not is_address(signer) or not isinstance(ts_text, str) or re.fullmatch(r"[0-9]+", ts_text) is None:
        return "bad-auth"
    ts = int(ts_text)
    if ts > MAX_INT or not is_hex(sig, 64):
        return "bad-auth"
    hops: Any = []
    if "ac-auth" in h:
        try:
            text = h["ac-auth"].strip().rstrip("=")
            raw = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
            hops = parse_json(raw, "bad-auth")
            check_chain_shape(hops)
        except (Rejected, ValueError, TypeError, AttributeError):
            return "bad-auth"
    if not any(verify_preimage(signer, ["ac/fetch/1", signer, c["id"], ts, base], sig) for base in c["accepted"]):
        return "bad-auth"
    if ts + SKEW < now:
        return "stale-ts"
    if ts > now + SKEW:
        return "future-ts"
    try:
        root = verify_chain(hops, signer, ts)["root"]
    except Rejected:
        return "not-authorized"
    return "ok" if root in c["parties"] else "not-authorized"


def check_canonical(f: dict[str, Any], t: Tally) -> None:
    for c in f["cases"]:
        w = f"canonical.json {c['name']!r}"
        t.run("canonical string", w, lambda c=c: canonical(c["value"]) == c["canonical"])
        t.run("sha256", w, lambda c=c: sha256hex(c["canonical"]) == c["sha256"])
    for c in f["invalid"]:
        value = utf16(c["utf16_hex"]) if "utf16_hex" in c else c["value"]
        w = f"canonical.json invalid {c['name']!r}"
        t.run("canonical rejection", w, lambda v=value, c=c: verdict(lambda: canonical(v)) == c["result"])
    for c in f["preimages"]:
        w = f"canonical.json preimage {c['table']!r}"
        t.run("canonical string", w, lambda c=c: canonical(c["preimage"]) == c["canonical"])
        t.run("sha256", w, lambda c=c: sha256hex(c["canonical"]) == c["sha256"])
        if "signer" in c:
            t.run("signature", w, lambda c=c: verify_preimage(c["signer"], c["preimage"], c["sig"]))
        if c["table"] == "fetch auth":
            t.run("fetch auth fields", w, lambda c=c: fetch_auth_fields(c["preimage"]))
    t.run("fetch proofs present", "canonical.json fetch_proofs", lambda: bool(f.get("fetch_proofs")))
    for c in f.get("fetch_proofs", []):
        w = f"canonical.json fetch proof {c['name']!r}"
        t.run("fetch proof members", w, lambda c=c: list(c) == FETCH_PROOF_MEMBERS)
        t.run("fetch proof verdict", w, lambda c=c: fetch_verdict(c) == c["result"])


def check_hops(w: str, auth: list[dict[str, Any]], expected: list[dict[str, str]], t: Tally) -> None:
    for i, h in enumerate(auth):
        wh = f"{w} hop {i}"
        t.run("canonical string", wh, lambda h=h, i=i: canonical(hop_preimage(h)) == expected[i]["canonical"])
        t.run("sha256", wh, lambda h=h, i=i: digest(hop_preimage(h)).hex() == expected[i]["digest"])
        t.run("signature", wh, lambda h=h: verify_preimage(h["iss"], hop_preimage(h), h["sig"]))


def check_wrap(w: str, r: dict[str, str], wrap: dict[str, str], key: bytes, sk_e: bytes, t: Tally) -> None:
    seed = bytes.fromhex(r["sealing_seed"])
    aad = r["address"].encode("utf-8")
    enc, ct = bytes.fromhex(wrap["enc"]), bytes.fromhex(wrap["ct"])
    t.run("key from seed", w, lambda: x25519_public(seed).hex() == r["sealing_key"])
    t.run("hpke open", w, lambda: open_base(enc, seed, SEAL_INFO, aad, ct) == key)
    t.run("hpke seal", w, lambda: seal_base(bytes.fromhex(r["sealing_key"]), SEAL_INFO, aad, key, sk_e) == (enc, ct))


def case_bytes(c: dict[str, Any], *path: str) -> bytes:
    """The hex member of a case at `path` (member names), as bytes."""
    node: Any = c
    for step in path:
        node = node[step]
    return bytes.fromhex(node)


# The members of each forward-secrecy case, exactly (as check_record holds a record to KEY_KEYS): a member the reader
# would not read is a mismatch, never passed over. A key_record_seal case that is not ok has no target, and so no wrap.
KEY_RECORD_SEAL_KEYS = frozenset(
    {"name", "address", "key_record", "now", "epoch_seed", "content_key", "ephemeral_seed", "wrap", "result"}
)
STOLEN_KEY_KEYS = frozenset(
    {
        "name", "address", "long_term_seed", "epoch", "current", "sealed_at", "stolen_at", "content_key",
        "ephemeral_seed", "wrap", "result",
    }
)
EPOCH_KEYS = frozenset({"key_record", "seed"})
WRAP_KEYS = frozenset({"enc", "ct"})


def key_record_seal_shape(c: dict[str, Any]) -> bool:
    if c.get("result") != "ok":
        return set(c) == KEY_RECORD_SEAL_KEYS - {"wrap"} and is_int(c["now"])
    return set(c) == KEY_RECORD_SEAL_KEYS and isinstance(c["wrap"], dict) and set(c["wrap"]) == WRAP_KEYS and is_int(c["now"])


def stolen_key_shape(c: dict[str, Any]) -> bool:
    nested = all(isinstance(c[k], dict) and set(c[k]) == EPOCH_KEYS for k in ("epoch", "current"))
    wrap = isinstance(c["wrap"], dict) and set(c["wrap"]) == WRAP_KEYS
    return set(c) == STOLEN_KEY_KEYS and nested and wrap and is_int(c["sealed_at"]) and is_int(c["stolen_at"])


def fs_cases(name: str, f: dict[str, Any], key: str, t: Tally) -> list[tuple[str, dict[str, Any]]]:
    """A forward-secrecy list's cases with their labels. A list that is not a JSON list, or an entry that is not an
    object, is a mismatch, never a crash."""
    cases = f.get(key, [])
    if not isinstance(cases, list):
        t.run("case list", f"{name} {key!r} (not a list)", lambda: False)
        return []
    out = []
    for i, c in enumerate(cases):
        w = f"{name} {key.replace('_', ' ')} {c.get('name') if isinstance(c, dict) else i!r}"
        if isinstance(c, dict):
            out.append((w, c))
        else:
            t.run("case list", f"{w} (not an object)", lambda: False)
    return out


def check_key_record_seal(w: str, c: dict[str, Any], t: Tally) -> None:
    """Forward secrecy, §4.3 step 3: a wrap to `address` sealed at `now` to its key record. The verdict of the key
    record for that address at that time; when ok, the epoch seed gives the record's sealing key, the wrap recomputes
    from that key and the injected ephemeral key, and the epoch key opens it to the content key; otherwise the sender
    has no target."""
    # Every member is read inside a check, so a malformed case is a mismatch, never a crash (Tally).
    t.run("case shape", w, lambda: key_record_seal_shape(c))
    target = (lambda: sealing_target(c["address"], [c["key_record"]], c["now"], SKEW))
    t.run("key record verdict", w, lambda: key_record_verdict(c["address"], c["key_record"], c["now"], SKEW) == c["result"])
    if c.get("result") != "ok":
        t.run("sealing target", w, lambda: target() is None)
        return

    def seal() -> bool:
        key, sk_e = case_bytes(c, "content_key"), case_bytes(c, "ephemeral_seed")
        pk = target()
        sealed = None if pk is None else seal_base(pk, SEAL_INFO, c["address"].encode("utf-8"), key, sk_e)
        return sealed == (case_bytes(c, "wrap", "enc"), case_bytes(c, "wrap", "ct"))

    def opened() -> bool:
        return open_wrap(c["address"], c["wrap"]["enc"], c["wrap"]["ct"], case_bytes(c, "epoch_seed")) == case_bytes(c, "content_key")

    t.run("key from seed", w, lambda: x25519_public(case_bytes(c, "epoch_seed")).hex() == c["key_record"]["sealing_key"])
    t.run("hpke seal", w, seal)
    t.run("hpke open", w, opened)


def check_stolen_key(w: str, c: dict[str, Any], t: Tally) -> None:
    """Forward secrecy, §10: a wrap sealed at `sealed_at` to epoch key E (`epoch`), read at `stolen_at`, after E's
    deletion horizon, by a thief who holds the recipient's long-term signing seed and its current epoch key (`current`,
    a different key record valid then). The wrap recomputes to E's sealing key and E's seed opens it, so it is E's;
    every key the thief holds gives open-failed, the only result the case may state. Every member is read inside a check
    (Tally)."""

    def from_seed(name: str) -> bool:
        return x25519_public(case_bytes(c, name, "seed")).hex() == c[name]["key_record"]["sealing_key"]

    def valid(name: str, at: str) -> bool:
        return key_record_verdict(c["address"], c[name]["key_record"], c[at], SKEW) == "ok"

    def target_is(name: str, at: str) -> bool:  # of the two records, the one a sender seals to at that time
        held = [c["epoch"]["key_record"], c["current"]["key_record"]]
        return sealing_target(c["address"], held, c[at], SKEW) == case_bytes(c, name, "key_record", "sealing_key")

    def sealed() -> bool:
        pk, key, sk_e = case_bytes(c, "epoch", "key_record", "sealing_key"), case_bytes(c, "content_key"), case_bytes(c, "ephemeral_seed")
        return seal_base(pk, SEAL_INFO, c["address"].encode("utf-8"), key, sk_e) == (case_bytes(c, "wrap", "enc"), case_bytes(c, "wrap", "ct"))

    def opened() -> bool:
        return open_wrap(c["address"], c["wrap"]["enc"], c["wrap"]["ct"], case_bytes(c, "epoch", "seed")) == case_bytes(c, "content_key")

    def refused() -> bool:
        opens = stolen_key_opens(c["address"], c["wrap"], case_bytes(c, "long_term_seed"), case_bytes(c, "current", "seed"))
        return c["result"] == "open-failed" and set(opens.values()) == {"open-failed"}

    t.run("case shape", w, lambda: stolen_key_shape(c))
    t.run("key from seed", f"{w} long-term", lambda: "ed25519:" + ed25519_public(case_bytes(c, "long_term_seed")).hex() == c["address"])
    t.run("key from seed", f"{w} epoch", lambda: from_seed("epoch"))
    t.run("key from seed", f"{w} current", lambda: from_seed("current"))
    t.run("key record verdict", f"{w} epoch", lambda: valid("epoch", "sealed_at"))
    t.run("key record verdict", f"{w} current", lambda: valid("current", "stolen_at"))
    t.run("sealing target", f"{w} at sealed_at", lambda: target_is("epoch", "sealed_at"))
    t.run("sealing target", f"{w} at stolen_at", lambda: target_is("current", "stolen_at"))
    t.run("deletion horizon", w, lambda: c["stolen_at"] > deletion_horizon(c["epoch"]["key_record"]))
    t.run("distinct epoch keys", w, lambda: c["current"]["key_record"]["sealing_key"] != c["epoch"]["key_record"]["sealing_key"])
    t.run("hpke seal", w, sealed)
    t.run("hpke open", w, opened)
    t.run("stolen key verdict", w, refused)


def check_envelope_case(name: str, c: dict[str, Any], t: Tally) -> None:
    w = f"{name} {c['name']!r}"
    inp, exp = c["inputs"], c["expected"]
    env = exp["envelope"]
    raw = exp["bytes"].encode("utf-8")
    t.run("exact bytes", w, lambda: dumps(env) == exp["bytes"] and len(raw) == exp["size"])
    t.run("parse verdict", w, lambda: verdict(lambda: parse_envelope(raw)) == "ok")
    t.run("canonical string", w, lambda: canonical(sealed_hash_preimage(env["sealed"])) == exp["sealed_hash_canonical"])
    t.run("sealed hash", w, lambda: sha256hex(exp["sealed_hash_canonical"]) == exp["sealed_hash"])
    t.run("canonical string", w, lambda: canonical(envelope_id_preimage(env)) == exp["id_canonical"])
    t.run("envelope id", w, lambda: sha256hex(exp["id_canonical"]) == exp["id"] == env["id"])
    t.run("canonical string", w, lambda: canonical([1, env["to"], env["from"]]) == exp["content_aad"])
    t.run("plaintext", w, lambda: dumps(inp["content"]) == exp["plaintext"])
    check_hops(w, env["auth"], exp["hops"], t)
    from_key = bytes.fromhex(env["from"][len("ed25519:") :])
    t.run("signature", w, lambda: verify_sig(from_key, bytes.fromhex(env["id"]), bytes.fromhex(env["sig"])))
    t.run("chain verdict", w, lambda: verify_chain(env["auth"], env["from"], env["ts"]) == exp["chain"])
    t.run("outer verdict", w, lambda: verdict(lambda: verify_outer(env, inp["ts"], TTL, SKEW)) == "ok")
    t.run("coding profile", w, lambda: evaluate_coding(exp["chain"]["caveats"], inp["content"]) == exp["coding_profile"])
    t.run("key from seed", w, lambda: ed25519_public(bytes.fromhex(inp["from_seed"])) == from_key)
    key, nonce = bytes.fromhex(inp["content_key"]), bytes.fromhex(inp["nonce"])
    aad = canonical([1, env["to"], env["from"]]).encode("utf-8")
    plaintext = exp["plaintext"].encode("utf-8")
    t.run("content open", w, lambda: aead_open(key, nonce, aad, bytes.fromhex(env["sealed"]["ct"])) == plaintext)
    t.run("content seal", w, lambda: aead_seal(key, nonce, aad, plaintext).hex() == env["sealed"]["ct"])
    for i, (r, wrap) in enumerate(zip(inp["to"], env["sealed"]["wraps"], strict=True)):
        check_wrap(f"{w} wrap {i}", r, wrap, key, bytes.fromhex(inp["ephemeral_seeds"][i]), t)


def check_envelopes(name: str, f: dict[str, Any], t: Tally) -> None:
    for c in f["cases"]:
        check_envelope_case(name, c, t)
    for c in f.get("parse", []):
        if "bytes_hex" in c:
            raw = bytes.fromhex(c["bytes_hex"])
        else:
            raw = (c["bytes"] + " " * c.get("pad_with_spaces", 0)).encode("utf-8")
        w = f"{name} parse {c['name']!r}"
        t.run("parse verdict", w, lambda raw=raw, c=c: verdict(lambda: parse_envelope(raw)) == c["result"])
    for c in f.get("verify", []):
        e = parse_envelope(c["bytes"].encode("utf-8"))
        w = f"{name} verify {c['name']!r}"
        outer = (lambda e=e, c=c: verify_outer(e, c["now"], c["ttl"], c["skew"]))
        t.run("outer verdict", w, lambda outer=outer, c=c: verdict(outer) == c["result"])
    for c in f.get("open", []):
        w = f"{name} open {c['name']!r}"
        t.run("open verdict", w, lambda c=c: open_verdict(c) == (c["result"], c.get("content")))
    for c in f.get("seal", []):
        w = f"{name} seal {c['name']!r}"
        t.run("seal verdict", w, lambda c=c: verdict(lambda: seal_to(c)) == c["result"])
    for w, c in fs_cases(name, f, "key_record_seal", t):
        check_key_record_seal(w, c, t)
    for w, c in fs_cases(name, f, "stolen_key", t):
        check_stolen_key(w, c, t)


def open_verdict(c: dict[str, Any]) -> tuple[str, Any]:
    """The verdict of opening, and the content when it opens."""
    try:
        return "ok", open_sealed(c)
    except Rejected as r:
        return r.code, None


def check_chains(name: str, f: dict[str, Any], t: Tally) -> None:
    for c in f["cases"]:
        w = f"{name} {c['name']!r}"
        chain = (lambda c=c: verify_chain(c["auth"], c["from"], c["ts"]))
        if c["result"] == "ok":
            t.run("chain verdict", w, lambda chain=chain, c=c: chain() == c["chain"])
            check_hops(w, c["auth"], c["hops"], t)
        else:
            t.run("chain verdict", w, lambda chain=chain, c=c: verdict(chain) == c["result"])
    for c in f.get("caveats", []):
        w = f"{name} caveats {c['name']!r}"
        t.run("caveat verdict", w, lambda c=c: caveat_verdict(c) == (c["result"], c.get("caveat")))


def caveat_verdict(c: dict[str, Any]) -> tuple[str, str | None]:
    """The coding profile's verdict on a case's effective caveats against its sealed content (§6.3, §6.4)."""
    r = evaluate_coding(c["caveats"], c["content"])
    return ("ok", None) if r["ok"] else (r["code"], r["caveat"])


def check_records(f: dict[str, Any], t: Tally) -> None:
    for c in f["cases"]:
        w = f"records.json {c['name']!r}"
        r = c["record"]
        signed = all(k["result"] != "bad-record-sig" for k in c["checks"])
        t.run("canonical string", w, lambda r=r, c=c: canonical(record_preimage(r)) == c["canonical"])
        t.run("sha256", w, lambda r=r, c=c: digest(record_preimage(r)).hex() == c["digest"])
        t.run("record signer", w, lambda r=r, c=c: record_signer(r) == c["signer"])
        t.run("signature", w, lambda r=r, s=signed: verify_preimage(record_signer(r), record_preimage(r), r["sig"]) == s)
        for k in c["checks"]:
            check = (lambda r=r, k=k: verify_record(r, k["now"], k["skew"]))
            t.run("record verdict", f"{w} at {k['now']}", lambda check=check, k=k: verdict(check) == k["result"])
    for c in f["invalid"]:
        w = f"records.json invalid {c['name']!r}"
        t.run("record verdict", w, lambda c=c: verdict(lambda: check_record(c["record"])) == c["result"])
    for c in f["rotations"]:
        w = f"records.json rotation {c['name']!r}"
        t.run("rotation verdict", w, lambda c=c: verdict(lambda: verify_rotation(c["prev"], c["next"])) == c["result"])
    for c in f.get("parse", []):
        w = f"records.json parse {c['name']!r}"
        raw = bytes.fromhex(c["bytes_hex"]) if "bytes_hex" in c else c["bytes"].encode("utf-8")
        t.run("record parse verdict", w, lambda raw=raw, c=c: verdict(lambda: check_record(parse_json(raw))) == c["result"])
    for c in f.get("rotation_claims", []):
        w = f"records.json rotation claim {c['name']!r}"
        t.run("rotation claim verdict", w, lambda c=c: verdict(lambda: verify_rotation_claim(c["next"])) == c["result"])


def check_discovery(f: dict[str, Any], t: Tally) -> None:
    for c in f["presentation"]:
        w = f"discovery.json presentation {c['name']!r}"
        t.run("txt text verdict", w, lambda c=c: verdict(lambda: parse_presentation(c["text"])) == c["result"])
        if c["result"] == "ok":
            t.run("txt strings", w, lambda c=c: [s.hex() for s in parse_presentation(c["text"])] == c["strings_hex"])
    for c in f["txt"]:
        w = f"discovery.json txt {c['name']!r}"
        records = [[s.encode("utf-8") for s in r] for r in c["records"]]
        t.run("txt name", w, lambda c=c: txt_name(c["domain"]) == c["txt_name"])
        t.run("txt verdict", w, lambda c=c, r=records: verdict(lambda: discover(r, c["domain"])) == c["result"])
        if c["result"] == "ok":
            t.run("txt discovery", w, lambda c=c, r=records: discover(r, c["domain"]) == (c["key"], c["url"], c["origin"]))
    for c in f["agreement"]:
        w = f"discovery.json agreement {c['name']!r}"
        ok = (lambda c=c: agrees(c["txt_key"], c["record"]))
        t.run("agreement verdict", w, lambda c=c, ok=ok: ("ok" if ok() else "resolve-failed") == c["result"])
        after = (lambda c=c, ok=ok: pin_after(c["pinned"], c["record"]) if ok() else (c["pinned"] or {}).get("key"))
        t.run("pin after", w, lambda c=c, after=after: after() == c["pin"])
    for c in f["handles"]:
        w = f"discovery.json handle {c['name']!r}"
        t.run("handle verdict", w, lambda c=c: verdict(lambda: parse_handle(c["handle"])) == c["result"])
        if c["result"] == "ok":
            t.run("handle parts", w, lambda c=c: parse_handle(c["handle"]) == (c["local"], c["domain"]) and handle_path(c["handle"]) == c["path"])
    for c in f["cases"]:
        w = f"discovery.json handle record {c['name']!r}"
        r = c["record"]
        signed = all(k["result"] != "bad-record-sig" for k in c["checks"])
        t.run("canonical string", w, lambda r=r, c=c: canonical(handle_record_preimage(r)) == c["canonical"])
        t.run("sha256", w, lambda r=r, c=c: digest(handle_record_preimage(r)).hex() == c["digest"])
        t.run("record signer", w, lambda r=r, c=c: r["org"] == c["signer"])
        t.run("signature", w, lambda r=r, s=signed: verify_preimage(r["org"], handle_record_preimage(r), r["sig"]) == s)
        for k in c["checks"]:
            check = (lambda r=r, k=k: verify_handle_record(r, k["org"], k["handle"], k["revoked"], k["now"], k["skew"]))
            t.run("handle record verdict", f"{w} at {k['now']}", lambda check=check, k=k: verdict(check) == k["result"])
    for c in f["invalid"]:
        w = f"discovery.json invalid {c['name']!r}"
        t.run("handle record verdict", w, lambda c=c: verdict(lambda: check_handle_record(c["record"])) == c["result"])
    for c in f["parse"]:
        w = f"discovery.json parse {c['name']!r}"
        raw = c["bytes"].encode("utf-8")
        t.run("handle record parse verdict", w, lambda raw=raw, c=c: verdict(lambda: check_handle_record(parse_json(raw))) == c["result"])


def check_rfc9180(f: dict[str, Any], t: Tally) -> None:
    for n, c in enumerate(f["cases"]):
        w = f"hpke-rfc9180-subset.json case {n}"
        t.run("rfc9180 field", w, lambda c=c: (c["mode"], c["kem_id"], c["kdf_id"], c["aead_id"]) == (0, 0x20, 1, 2))
        try:
            sk_r, pk_r = derive_key_pair(bytes.fromhex(c["ikmR"]))
            sk_e, pk_e = derive_key_pair(bytes.fromhex(c["ikmE"]))
            shared, enc = encap(pk_r, sk_e)
            ks = key_schedule(shared, bytes.fromhex(c["info"]))
        except NeedCrypto:  # every field, encryption and export below needs X25519: each is a skipped check
            for k in ("skRm", "pkRm", "skEm", "pkEm", "enc", "shared_secret", "key_schedule_context", "secret"):
                t.run("rfc9180 field", f"{w} {k}", need_crypto)
            for k in ("key", "base_nonce", "exporter_secret", "decap"):
                t.run("rfc9180 field", f"{w} {k}", need_crypto)
            for seq in range(len(c["encryptions"])):
                t.run("rfc9180 encryption", f"{w} encryption {seq}", need_crypto)
            for i in range(len(c["exports"])):
                t.run("rfc9180 export", f"{w} export {i}", need_crypto)
            continue
        fields = {"skRm": sk_r, "pkRm": pk_r, "skEm": sk_e, "pkEm": pk_e, "enc": enc, "shared_secret": shared, **ks}
        for k, v in fields.items():
            t.run("rfc9180 field", f"{w} {k}", lambda k=k, v=v, c=c: v.hex() == c[k])
        t.run("rfc9180 field", f"{w} decap", lambda c=c: decap(bytes.fromhex(c["enc"]), sk_r).hex() == c["shared_secret"])
        for seq, x in enumerate(c["encryptions"]):
            nonce = nonce_for(ks["base_nonce"], seq)
            aad, pt, ct = bytes.fromhex(x["aad"]), bytes.fromhex(x["pt"]), bytes.fromhex(x["ct"])

            def encryption(x=x, nonce=nonce, aad=aad, pt=pt, ct=ct) -> bool:
                sealed = aead_seal(ks["key"], nonce, aad, pt)
                return nonce.hex() == x["nonce"] and sealed == ct and aead_open(ks["key"], nonce, aad, ct) == pt

            t.run("rfc9180 encryption", f"{w} encryption {seq}", encryption)
        for i, x in enumerate(c["exports"]):
            context = bytes.fromhex(x["exporter_context"])

            def export(x=x, context=context) -> bool:
                value = labeled_expand(HPKE_SUITE, ks["exporter_secret"], b"sec", context, x["L"])
                return value.hex() == x["exported_value"]

            t.run("rfc9180 export", f"{w} export {i}", export)


ENVELOPE_LISTS = frozenset({"cases", "parse", "verify", "open", "seal", "key_record_seal", "stolen_key"})
# The case lists each file's reader reads. A list member outside them is a mismatch, so a list the generator adds is
# never skipped in silence (added 2026-10-28 with the forward-secrecy lists); `notes` is prose.
READ_LISTS: dict[str, frozenset[str]] = {
    "canonical.json": frozenset({"cases", "invalid", "preimages", "fetch_proofs"}),
    "envelope.json": ENVELOPE_LISTS,
    "sealed-multi.json": ENVELOPE_LISTS,
    "chain-valid.json": frozenset({"cases", "caveats"}),
    "chain-invalid.json": frozenset({"cases", "caveats"}),
    "records.json": frozenset({"cases", "invalid", "rotations", "parse", "rotation_claims"}),
    "hpke-rfc9180-subset.json": frozenset({"cases"}),
    "discovery.json": frozenset({"presentation", "txt", "agreement", "handles", "cases", "invalid", "parse"}),
    "pair-code.json": frozenset(),
}


def check_pair_code(f: dict[str, Any], t: Tally) -> None:
    """Pairing (SPEC §8.10): S = HKDF-SHA256 over the words, the lenient codec, the check digits, the request mac, the
    invite string and the pair/open signature."""
    for c in f.get("s_derivation", {}).get("cases", []):
        where = f"pair-code S {c.get('nameplate')}-{'-'.join(c.get('words', []))}"

        def recompute(c: dict[str, Any] = c) -> bool:
            ikm = unicodedata.normalize("NFKC", " ".join(c["words"]).lower()).encode("utf-8")
            salt = (c["nameplate"] + "|" + c["invitation"]).encode("utf-8")
            s = hkdf_expand(hkdf_extract(salt, ikm), b"ac/peer-code/1", 16).hex()
            if s != c["s_hex"]:
                raise AssertionError(f"S {s} != {c['s_hex']}")
            return True

        t.run("pair code S", where, recompute)
    for c in f.get("codec", {}).get("cases", []):
        raw = c.get("code", c.get("input", ""))

        def parse_check(c: dict[str, Any] = c, raw: str = raw) -> bool:
            toks = unicodedata.normalize("NFKC", raw).strip().lower().replace("-", " ").split()
            if not toks or toks[0] != c["nameplate"] or toks[1:] != c["words"]:
                raise AssertionError(f"parse {toks} != {c['nameplate']},{c['words']}")
            if "code" in c and c["code"] != c["nameplate"] + "-" + "-".join(c["words"]):
                raise AssertionError(f"canonical format mismatch for {c['code']}")
            return True

        t.run("pair code codec", f"pair-code codec {raw!r}", parse_check)
    # Added 2026-11-03: the cases the edge writes (packages/edge/scripts/gen-pair-code-vectors.ts), recomputed here.
    for c in f.get("check_digits", {}).get("cases", []):

        def digits(c: dict[str, Any] = c) -> bool:
            pre = ["ac/peer-code/1", c["inviter"], c["invitation"], c["requester"], c["sealing"], c["s_hex"]]
            d = digest(pre)
            n = f"{int.from_bytes(d[:4], 'big') % 1_000_000:06d}"
            shown = f"{n[:3]} {n[3:]}"
            return (canonical(pre), d.hex(), n, shown) == (c["canonical"], c["sha256"], c["digits"], c["shown"])

        t.run("pair check digits", f"pair-code check digits {c.get('name')!r}", digits)
    for c in f.get("request_mac", {}).get("cases", []):

        def mac(c: dict[str, Any] = c) -> bool:
            pre = ["ac/peer-request/1", c["inviter"], c["invitation"], c["requester"], c["sealing"], c["exp"]]
            text = canonical(pre)
            m = hmac.new(bytes.fromhex(c["s_hex"]), text.encode("utf-8"), hashlib.sha256).hexdigest()
            return (text, m) == (c["canonical"], c["mac"])

        t.run("pair request mac", f"pair-code request mac {c.get('name')!r}", mac)
    for c in f.get("invite_string", {}).get("cases", []):

        def invite(c: dict[str, Any] = c) -> bool:
            text = canonical(["ac/peer-invite/1", c["inviter"], c["invitation"], c["relay"], c["s_hex"]])
            b64 = base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")
            return (text, "ac-peer1:" + b64) == (c["canonical"], c["invite"])

        t.run("pair invite string", f"pair-code invite string {c.get('name')!r}", invite)
    for c in f.get("pair_open", {}).get("cases", []):

        def pair_open(c: dict[str, Any] = c) -> bool:
            pre = ["ac/pair-open/1", c["inviter"], c["invitation"], c["relays"], c["ttl"]]
            body = json.loads(c["body"])
            fields = {k: c[k] for k in ("inviter", "invitation", "relays", "ttl", "sig")}
            ok = verify_preimage(c["invitation"], pre, c["sig"])
            return ok and (canonical(pre), digest(pre).hex(), body) == (c["canonical"], c["sha256"], fields)

        t.run("pair open", f"pair-code pair/open {c.get('name')!r}", pair_open)


def check_file(name: str, f: dict[str, Any], t: Tally) -> None:
    for k in sorted(k for k, v in f.items() if isinstance(v, list) and k != "notes" and k not in READ_LISTS[name]):
        t.run("list read", f"{name} {k!r} (a list the verifier does not read)", lambda: False)
    if name == "canonical.json":
        check_canonical(f, t)
    elif name in ("envelope.json", "sealed-multi.json"):
        check_envelopes(name, f, t)
    elif name in ("chain-valid.json", "chain-invalid.json"):
        check_chains(name, f, t)
    elif name == "records.json":
        check_records(f, t)
    elif name == "discovery.json":
        check_discovery(f, t)
    elif name == "pair-code.json":
        check_pair_code(f, t)
    else:
        check_rfc9180(f, t)


# ---- the codes with a verdict ---------------------------------------------------------------------------------------


def appendix_a_codes(spec: Path = SPEC) -> list[str]:
    """The codes of spec/SPEC.md Appendix A, in the table's order."""
    text = spec.read_text(encoding="utf-8")
    section = text[text.index("## Appendix A.") : text.index("## Appendix B.")]
    return re.findall(r"^\| `([a-z0-9-]+)` \|", section, re.MULTILINE)


def verdicts(v: Any) -> set[str]:
    """Every `result` member's value, in any list of any case, `checks` included."""
    if isinstance(v, dict):
        found = {v["result"]} if isinstance(v.get("result"), str) else set()
        return found.union(*(verdicts(x) for x in v.values()))
    if isinstance(v, list):
        return set().union(*(verdicts(x) for x in v))
    return set()


def codes_with_a_verdict(files: dict[str, dict[str, Any]]) -> tuple[list[str], list[str]]:
    """(the Appendix A codes some vector gives as its verdict, every Appendix A code): the unit of the vector claim."""
    codes = appendix_a_codes()
    found = set().union(*(verdicts(f) for f in files.values()))
    return [c for c in codes if c in found], codes


# ---- negative controls --------------------------------------------------------------------------------------------


def flip_hex(s: str) -> str:
    return ("1" if s[0] == "0" else "0") + s[1:]


def flip_char(s: str) -> str:
    return s[:1] + ("y" if s[1:2] == "x" else "x") + s[2:]


def at(path: tuple[str | int, ...], change: Callable[[Any], Any]) -> Callable[[dict[str, Any]], None]:
    """A one-byte change to the value at `path` (member names and list indexes) of a loaded vector file."""

    def apply(f: dict[str, Any]) -> None:
        node: Any = f
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = change(node[path[-1]])

    return apply


def past_a_key_life(v: int) -> int:
    return v + MAX_KEY_LIFETIME + 1  # a time after the exp of any key record valid at v


def stolen_at_the_horizon(f: dict[str, Any]) -> None:
    c = f["stolen_key"][0]
    c["stolen_at"] = deletion_horizon(c["epoch"]["key_record"])  # E may still be held: not yet past its horizon


# (what is changed, in which file, whether catching it needs cryptography, the change)
CONTROLS: list[tuple[str, str, bool, Callable[[dict[str, Any]], None]]] = [
    ("an envelope id", "envelope.json", False, at(("cases", 0, "expected", "id"), flip_hex)),
    ("a canonical string", "canonical.json", False, at(("cases", 6, "canonical"), flip_char)),
    ("a sealed hash", "sealed-multi.json", False, at(("cases", 2, "expected", "sealed_hash"), flip_hex)),
    ("a chain verdict", "chain-invalid.json", False, at(("cases", 4, "result"), lambda _: "chain-broken")),
    ("a parse verdict", "envelope.json", False, at(("parse", 8, "result"), lambda _: "bad-shape")),
    ("a record verdict", "records.json", False, at(("invalid", 3, "result"), lambda _: "bad-record")),
    ("an outer signature", "envelope.json", True, at(("cases", 1, "expected", "envelope", "sig"), flip_hex)),
    ("a hop signature", "chain-valid.json", True, at(("cases", 2, "auth", 0, "sig"), flip_hex)),
    ("a wrap", "sealed-multi.json", True, at(("cases", 0, "expected", "envelope", "sealed", "wraps", 1, "ct"), flip_hex)),
    ("an RFC 9180 ciphertext", "hpke-rfc9180-subset.json", True, at(("cases", 0, "encryptions", 100, "ct"), flip_hex)),
    # The lists of 2026-10-25: a degenerate-key verdict, an open, a seal, a caveat, a record parse and a claim.
    ("a degenerate key's verdict", "envelope.json", True, at(("verify", 11, "result"), lambda _: "ok")),
    ("an open verdict", "envelope.json", True, at(("open", 2, "result"), lambda _: "ok")),
    ("a seal verdict", "envelope.json", True, at(("seal", 0, "result"), lambda _: "ok")),
    ("a caveat verdict", "chain-valid.json", False, at(("caveats", 3, "result"), lambda _: "caveat-failed")),
    ("a record parse verdict", "records.json", False, at(("parse", 1, "result"), lambda _: "ok")),
    ("a rotation claim verdict", "records.json", True, at(("rotation_claims", 1, "result"), lambda _: "ok")),
    # discovery.json (2026-10-26): a TXT verdict (two bag records) and a handle record's signature.
    ("a txt verdict", "discovery.json", False, at(("txt", 20, "result"), lambda _: "ok")),
    # An agreement verdict (k11 naming k10 with no rotation_sig) turned to ok.
    ("an agreement verdict", "discovery.json", False, at(("agreement", 7, "result"), lambda _: "ok")),
    ("a handle record's signature", "discovery.json", True, at(("cases", 0, "record", "sig"), flip_hex)),
    # The forward-secrecy lists (2026-10-28): a key-record seal's wrap and key record, a stolen-key wrap and verdict.
    ("a key-record seal's wrap", "envelope.json", True, at(("key_record_seal", 0, "wrap", "ct"), flip_hex)),
    ("a key-record seal's key record", "envelope.json", True, at(("key_record_seal", 0, "key_record", "sig"), flip_hex)),
    ("a stolen-key wrap", "envelope.json", True, at(("stolen_key", 0, "wrap", "enc"), flip_hex)),
    ("a stolen-key verdict", "envelope.json", True, at(("stolen_key", 0, "result"), lambda _: "ok")),
    ("a key-record seal's time, past the record's life", "envelope.json", True, at(("key_record_seal", 0, "now"), past_a_key_life)),
    ("a stolen-key long-term seed", "envelope.json", True, at(("stolen_key", 0, "long_term_seed"), flip_hex)),
    ("a stolen-key sealing time, past E's life", "envelope.json", True, at(("stolen_key", 0, "sealed_at"), past_a_key_life)),
    ("a stolen-key theft at E's deletion horizon", "envelope.json", True, stolen_at_the_horizon),
    # The fetch proofs (2026-11-02, §8.3): the cross-relay replay's verdict turned to ok, and the base of the proof
    # that verifies changed by one byte.
    ("a fetch proof verdict", "canonical.json", True, at(("fetch_proofs", 1, "result"), lambda _: "ok")),
    ("a fetch proof's accepted base", "canonical.json", True, at(("fetch_proofs", 0, "accepted", 0), flip_char)),
]


def run_controls(files: dict[str, dict[str, Any]]) -> tuple[int, int, int]:
    """(caught, missed, skipped): each one-byte change must give at least one mismatch."""
    caught = missed = skipped = 0
    for label, name, crypto, change in CONTROLS:
        if crypto and CRYPTO is None:
            print(f"  skipped (cryptography missing): control {label}")
            skipped += 1
            continue
        f = copy.deepcopy(files[name])
        try:
            change(f)
        except (KeyError, IndexError, TypeError):  # the vector it changes is missing: the control cannot run
            missed += 1
            print(f"  CONTROL MISSED: the vector {label} changes is missing from {name}")
            continue
        t = Tally(quiet=True)
        check_file(name, f, t)
        if t.mismatches:
            caught += 1
        else:
            missed += 1
            print(f"  CONTROL MISSED: one byte changed in {label} ({name}) was not reported")
    return caught, missed, skipped


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dir", nargs="?", type=Path, default=ROOT / "spec" / "vectors", help="default: spec/vectors")
    a = ap.parse_args(argv)
    print(f"verify_vectors: {a.dir} (cryptography {CRYPTO or 'missing'})")
    files: dict[str, dict[str, Any]] = {}
    t = Tally()
    for name in FILES:
        path = a.dir / name
        if not path.is_file():
            t.run("file", name, lambda: False)
            continue
        files[name] = json.loads(path.read_text(encoding="utf-8"))
    for extra in sorted(p.name for p in a.dir.glob("*.json") if p.name not in FILES):
        t.run("file", f"{extra} (not a vector file)", lambda: False)
    for name, f in files.items():
        before = (t.total(0), t.total(1), t.total(2))
        check_file(name, f, t)
        run, bad, skip = (t.total(i) - before[i] for i in range(3))
        print(f"  {name}: {run} checks, {bad} mismatches, {skip} skipped")
    print("  by kind (matched of run, skipped):")
    for kind, (run, bad, skip) in sorted(t.kinds.items()):
        print(f"    {kind:<20} {run - bad:>5} of {run:<5} skipped {skip}")
    caught, missed, control_skips = (0, 0, 0)
    if len(files) == len(FILES):
        caught, missed, control_skips = run_controls(files)
    print(f"  controls: {caught} of {len(CONTROLS)} one-byte changes caught, {missed} missed, {control_skips} skipped")
    with_verdict, codes = codes_with_a_verdict(files)
    print(f"  codes of Appendix A with a vector verdict: {len(with_verdict)} of {len(codes)}")
    run, bad, skip = t.total(0), t.total(1), t.total(2) + control_skips
    ids = t.kinds.get("envelope id", [0, 0, 0])
    sigs = t.kinds.get("signature", [0, 0, 0])
    opens = t.kinds.get("hpke open", [0, 0, 0])
    summary = (
        f"{run} checks, {bad} mismatches, {skip} skipped; envelope ids {ids[0] - ids[1]} of {ids[0]}, "
        f"signatures {sigs[0] - sigs[1]} of {sigs[0]}, HPKE opens {opens[0] - opens[1]} of {opens[0]}"
    )
    if bad or missed:
        print(f"verify_vectors: FAIL: {summary}")
        return 1
    if skip:
        print(f"verify_vectors: NOT RUN IN FULL: {summary}; a skipped check is not a pass")
        return 2
    print(f"verify_vectors: OK: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

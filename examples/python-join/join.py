"""A bag participant in Python, written from spec/SPEC.md and spec/vectors/ alone.

    join.py --home DIR keygen                                      # prints the new address
    join.py --home DIR records --relay URL [--accept ADDRESS]...   # its address and accept-from records
    join.py --home DIR send --relay URL --to ADDRESS [--type T] [--body JSON]   # prints the envelope's id
    join.py --home DIR receive --relay URL [--trust ADDRESS]...    # accept <id> <from> <root> <type> <body>

Self-rooted senders only (an empty chain), one recipient per envelope, one relay. README.md lists the rest.
"""

import argparse
import json
import os
import re
import secrets
import time
import unicodedata
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from wire import WebSocket, canonical, digest, dumps, hpke_open, hpke_seal, public, strict_json, verified

# The defaults of §5.5, and the members of each record in the order of its preimage (§2.4)
TTL, SKEW = 604_800, 300
ADDRESS = ("key", "sealing_key", "relays", "rotation_key", "revoked", "ttl", "iat", "rotated_from")
ACCEPT = ("owner", "roots", "max_bytes", "ttl", "iat")
KEY = ("key", "sealing_key", "iat", "exp")
SEAL_INFO = b"ac/seal/1"
# The CLI's short token for a type (shownType, packages/cli/src/commands/inbox.ts): /^[\w.+*-]{1,64}$/. re.ASCII makes
# \w JavaScript's [A-Za-z0-9_] (Python's own \w takes any Unicode letter or digit), and fullmatch, unlike Python's $,
# never takes a final newline; the token is ASCII only, so its 64 counts the same in UTF-16 units and code points.
SHOWN_TYPE = re.compile(r"[\w.+*-]{1,64}", re.ASCII)
# U+2028 and U+2029, written as escapes, never as the raw characters
LINE_SEPARATORS = "\u2028\u2029"
# An id as a line shows it: 64 lowercase hex characters (§5.3), else "(not shown)"
SHOWN_ID = re.compile(r"[0-9a-f]{64}")


# A refusal: its message is a code of the spec's Appendix A, or says what differed
class Reject(Exception):
    pass


def check(ok, code):
    if not ok:
        raise Reject(code)


# The signing key, the sealing key and the address of the identity in `home`
def identity(home):
    keys = json.loads((Path(home) / "keys.json").read_text())
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["sign"]))
    return sk, X25519PrivateKey.from_private_bytes(bytes.fromhex(keys["seal"])), "ed25519:" + public(sk).hex()


def sign(sk, preimage):
    return sk.sign(digest(preimage)).hex()


# One call to the relay (§8); an error status raises HTTPError, whose body names the code
def http(relay, path, body=None, headers=None):
    headers = {"Content-Type": "application/json", **(headers or {})}
    with urlopen(Request(relay.rstrip("/") + path, body, headers), timeout=10) as response:
        return response.read()


# An Ed25519 signing key and a separate X25519 sealing key, 32 random bytes each (§3.3), in a 0600 file
def keygen(a):
    Path(a.home).mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(Path(a.home) / "keys.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"sign": secrets.token_hex(32), "seal": secrets.token_hex(32)}, f)
    print(identity(a.home)[2])


# A record whose preimage is [tag, *values] (§2.4), signed by its own key (§7.1)
def signed(sk, kind, tag, fields, values, **rest):
    return {"kind": kind, **dict(zip(fields, values, strict=True)), **rest, "sig": sign(sk, [tag, *values])}


# Forward secrecy: publish a key record over a fresh epoch sealing key (§7.3), an address record with a null
# sealing key (§7.2) and an accept-from record (§7.4), all published (§8.2). The epoch private key is kept in key.json
# for receive to open with; a fresh one each time records runs, so an old key record's private half can be let go. The
# null address sealing key is what forbids a sender from downgrading to a long-lived key: there is none to seal to.
def records(a):
    sk, _, me = identity(a.home)
    now = int(time.time())
    ek_seed = secrets.token_hex(32)
    ek = X25519PrivateKey.from_private_bytes(bytes.fromhex(ek_seed))
    exp = now + 86_400  # the most a key record may live (§7.3)
    fd = os.open(Path(a.home) / "key.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"seal": ek_seed, "iat": now, "exp": exp}, f)
    key = signed(sk, "key", "ac/key/1", KEY, [me, public(ek).hex(), now, exp])
    # No sealing key in the address record, no rotation key, nothing revoked, valid for a day (the most §7.2 allows)
    values = [me, None, [a.relay], None, [], 86_400, now, None]
    address = signed(sk, "address", "ac/addr/1", ADDRESS, values, rotation_sig=None)
    accept = signed(sk, "accept-from", "ac/accept/1", ACCEPT, [me, a.accept or ["*"], 65_536, TTL, now])
    # The key record first, so a sender that prefers it finds it before the null address record is served
    for record in (key, address, accept):
        http(a.relay, "/v0/publish", dumps(record).encode())
    print(me)


# The recipient's sealing key, preferring its key record (§7.3), verified (§7.5): the current key record's
# sealing key when it has one, else the address record's (a peer that still publishes one, e.g. a group's generation
# key). A sender is never downgraded to a long-lived key while a key record stands.
def resolve(relay, address):
    try:
        r = strict_json(http(relay, f"/v0/fetch/record/{address}/key"))
    except HTTPError as err:
        if err.code != 404:
            raise
    else:
        ok = verified(address, digest(["ac/key/1", *(r[f] for f in KEY)]), r["sig"]) and r["key"] == address
        check(ok and r["iat"] - SKEW <= time.time() <= r["exp"], "resolve-failed")
        return bytes.fromhex(r["sealing_key"])
    r = strict_json(http(relay, f"/v0/fetch/record/{address}/address"))
    ok = verified(address, digest(["ac/addr/1", *(r[f] for f in ADDRESS)]), r["sig"]) and r["key"] == address
    check(ok and r["iat"] - SKEW <= time.time() <= r["iat"] + r["ttl"], "resolve-failed")
    check(r["sealing_key"] is not None, "resolve-failed")
    return bytes.fromhex(r["sealing_key"])


# The sealed hash: position 6 of the id's preimage (§5.3)
def sealed_hash(s):
    return digest([[[w["to"], w["enc"], w["ct"]] for w in s["wraps"]], s["nonce"], s["ct"]]).hex()


# §4.3 and §5.3: the envelope's bytes. `rand` draws the content key, the nonce, then one ephemeral key
# per recipient, so that the vectors can inject theirs.
def seal(sk, me, recipients, content, ts, rand=secrets.token_bytes):
    key, nonce, to = rand(32), rand(12), [address for address, _ in recipients]
    ct = AESGCM(key).encrypt(nonce, dumps(content).encode(), canonical([1, to, me]).encode())
    wraps = []
    # One wrap per recipient, in the order of `to`, bound to its address by the AAD
    for address, sealing_key in recipients:
        enc, wrapped = hpke_seal(sealing_key, SEAL_INFO, address.encode(), key, rand(32))
        wraps.append({"to": address, "enc": enc.hex(), "ct": wrapped.hex()})
    sealed = {"wraps": wraps, "nonce": nonce.hex(), "ct": ct.hex()}
    eid = digest([1, to, me, [], 1, ts, sealed_hash(sealed)]).hex()
    envelope = {"v": 1, "id": eid, "to": to, "from": me, "auth": [], "suite": 1, "ts": ts, "sealed": sealed}
    envelope["sig"] = sk.sign(bytes.fromhex(eid)).hex()
    return dumps(envelope).encode()


# Build and seal (§5.6), publish (§8.2), then fetch it back by id with the proof of §8.3
def send(a):
    sk, _, me = identity(a.home)
    # A new thread (§5.2)
    thread = {"id": secrets.token_hex(32), "prev": []}
    content = {"type": a.type, "thread": thread, "body": json.loads(a.body)}
    raw = seal(sk, me, [(a.to, resolve(a.relay, a.to))], content, int(time.time()))
    eid = json.loads(raw)["id"]
    # The exact bytes, kept before the first publish (§9 item 1)
    (Path(a.home) / f"{eid}.json").write_bytes(raw)
    answer = json.loads(http(a.relay, "/v0/publish", raw))
    ts = int(time.time())
    # The audience is the relay's base as this client addresses it, trailing slashes dropped (§8.3)
    audience = a.relay.rstrip("/")
    proof = {"AC-Signer": me, "AC-Ts": str(ts), "AC-Sig": sign(sk, ["ac/fetch/1", me, eid, ts, audience])}
    check(answer["id"] == eid, f"the relay's id is {answer['id']}")
    check(http(a.relay, f"/v0/fetch/{eid}", headers=proof) == raw, "fetch by id returned other bytes")
    print(eid)


# §5.5's outer checks, a trusted root (§9 item 5), then unsealing (§4.4): the sealed content
def open_envelope(e, xk, me, trust, now, ttl=TTL, skew=SKEW):
    check(set(e) == {"v", "id", "to", "from", "auth", "suite", "ts", "sealed", "sig"}, "bad-shape")
    check(e["v"] == 1, "bad-version")
    check(e["suite"] == 1, "bad-suite")
    s = e["sealed"]
    auth = [[h["iss"], h["sub"], h["caveats"], h["exp"], h["sig"]] for h in e["auth"]]
    preimage = [e["v"], e["to"], e["from"], auth, e["suite"], e["ts"], sealed_hash(s)]
    check(digest(preimage).hex() == e["id"], "bad-id")
    check(verified(e["from"], bytes.fromhex(e["id"]), e["sig"]), "bad-sig")
    check(now - (ttl + skew) <= e["ts"], "stale-ts")
    check(e["ts"] <= now + skew, "future-ts")
    # No chain is verified here, so none is trusted: a trusted sender is its own root
    check(e["auth"] == [] and e["from"] in trust, "untrusted-root")
    wrap = [w for w in s["wraps"] if w["to"] == me]
    check(len(wrap) == 1, "not-recipient")
    try:
        enc, wrapped = bytes.fromhex(wrap[0]["enc"]), bytes.fromhex(wrap[0]["ct"])
        key = hpke_open(enc, xk, SEAL_INFO, me.encode(), wrapped)
        aad = canonical([e["v"], e["to"], e["from"]]).encode()
        plaintext = AESGCM(key).decrypt(bytes.fromhex(s["nonce"]), bytes.fromhex(s["ct"]), aad)
    except (InvalidTag, ValueError):
        raise Reject("open-failed") from None
    content = json.loads(plaintext)
    check(isinstance(content, dict) and set(content) == {"type", "thread", "body"}, "bad-content")
    # The content.type rule of 2026-10-27, SPEC §5.2: a non-empty string holding no Unicode control character
    # (category Cc: C0, DEL, C1) and no line or paragraph separator (U+2028, U+2029), so none can forge a line
    t = content["type"]
    check(isinstance(t, str) and t != "", "bad-content")
    check(not any(unicodedata.category(ch) == "Cc" or ch in LINE_SEPARATORS for ch in t), "bad-content")
    return content


# A type as a line shows it, as the CLI's shownType does: a short token as is, anything else "(not shown)".
# open_envelope has refused a control character and a line separator, but the rule allows a space, which would
# forge fields, so the display guard stays.
def shown_type(t):
    return t if isinstance(t, str) and SHOWN_TYPE.fullmatch(t) else "(not shown)"


# An envelope's id as a line shows it. Every refusal before bad-id's check prints the sender's own string, so a
# newline in it would forge a reject line; an accept line is safe, since bad-id has forced the id to the digest.
def shown_id(e):
    i = e.get("id") if isinstance(e, dict) else None
    return i if isinstance(i, str) and SHOWN_ID.fullmatch(i) else "(not shown)"


# reject <id> <code> for an envelope refused for `err`: a code of Appendix A, else bad-shape
def reject_line(e, err):
    return ["reject", shown_id(e), str(err) if isinstance(err, Reject) else "bad-shape"]


# accept <id> <from> <root> <type> <body> for an opened envelope; a self-rooted sender is its own root
def accept_line(e, content):
    return ["accept", e["id"], e["from"], e["from"], shown_type(content["type"]), dumps(content["body"])]


# The current epoch sealing key (key.json), the one the key record published and mail is now sealed to; the identity
# sealing key when no key record has been published yet (keygen but no records)
def epoch_key(home, fallback):
    path = Path(home) / "key.json"
    if not path.exists():
        return fallback
    return X25519PrivateKey.from_private_bytes(bytes.fromhex(json.loads(path.read_text())["seal"]))


# Subscribe (§8.5), open the next envelope, and ack it only once it is accepted
def receive(a):
    sk, xk, me = identity(a.home)
    xk = epoch_key(a.home, xk)
    ws = WebSocket(a.relay.rstrip("/") + "/v0/subscribe")
    nonce = strict_json(ws.recv())["nonce"]
    proof = sign(sk, ["ac/sub/1", nonce, me, me, None])
    ws.send(dumps({"t": "auth", "mailbox": me, "signer": me, "auth": [], "cursor": None, "sig": proof}))
    check(strict_json(ws.recv())["t"] == "ok", "bad-auth")
    frame = strict_json(ws.recv())
    # The envelope is a JSON string of the exact bytes the relay stored (§8.5 step 4): those bytes are verified
    check(isinstance(frame["envelope"], str), "bad-shape")
    e = strict_json(frame["envelope"].encode())
    try:
        line = accept_line(e, open_envelope(e, xk, me, a.trust, int(time.time())))
        ws.send(dumps({"t": "ack", "cursor": frame["cursor"]}))
    # Fail closed: anything malformed that no check names is bad-shape
    except Exception as err:
        line = reject_line(e, err)
    ws.close()
    print(*line)
    return 0 if line[0] == "accept" else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=("keygen", "records", "send", "receive"))
    ap.add_argument("--home", required=True, help="the identity's directory (0700), with keys.json (0600)")
    ap.add_argument("--relay", help="the relay's URL, as its AC_RELAY_URL line prints it")
    ap.add_argument("--accept", action="append", help="records: a root the mailbox accepts; default any (*)")
    ap.add_argument("--to", help="send: the recipient's address")
    ap.add_argument("--type", default="chat.v1", help="send: the sealed type")
    ap.add_argument("--body", default='{"text":"hi"}', help="send: the body, as JSON text")
    ap.add_argument("--trust", action="append", default=[], help="receive: a sender trusted as its own root")
    a = ap.parse_args()
    commands = {"keygen": keygen, "records": records, "send": send, "receive": receive}
    try:
        raise SystemExit(commands[a.command](a))
    except HTTPError as err:
        raise SystemExit(f"join.py: {a.command}: HTTP {err.code} {err.read().decode()}") from None
    # A refused check, a refused connection, a timeout, malformed JSON or hex
    except (Reject, OSError, ValueError) as err:
        raise SystemExit(f"join.py: {a.command}: {err}") from None


if __name__ == "__main__":
    main()

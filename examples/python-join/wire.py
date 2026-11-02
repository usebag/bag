"""The byte-level helpers of join.py, written from spec/SPEC.md and RFC 9180 alone.

The canonical form and its digest (spec §2), compact JSON, Ed25519 verification, RFC 9180 base mode for
suite 1 (spec §4.1), and a minimal WebSocket client (RFC 6455) for subscribe (spec §8.5). Standard library
and `cryptography` only. The `hpke` module of cryptography 50 takes no AAD, and suite 1 seals each wrap with
one, so the key schedule is written out here.
"""

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import socket
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# The canonical form (§2), JSON and Ed25519; the field prime and the order of the prime subgroup

P, L = 2**255 - 19, 2**252 + 27742317777372353535851937790883648493


def canonical(value):
    """§2.1, §2.2: strings without a lone surrogate, integers from 0 to 2^53 - 1, null, and lists of them."""

    def ok(v):
        if isinstance(v, list):
            return all(ok(x) for x in v)
        if isinstance(v, str):
            return not any(0xD800 <= ord(c) <= 0xDFFF for c in v)
        return v is None or (type(v) is int and 0 <= v <= 2**53 - 1)

    if not ok(value):
        raise ValueError("bad-canonical")
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


# §2.3: every signature is over these 32 bytes
def digest(preimage):
    return hashlib.sha256(canonical(preimage).encode()).digest()


# Compact JSON, as envelopes, records, the sealed content and frames are written (§4.2, §5.1)
def dumps(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


# §2.5: a number not written as a plain decimal integer of at most 2^53 - 1 reads as NaN, which equals
# nothing, so the check of the place that reads it refuses it. Never used on the sealed body, which may hold
# any number.
def strict_json(text):
    return json.loads(text, parse_int=plain_int, parse_float=lambda s: math.nan)


def plain_int(s):
    return int(s) if re.fullmatch("0|[1-9][0-9]*", s) and int(s) < 2**53 else math.nan


# The raw 32-byte public key of an Ed25519 or X25519 private key
def public(private_key):
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


# An Ed25519 signature under the key an address names (§3.2). Before the library sees them, §10 refuses a weak
# key or R and an S at or above L; cryptography 50 itself accepts a small-order key and R
def verified(address, message, sig):
    try:
        key, sig = bytes.fromhex(address.removeprefix("ed25519:")), bytes.fromhex(sig)
        if weak(key) or weak(sig[:32]) or int.from_bytes(sig[32:], "little") >= L:
            return False
        Ed25519PublicKey.from_public_bytes(key).verify(sig, message)
    except (InvalidSignature, ValueError):
        return False
    return True


# §10: a point encoded non-canonically (y >= p, the sign bit aside) or of order 1, 2, 4 or 8. For the order:
# on the equivalent Montgomery curve, X25519 with a scalar that is a multiple of 8 takes such a point to the
# identity, which cryptography refuses as an all-zero output
def weak(encoding):
    y = int.from_bytes(encoding, "little") & ((1 << 255) - 1)
    if y >= P or y == 1:
        return True
    u = (1 + y) * pow(1 - y, -1, P) % P
    try:
        shared = X25519PrivateKey.from_private_bytes(bytes(32)).exchange(
            X25519PublicKey.from_public_bytes(u.to_bytes(32, "little"))
        )
    except ValueError:
        return True
    return shared == bytes(32)


# RFC 9180 base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM (§4.1)

KEM_ID = b"KEM\x00\x20"
SUITE_ID = b"HPKE\x00\x20\x00\x01\x00\x02"


def extract(suite, salt, label, ikm):
    return hmac.new(salt, b"HPKE-v1" + suite + label + ikm, hashlib.sha256).digest()


# One HKDF-Expand block is enough: no output here is longer than 32 bytes
def expand(suite, prk, label, info, length):
    labeled = length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info
    return hmac.new(prk, labeled + b"\x01", hashlib.sha256).digest()[:length]


# ExtractAndExpand, then the key schedule of mode 0: the AEAD with its key, and the base nonce
def key_schedule(dh, enc, pk_r, info):
    shared = expand(KEM_ID, extract(KEM_ID, b"", b"eae_prk", dh), b"shared_secret", enc + pk_r, 32)
    context = b"\x00" + extract(SUITE_ID, b"", b"psk_id_hash", b"")
    context += extract(SUITE_ID, b"", b"info_hash", info)
    secret = extract(SUITE_ID, shared, b"secret", b"")
    key = expand(SUITE_ID, secret, b"key", context, 32)
    return AESGCM(key), expand(SUITE_ID, secret, b"base_nonce", context, 12)


# X25519; a small-order peer key gives all zeros, and the KEM must abort (§4.1)
def exchange(private_key, peer):
    dh = private_key.exchange(X25519PublicKey.from_public_bytes(peer))
    if dh == bytes(32):
        raise ValueError("small-order X25519 key")
    return dh


# SealBase with the given 32-byte ephemeral private key: (enc, ct)
def hpke_seal(pk_r, info, aad, pt, ephemeral):
    sk_e = X25519PrivateKey.from_private_bytes(ephemeral)
    aead, nonce = key_schedule(exchange(sk_e, pk_r), public(sk_e), pk_r, info)
    return public(sk_e), aead.encrypt(nonce, pt, aad)


# OpenBase: raises InvalidTag when the ciphertext does not authenticate
def hpke_open(enc, sk_r, info, aad, ct):
    aead, nonce = key_schedule(exchange(sk_r, enc), enc, public(sk_r), info)
    return aead.decrypt(nonce, ct, aad)


# A minimal WebSocket client (RFC 6455) over plain TCP, for a relay on loopback or a LAN: no TLS

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WebSocket:
    def __init__(self, url, timeout=10):
        u = urlsplit(url)
        self.sock = socket.create_connection((u.hostname, u.port or 80), timeout=timeout)
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        self.sock.sendall(
            f"GET {u.path} HTTP/1.1\r\nHost: {u.netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode()
        )
        self.file = self.sock.makefile("rb")
        # The status line and the header lines, up to the blank line (or the end of the stream)
        status, *lines = iter(lambda: self.file.readline().rstrip(b"\r\n") or None, None)
        fields = (x.decode("latin-1").partition(":") for x in lines)
        headers = {k.strip().lower(): v.strip() for k, _, v in fields}
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        if status.split()[1] != b"101" or headers.get("sec-websocket-accept") != accept:
            raise ConnectionError(f"no WebSocket upgrade: {status.decode('latin-1')}")

    # One masked frame, a text frame unless another opcode is given
    def send(self, data, opcode=0x1):
        data = data.encode() if isinstance(data, str) else data
        if len(data) < 126:
            length = bytes([0x80 | len(data)])
        elif len(data) < 65536:
            length = bytes([0x80 | 126]) + len(data).to_bytes(2, "big")
        else:
            raise ValueError("a frame over 65,535 bytes")
        mask = secrets.token_bytes(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(bytes([0x80 | opcode]) + length + mask + masked)

    # The next text message; answers a ping, and raises when the relay closes
    def recv(self):
        message = b""
        while True:
            b0, b1 = self.file.read(2)
            n = b1 & 0x7F
            if n >= 126:
                n = int.from_bytes(self.file.read(2 if n == 126 else 8), "big")
            # A server's frames are never masked
            data, opcode = self.file.read(n), b0 & 0x0F
            if opcode == 0x8:
                raise ConnectionError("closed by the relay")
            if opcode == 0x9:
                self.send(data, 0xA)
            elif opcode in (0x0, 0x1):
                message += data
                if b0 & 0x80:
                    return message.decode()

    # The closing handshake: the relay reads every frame sent before ours, then answers with its own
    def close(self):
        self.send(b"\x03\xe8", 0x8)
        try:
            while True:
                self.recv()
        except (OSError, ValueError):
            self.sock.close()

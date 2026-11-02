"""examples/python-join/join.py: its accept line shows a type as the CLI's shownType does, a short token as
is and anything else `(not shown)`, so a sealed type with a space cannot forge a field; and a type that is not a
non-empty string, or holds a control character (Cc) or U+2028 or U+2029, is refused bad-content before anything prints
(branch examples/python-join-type-guard). Offline: the envelopes are sealed and opened in memory, no relay."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "examples" / "python-join"))
# A missing cryptography fails the import here, never skips
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

import join  # noqa: E402
from wire import public  # noqa: E402

NOT_SHOWN = "(not shown)"


@pytest.mark.parametrize(
    "t",
    ["chat.v1", "a+b*c-d_e.f", "A9", "x" * 64, "-", "ask.v1+json"],
)
def test_a_short_token_is_shown_as_is(t: str) -> None:
    assert join.shown_type(t) == t


@pytest.mark.parametrize(
    "t",
    [
        "",
        "x" * 65,
        "chat.v1\naccept forged",
        "chat.v1\n",  # Python's $ would take a final newline; fullmatch, like JavaScript's $, does not
        "a b",
        "a\tb",
        "a\rb",
        "\x1b[2J",
        "a/b",
        "café",  # a Unicode letter: JavaScript's \w is ASCII, and re.ASCII makes Python's agree
        "٣",  # an Arabic-Indic digit, which Python's Unicode \w takes
        "\u2028",
        1,
        None,
    ],
)
def test_anything_else_is_not_shown(t: object) -> None:
    assert join.shown_type(t) == NOT_SHOWN


def party() -> tuple[Ed25519PrivateKey, X25519PrivateKey, str]:
    sk = Ed25519PrivateKey.generate()
    return sk, X25519PrivateKey.generate(), "ed25519:" + public(sk).hex()


def sealed(type_value: object) -> tuple[dict, X25519PrivateKey, str, str, int]:
    """An envelope from Alice to Bob whose sealed content has this type, as Bob's receive reads it."""
    a_sk, _, alice = party()
    _, b_xk, bob = party()
    ts = int(time.time())
    content = {"type": type_value, "thread": {"id": "ab" * 32, "prev": []}, "body": {"text": "hi"}}
    raw = join.seal(a_sk, alice, [(bob, public(b_xk))], content, ts)
    return json.loads(raw), b_xk, bob, alice, ts


def test_a_plain_type_prints_as_is_on_the_accept_line() -> None:
    e, xk, bob, alice, ts = sealed("chat.v1")
    line = join.accept_line(e, join.open_envelope(e, xk, bob, [alice], ts))
    assert line == ["accept", e["id"], alice, alice, "chat.v1", '{"text":"hi"}']


def test_a_type_with_a_space_prints_as_not_shown_on_one_line() -> None:
    """The display guard still decides what prints: a type with a space opens, having no control character, unshown."""
    forged = "chat.v1 {} accept " + "00" * 32
    e, xk, bob, alice, ts = sealed(forged)
    content = join.open_envelope(e, xk, bob, [alice], ts)
    assert content["type"] == forged
    line = join.accept_line(e, content)
    assert line == ["accept", e["id"], alice, alice, NOT_SHOWN, '{"text":"hi"}']
    assert "\n" not in " ".join(line)


def test_a_plain_type_still_opens() -> None:
    e, xk, bob, alice, ts = sealed("chat.v1")
    assert join.open_envelope(e, xk, bob, [alice], ts)["type"] == "chat.v1"


@pytest.mark.parametrize("t", ["caf\u00e9", "a\u00a0b", "a\u00a1b", "a\u00a0"])
def test_the_characters_next_to_the_controls_still_open(t: str) -> None:
    """U+00A0 and U+00A1 follow the C1 block, so they are not Cc; a letter and a no-break space open."""
    e, xk, bob, alice, ts = sealed(t)
    assert join.open_envelope(e, xk, bob, [alice], ts)["type"] == t


@pytest.mark.parametrize(
    "t",
    [
        "\x1b[2J",
        "chat.v1\n",
        "chat.v1\naccept forged",
        "a\x00b",
        "a\tb",
        "a\rb",
        "a\x7fb",  # DEL, category Cc
        "a\x1fb",  # the last C0 control
        "a\x85b",  # a C1 control (NEL), category Cc
        "a\x9fb",  # the last C1 control
        "a\u2028b",  # line separator, category Zl
        "a\u2029b",  # paragraph separator, category Zp
    ],
)
def test_a_type_with_a_control_character_or_a_line_separator_is_refused_bad_content(t: str) -> None:
    """The content.type rule of 2026-10-27: no category Cc character, no U+2028 or U+2029."""
    e, xk, bob, alice, ts = sealed(t)
    with pytest.raises(join.Reject) as err:
        join.open_envelope(e, xk, bob, [alice], ts)
    assert str(err.value) == "bad-content"


@pytest.mark.parametrize("t", ["", 1, None, True, [], {"a": "b"}, ["chat.v1"]])
def test_a_type_that_is_not_a_non_empty_string_is_refused_bad_content(t: object) -> None:
    e, xk, bob, alice, ts = sealed(t)
    with pytest.raises(join.Reject) as err:
        join.open_envelope(e, xk, bob, [alice], ts)
    assert str(err.value) == "bad-content"


def refused(e: object, xk: X25519PrivateKey, bob: str, alice: str, ts: int) -> list:
    """What `receive` prints for an envelope open_envelope refuses: the reject line its except clause builds."""
    try:
        join.open_envelope(e, xk, bob, [alice], ts)
    except Exception as err:
        return join.reject_line(e, err)
    raise AssertionError("the envelope was opened")


def test_a_reject_prints_a_hex_id_as_is() -> None:
    e, xk, bob, alice, ts = sealed("chat.v1")
    e["suite"] = 2
    assert refused(e, xk, bob, alice, ts) == ["reject", e["id"], "bad-suite"]


@pytest.mark.parametrize("bad_id", ["ab\nreject " + "00" * 32 + " bad-sig", "AB" * 32, "ab" * 31, "", 1, None, ["ab"]])
def test_a_reject_with_a_forged_id_prints_not_shown_on_one_line(bad_id: object) -> None:
    for how in ("id", "shape", "version", "suite"):
        e, xk, bob, alice, ts = sealed("chat.v1")
        e["id"] = bad_id
        if how == "shape":
            e["extra"] = 1
        elif how == "version":
            e["v"] = 2
        elif how == "suite":
            e["suite"] = 2
        line = refused(e, xk, bob, alice, ts)
        assert line[:2] == ["reject", NOT_SHOWN], how
        assert line[2] in ("bad-id", "bad-shape", "bad-version", "bad-suite"), how
        assert "\n" not in " ".join(str(x) for x in line), how


def test_a_reject_of_an_envelope_with_no_id_does_not_crash() -> None:
    assert join.reject_line({}, KeyError("id")) == ["reject", NOT_SHOWN, "bad-shape"]
    assert join.reject_line("not an object", ValueError()) == ["reject", NOT_SHOWN, "bad-shape"]

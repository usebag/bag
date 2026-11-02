"""Fail when Cargo.lock holds a crate version younger than the cooldown, or a crate not from crates.io.

    .venv/bin/python -I scripts/check-crate-age.py                # Cargo.lock against a 7-day cooldown
    .venv/bin/python -I scripts/check-crate-age.py --days 7 --lock Cargo.lock
    .venv/bin/python -I scripts/check-crate-age.py --self-test    # the pure functions on synthetic data, offline

The Rust half of the supply-chain rule in CONTRIBUTING.md: a malicious publish has so far been found and pulled
within hours to a few days, so no version is adopted until it has been public for 7 days. Cargo has no
min-release-age setting, so this check holds Cargo.lock to the rule, as scripts/check-release-age.mjs holds
package-lock.json. Ages only grow, so a lock that passes once keeps passing.

Rules, each a problem on its own:
* every locked package with a `source` comes from crates.io (the git index or the sparse index) with a checksum;
  workspace members have no source and are skipped;
* its locked version was published at least `--days` days ago;
* its locked version is not yanked.

An exclusion goes in crate-age-allowlist.txt as `<name> <version> | <YYYY-MM-DD> | <reason>`: a security fix let
through by hand, dated, with why. It exempts that exact version from the age rule only, never from the source,
checksum or yank rules, and it comes out once the version is 7 days old. An entry fails the check once `--days`
(7) days have passed since the end of its date, UTC (that is 00:00 UTC of its date plus 1 + `--days` days): a
version is published on or before the day it is let in, so once the end of that day is `--days` behind, the
version is at least `--days` old and needs no exemption, and the line is to be removed.

Publish times come from the crates.io API, https://crates.io/api/v1/crates/<name>/versions, with a descriptive
User-Agent and at most one request a second (the crates.io crawler policy). Answers are cached per crate in a
temporary directory, `$AC_TEST_TMP` (else `$TMPDIR`, else /tmp) /bag-crate-age, for 24 hours: a publish time
never changes, and the 24 hours bound how stale a yank can be. Stdlib only; run it with -I. Nothing is installed or
built.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

CRATES_IO_SOURCES = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)
API = "https://crates.io/api/v1/crates/{name}/versions?per_page=100"
USER_AGENT = (
    "bag-check-crate-age/0.1 (private repository; checks that a Rust lockfile holds no version younger "
    "than 7 days; one request a second, cached)"
)
CACHE_HOURS = 24
ALLOW_LINE = re.compile(r"^(\S+)\s+(\S+)\s*\|\s*(\d{4}-\d{2}-\d{2})\s*\|\s*(\S.*)$")
NAME = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass(frozen=True)
class Locked:
    name: str
    version: str
    source: str | None
    checksum: str | None


@dataclass
class Published:
    created_at: str  # ISO 8601, UTC
    yanked: bool


def locked_crates(lock_text: str) -> list[Locked]:
    """Every package of a Cargo.lock (version 3 or 4), workspace members included (they have no source)."""
    lock = tomllib.loads(lock_text)
    out = []
    for p in lock.get("package", []):
        out.append(Locked(p["name"], p["version"], p.get("source"), p.get("checksum")))
    return out


def registry_crates(crates: list[Locked]) -> list[Locked]:
    """The packages that come from somewhere: everything but the workspace members."""
    return [c for c in crates if c.source is not None]


def source_problems(crates: list[Locked]) -> list[str]:
    """A package not from crates.io, or without a checksum: each is a problem, allowlisted or not."""
    problems = []
    for c in registry_crates(crates):
        if c.source not in CRATES_IO_SOURCES:
            problems.append(f"{c.name} {c.version}: source {c.source}, not crates.io")
        elif not c.checksum or not re.fullmatch(r"[0-9a-f]{64}", c.checksum):
            problems.append(f"{c.name} {c.version}: no sha256 checksum in Cargo.lock")
    return problems


def read_allowlist(text: str, now: datetime, days: float) -> tuple[dict[tuple[str, str], str], list[str]]:
    """({(name, version): reason}, problems) from the text of crate-age-allowlist.txt.

    An entry expires at the end of its date, UTC, plus `days`: 00:00 UTC of its date plus 1 + `days` days, which is
    00:00 UTC of a date at the default 7. From then on it is a problem. A version is published on or before the day
    it is let in, so once the end of that day is `days` behind, the version is at least `days` old and needs no
    exemption. An expired entry stays in the dict (its problem is what fails the check).
    """
    allowed: dict[tuple[str, str], str] = {}
    problems = []
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = ALLOW_LINE.match(line)
        if not m:
            problems.append(f"crate-age-allowlist.txt:{n}: needs `<name> <version> | <YYYY-MM-DD> | <reason>`")
            continue
        name, version, day, reason = m.groups()
        try:
            let_in = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            problems.append(f"crate-age-allowlist.txt:{n}: {day} is not a date")
            continue
        expiry = let_in + timedelta(days=1 + days)
        if now >= expiry:
            problems.append(
                f"crate-age-allowlist.txt:{n}: {name} {version} was let in on {day} and expired on "
                f"{expiry.strftime('%Y-%m-%d')}; its version is now past the cooldown, so remove the line"
            )
        allowed[(name, version)] = f"{day}: {reason}"
    return allowed, problems


def age_problems(
    crates: list[Locked],
    published: dict[tuple[str, str], Published],
    now: datetime,
    days: float,
    allowed: dict[tuple[str, str], str],
) -> list[str]:
    """Versions younger than `days` at `now` (unless allowlisted), yanked, or unknown to the registry."""
    cutoff = now - timedelta(days=days)
    problems = []
    seen = set()
    for c in registry_crates(crates):
        key = (c.name, c.version)
        if key in seen or c.source not in CRATES_IO_SOURCES:
            continue
        seen.add(key)
        p = published.get(key)
        if p is None:
            problems.append(f"{c.name} {c.version}: no publish time on crates.io")
            continue
        if p.yanked:
            problems.append(f"{c.name} {c.version}: yanked on crates.io")
        at = datetime.fromisoformat(p.created_at.replace("Z", "+00:00"))
        if at > cutoff and key not in allowed:
            hours = int((now - at).total_seconds() // 3600)
            problems.append(
                f"{c.name} {c.version}: published {at.strftime('%Y-%m-%d %H:%M')} UTC, "
                f"{hours // 24} days {hours % 24} h ago"
            )
    return problems


def parse_versions_page(data: dict) -> tuple[dict[str, Published], str | None]:
    """({version: Published}, next page query or None) from one page of the crates.io versions API."""
    out = {v["num"]: Published(v["created_at"], bool(v["yanked"])) for v in data.get("versions", [])}
    return out, (data.get("meta") or {}).get("next_page")


class Registry:
    """The crates.io versions API with a per-crate cache and at most one request a second."""

    def __init__(self, cache_dir: Path, now: datetime) -> None:
        self.cache_dir = cache_dir
        self.now = now
        self.fetched = 0
        self.cached = 0
        self._last = 0.0

    def _get(self, url: str) -> dict:
        wait = self._last + 1.0 - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)

    def versions(self, name: str, wanted: set[str]) -> dict[str, Published]:
        if not NAME.match(name):
            raise ValueError(f"{name!r} is not a crate name")
        path = self.cache_dir / f"{name}.json"
        try:
            cached = json.loads(path.read_text())
            fresh = self.now - datetime.fromisoformat(cached["fetched_at"]) < timedelta(hours=CACHE_HOURS)
            known = {k: Published(**v) for k, v in cached["versions"].items()}
            if fresh and wanted <= known.keys():
                self.cached += 1
                return known
        except (OSError, ValueError, KeyError, TypeError):
            pass
        known: dict[str, Published] = {}
        url = API.format(name=name)
        while url:
            page, next_page = parse_versions_page(self._get(url))
            known.update(page)
            if wanted <= known.keys() or not next_page:
                break
            url = f"https://crates.io/api/v1/crates/{name}/versions{next_page}"
        self.fetched += 1
        body = {"fetched_at": self.now.isoformat(), "versions": {k: vars(v) for k, v in known.items()}}
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(body))
        tmp.replace(path)
        return known


def default_cache_dir() -> Path:
    root = os.environ.get("AC_TEST_TMP") or os.environ.get("TMPDIR") or "/tmp"
    return Path(root) / "bag-crate-age"


def check(lock: Path, allowlist: Path, days: float, cache_dir: Path, now: datetime) -> int:
    crates = locked_crates(lock.read_text())
    problems = source_problems(crates)
    allowed, allow_problems = (
        read_allowlist(allowlist.read_text(), now, days) if allowlist.exists() else ({}, [f"{allowlist} is missing"])
    )
    problems += allow_problems
    wanted: dict[str, set[str]] = {}
    for c in registry_crates(crates):
        if c.source in CRATES_IO_SOURCES:
            wanted.setdefault(c.name, set()).add(c.version)
    cache_dir.mkdir(parents=True, exist_ok=True)
    registry = Registry(cache_dir, now)
    published: dict[tuple[str, str], Published] = {}
    try:
        for name in sorted(wanted):
            for version, p in registry.versions(name, wanted[name]).items():
                published[(name, version)] = p
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        print(f"check-crate-age: crates.io lookup failed: {e}", file=sys.stderr)
        return 2
    problems += age_problems(crates, published, now, days, allowed)
    for line in problems:
        print(f"check-crate-age: {line}", file=sys.stderr)
    n = sum(len(v) for v in wanted.values())
    if problems:
        print(
            f"check-crate-age: {len(problems)} problem(s) in {n} locked crates (cooldown {days:g} days); wait, "
            "pin an older version (cargo update -p <name> --precise <version>), or allowlist a security fix "
            "with a dated reason",
            file=sys.stderr,
        )
        return 1
    used = len(allowed)
    print(
        f"check-crate-age: pass ({n} locked crates from crates.io, cooldown {days:g} days, "
        f"{used} allowlisted; {registry.fetched} fetched, {registry.cached} from the cache)"
    )
    return 0


def self_test() -> int:
    """The pure functions on synthetic data, with no network."""
    lock = """
version = 4

[[package]]
name = "ac-core"
version = "0.0.0"

[[package]]
name = "old"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{c}"

[[package]]
name = "young"
version = "2.0.0"
source = "sparse+https://index.crates.io/"
checksum = "{c}"

[[package]]
name = "fix"
version = "3.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{c}"

[[package]]
name = "pulled"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{c}"

[[package]]
name = "fromgit"
version = "0.2.0"
source = "git+https://example.invalid/fromgit#abc"

[[package]]
name = "nosum"
version = "0.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
""".replace("{c}", "0" * 64)
    crates = locked_crates(lock)
    now = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
    published = {
        ("old", "1.0.0"): Published("2026-01-01T00:00:00.000000Z", False),
        ("young", "2.0.0"): Published("2026-10-20T12:00:00.000000+00:00", False),
        ("fix", "3.0.1"): Published("2026-10-23T00:00:00Z", False),
        ("pulled", "0.1.0"): Published("2025-01-01T00:00:00Z", True),
    }
    allowed, problems = read_allowlist(
        "# comment\n\nfix 3.0.1 | 2026-10-23 | RUSTSEC-0000-0000, cannot wait\nbad line\nx 1 | 2026-13-40 | r\n", now, 7
    )
    # expiry: an entry dated D expires at 00:00 UTC of D plus 1 + 7 days; now is 2026-10-24 12:00 UTC
    expiry_text = "a 1.0.0 | 2026-10-16 | r\nb 2.0.0 | 2026-10-17 | r\n"
    _, expiry_problems = read_allowlist(expiry_text, now, 7)
    _, at_expiry = read_allowlist("a 1.0.0 | 2026-10-16 | r\n", datetime(2026, 10, 24, tzinfo=UTC), 7)
    _, before_expiry = read_allowlist("a 1.0.0 | 2026-10-16 | r\n", datetime(2026, 10, 23, 23, 59, tzinfo=UTC), 7)
    checks = [
        ("members skipped", len(registry_crates(crates)) == 6),
        ("allowlist parsed", allowed == {("fix", "3.0.1"): "2026-10-23: RUSTSEC-0000-0000, cannot wait"}),
        ("allowlist problems", len(problems) == 2),
        ("entry dated 2026-10-23 not expired", not any("fix 3.0.1" in p for p in problems)),
        (
            "entry dated 2026-10-16 expired",
            expiry_problems
            == [
                "crate-age-allowlist.txt:1: a 1.0.0 was let in on 2026-10-16 and expired on 2026-10-24; "
                "its version is now past the cooldown, so remove the line"
            ],
        ),
        ("entry dated 2026-10-17 not expired", not any("b 2.0.0" in p for p in expiry_problems)),
        ("expired at the instant of expiry", len(at_expiry) == 1),
        ("not expired a minute before", before_expiry == []),
        (
            "source problems",
            source_problems(crates)
            == [
                "fromgit 0.2.0: source git+https://example.invalid/fromgit#abc, not crates.io",
                "nosum 0.3.0: no sha256 checksum in Cargo.lock",
            ],
        ),
    ]
    ages = age_problems(crates, published, now, 7, allowed)
    checks += [
        ("young flagged", any(p.startswith("young 2.0.0: published 2026-10-20 12:00 UTC, 4 days 0 h") for p in ages)),
        ("old passes", not any(p.startswith("old ") for p in ages)),
        ("allowlisted passes", not any(p.startswith("fix ") for p in ages)),
        ("yanked flagged", "pulled 0.1.0: yanked on crates.io" in ages),
        ("unknown flagged", "nosum 0.3.0: no publish time on crates.io" in ages),
        ("git skipped by age", not any(p.startswith("fromgit ") for p in ages)),
        ("count", len(ages) == 3),
    ]
    page, nxt = parse_versions_page(
        {"versions": [{"num": "1.0.0", "created_at": "2026-01-01T00:00:00Z", "yanked": False}],
         "meta": {"next_page": "?per_page=100&seek=x"}}
    )
    checks += [("page parsed", page == {"1.0.0": Published("2026-01-01T00:00:00Z", False)} and nxt is not None)]
    with tempfile.TemporaryDirectory() as d:
        cache = Path(d)
        (cache / "old.json").write_text(
            json.dumps({"fetched_at": now.isoformat(), "versions": {"1.0.0": vars(published[("old", "1.0.0")])}})
        )
        r = Registry(cache, now)
        checks += [("cache hit", r.versions("old", {"1.0.0"})["1.0.0"].yanked is False and r.cached == 1)]
        try:
            r.versions("../etc", {"1"})
            checks.append(("bad name refused", False))
        except ValueError:
            checks.append(("bad name refused", True))
    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"check-crate-age self-test: {'ok ' if ok else 'FAIL'} {name}")
    print(f"check-crate-age self-test: {len(checks) - len(failed)} of {len(checks)} passed")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lock", type=Path, default=Path("Cargo.lock"))
    ap.add_argument("--allowlist", type=Path, default=Path("crate-age-allowlist.txt"))
    ap.add_argument("--days", type=float, default=7.0)
    ap.add_argument("--cache-dir", type=Path, default=None)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.days < 0:
        ap.error("--days must not be negative")
    return check(args.lock, args.allowlist, args.days, args.cache_dir or default_cache_dir(), datetime.now(UTC))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

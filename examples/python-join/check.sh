#!/usr/bin/env bash
# The Python participant against the reference relay and the reference CLI. Run it from anywhere; it
# works from the repository root. It needs .venv (Python 3.10 or later with cryptography), Node 24 or later in PATH, and
# target/release/ac-relay (cargo build --release --locked -p ac-relay) or AC_RELAY_CMD.
#
#   examples/python-join/check.sh
#
# 1. vectors.py: join.py and wire.py against spec/vectors/, offline.
# 2. A relay on port 0 with a fresh --db; four envelopes, each accept line compared byte for byte with the line
#    built from the sender's printed id, its address, the type and the body text it was given:
#    Python Alice to Python Bob, Python Bob to Python Alice, the CLI's ts-alice to Python Bob, and Python Alice to
#    the CLI's ts-bob (inbox --once --trust-root). Each Python send also checks the relay's id and fetches the
#    envelope back by id with the fetch proof, which must return the exact bytes it published.
# 3. Negative controls: a copy of a Python envelope with one hex digit of sig changed is refused 422 bad-sig, one
#    with a digit of sealed.ct changed 422 bad-id; Bob given a trust list without the sender rejects
#    untrusted-root, acks nothing, and accepts the same id once he trusts the sender.
# Prints one summary line, "python-join: ok: ..." or "python-join: FAIL: ...", and exits 1 on any mismatch.
# Temporary files go under AC_TEST_TMP (default TMPDIR), removed unless the check fails or AC_KEEP_TMP=1.
set -euo pipefail

cd "$(dirname "$0")/../.."
py=.venv/bin/python
relay="${AC_RELAY_CMD:-target/release/ac-relay}"
[[ -x "$py" ]] || { echo "python-join: FAIL: no $py (a venv with Python 3.10 or later and cryptography)" >&2; exit 1; }
if [[ ! -x "$relay" ]]; then
  echo "python-join: FAIL: no relay at $relay; cargo build --release --locked -p ac-relay" >&2
  exit 1
fi
now() { "$py" -I -c 'import time; print(f"{time.time():.1f}")'; }
t0="$(now)"
root="${AC_TEST_TMP:-${TMPDIR:-/tmp}}"
tmp="$(mktemp -d "${root%/}/bag-python-join.XXXXXX")"
relay_pid=""
fails=()

stop_relay() { # SIGTERM, then SIGKILL after 5 s, by pid (never by name)
  [[ -n "$relay_pid" ]] && kill -TERM "$relay_pid" 2>/dev/null || return 0
  for _ in $(seq 50); do
    kill -0 "$relay_pid" 2>/dev/null || return 0
    sleep 0.1
  done
  kill -KILL "$relay_pid" 2>/dev/null || true
}
finish() {
  stop_relay
  if [[ ${#fails[@]} -eq 0 && "${AC_KEEP_TMP:-}" != 1 ]]; then
    # The directory this run made, as the e2e harness removes its own (packages/e2e/test/harness.ts)
    "$py" -I -c 'import shutil, sys; shutil.rmtree(sys.argv[1])' "$tmp"
  else
    echo "python-join: files kept in $tmp" >&2
  fi
}
trap finish EXIT

expect() { # expect <label> <got> <want>: 1 on a mismatch, which is counted and shown; the check goes on
  [[ "$2" == "$3" ]] && return 0
  fails+=("$1")
  printf 'python-join: MISMATCH %s\n  got:  %s\n  want: %s\n' "$1" "$2" "$3" >&2
  return 1
}
# join.py imports wire.py from its own directory, which python -I would leave off sys.path: -E -s -B instead
j() { "$py" -E -s -B examples/python-join/join.py "$@"; }
c() { AC_HOME="$tmp/ts" node packages/cli/src/main.ts "$@" 2>>"$tmp/cli.stderr"; }
# tamper <file> <member>: the file's bytes with the first hex digit of the last "<member>":" value changed
tamper() {
  "$py" -I -c 'import sys
raw, key = open(sys.argv[1], "rb").read(), b"\"%s\":\"" % sys.argv[2].encode()
i = raw.rindex(key) + len(key)
sys.stdout.buffer.write(raw[:i] + (b"1" if raw[i:i + 1] == b"0" else b"0") + raw[i + 1:])' "$@"
}

# 1. The vectors, offline
vectors="$("$py" -E -s -B examples/python-join/vectors.py)" || fails+=("vectors")
echo "$vectors"

# 2. A relay on port 0, read from its AC_RELAY_URL line within 10 s. Its stdin is a fifo whose only writer is this
# script's descriptor 3 (closed for the relay itself), so with --exit-on-stdin-eof the relay stops when this script
# ends, however it ends: a SIGKILL skips the trap, not the close. Not the flag on a plain `&`: a background job's stdin
# is /dev/null in a non-interactive shell, and the relay would stop at once.
mkfifo "$tmp/stdin.fifo"
exec 3<>"$tmp/stdin.fifo"
"$relay" --port 0 --db "$tmp/relay.sqlite" --exit-on-stdin-eof <"$tmp/stdin.fifo" 3>&- >"$tmp/relay.stdout" \
  2>"$tmp/relay.stderr" &
relay_pid=$!
R=""
for _ in $(seq 100); do
  R="$(sed -n 's/^AC_RELAY_URL=//p' "$tmp/relay.stdout")"
  [[ -n "$R" ]] || ! kill -0 "$relay_pid" 2>/dev/null && break
  sleep 0.1
done
if [[ -z "$R" ]]; then
  fails+=("relay")
  echo "python-join: FAIL: the relay printed no AC_RELAY_URL line within 10 s" >&2
  exit 1
fi

# The bodies: non-ASCII of 2, 3 and 4 UTF-8 bytes, escapes, nesting, true, null, a negative number, a fraction and
# 2^53 - 1, each written as both JSON writers write it, so the same bytes go in and come out
body() {
  printf '{"leg":"%s","text":"héllo ✓ 🚀","esc":"a \\" b \\\\ c \\n d \\t e \\u0001 f /","n":9007199254740991,' "$1"
  printf '"neg":-5,"f":0.5,"ok":true,"none":null,"list":[1,"two",{"three":[3]}]}'
}
A="$(j --home "$tmp/alice" keygen)"
B="$(j --home "$tmp/bob" keygen)"
c keygen ts-alice >/dev/null
c keygen ts-bob >/dev/null
TA="$(c address ts-alice)"
TB="$(c address ts-bob)"
j --home "$tmp/alice" records --relay "$R" --accept "$B" >/dev/null
j --home "$tmp/bob" records --relay "$R" --accept "$A" --accept "$TA" >/dev/null
c record address ts-bob --relay "$R" --sealing-key --out "$tmp/ts-bob.address.json" >/dev/null
c publish "$R" "$tmp/ts-bob.address.json" >/dev/null
c record accept-from ts-bob --root "$A" --max-bytes 65536 --ttl 86400 --out "$tmp/ts-bob.accept.json" >/dev/null
c publish "$R" "$tmp/ts-bob.accept.json" >/dev/null

sends=0
deliveries=0
controls=0
# Python Alice to Python Bob; Bob first trusts only ts-alice (a negative control), then Alice too
id1="$(j --home "$tmp/alice" send --relay "$R" --to "$B" --body "$(body python-to-python)")" && sends=$((sends + 1))
line="$(j --home "$tmp/bob" receive --relay "$R" --trust "$TA")" && status=0 || status=$?
expect "Bob, not trusting Alice, rejects" "$line exit $status" "reject $id1 untrusted-root exit 1" &&
  controls=$((controls + 1))
line="$(j --home "$tmp/bob" receive --relay "$R" --trust "$A" --trust "$TA")" || true
expect "Python Alice to Python Bob" "$line" "accept $id1 $A $A chat.v1 $(body python-to-python)" &&
  deliveries=$((deliveries + 1))
# Python Bob to Python Alice
id2="$(j --home "$tmp/bob" send --relay "$R" --to "$A" --body "$(body python-to-python-back)")" && sends=$((sends + 1))
line="$(j --home "$tmp/alice" receive --relay "$R" --trust "$B")" || true
expect "Python Bob to Python Alice" "$line" "accept $id2 $B $B chat.v1 $(body python-to-python-back)" &&
  deliveries=$((deliveries + 1))
# The CLI's ts-alice to Python Bob
out="$(c send --as ts-alice --to "$B" --relay "$R" --type chat.v1 --body "$(body typescript-to-python)")" || true
line="$(j --home "$tmp/bob" receive --relay "$R" --trust "$A" --trust "$TA")" || true
expect "TypeScript to Python" "$line" "accept ${out%%$'\n'*} $TA $TA chat.v1 $(body typescript-to-python)" &&
  deliveries=$((deliveries + 1))
# Python Alice to the CLI's ts-bob
id4="$(j --home "$tmp/alice" send --relay "$R" --to "$TB" --body "$(body python-to-typescript)")" &&
  sends=$((sends + 1))
line="$(c inbox --as ts-bob --relay "$R" --once --trust-root "$A")" || true
expect "Python to TypeScript" "$line" "accept $id4 $A $A chat.v1 $(body python-to-typescript)" &&
  deliveries=$((deliveries + 1))
expect "Python sends, each fetched back by id with the same bytes" "$sends" 3 || true

# 3. Tampered copies of Alice's first envelope, published again
tamper "$tmp/alice/$id1.json" sig >"$tmp/tampered-sig.json" || true
tamper "$tmp/alice/$id1.json" ct >"$tmp/tampered-ct.json" || true
for want in "tampered-sig 422 {\"error\":\"bad-sig\"}" "tampered-ct 422 {\"error\":\"bad-id\"}"; do
  file="${want%% *}"
  got="$(curl -sS -o "$tmp/$file.answer" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    --data-binary "@$tmp/$file.json" "$R/v0/publish")" || true
  expect "the relay refuses $file" "$file $got $(cat "$tmp/$file.answer" 2>/dev/null)" "$want" &&
    controls=$((controls + 1))
done

elapsed="$("$py" -I -c 'import sys, time; print(f"{time.time() - float(sys.argv[1]):.1f}")' "$t0")"
v="${vectors#vectors: }"
counts="vectors ${v%% checks*}; deliveries $deliveries of 4 accepted with identical bodies (Python to Python 2,"
counts="$counts TypeScript to Python 1, Python to TypeScript 1); Python sends $sends of 3 fetched back by id"
counts="$counts byte for byte; negative controls $controls of 3 refused (untrusted-root, bad-sig, bad-id); ${elapsed} s"
if [[ ${#fails[@]} -gt 0 ]]; then
  echo "python-join: relay stderr, last lines:" >&2
  tail -n 5 "$tmp/relay.stderr" >&2
  grep -v -e ExperimentalWarning -e trace-warnings "$tmp/cli.stderr" >&2 || true
  printf -v failed '%s; ' "${fails[@]}"
  echo "python-join: FAIL: ${#fails[@]} mismatches (${failed%; }); $counts"
  exit 1
fi
echo "python-join: ok: $counts"

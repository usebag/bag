#!/usr/bin/env bash
# The local dry run of the relay load generator: the relay image
# in Docker (OrbStack), driven from this Mac by packages/e2e/bench/relay-load.ts, one line a run.
# It observes and judges nothing.
#
#   packages/e2e/bench/dry-run-local.sh l1|l2|l3       # one line a run, each under ten minutes
#   DRY_IMAGE=usebag/relay:<rev> ...            # a built image; its relay sources must equal this head's
#   Knobs: DRY_PORT (7840), DRY_MEMORY (256m), DRY_CPUS (1), L1_MAX (8000), L1_BATCH (100), L2_SIZES ("100 1000"),
#   L2_RATES (25,50,100,200,400,800), L2_STEP (15), L3_MAILBOXES (10), L3_RATE (50), L3_SECONDS (300),
#   BODY_CHARS (1000).
#
# It refuses a dirty tree, so that the record names what ran, and starts nothing while a gate runs; a watcher sends
# the generator SIGTERM if a gate starts meanwhile (it closes its sockets and exits 4). Each container and volume is fresh, and removed by name however the run ends.
#
# The container against the Fly deploy's cmd: the same image and flags, with these differences, each
# local only. --advertise is http://127.0.0.1:<port>, and there is no --trust-proxy or
# --client-ip-header: no proxy stands in front, so every connection, a call or a subscription, counts under one client
# address. The run's raised flags: --connections-per-ip 100000 --connection-reserve-permille 0 --rate-per-ip 1000000 --fetch-per-ip 1000000
# --rate-per-from 1000000 --rate-per-root 1000000 --record-signers-per-day 1000000, so that no per-address limit is what
# a line measures. A read-only root, no capabilities, --memory 256m with no swap and --cpus 1 (the Machine's 256 MB and
# one CPU, not its shared-CPU quota), and --ulimit nofile=65536:65536 (stated, above any count a line reaches). The image
# is linux/amd64, run under OrbStack's emulation on this Apple-silicon Mac.
#
# Records go to packages/e2e/bench/out/dry-run-local/ (gitignored) of the shared checkout (the parent of
# `git rev-parse --git-common-dir`): <rev>-<stamp>-<line>.txt (this output), the generator's .json, and
# per container <suffix>.relay.log (its log) and <suffix>.mem.txt (docker stats, about every 3 s).
set -euo pipefail

cd "$(dirname "$0")/../../.."
line="${1:-}"
case "$line" in
  l1 | l2 | l3) ;;
  *)
    echo "usage: packages/e2e/bench/dry-run-local.sh l1|l2|l3" >&2
    exit 2
    ;;
esac
if [[ -n "$(git status --porcelain)" ]]; then
  echo "dry-run-local: the tree is dirty; commit first, so that the record names what ran" >&2
  exit 1
fi
gate_runs() { pgrep -lf 'last_step[.]sh' >/dev/null 2>&1; }
if gate_runs; then
  echo "dry-run-local: a gate runs; nothing started:" >&2
  pgrep -lf 'last_step[.]sh' >&2 || true
  exit 4
fi

rev="$(git rev-parse --short HEAD)"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
common="$(cd "$(git rev-parse --git-common-dir)/.." && pwd)"
outdir="$common/packages/e2e/bench/out/dry-run-local"
mkdir -p "$outdir"
base="$outdir/$rev-$stamp-$line"
exec > >(tee "$base.txt") 2>&1

port="${DRY_PORT:-7840}"
url="http://127.0.0.1:$port"
memory="${DRY_MEMORY:-256m}"
cpus="${DRY_CPUS:-1}"
body="${BODY_CHARS:-1000}"
prefix="ac-load-$rev-$$"
made_containers=""
made_volumes=""
helpers=""
current=""

# Node 24 first in PATH: the first node on this Mac is nvm's 20.12.2.
node_major() { node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0; }
if [[ "$(node_major)" -lt 24 ]]; then
  for dir in /opt/homebrew/Cellar/node/24.4.1/bin /opt/homebrew/opt/node@24/bin; do
    if [[ -x "$dir/node" ]]; then
      PATH="$dir:$PATH"
      break
    fi
  done
fi
if [[ "$(node_major)" -lt 24 ]]; then
  echo "dry-run-local: Node 24 or later is not first in PATH" >&2
  exit 1
fi

say() { printf '%s\n' "$*"; }
utc() { date -u '+%Y-%m-%d %H:%M:%S UTC'; }

save_log() { # save_log <container>: its log beside the record, if it still exists
  if docker inspect "$1" >/dev/null 2>&1; then
    docker logs "$1" >"$outdir/$rev-$stamp-${1#"$prefix"-}.relay.log" 2>&1 || true
  fi
}

cleanup() {
  local c v p
  for p in $helpers; do kill "$p" 2>/dev/null || true; done
  for c in $made_containers; do
    save_log "$c"
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  for v in $made_volumes; do docker volume rm "$v" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

wait_health() { # wait_health <seconds>: 0 when /v0/health answers within the time
  local i=0
  while [[ $i -lt $1 ]]; do
    if curl -fsS -m 2 "$url/v0/health" >/dev/null 2>&1; then return 0; fi
    sleep 1
    i=$((i + 1))
  done
  return 1
}

state() { docker inspect -f 'status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}}' "$1" 2>&1 || true; }

# start_relay <suffix>: a fresh container and volume named by the suffix, health waited for; its name in $current.
start_relay() {
  local c="$prefix-$1"
  made_containers="$made_containers $c"
  made_volumes="$made_volumes $c-data"
  docker volume create "$c-data" >/dev/null
  docker run -d --platform linux/amd64 --name "$c" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --memory "$memory" --memory-swap "$memory" --cpus "$cpus" --ulimit nofile=65536:65536 \
    -p "127.0.0.1:$port:7701" -v "$c-data:/data" "$image" \
    --bind 0.0.0.0 --port 7701 --db /data/relay.sqlite --advertise "$url" --log-ip prefix \
    --domain-publishes-per-day 10000 --blocklist /data/blocklist --abuse-contact mailto:abuse@example.invalid \
    --connections-per-ip 100000 --connection-reserve-permille 0 --rate-per-ip 1000000 --fetch-per-ip 1000000 --fetch-global-per-minute 0 --bytes-per-ip-per-day 0 --rate-per-from 1000000 \
    --rate-per-root 1000000 --record-signers-per-day 1000000 >/dev/null
  if ! wait_health 60; then
    say "$c did not answer /v0/health within 60 s: $(state "$c")"
    return 1
  fi
  current="$c"
  say "$c up at $(utc): $(state "$c"); the listening line's limits:"
  docker logs "$c" 2>&1 | grep -m 1 '"event":"listening"' |
    grep -oE '"(connections_per_ip|subscriptions_per_ip|rate_per_ip|rate_per_from|rate_per_root|record_signers_per_day)":[0-9]+' |
    tr '\n' ' ' | sed 's/^/    /'
  echo
}

# stop_relay: the current container's log saved and the container removed, freeing the port.
stop_relay() {
  save_log "$current"
  docker rm -f "$current" >/dev/null 2>&1 || true
}

# sample_mem <file>: docker stats of the current container, about every 3 s, while it runs; its pid in $helpers.
sample_mem() {
  local c="$current" file="$1"
  echo 'utc|mem_usage|cpu|pids' >"$file"
  (
    while [[ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" == true ]]; do
      echo "$(date -u +%H:%M:%S)|$(docker stats --no-stream --format '{{.MemUsage}}|{{.CPUPerc}}|{{.PIDs}}' "$c" 2>/dev/null)" >>"$file"
      sleep 1
    done
  ) &
  helpers="$helpers $!"
  disown "$!" # its end by the cleanup's kill is no news
}

# mem_summary <file>: the first, the largest and the last memory sample, in MiB.
mem_summary() {
  awk -F'|' 'NR > 1 && $2 != "" {
      split($2, m, " ")
      v = m[1] + 0
      if (m[1] ~ /GiB/) v *= 1024
      else if (m[1] ~ /KiB/) v /= 1024
      else if (m[1] !~ /iB/) v /= 1048576
      if (n == 0) { first = v; t0 = $1 }
      if (v > max) { max = v; tmax = $1 }
      last = v; tl = $1; n++
    }
    END { printf "    memory MiB: first %.1f (%s), max %.1f (%s), last %.1f (%s), %d samples\n", first, t0, max, tmax, last, tl, n }' "$1"
}

# run_gen <args...>: the generator, watched for a gate.
run_gen() {
  local pid wpid rc=0
  node --disable-warning=ExperimentalWarning packages/e2e/bench/relay-load.ts "$@" &
  pid=$!
  (
    while kill -0 "$pid" 2>/dev/null; do
      if gate_runs; then
        echo "dry-run-local: a gate started at $(utc); stopping the generator (SIGTERM)"
        kill -TERM "$pid" 2>/dev/null || true
        exit 0
      fi
      sleep 5
    done
  ) &
  wpid=$!
  wait "$pid" || rc=$?
  kill "$wpid" 2>/dev/null || true
  wait "$wpid" 2>/dev/null || true
  say "generator exit $rc at $(utc)"
  stop_if_gate
}

# stop_if_gate: a gate that runs now ends the whole line here (exit 4), after the cleanup; nothing more is started.
stop_if_gate() {
  if gate_runs; then
    say "dry-run-local: a gate runs at $(utc); the line stops here, nothing more is started"
    if [[ -n "$current" ]]; then relay_counts; fi
    exit 4
  fi
}

# relay_counts: the current container's log lines that say what the relay did.
relay_counts() {
  local c="$current" e
  say "relay log of $c, lines by event:"
  for e in subscribe subscribe-closed connection-closed connection-refused connection-timeout accept-error \
    rate-limited publish publish-record publish-refused fetch fetch-refused store-error fatal store-size; do
    printf '    %s %s\n' "$e" "$(docker logs "$c" 2>&1 | grep -c "\"event\":\"$e\"" || true)"
  done
  docker logs "$c" 2>&1 | grep -E '"event":"(accept-error|store-error|fatal|connection-refused)"' | head -n 3 |
    cut -c1-300 | sed 's/^/    first: /' || true
}

# files_in_data: the size and name of each file in the current container's /data.
files_in_data() { docker cp "$current:/data/." - 2>/dev/null | tar -tvf - 2>/dev/null | awk '$9 !~ /^\.?\/?$/ {print $5, $9}'; }

# db_bytes: relay.sqlite plus relay.sqlite-wal, in bytes.
db_bytes() { files_in_data | awk '$2 ~ /(^|\/)relay\.sqlite(-wal)?$/ {n += $1} END {print n + 0}'; }

last_store_size() {
  docker logs "$current" 2>&1 | grep '"event":"store-size"' | tail -n 1 |
    grep -oE '"(bytes|live|envelopes|mailbox|records)":[0-9]+' | tr '\n' ' '
}

l1() {
  local max="${L1_MAX:-8000}" batch="${L1_BATCH:-100}"
  start_relay l1
  sample_mem "$outdir/$rev-$stamp-l1.mem.txt"
  sleep 5
  say "--- L1: up to $max subscriptions, $batch at a time ($(utc))"
  run_gen l1 "$url" --max-identities "$max" --max-subs "$max" --batch "$batch" --hold-s 15 --deadline-s 480 \
    --out "$base.json"
  sleep 3
  say "container after L1: $(state "$current")"
  relay_counts
  mem_summary "$outdir/$rev-$stamp-l1.mem.txt"
}

l2() {
  local n rates="${L2_RATES:-25,50,100,200,400,800}" step="${L2_STEP:-15}"
  for n in ${L2_SIZES:-100 1000}; do
    stop_if_gate
    start_relay "l2n$n"
    sample_mem "$outdir/$rev-$stamp-l2n$n.mem.txt"
    sleep 3
    say "--- L2 at $n mailboxes, rates $rates, $step s a step ($(utc))"
    run_gen l2 "$url" --max-identities "$n" --mailboxes "$n" --rates "$rates" --step-s "$step" --max-rate 2000 \
      --inflight 64 --body-chars "$body" --deadline-s 400 --out "$base-n$n.json"
    say "container after L2 at $n: $(state "$current")"
    relay_counts
    mem_summary "$outdir/$rev-$stamp-l2n$n.mem.txt"
    stop_relay
  done
}

l3() {
  local m="${L3_MAILBOXES:-10}" rate="${L3_RATE:-50}" seconds="${L3_SECONDS:-300}" before after restarted ok envb
  start_relay l3
  sample_mem "$outdir/$rev-$stamp-l3.mem.txt"
  sleep 3
  before="$(db_bytes)"
  say "L3 before: files in /data:"
  files_in_data | sed 's/^/    /'
  say "L3 before: store-size line: $(last_store_size)"
  say "--- L3: $m mailboxes, $rate/s for $seconds s, bodies of $body characters ($(utc))"
  run_gen l3 "$url" --max-identities "$m" --mailboxes "$m" --rate "$rate" --seconds "$seconds" --max-rate 2000 \
    --body-chars "$body" --deadline-s 480 --out "$base.json"
  ok="$(node -p "JSON.parse(require('node:fs').readFileSync(process.argv[1], 'utf8')).result?.ok ?? ''" "$base.json" 2>/dev/null || true)"
  envb="$(node -p "JSON.parse(require('node:fs').readFileSync(process.argv[1], 'utf8')).result?.envelope_bytes?.p50 ?? ''" "$base.json" 2>/dev/null || true)"
  after="$(db_bytes)"
  say "L3 after: files in /data (the WAL not yet checkpointed):"
  files_in_data | sed 's/^/    /'
  say "--- L3: a restart, for the first sweep's store-size line and the WAL checkpointed at the stop ($(utc))"
  docker restart -t 10 "$current" >/dev/null
  wait_health 60 || say "L3: not healthy within 60 s after the restart"
  sleep 2
  restarted="$(db_bytes)"
  say "L3 after the restart: files in /data:"
  files_in_data | sed 's/^/    /'
  say "L3 after the restart: store-size line: $(last_store_size)"
  say "container after L3: $(state "$current")"
  relay_counts
  mem_summary "$outdir/$rev-$stamp-l3.mem.txt"
  if [[ "$ok" =~ ^[0-9]+$ && "$ok" -gt 0 && "$envb" =~ ^[0-9.]+$ ]]; then
    awk -v b0="$before" -v b1="$after" -v b2="$restarted" -v n="$ok" -v e="$envb" -v r="$rate" 'BEGIN {
      g = b2 - b0; per = g / n
      printf "L3 store before=%d after=%d (db+wal) after_restart=%d growth=%d envelopes=%d envelope_bytes_p50=%d ", b0, b1, b2, g, n, e
      printf "bytes_per_envelope=%.0f ratio=%.2f per_hour_at_%d/s=%.0f per_day=%.0f at_7_days=%.0f\n", per, per / e, r, per * r * 3600, per * r * 86400, per * r * 604800
    }'
  else
    say "L3 store: no reading (ok=${ok:-none} envelope_bytes=${envb:-none})"
  fi
}

say "dry-run-local: $(utc) head $(git rev-parse HEAD) dirty=0 line $line"
say "dry-run-local: node $(node --version), docker $(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null || echo unavailable), context $(docker context show 2>/dev/null || echo unknown)"
say "dry-run-local: this Mac: ulimit -n $(ulimit -n), kern.maxfilesperproc $(sysctl -n kern.maxfilesperproc 2>/dev/null), ephemeral ports $(sysctl -n net.inet.ip.portrange.first 2>/dev/null) to $(sysctl -n net.inet.ip.portrange.last 2>/dev/null)"
image="${DRY_IMAGE:-usebag/relay:$rev}"
if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker build --platform linux/amd64 -f deploy/relay/Dockerfile --build-arg AC_REV="$(git rev-parse HEAD)" -t "$image" .
fi
built="$(docker image inspect "$image" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')"
if ! git diff --quiet "$built" HEAD -- Cargo.toml Cargo.lock rust-toolchain.toml crates deploy/relay/Dockerfile \
  deploy/relay/Dockerfile.dockerignore; then
  echo "dry-run-local: $image was built from $built, whose relay sources differ from this head's" >&2
  exit 1
fi
say "--- image: $image $(docker image inspect "$image" --format '{{.Id}} {{.Os}}/{{.Architecture}}'), built from $built (relay sources equal to this head's)"
"$line"
say "dry-run-local: $(utc) done; record $base.txt"

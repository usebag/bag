#!/usr/bin/env bash
# An organization's signed address record: the file the well-known Worker serves at
# https://<label>.usuals.now/.well-known/bag/address.json.
#
#   AC_HOME=<the org keys' home> deploy/make-org-records.sh <label> [<relay URL>] [--ttl <seconds>] [--key <name>]
#                                [--rotated-from <name>] [--rotation-key <address>] [--revoke <address>]...
#   AC_HOME=<the org keys' home> deploy/make-org-records.sh --domain <domain> [<relay URL>] [--out <dir>] [--ttl <seconds>]
#                                [--key <name>] [--rotated-from <name>] [--rotation-key <address>] [--revoke <address>]...
#
# Creates the key <name> (default org-<label>) with the CLI's keygen unless it exists, then writes its address record,
# with the relay URL (default https://relay-<label>.usuals.now), its sealing key and the TTL (default 86400 s, the
# most a record may have), to deploy/well-known/public/<label>/.well-known/bag/address.json, formatted by Biome
# so that the file can be committed as it is (white space only: a record's signature is over its canonical form).
# --rotated-from <name> makes the record a rotation from that key, which countersigns it (spec/SPEC.md §7.3); without
# it, a record of a new key is a replacement that pinned edges refuse (pin-mismatch). --rotation-key <address> names a
# separate, colder key that may countersign this key's next rotation, and each --revoke <address> a principal
# key whose hops the org revokes; keep an entry in every record until its hop's exp + TTL +
# skew, 604,800 + 300 s after the hop's exp with the relay defaults, the last second an envelope under
# that hop passes the stale-ts check. The keys stay in $AC_HOME (an absolute path; 0600 files in a 0700 directory) and
# nothing prints key material: two lines, the key's address and the record's fields. The delegations from the org to its principals are separate `delegate` commands.
# Needs Node 24 or later first in PATH and `npm ci` done in this clone (the CLI's workspace links, and Biome).
#
# The second form (Stream 4, W-scripts) takes the org's full domain, as deploy/make-handle-record.sh --domain does: a
# lower-case ASCII host of two or more DNS labels (each 1 to 63 of a-z, 0-9 and -, from and to a letter or a digit), at
# most 253 characters, with no trailing dot and no IP literal, whose last label is none of alt, arpa, internal,
# invalid, local, localhost and onion (isDomainHost and isSpecialUseDomain in packages/core, spec/SPEC.md §12.3 item 1).
# One label, a trailing dot, a non-ASCII name (give the xn-- form) and an upper-case letter are refused, exit 2,
# nothing written. --domain <label>.usuals.now is the first form with that label (same file, key and relay defaults).
# For any other domain the relay URL is required (there is no default) and the key defaults to org-<domain> (give
# --key when that is over 64 characters); the record goes to deploy/well-known/public/<domain>/.well-known/bag/
# address.json, the tree make-handle-record.sh --domain reads the org record from. The record carries the sealing key,
# as the first form's does (spec/SPEC.md §7.2: `sealing_key` is the key's X25519 public key or null). A third line is
# printed, the DNS TXT record the owner may add (spec/SPEC.md §12.2; the origin is then https://<domain>):
#   dns _bag.<domain>.  IN  TXT  "v=ac1; key=<the record's key>"
#
# --out <dir> (with --domain only; the first form is unchanged and refuses it) writes the record to <dir>/address.json
# instead of under deploy/well-known/, for a static host outside this clone (serve <dir> at
# https://<domain>/.well-known/bag/). <dir> must already exist and be writable (never made), and may be
# relative to where the script is run. An existing regular file there is replaced, for the daily re-sign, atomically:
# the record is written to a temporary file in the same directory and renamed onto it, so a reader sees the old record
# or the new one and never none; a link (dangling or not) and anything that is not a regular file are refused. The file
# holds the bytes the default form would (Biome-formatted), verified by the core's verifyRecord before it is put in
# place, with mode 0644; nothing is written under deploy/well-known/ and no key or seed is written anywhere. The record
# line printed ends with the path of the file written. Without --domain nothing changes, byte for byte.
set -euo pipefail

usage() {
  echo "usage: AC_HOME=<home> deploy/make-org-records.sh <label> [<relay URL>] [--ttl <seconds>] [--key <name>] [--rotated-from <name>] [--rotation-key <address>] [--revoke <address>]..." >&2
  if [[ -n "${domain_given:-}" ]]; then
    echo "   or: AC_HOME=<home> deploy/make-org-records.sh --domain <domain> [<relay URL>] [--out <dir>] [--ttl <seconds>] [--key <name>] [--rotated-from <name>] [--rotation-key <address>] [--revoke <address>]..." >&2
  fi
  exit 2
}
die() { echo "make-org-records: $*" >&2; exit 2; }

label="" relay="" ttl=86400 key="" rotated_from="" rotation_key="" revoke=()
domain="" domain_given="" out_dir="" out_given="" dir_name=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ttl | --key | --rotated-from | --rotation-key | --revoke | --domain | --out)
      [[ $# -ge 2 ]] || usage
      case "$1" in
        --ttl) ttl="$2" ;;
        --key) key="$2" ;;
        --rotated-from) rotated_from="$2" ;;
        --rotation-key) rotation_key="$2" ;;
        --revoke) revoke+=("$2") ;;
        --domain) domain="$2" domain_given=1 ;;
        --out) out_dir="$2" out_given=1 ;;
      esac
      shift 2
      ;;
    -*) usage ;;
    *)
      if [[ -z "$label" ]]; then label="$1"; elif [[ -z "$relay" ]]; then relay="$1"; else usage; fi
      shift
      ;;
  esac
done
# --out goes with --domain only, so that every argv of the first form reads as it did before (--out was a usage error).
if [[ -n "$out_given" && -z "$domain_given" ]]; then usage; fi

# The domain, as the core reads an org's domain (isDomainHost, isSpecialUseDomain; spec/SPEC.md §12.3 item 1). Each
# label is checked on its own, its length outright: no bounded repetition inside a repeated group, which macOS's bash
# 3.2 does not hold, and no array.
check_domain() {
  local d="$1" rest l n=0 last not_printable='[^ -~]'
  local shape="the domain is a lower-case host of two or more DNS labels, each 1 to 63 of a-z, 0-9 and - from and to a letter or a digit, at most 253 characters, not $d"
  if [[ "$d" =~ $not_printable ]]; then
    die "the domain is ASCII; give an internationalized name in its xn-- form, which the core reads as written and never decodes (spec/SPEC.md §12.3 item 1), not $d"
  fi
  [[ "$d" != *. ]] || die "the domain has no trailing dot (the core refuses one), not $d"
  [[ ${#d} -le 253 ]] || die "$shape"
  rest="$d"
  while :; do
    l="${rest%%.*}"
    [[ "$l" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ && ${#l} -le 63 ]] || die "$shape"
    n=$((n + 1))
    [[ "$rest" == *.* ]] || break
    rest="${rest#*.}"
  done
  [[ $n -ge 2 ]] || die "$shape"
  last="${d##*.}"
  if [[ "$last" =~ ^([0-9]+|0x[0-9a-f]*)$ ]]; then die "the domain is a name, not an IP literal (its last label is a number), not $d"; fi
  case "$last" in
    alt | arpa | internal | invalid | local | localhost | onion)
      die "the domain's last label is a special-use name (alt, arpa, internal, invalid, local, localhost, onion), which names no org on the public DNS (spec/SPEC.md §12.3 item 1), not $d"
      ;;
  esac
}

if [[ -n "$domain_given" ]]; then
  # The domain form: one positional, the relay URL.
  [[ -z "$relay" ]] || usage
  relay="$label" label=""
  export LC_ALL=C # bytes, so that a non-ASCII name cannot pass a-z and the checks read the same on every Mac
  check_domain "$domain"
  rest="${domain%.usuals.now}"
  if [[ "$rest" != "$domain" && "$rest" != *.* ]]; then
    label="$rest" # <label>.usuals.now is the label form: the same file, key and relay defaults as before
  else
    dir_name="$domain"
    [[ -n "$relay" ]] || die "the relay URL is required with --domain $domain (the default is for <label>.usuals.now only)"
    if [[ -n "$key" ]]; then
      [[ ${#key} -le 64 ]] || die "the key name $key is over 64 characters"
    else
      key="org-$domain"
      [[ ${#key} -le 64 ]] || die "the default key name org-$domain is over 64 characters; give --key <name>"
    fi
  fi
else
  [[ -n "$label" ]] || usage
fi
if [[ -n "$label" ]]; then
  if ! [[ "$label" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
    echo "make-org-records: the label is one DNS label, such as acme, not $label" >&2
    exit 2
  fi
fi
if [[ "${AC_HOME:-}" != /* ]]; then
  echo "make-org-records: set AC_HOME to the absolute path of the home that keeps the org keys" >&2
  exit 2
fi
if [[ -n "$label" ]]; then
  key="${key:-org-$label}"
  relay="${relay:-https://relay-$label.usuals.now}"
  dir_name="$label"
fi
if [[ -n "$out_given" ]]; then
  # Checked before the cd below, so that a relative <dir> means the directory the script was run from.
  [[ -n "$out_dir" ]] || die "--out takes the directory to write address.json in"
  [[ "$out_dir" == /* ]] || out_dir="$PWD/$out_dir"
  out_dir="${out_dir%/}"
  [[ -d "${out_dir:-/}" ]] || die "the --out directory does not exist (it is never made): ${out_dir:-/}"
  [[ -w "${out_dir:-/}" ]] || die "the --out directory is not writable: ${out_dir:-/}"
  if [[ -L "$out_dir/address.json" ]] || { [[ -e "$out_dir/address.json" ]] && [[ ! -f "$out_dir/address.json" ]]; }; then
    die "refusing to replace $out_dir/address.json: it is a link or not a regular file"
  fi
fi

cd "$(dirname "$0")/.." # the repository root: the CLI, Biome and the output path are relative to it
c() { node --disable-warning=ExperimentalWarning packages/cli/src/main.ts "$@"; } # no SQLite warning on Node 24
out="deploy/well-known/public/$dir_name/.well-known/bag/address.json"
shown="$out" # the path the record line prints
sign_to="$out"
if [[ -n "$out_given" ]]; then
  # Signed and formatted in a private scratch directory, verified there, then renamed into place.
  work="$(mktemp -d "${TMPDIR:-/tmp}/make-org-records.XXXXXX")"
  dest_tmp=""
  cleanup() {
    rm -f "$work/raw" "$work/fmt"
    rmdir "$work" 2>/dev/null || true
    if [[ -n "$dest_tmp" ]]; then rm -f "$dest_tmp"; fi
  }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  shown="$out_dir/address.json"
  sign_to="$work/raw"
fi

if address="$(c address "$key" 2>/dev/null)"; then
  state=existing
else
  address="$(c keygen "$key")"
  state=new
fi
echo "key $key $address $state"

args=(record address "$key" --relay "$relay" --sealing-key --ttl "$ttl" --out "$sign_to")
if [[ -n "$rotated_from" ]]; then args+=(--rotated-from "$rotated_from"); fi
if [[ -n "$rotation_key" ]]; then args+=(--rotation-key "$rotation_key"); fi
# ${revoke[@]+...}: an empty array is unset to bash 3.2's set -u (macOS's /bin/bash).
for r in ${revoke[@]+"${revoke[@]}"}; do args+=(--revoke "$r"); done
if [[ -z "$out_given" ]]; then mkdir -p "$(dirname "$out")"; fi
c "${args[@]}"
if [[ -z "$out_given" ]]; then
  node_modules/.bin/biome format --write "$out" >/dev/null
  # shellcheck disable=SC2016 # the ${...} below are JavaScript's, not the shell's
  node -e '
const [label, out] = process.argv.slice(1)
const r = JSON.parse(require("node:fs").readFileSync(out, "utf8"))
console.log(`record ${label} key ${r.key} relays ${r.relays.join(",")} ttl ${r.ttl} iat ${r.iat} exp ${r.iat + r.ttl} rotated_from ${r.rotated_from ?? "-"} rotation_key ${r.rotation_key ?? "-"} revoked ${r.revoked.length} out ${out}`)
' "${label:-$domain}" "$out"
else
  # The default form's path names the file to Biome (its language and its rules); the bytes come on stdin.
  node_modules/.bin/biome format --stdin-file-path="$out" <"$work/raw" >"$work/fmt"
  # shellcheck disable=SC2016 # JavaScript, not the shell
  report=$(node --disable-warning=ExperimentalWarning --input-type=module -e '
import { readFileSync } from "node:fs"
import { parseRecord, verifyRecord } from "@usebag/core"
const [name, file, key, out] = process.argv.slice(1)
let r
try {
  r = verifyRecord(parseRecord(readFileSync(file)), Math.floor(Date.now() / 1000))
} catch (e) {
  console.error(`make-org-records: the record written does not verify (${e.code ?? e.name})`)
  process.exit(2)
}
if (r.kind !== "address" || r.key !== key) {
  console.error(`make-org-records: the record written is not the address record of ${key}`)
  process.exit(2)
}
console.log(`record ${name} key ${r.key} relays ${r.relays.join(",")} ttl ${r.ttl} iat ${r.iat} exp ${r.iat + r.ttl} rotated_from ${r.rotated_from ?? "-"} rotation_key ${r.rotation_key ?? "-"} revoked ${r.revoked.length} out ${out}`)
' "${label:-$domain}" "$work/fmt" "$address" "$shown")
  # The verified bytes go to a temporary file beside the target (mode 0644), then a rename within one directory puts
  # them in place: an existing regular file is replaced atomically, and a link or other file is refused again here.
  dest_tmp="$(mktemp "$out_dir/.address.json.XXXXXX" 2>/dev/null)" || die "could not write in $out_dir"
  cat "$work/fmt" >"$dest_tmp" 2>/dev/null || die "could not write $shown"
  chmod 0644 "$dest_tmp"
  if [[ -L "$shown" ]] || { [[ -e "$shown" ]] && [[ ! -f "$shown" ]]; }; then
    die "refusing to replace $shown: it is a link or not a regular file"
  fi
  mv -f "$dest_tmp" "$shown" 2>/dev/null || die "could not write $shown"
  dest_tmp=""
  printf '%s\n' "$report"
fi
if [[ -n "$domain_given" && ${#domain} -le 240 ]]; then
  # The TXT record of spec/SPEC.md §12.2 for the org record above (no host field: the origin is https://<domain>).
  printf 'dns _bag.%s.  IN  TXT  "v=ac1; key=%s"\n' "$domain" "$address"
fi

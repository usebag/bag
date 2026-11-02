#!/usr/bin/env bash
# A handle record (spec/SPEC.md §12.4): the org's signed word that <local>@<domain> names an address, the file the
# org serves at https://<domain>/.well-known/bag/handles/<local>.json (for a usuals.now org, the well-known
# Worker serves it at https://<label>.usuals.now/...), one record per handle and never a list.
#
#   AC_HOME=<the org keys' home> deploy/make-handle-record.sh <label> <local> <address> [--ttl <seconds>] [--key <name>] [--out <dir>]
#   AC_HOME=<the org keys' home> deploy/make-handle-record.sh --domain <domain> <local> <address> [--ttl <seconds>] [--key <name>] [--out <dir>]
#
# The first form is the usuals default and is unchanged: the handle is <local>@<label>.usuals.now. The second takes the
# org's full domain and the handle is <local>@<domain>. The domain must be a handle's domain as the
# core reads one (isDomainHost and isSpecialUseDomain in packages/core, spec/SPEC.md §12.3 item 1): a lowercase ASCII
# host of two or more DNS labels (each 1 to 63 of a-z, 0-9 and -, from and to a letter or a digit), at most 253
# characters, with no trailing dot, port or IP literal (a last label that is a number), whose last label is none of
# alt, arpa, internal, invalid, local, localhost and onion. A two-label and a three-label name are accepted. Refused,
# exit 2, nothing written: a trailing dot (the core refuses one rather than reading it as the root zone, so the script
# does not fold it away); a non-ASCII name, because the core never decodes an IDN: give the xn-- form as the core reads
# it; an upper-case letter (the core folds nothing; a person's typing is folded by the client, not here). --domain
# <label>.usuals.now with one label is the first form with that label (same files, same default key).
#
# Signs with the existing org key <name> (default org-<label>, or org-<domain> with --domain; give --key when that is
# over 64 characters) from $AC_HOME (an absolute path; a file key or a keychain item, through the edge's HomeCustody,
# as the CLI reads it), never making one: a handle record is valid only under the domain's current key (§12.4 item 3),
# so that key must be the key of the org's address record in
# deploy/well-known/public/<label>/.well-known/bag/address.json (public/<domain>/... with --domain), which
# must exist (make-org-records.sh --domain <domain> <relay URL> writes it there; or place the org's signed record there),
# and <address> must not be in its revoked list. The TTL defaults to 86,400 s, the most a handle record may have, so
# re-sign it daily, as the org record. Refuses a label that is not one DNS label, a local part outside §12.3 item 1
# (1 to 64 of a-z, 0-9, ., - and _, from and to a letter or a digit) and an address that is not ed25519:<64 hex>.
# Writes <the org record's directory>/handles/<local>.json, formatted by Biome so that the file can be committed as it
# is (white space only: the signature is over the canonical preimage), and prints two lines, the handle and its
# address, then the record's org, iat, ttl and exp; never key material. The core's signHandleRecord signs; its
# verifyHandleRecord checks the written file before the script ends. Needs Node 24 or later first in PATH and `npm ci`
# done in this clone (the workspace links, and Biome).
#
# --out <dir> writes the record to <dir>/<local>.json instead of under deploy/well-known/, so that
# a record can be signed for a place outside this clone (the file name is the one the URL asks for, handles/<local>.json).
# <dir> must already exist and be writable (never made), and may be relative to where the script is run. An existing
# regular file there is replaced, for the daily re-sign, atomically: the record is written to a temporary file in the
# same directory and renamed onto it, so a reader sees the old record or the new one and never none; a link (dangling
# or not) and anything that is not a regular file are refused. The file holds the same bytes as the default form would
# (Biome-formatted, then verified by the core before it is put in place), with mode 0644; nothing is written under
# deploy/well-known/ and no key or seed is written anywhere. The org
# record is still read from deploy/well-known/public/<label or domain>/.well-known/bag/address.json, as above,
# and the last line printed ends with the path of the file written. Without --out nothing changes, byte for byte.
set -euo pipefail

export LC_ALL=C # bytes, so that a non-ASCII name cannot pass a-z and the checks below read the same on every Mac

usage() {
  echo "usage: AC_HOME=<home> deploy/make-handle-record.sh <label> <local> <address> [--ttl <seconds>] [--key <name>] [--out <dir>]" >&2
  echo "   or: AC_HOME=<home> deploy/make-handle-record.sh --domain <domain> <local> <address> [--ttl <seconds>] [--key <name>] [--out <dir>]" >&2
  exit 2
}
die() { echo "make-handle-record: $*" >&2; exit 2; }

label="" domain="" local="" address="" ttl=86400 key="" out_dir="" out_given="" pos=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ttl | --key | --domain | --out)
      [[ $# -ge 2 ]] || usage
      case "$1" in
        --ttl) ttl="$2" ;;
        --key) key="$2" ;;
        --domain) domain="$2" ;;
        --out) out_dir="$2" out_given=1 ;;
      esac
      shift 2
      ;;
    -*) usage ;;
    *)
      pos+=("$1")
      shift
      ;;
  esac
done
if [[ -n "$domain" ]]; then
  # The domain form: <local> <address>; the domain is the org's.
  [[ ${#pos[@]} -eq 2 ]] || usage
  local="${pos[0]}" address="${pos[1]}"
else
  [[ ${#pos[@]} -eq 3 ]] || usage
  label="${pos[0]}" local="${pos[1]}" address="${pos[2]}"
  [[ -n "$label" ]] || usage
fi
[[ -n "$local" && -n "$address" ]] || usage

# The domain, as the core reads a handle's domain (isDomainHost, isSpecialUseDomain; spec/SPEC.md §12.3 item 1).
check_domain() {
  local d="$1" dns_label='[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?' not_printable='[^ -~]' last
  if [[ "$d" =~ $not_printable ]]; then
    die "the domain is ASCII; give an internationalized name in its xn-- form, which the core reads as written and never decodes (spec/SPEC.md §12.3 item 1), not $d"
  fi
  [[ "$d" != *. ]] || die "the domain has no trailing dot (the core refuses one), not $d"
  [[ "$d" =~ ^($dns_label\.)+$dns_label$ && ${#d} -le 253 ]] ||
    die "the domain is a lower-case host of two or more DNS labels, each 1 to 63 of a-z, 0-9 and - from and to a letter or a digit, at most 253 characters, not $d"
  # macOS bash's regex does not hold the {0,61} bound inside the repeated group (a 64-character label passed), so
  # each label's length is checked again here.
  IFS=. read -ra labels <<<"$d"
  for l in "${labels[@]}"; do
    [[ ${#l} -le 63 ]] ||
      die "the domain is a lower-case host of two or more DNS labels, each 1 to 63 of a-z, 0-9 and - from and to a letter or a digit, at most 253 characters, not $d"
  done
  last="${d##*.}"
  if [[ "$last" =~ ^([0-9]+|0x[0-9a-f]*)$ ]]; then die "the domain is a name, not an IP literal (its last label is a number), not $d"; fi
  case "$last" in
    alt | arpa | internal | invalid | local | localhost | onion)
      die "the domain's last label is a special-use name (alt, arpa, internal, invalid, local, localhost, onion), which names no org on the public DNS (spec/SPEC.md §12.3 item 1), not $d"
      ;;
  esac
}

if [[ -n "$domain" ]]; then
  check_domain "$domain"
  # <label>.usuals.now is the label form: the same directory and default key as before.
  if [[ "$domain" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)\.usuals\.now$ ]]; then
    label="${BASH_REMATCH[1]}"
  else
    dir_name="$domain"
    if [[ -n "$key" ]]; then
      [[ ${#key} -le 64 ]] || die "the key name $key is over 64 characters"
    else
      key="org-$domain"
      [[ ${#key} -le 64 ]] || die "the default key name org-$domain is over 64 characters; give --key <name>"
    fi
  fi
fi
if [[ -n "$label" ]]; then
  [[ "$label" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ && ${#label} -le 63 ]] || die "the label is one DNS label, such as acme, not $label"
  dir_name="$label" domain="$label.usuals.now" key="${key:-org-$label}"
fi
[[ "$local" =~ ^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$ && ${#local} -le 64 ]] ||
  die "the local part is 1 to 64 of a-z, 0-9, ., - and _, from and to a letter or a digit (spec/SPEC.md §12.3), not $local"
[[ "$address" =~ ^ed25519:[0-9a-f]{64}$ ]] || die "the address is ed25519:<64 lowercase hex>, not $address"
if ! [[ "$ttl" =~ ^[1-9][0-9]{0,4}$ ]] || ((ttl > 86400)); then die "the ttl is 1 to 86400 seconds, not $ttl"; fi
[[ "${AC_HOME:-}" == /* ]] || die "set AC_HOME to the absolute path of the home that keeps the org keys"
handle="$local@$domain"
if [[ -n "$out_given" ]]; then
  # Checked before the cd below, so that a relative <dir> means the directory the script was run from.
  [[ -n "$out_dir" ]] || die "--out takes the directory to write <local>.json in"
  [[ "$out_dir" == /* ]] || out_dir="$PWD/$out_dir"
  out_dir="${out_dir%/}"
  [[ -d "${out_dir:-/}" ]] || die "the --out directory does not exist (it is never made): ${out_dir:-/}"
  [[ -w "${out_dir:-/}" ]] || die "the --out directory is not writable: ${out_dir:-/}"
  if [[ -L "$out_dir/$local.json" ]] || { [[ -e "$out_dir/$local.json" ]] && [[ ! -f "$out_dir/$local.json" ]]; }; then
    die "refusing to replace $out_dir/$local.json: it is a link or not a regular file"
  fi
fi

cd "$(dirname "$0")/.." # the repository root: the workspace packages, Biome and the output path are relative to it
dir="deploy/well-known/public/$dir_name/.well-known/bag"
org_record="$dir/address.json"
out="$dir/handles/$local.json"
shown="$out" # the path the last line prints
if [[ -n "$out_given" ]]; then
  # Signed and formatted in a private scratch directory, verified there, then renamed into place.
  work="$(mktemp -d "${TMPDIR:-/tmp}/make-handle-record.XXXXXX")"
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
  shown="$out_dir/$local.json"
  sign_to="$work/raw"
else
  sign_to="$out"
fi
if [[ ! -f "$org_record" ]]; then
  if [[ -n "$label" ]]; then die "no org record at $org_record: run deploy/make-org-records.sh $label first"; fi
  die "no org record at $org_record: place the org's signed address record there first"
fi

if [[ -z "$out_given" ]]; then mkdir -p "$(dirname "$out")"; fi
# The org key is read and used inside this one process and never printed: SigningKey prints its address only.
# shellcheck disable=SC2016 # the ${...} below are JavaScript's, not the shell's
node --disable-warning=ExperimentalWarning --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs"
import { parseRecord, serializeHandleRecord, signHandleRecord } from "@usebag/core"
import { HomeCustody, runSecurity } from "@usebag/edge"
const [home, name, handle, address, ttl, orgRecord, out] = process.argv.slice(1)
const fail = (why) => { console.error(`make-handle-record: ${why}`); process.exit(2) }
const org = parseRecord(readFileSync(orgRecord))
if (org.kind !== "address") fail(`${orgRecord} is not an address record`)
let signing
try {
  signing = new HomeCustody(home, { run: runSecurity }).keys(name).signing
} catch (e) {
  fail(`no key ${name} in the home (${e.code ?? e.name})`)
}
if (signing.address !== org.key) fail(`the key ${name} is ${signing.address}, the org record served is ${org.key}`)
if (org.revoked.includes(address)) fail(`${address} is in the org record'\''s revoked list`)
const r = signHandleRecord(signing, {
  kind: "handle", org: org.key, handle, address, iat: Math.floor(Date.now() / 1000), ttl: Number(ttl),
})
writeFileSync(out, `${new TextDecoder().decode(serializeHandleRecord(r))}\n`)
' "$AC_HOME" "$key" "$handle" "$address" "$ttl" "$org_record" "$sign_to"
if [[ -n "$out_given" ]]; then
  # The default form's path names the file to Biome (its language and its rules); the bytes come on stdin.
  node_modules/.bin/biome format --stdin-file-path="$out" <"$work/raw" >"$work/fmt"
  verify="$work/fmt"
else
  node_modules/.bin/biome format --write "$out" >/dev/null
  verify="$out"
fi
# shellcheck disable=SC2016 # JavaScript, not the shell
report=$(node --disable-warning=ExperimentalWarning --input-type=module -e '
import { readFileSync } from "node:fs"
import { parseRecord, verifyHandleRecord } from "@usebag/core"
const [file, orgRecord, handle, out] = process.argv.slice(1)
const org = parseRecord(readFileSync(orgRecord))
const r = verifyHandleRecord(JSON.parse(readFileSync(file, "utf8")), { org: org.key, handle, revoked: org.revoked },
  Math.floor(Date.now() / 1000))
console.log(`handle ${r.handle} address ${r.address}`)
console.log(`record handle org ${r.org} iat ${r.iat} ttl ${r.ttl} exp ${r.iat + r.ttl} out ${out}`)
' "$verify" "$org_record" "$handle" "$shown")
if [[ -n "$out_given" ]]; then
  # The verified bytes go to a temporary file beside the target (mode 0644), then a rename within one directory puts
  # them in place: an existing regular file is replaced atomically, and a link or other file is refused again here.
  dest_tmp="$(mktemp "$out_dir/.$local.json.XXXXXX" 2>/dev/null)" || die "could not write in $out_dir"
  cat "$work/fmt" >"$dest_tmp" 2>/dev/null || die "could not write $shown"
  chmod 0644 "$dest_tmp"
  if [[ -L "$shown" ]] || { [[ -e "$shown" ]] && [[ ! -f "$shown" ]]; }; then
    die "refusing to replace $shown: it is a link or not a regular file"
  fi
  mv -f "$dest_tmp" "$shown" 2>/dev/null || die "could not write $shown"
fi
printf '%s\n' "$report"

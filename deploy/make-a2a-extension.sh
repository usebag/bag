#!/usr/bin/env bash
# The public A2A extension of an org's bag address, made from its address record (spec/SPEC.md §7.2) and
# written beside it: deploy/well-known/public/<label>/.well-known/bag/a2a.json, served at
# https://<label>.usuals.now/.well-known/bag/a2a.json by the well-known Worker, next to address.json.
#
#   deploy/make-a2a-extension.sh <label> [--record <address.json>] [--out <dir>]
#   deploy/make-a2a-extension.sh --domain <domain> [--record <address.json>] [--out <dir>]
#
# By decision, no public /.well-known/agent-card.json is served at all.
# A2A 1.0.0 (https://a2a-protocol.org/v1.0.0/specification/) section 14.3 says the resource at that path MUST be an
# AgentCard, an AgentCard requires supportedInterfaces with an accurate URL (sections 4.4.1 and 8.3.1), and the only URL
# that reaches the agent is the caller's own bridge on loopback, which serves the full card at
# /a2a/<address>/.well-known/agent-card.json (packages/a2a). So the public file is the bag extension alone, an
# A2A AgentExtension object (section 4.4.4) with the uri urn:bag:a2a:v1, required, and the params address (the
# record's key), addressRecord (the record's URL) and envelopeType (a2a.jsonrpc.v1). It names no loopback URL and
# holds no secret. (The script was deploy/make-agent-card.sh until the file left the card path; the name would mislead.)
#
# The first form is the usuals default: the domain is <label>.usuals.now and the record is read from
# deploy/well-known/public/<label>/.well-known/bag/address.json. The second takes the org's full domain, a
# lower-case host of two or more DNS labels, and reads public/<domain>/... (make-handle-record.sh's --domain form).
# --record reads another record file; --out <dir> writes <dir>/a2a.json instead (the directory must exist).
# Refuses, exit 2 and nothing written, a record that is not an address record with a sealing key and relays.
#
# Prints one line: the extension, the address, the envelope type and the file written. Needs Node 24 or later first
# in PATH (packages/a2a/src/card.ts runs on Node's type stripping and imports no workspace package, so no `npm ci` is
# needed); when node_modules/.bin/biome exists, a file written under deploy/ is also passed through Biome, which
# changes nothing, the file being written in Biome's format already.
set -euo pipefail

export LC_ALL=C

usage() {
  echo "usage: deploy/make-a2a-extension.sh <label> [--record <address.json>] [--out <dir>]" >&2
  echo "   or: deploy/make-a2a-extension.sh --domain <domain> [--record <address.json>] [--out <dir>]" >&2
  exit 2
}
die() { echo "make-a2a-extension: $*" >&2 && exit 2; }

label="" domain="" record="" out_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain | --record | --out)
      [[ $# -ge 2 ]] || usage
      case "$1" in
        --domain) domain="$2" ;;
        --record) record="$2" ;;
        --out) out_dir="$2" ;;
      esac
      shift 2
      ;;
    -*) usage ;;
    *)
      [[ -z "$label" ]] || usage
      label="$1"
      shift
      ;;
  esac
done

dns_label='[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
if [[ -n "$domain" ]]; then
  [[ -z "$label" ]] || usage
  [[ "$domain" =~ ^($dns_label\.)+$dns_label$ && ${#domain} -le 253 ]] ||
    die "the domain is a lower-case host of two or more DNS labels, such as acme.example, not $domain"
  dir_name="$domain"
else
  [[ -n "$label" ]] || usage
  [[ "$label" =~ ^$dns_label$ && ${#label} -le 63 ]] || die "the label is one DNS label, such as acme, not $label"
  domain="$label.usuals.now" dir_name="$label"
fi
# Relative paths mean the directory the script was run from, so they are made absolute before the cd below.
if [[ -n "$record" && "$record" != /* ]]; then record="$PWD/$record"; fi
if [[ -n "$out_dir" ]]; then
  [[ "$out_dir" == /* ]] || out_dir="$PWD/$out_dir"
  out_dir="${out_dir%/}"
  [[ -d "${out_dir:-/}" ]] || die "the --out directory does not exist (it is never made): ${out_dir:-/}"
fi

cd "$(dirname "$0")/.." # the repository root
major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
((major >= 24)) || die "needs Node 24 or later first in PATH (found $(node --version 2>/dev/null || echo none))"
well_known="deploy/well-known/public/$dir_name/.well-known"
record="${record:-$well_known/bag/address.json}"
[[ -f "$record" ]] || die "no address record at $record: run deploy/make-org-records.sh first, or give --record"
if [[ -n "$out_dir" ]]; then out="$out_dir/a2a.json"; else out="$well_known/bag/a2a.json"; fi

node --disable-warning=ExperimentalWarning packages/a2a/src/card.ts --record "$record" --out "$out" --domain "$domain"
# Under deploy/ (no --out), Biome too, as for the records; a file elsewhere is outside Biome's project, and is left as
# card.ts wrote it (the same bytes).
if [[ -z "$out_dir" && -x node_modules/.bin/biome ]]; then node_modules/.bin/biome format --write "$out" >/dev/null; fi

#!/usr/bin/env bash
# Fails when packages/*/src/ holds a coverage-ignore comment (v8, c8 or istanbul ignore) that
# coverage-allowlist.txt does not list with a reason. Allowlist entries are `<path> | <comment text> | <reason>`,
# the path from the repository root (packages/<p>/src/...). From a sibling repository,
# with packages/*/src/ in place of src/.
set -euo pipefail

cd "$(dirname "$0")/.."
allowlist=coverage-allowlist.txt
pattern='(v8|c8|istanbul)[[:space:]]+ignore'

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

# Read the allowlist: skip comments and blank lines, reject entries without a reason.
paths=()
texts=()
status=0
lineno=0
while IFS= read -r line || [[ -n "$line" ]]; do
  lineno=$((lineno + 1))
  [[ -z "$(trim "$line")" || "$(trim "$line")" == \#* ]] && continue
  IFS='|' read -r path text reason <<<"$line"
  path="$(trim "${path:-}")"
  text="$(trim "${text:-}")"
  reason="$(trim "${reason:-}")"
  if [[ -z "$path" || -z "$text" || -z "$reason" ]]; then
    echo "check-pragmas: $allowlist:$lineno needs <path> | <comment text> | <reason>" >&2
    status=1
    continue
  fi
  paths+=("$path")
  texts+=("$text")
done <"$allowlist"

shopt -s nullglob
sources=(packages/*/src)
hits=""
if [[ ${#sources[@]} -gt 0 ]]; then
  hits="$(grep -rnEi "$pattern" "${sources[@]}" || true)"
fi
count=0
if [[ -n "$hits" ]]; then
  while IFS= read -r hit; do
    count=$((count + 1))
    file="${hit%%:*}"
    rest="${hit#*:}"
    source_line="${rest#*:}"
    allowed=0
    for i in "${!paths[@]}"; do
      if [[ "${paths[$i]}" == "$file" && "$source_line" == *"${texts[$i]}"* ]]; then
        allowed=1
        break
      fi
    done
    if [[ $allowed -eq 0 ]]; then
      echo "check-pragmas: $file:${rest%%:*} has a coverage-ignore comment not listed in $allowlist" >&2
      status=1
    fi
  done <<<"$hits"
fi

if [[ $status -eq 0 ]]; then
  echo "check-pragmas: ok ($count coverage-ignore comments in packages/*/src/, ${#paths[@]} allowlist entries)"
fi
exit "$status"

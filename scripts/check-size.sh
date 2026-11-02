#!/usr/bin/env bash
# Size ceilings: fails when a component holds more
# physical source lines than its ceiling in size-ceilings.toml, when a component listed there has no source files,
# when a packages/*/src or crates/*/src exists that the file does not list, or when the file is missing. Prints one
# line per component, `<name> <measured>/<ceiling>`, and the total.
#
# Ceilings are floors in reverse: a ceiling is raised only by a maintainer's decision entry, never
# by the PR that needs the room. So, as scripts/check-ratchet.sh guards the floors, this fails any ceiling higher
# than the ceiling of the same path on main (override with SIZE_BASE; scripts/last_step.sh passes LAST_STEP_BASE,
# CI passes origin/main), and size-ceilings.toml removed while the base has it. When the base has no
# size-ceilings.toml at all, the ceilings are new and the rise check passes: there is nothing to rise from. A no-op
# comparison on main itself; the counts are checked everywhere.
#
# The count, per component, is the number of physical lines (`wc -l` over the concatenated files) of
#   packages/<p>/src: every *.ts but *.test.ts, *.spec.ts and files under test/, tests/, fixtures/ or __tests__/;
#   crates/<c>/src:   every *.rs but tests.rs, testkit.rs and files under tests/ (as coverage-floors.toml leaves
#                     them out of coverage); an inline #[cfg(test)] module with a body is counted as source.
set -euo pipefail

cd "$(dirname "$0")/.."
base="${SIZE_BASE:-main}"
ceilings=size-ceilings.toml
status=0

# Prints `name<TAB>path<TAB>ceiling` for each [table] of TOML text on stdin (one `key = value` per line; `path` a
# single-quoted literal string, `ceiling` a bare integer; a trailing comment allowed).
components() {
  awk -v q="'" '
    function value(line) {
      sub(/^[^=]*=[[:space:]]*/, "", line)
      sub(/[[:space:]]*(#.*)?$/, "", line)
      if (length(line) >= 2 && substr(line, 1, 1) == q && substr(line, length(line), 1) == q) line = substr(line, 2, length(line) - 2)
      return line
    }
    function flush() { if (name != "") print name "\t" path "\t" ceiling }
    /^[[:space:]]*\[[^]]*\][[:space:]]*(#.*)?$/ {
      flush()
      name = $0
      sub(/^[[:space:]]*\[[[:space:]]*/, "", name)
      sub(/[[:space:]]*\].*$/, "", name)
      path = ""
      ceiling = ""
      next
    }
    /^[[:space:]]*path[[:space:]]*=/ { path = value($0); next }
    /^[[:space:]]*ceiling[[:space:]]*=/ { ceiling = value($0); next }
    END { flush() }
  '
}

# Prints the source files of a component, NUL-separated, by the counting rule above.
sources() {
  case "$1" in
    packages/*/src)
      find "$1" -type f -name '*.ts' ! -name '*.test.ts' ! -name '*.spec.ts' ! -path '*/test/*' ! -path '*/tests/*' \
        ! -path '*/fixtures/*' ! -path '*/__tests__/*' -print0
      ;;
    crates/*/src)
      find "$1" -type f -name '*.rs' ! -name tests.rs ! -name testkit.rs ! -path '*/tests/*' -print0
      ;;
  esac
}

if [[ ! -f "$ceilings" ]]; then
  if git cat-file -e "$base:$ceilings" 2>/dev/null; then
    echo "check-size: $ceilings exists on $base and was removed; the components keep their ceilings" >&2
  else
    echo "check-size: $ceilings is missing; every packages/*/src and crates/*/src needs a ceiling" >&2
  fi
  exit 1
fi

head_list="$(components <"$ceilings")"
if [[ -z "$head_list" ]]; then
  echo "check-size: $ceilings lists no component" >&2
  exit 1
fi

# --- the counts ---------------------------------------------------------------------------------------------------

total=0
total_ceiling=0
seen_names=" "
seen_paths=" "
while IFS=$'\t' read -r name path ceiling; do
  if [[ "$seen_names" == *" $name "* || "$seen_paths" == *" $path "* ]]; then
    echo "check-size: $ceilings: [$name] ($path) is listed twice" >&2
    status=1
    continue
  fi
  seen_names+="$name "
  seen_paths+="$path "
  if [[ ! "$path" =~ ^(packages|crates)/[A-Za-z0-9._-]+/src$ || "$path" == *..* ]]; then
    echo "check-size: $ceilings: [$name] path '${path}' is not packages/<name>/src or crates/<name>/src" >&2
    status=1
    continue
  fi
  if [[ ! "$ceiling" =~ ^[1-9][0-9]*$ ]]; then
    echo "check-size: $ceilings: [$name] ceiling '${ceiling}' is not a positive integer" >&2
    status=1
    continue
  fi
  files="$( (sources "$path" 2>/dev/null || true) | tr -cd '\0' | wc -c | tr -d ' ')"
  if [[ "$files" -eq 0 ]]; then
    echo "check-size: $name: $path has no source files; remove its table only with the component" >&2
    status=1
    continue
  fi
  lines="$(sources "$path" | xargs -0 cat | wc -l | tr -d ' ')"
  total=$((total + lines))
  total_ceiling=$((total_ceiling + ceiling))
  if [[ "$lines" -gt "$ceiling" ]]; then
    echo "check-size: $name $lines/$ceiling ($path, $files files): over its ceiling by $((lines - ceiling)) lines" >&2
    status=1
  else
    echo "check-size: $name $lines/$ceiling ($path, $files files)"
  fi
done <<<"$head_list"
echo "check-size: total $total/$total_ceiling (the sum of the components counted)"

# Every gated directory has a ceiling.
for dir in packages/*/src crates/*/src; do
  [[ -d "$dir" ]] || continue
  if [[ "$seen_paths" != *" $dir "* ]]; then
    echo "check-size: $dir exists and $ceilings does not list it; a component gets its ceiling with its first lines" >&2
    status=1
  fi
done

# --- no ceiling raised against the base ---------------------------------------------------------------------------

branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "${GITHUB_REF:-}" == "refs/heads/main" || "$branch" == "main" ]]; then
  echo "check-size: on main, no ceilings to compare"
elif ! git rev-parse --verify --quiet "$base^{commit}" >/dev/null; then
  echo "check-size: $base is not available; fetch it (git fetch origin main) and run again" >&2
  status=1
elif base_text="$(git show "$base:$ceilings" 2>/dev/null)"; then
  while IFS=$'\t' read -r base_name base_path base_ceiling; do
    [[ -z "$base_path" ]] && continue
    head_ceiling="$(awk -F'\t' -v p="$base_path" '$2 == p { print $3; exit }' <<<"$head_list")"
    if [[ -z "$head_ceiling" ]]; then
      echo "check-size: $base_path ([$base_name], $base_ceiling on $base) is no longer listed"
    elif [[ "$head_ceiling" =~ ^[0-9]+$ && "$base_ceiling" =~ ^[0-9]+$ && "$head_ceiling" -gt "$base_ceiling" ]]; then
      echo "check-size: $base_path: the ceiling went up from $base_ceiling to $head_ceiling against $base; a ceiling is raised only by a maintainer's decision entry" >&2
      status=1
    else
      echo "check-size: $base_path ceiling $base_ceiling -> $head_ceiling"
    fi
  done <<<"$(components <<<"$base_text")"
else
  echo "check-size: $ceilings is new against $base; no ceilings to compare, so none was raised"
fi

if [[ $status -eq 0 ]]; then
  echo "check-size: ok against $base"
fi
exit "$status"

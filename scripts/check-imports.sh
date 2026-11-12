#!/usr/bin/env bash
# Dependency direction: fails when a package's code imports a workspace package it may not use,
# or a relative path out of its own package, or when its package.json depends on one. The rules: core uses no
# workspace package; edge uses core; enterprise-client, the enterprise client, uses edge and core; cli uses
# enterprise-client, edge and core; mcp, the MCP server, uses enterprise-client, edge and core; shim, the bag
# service's stdio shim, uses no workspace package; nothing uses cli, mcp, shim or e2e, except e2e, the system test,
# and bag, the published package that bundles them (packages/bag/src/build.ts), which may use every package. The relay is Rust (crates/ac-relay),
# so it is no npm package here; e2e reaches it as a process. tsconfig project references do not catch a
# package-name import (tsc lets in a file reached through node_modules),
# so this is the gate.
#
# Checked: every .ts, .mts, .cts, .js, .mjs and .cjs file under packages/<p>/ (node_modules and coverage skipped):
# the specifier of each `from '...'`, `import '...'`, `import('...')` and `require('...')`. A string that is not
# an import (a test's expected package name) is not an import and is not checked.
set -euo pipefail

cd "$(dirname "$0")/.."

allowed() {
  case "$1" in
    core) echo "" ;;
    edge) echo "core" ;;
    enterprise-client) echo "core edge" ;;
    cli) echo "core edge enterprise-client" ;;
    mcp) echo "core edge enterprise-client" ;;
    a2a) echo "core edge" ;;
    shim) echo "" ;;
    e2e) echo "core edge enterprise-client cli mcp a2a" ;;
    bag) echo "core edge enterprise-client cli mcp a2a shim" ;;
    *) return 1 ;;
  esac
}

# Prints `<line>:<specifier>` for each import-like specifier in a file.
specifiers() {
  grep -noE "(^|[^[:alnum:]_.\$])(from|import|require)[[:space:]]*\(?[[:space:]]*['\"][^'\"]+['\"]" "$1" |
    sed -E "s/^([0-9]+):.*['\"]([^'\"]+)['\"]\$/\1:\2/" || true
}

# Exit 0 when the relative specifier, taken from a file <depth> directories below the package root, stays inside
# the package at every step.
stays_inside() {
  awk -v depth="$1" -v spec="$2" 'BEGIN {
    n = split(spec, parts, "/")
    for (i = 1; i <= n; i++) {
      if (parts[i] == "..") depth--
      else if (parts[i] != "." && parts[i] != "") depth++
      if (depth < 0) exit 1
    }
    exit 0
  }'
}

status=0
files=0
imports=0
shopt -s nullglob
packages=(packages/*/)
if [[ ${#packages[@]} -eq 0 ]]; then
  echo "check-imports: no packages under packages/" >&2
  exit 1
fi

for dir in "${packages[@]}"; do
  p="$(basename "$dir")"
  if ! rule="$(allowed "$p")"; then
    echo "check-imports: packages/$p has no dependency rule; add one to scripts/check-imports.sh" >&2
    status=1
    continue
  fi
  ok=" $p $rule "

  while IFS= read -r dep; do
    [[ -z "$dep" ]] && continue
    if [[ "$ok" != *" $dep "* ]]; then
      echo "check-imports: packages/$p/package.json depends on @usebag/$dep, which $p may not use" >&2
      status=1
    fi
  done < <(node -e '
    const pkg = require(process.argv[1])
    for (const k of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"])
      for (const name of Object.keys(pkg[k] ?? {}))
        if (name.startsWith("@usebag/")) console.log(name.slice("@usebag/".length))
  ' "$PWD/packages/$p/package.json")

  while IFS= read -r -d '' file; do
    files=$((files + 1))
    rel="${file#packages/"$p"/}"
    slashes="${rel//[^\/]/}"
    depth=${#slashes}
    while IFS= read -r hit; do
      [[ -z "$hit" ]] && continue
      line="${hit%%:*}"
      spec="${hit#*:}"
      if [[ "$spec" == @usebag/* ]]; then
        imports=$((imports + 1))
        name="${spec#@usebag/}"
        name="${name%%/*}"
        if [[ "$ok" != *" $name "* ]]; then
          echo "check-imports: $file:$line imports @usebag/$name, which $p may not use" >&2
          status=1
        fi
      elif [[ "$spec" == .* ]] && ! stays_inside "$depth" "$spec"; then
        echo "check-imports: $file:$line imports '$spec', a path out of packages/$p" >&2
        status=1
      fi
    done < <(specifiers "$file")
  done < <(find "packages/$p" \( -name node_modules -o -name coverage \) -prune -o -type f \
    \( -name '*.ts' -o -name '*.mts' -o -name '*.cts' -o -name '*.js' -o -name '*.mjs' -o -name '*.cjs' \) -print0)
done

if [[ $status -eq 0 ]]; then
  echo "check-imports: ok (${#packages[@]} packages, $files files, $imports workspace imports, all allowed)"
fi
exit "$status"

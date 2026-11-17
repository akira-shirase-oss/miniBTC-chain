#!/usr/bin/env bash
# Workflow hygiene gate (GitHub "Secure use reference"): every action is
# pinned to a full commit SHA, the token is read-only by default, no
# dangerous trigger, no ${{ }} expression inside a run: script (pass
# values through env: instead), no self-hosted runner, and checkouts keep
# no credentials. Usage: scripts/check-workflows.sh [workflow-dir]
set -euo pipefail
cd "$(dirname "$0")/.."
dir="${1:-.github/workflows}"
fail=0
err() { echo "error: $*" >&2; fail=1; }

shopt -s nullglob
files=("$dir"/*.yml "$dir"/*.yaml)
if [ "${#files[@]}" -eq 0 ]; then
  echo "workflows ok: none in $dir"
  exit 0
fi

for f in "${files[@]}"; do
  # 1. uses: owner/repo[/path]@<40 hex> (local ./ actions are fine).
  while IFS= read -r line; do
    ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]-]*uses:[[:space:]]*//; s/[[:space:]]+#.*$//; s/["'\'']//g')"
    case "$ref" in
      ./*) ;;
      *@*)
        sha="${ref##*@}"
        if ! printf '%s' "$sha" | grep -qE '^[0-9a-f]{40}$'; then
          err "$f: action not pinned to a full commit SHA: $ref"
        fi
        ;;
      *) err "$f: action without a ref: $ref" ;;
    esac
  done < <(grep -E '^[[:space:]-]*uses:' "$f" || true)

  # 2. Read-only token by default.
  if ! grep -qE '^permissions:' "$f"; then
    err "$f: no top-level permissions: block"
  fi
  if grep -qE 'write-all' "$f"; then
    err "$f: write-all permissions"
  fi

  # 3. Dangerous triggers.
  if grep -qE '^[[:space:]]*(pull_request_target|workflow_run)[[:space:]]*:' "$f"; then
    err "$f: pull_request_target/workflow_run trigger"
  fi

  # 4. No ${{ }} inside run: (single-line or block scalar).
  bad="$(awk '
    function indent(s) { match(s, /^[ ]*/); return RLENGTH }
    {
      if (inrun) {
        if ($0 ~ /^[[:space:]]*$/) next
        if (indent($0) > runind) { if (index($0, "${{")) print FILENAME ":" NR ": " $0; next }
        inrun = 0
      }
      if ($0 ~ /^[[:space:]-]*run:/) {
        line = $0; sub(/^[[:space:]-]*run:[[:space:]]*/, "", line)
        if (index(line, "${{")) print FILENAME ":" NR ": " $0
        if (line ~ /^[|>]/) { inrun = 1; runind = indent($0); if ($0 ~ /^[[:space:]]*-/) runind += 2 }
      }
    }' "$f")"
  if [ -n "$bad" ]; then
    err "$f: \${{ }} expression inside run: (use env: instead)"
    echo "$bad" >&2
  fi

  # 5. CI's advisory check stays online: the cached-database escape hatch
  #    is for a maintainer's offline machine only.
  if grep -qE 'MINIBTC_DENY_OFFLINE' "$f"; then
    err "$f: sets MINIBTC_DENY_OFFLINE (CI must fetch the live advisory database)"
  fi
  if grep -qE 'cargo deny[^#]*--offline' "$f"; then
    err "$f: runs cargo deny --offline (CI must fetch the live advisory database)"
  fi

  # 6. Hosted runners only.
  if grep -qE 'runs-on:.*self-hosted' "$f"; then
    err "$f: self-hosted runner"
  fi

  # 7. Every checkout drops its credentials.
  checkouts="$(grep -cE 'uses:[[:space:]]*actions/checkout@' "$f" || true)"
  dropped="$(grep -cE 'persist-credentials:[[:space:]]*false' "$f" || true)"
  if [ "$checkouts" -ne "$dropped" ]; then
    err "$f: $checkouts checkout(s) but $dropped persist-credentials: false"
  fi
done

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "workflows ok: ${#files[@]} file(s) pinned, read-only, no dangerous triggers or run: expressions"

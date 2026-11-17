#!/usr/bin/env bash
# Supply-chain gate: cargo-deny (advisories, bans, licences, sources).
# Advisories need the RustSec database, fetched over the network. When the
# fetch fails the gate FAILS and says why; it never passes silently. To
# check against the database already cached on this machine instead, run
# with MINIBTC_DENY_OFFLINE=1: the result is reported as offline, with the
# cache's age. CI never sets it (scripts/check-workflows.sh enforces that).
# A missing cargo-deny is a warning locally and an error with
# MINIBTC_REQUIRE_DENY=1 (CI).
set -uo pipefail
cd "$(dirname "$0")/.."

if ! cargo deny --version >/dev/null 2>&1; then
  if [ "${MINIBTC_REQUIRE_DENY:-0}" = "1" ]; then
    echo "error: cargo-deny is required (MINIBTC_REQUIRE_DENY=1) but not installed" >&2
    exit 1
  fi
  echo "warn: cargo-deny not installed; skipping supply-chain check" >&2
  exit 0
fi

# Advisory exceptions in deny.toml are dated: one whose "review by" date
# has passed fails the gate until it is re-justified or removed.
today="$(date -u +%Y-%m-%d)"
expired="$(grep -oE 'review by [0-9]{4}-[0-9]{2}-[0-9]{2}' deny.toml | awk -v t="$today" '$3 < t {print $3}' || true)"
if [ -n "$expired" ]; then
  echo "error: deny.toml has advisory exceptions past their review date ($(echo $expired | tr '\n' ' ')); re-check and update or remove them" >&2
  exit 1
fi
if grep -qE '^\s*\{ *id *= *"RUSTSEC-' deny.toml && grep -E '^\s*\{ *id *= *"RUSTSEC-' deny.toml | grep -vqE 'review by [0-9]{4}-[0-9]{2}-[0-9]{2}'; then
  echo "error: every deny.toml advisory exception needs a 'review by YYYY-MM-DD' in its reason" >&2
  exit 1
fi

if [ "${MINIBTC_DENY_OFFLINE:-0}" = "1" ]; then
  db="$(ls -dt "${CARGO_HOME:-$HOME/.cargo}"/advisory-dbs/*/ 2>/dev/null | head -1)"
  when="$( [ -n "$db" ] && git -C "$db" log -1 --format=%cI 2>/dev/null || echo unknown)"
  echo "warn: MINIBTC_DENY_OFFLINE=1: advisories checked against the cached RustSec database (last entry: $when), not the live one" >&2
  exec cargo deny --offline check
fi

out="$(mktemp)"
trap 'rm -f "$out"' EXIT
if cargo deny check 2> >(tee "$out" >&2); then
  exit 0
fi
if grep -q 'failed to fetch advisory database' "$out"; then
  echo "error: cargo-deny could not fetch the RustSec advisory database (offline or blocked network)." >&2
  echo "       The gate fails rather than pass without an advisory check." >&2
  echo "       To check against the cached database instead: MINIBTC_DENY_OFFLINE=1 scripts/check.sh" >&2
fi
exit 1

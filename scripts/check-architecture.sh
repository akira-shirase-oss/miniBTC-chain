#!/usr/bin/env bash
# Enforces the crate boundary rules in docs/ARCHITECTURE.md:
#  - pure crates (crypto, primitives, script, consensus) carry no I/O deps
#    and no std I/O imports;
#  - state crates (chainstate, storage, mempool, miner) never touch tokio/axum;
#  - nothing outside apps/ and crates/rpc depends on axum.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# 1. Cargo.toml dependency scan.
for crate in crypto primitives script consensus; do
  bad="$(sed -n '/^\[dependencies\]/,/^\[/p' "crates/$crate/Cargo.toml" \
    | grep -nE 'tokio|axum|redb|tower|hyper|reqwest|minibtc-(chainstate|storage|mempool|p2p|miner|wallet|rpc)' || true)"
  if [ -n "$bad" ]; then
    echo "error: minibtc-$crate must stay pure (no I/O or upper-layer deps):" >&2
    echo "$bad" >&2
    fail=1
  fi
done
for crate in chainstate storage mempool miner; do
  bad="$(sed -n '/^\[dependencies\]/,/^\[/p' "crates/$crate/Cargo.toml" \
    | grep -nE 'tokio|axum|tower|hyper|reqwest' || true)"
  if [ -n "$bad" ]; then
    echo "error: minibtc-$crate must not depend on async/HTTP crates:" >&2
    echo "$bad" >&2
    fail=1
  fi
done

# 2. Source-level scan for forbidden imports in pure crates: wall-clock time,
# threads, sockets, files and async runtimes are all I/O.
for crate in crypto primitives script consensus; do
  bad="$(grep -rnE 'SystemTime|UNIX_EPOCH|std::net|std::fs|std::thread|tokio|axum|redb|Instant::now' "crates/$crate/src" || true)"
  if [ -n "$bad" ]; then
    echo "error: minibtc-$crate sources must not touch I/O:" >&2
    echo "$bad" | head -20 >&2
    fail=1
  fi
done

# 3. axum may only appear in crates/rpc and apps/*.
bad="$(grep -rln 'axum' crates/*/src 2>/dev/null | grep -v '^crates/rpc/' || true)"
if [ -n "$bad" ]; then
  echo "error: axum may only be used by minibtc-rpc and apps/:" >&2
  echo "$bad" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "architecture ok: crate boundaries hold"

#!/usr/bin/env bash
# Runs what CI will run: toolchain check, Rust gates, architecture and
# secret-material rules. Run it before every commit.
set -euo pipefail
cd "$(dirname "$0")/.."

scripts/check-toolchain.sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
scripts/check-architecture.sh
scripts/check-wallet-secrets.sh
# cargo-deny is part of the gate: a failing check fails the gate. Only a
# missing binary is downgraded to a warning (it used to mask config errors).
if cargo deny --version >/dev/null 2>&1; then
  cargo deny check
else
  echo "warn: cargo-deny not installed; skipping supply-chain check" >&2
fi

#!/usr/bin/env bash
# Runs what CI runs (.github/workflows/ci.yml): toolchain check, Rust gates,
# architecture, secret-material and workflow rules, cargo-deny. Run it
# before every commit.
set -euo pipefail
cd "$(dirname "$0")/.."

scripts/check-toolchain.sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
scripts/check-architecture.sh
scripts/check-wallet-secrets.sh
scripts/check-workflows.sh
# cargo-deny is part of the gate: a failing check fails the gate. A missing
# binary is a warning locally and an error when MINIBTC_REQUIRE_DENY=1 (CI).
if cargo deny --version >/dev/null 2>&1; then
  cargo deny check
elif [ "${MINIBTC_REQUIRE_DENY:-0}" = "1" ]; then
  echo "error: cargo-deny is required (MINIBTC_REQUIRE_DENY=1) but not installed" >&2
  exit 1
else
  echo "warn: cargo-deny not installed; skipping supply-chain check" >&2
fi

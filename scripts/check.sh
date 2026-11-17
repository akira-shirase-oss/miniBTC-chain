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
# cargo-deny is part of the gate: a failing check, or an advisory database
# that cannot be fetched, fails it (scripts/check-deny.sh explains both).
scripts/check-deny.sh

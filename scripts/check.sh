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
cargo deny check 2>/dev/null || echo "warn: cargo-deny not installed; skipping"

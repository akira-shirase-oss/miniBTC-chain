#!/usr/bin/env bash
# Fails when the rustc on PATH is not the one rust-toolchain.toml pins.
# Homebrew's cargo ignores toolchain files; run cargo through rustup's proxies instead.
set -euo pipefail
cd "$(dirname "$0")/.."

want="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)"
got="$(rustc --version | awk '{print $2}')"
if [ "$got" != "$want" ]; then
  echo "error: rustc $got on PATH, but rust-toolchain.toml pins $want" >&2
  echo 'fix: export PATH="$(brew --prefix rustup)/bin:$PATH"' >&2
  exit 1
fi
echo "toolchain ok: rustc $got"

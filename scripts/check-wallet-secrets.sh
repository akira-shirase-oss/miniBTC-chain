#!/usr/bin/env bash
# Secret-material gate: library crates never print to stdout/stderr (tracing
# only), and no non-test source may log fields that can carry seed, key or
# passphrase material. Wallet secrets live behind secrecy/zeroize types.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# 1. No println!/eprintln!/dbg! in library crates (apps may print CLI output).
bad="$(grep -rnE '\b(println!|eprintln!|dbg!|print!)' crates/*/src || true)"
if [ -n "$bad" ]; then
  echo "error: libraries must log via tracing, not print macros:" >&2
  echo "$bad" | head -20 >&2
  fail=1
fi

# 2. No logging of secret-bearing identifiers outside tests.
bad="$(grep -rnE '(tracing::|log::|println!|eprintln!).*(mnemonic|seed_phrase|xprv|xpub_secret|private_key|passphrase|secret)' \
  crates apps --include='*.rs' | grep -v 'tests/' | grep -v '#\[cfg(test)\]' || true)"
if [ -n "$bad" ]; then
  echo "error: secret-bearing fields must never reach a log call:" >&2
  echo "$bad" | head -20 >&2
  fail=1
fi

# 3. Wallet keystore must wrap secret material in secrecy/zeroize types.
if ! grep -rqE 'SecretString|SecretVec|SecretBox|Zeroizing' crates/wallet/src; then
  echo "error: crates/wallet must use secrecy/zeroize for key material" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "secrets ok: no secret material reaches logs or stdout"

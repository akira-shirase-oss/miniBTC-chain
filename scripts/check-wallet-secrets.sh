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
#
# One exemption, and only in the CLI: a line carrying the marker
# `secret-display-once:` is the deliberate one-time display of a freshly
# generated seed. `wallet create` must show the mnemonic to the person
# creating the wallet exactly once (blueprint section 4: the mnemonic IS the
# backup, and it is never stored in plain text). That is terminal output the
# user asked for, not a log line, so the log-call rule is a false positive
# there. The marker is honoured only under apps/minibtc-cli/src, and every
# exempt line is printed on each run so a reviewer sees all of them.
MARKER='secret-display-once:'
hits="$(grep -rnE '(tracing::|log::|println!|eprintln!).*(mnemonic|seed_phrase|xprv|xpub_secret|private_key|passphrase|secret)' \
  crates apps --include='*.rs' | grep -v 'tests/' | grep -v '#\[cfg(test)\]' || true)"
exempt="$(printf '%s\n' "$hits" | grep -F "$MARKER" | grep '^apps/minibtc-cli/src/' || true)"
bad="$(printf '%s\n' "$hits" | grep -vF "$MARKER" | grep -v '^$' || true)"
misplaced="$(printf '%s\n' "$hits" | grep -F "$MARKER" | grep -v '^apps/minibtc-cli/src/' || true)"
if [ -n "$bad" ]; then
  echo "error: secret-bearing fields must never reach a log call:" >&2
  echo "$bad" | head -20 >&2
  fail=1
fi
if [ -n "$misplaced" ]; then
  echo "error: '$MARKER' exemptions are allowed only in apps/minibtc-cli/src:" >&2
  echo "$misplaced" | head -20 >&2
  fail=1
fi
if [ -n "$exempt" ]; then
  echo "note: one-time seed display exemptions (reviewed):"
  echo "$exempt" | sed 's/^/  /'
fi

# 3. Wallet keystore must wrap secret material in secrecy/zeroize types.
if ! grep -rqE 'SecretString|SecretVec|SecretBox|Zeroizing' crates/wallet/src; then
  echo "error: crates/wallet must use secrecy/zeroize for key material" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "secrets ok: no secret material reaches logs; stdout carries only the reviewed one-time seed display"

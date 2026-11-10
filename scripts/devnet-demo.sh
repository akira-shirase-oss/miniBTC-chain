#!/usr/bin/env bash
# MiniBTC 3-node devnet demonstration + fork/reorg proof.
#
#   Phase 1  3 nodes connect; mine 120 blocks on N1 → all converge.
#   Phase 2  Partition N3; N1 mines 40 more → N2 follows, N3 stale.
#   Phase 3  Reconnect N3 → headers-first catch-up of 40 blocks.
#   Phase 4  Isolate N3; it mines a 55-block private fork (height 216
#            vs network 161) → reconnect → most-work reorg: N1+N2
#            adopt N3's chain, orphaning N1's 55-block extension.
#   Phase 5  Two wallets: A sends 10 BTC to B through the live network;
#            one block confirms; B's balance reflects it.
#
# Evidence: every phase prints PASS/FAIL; full transcript is teed to
# perf/results/devnet-demo-<timestamp>.log.

set -euo pipefail
cd "$(dirname "$0")/.."

NODE=target/debug/minibtc-node
CLI=target/debug/minibtc-cli
ROOT="$(mktemp -d /tmp/mbtc-demo.XXXXXX)"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="perf/results/devnet-demo-${STAMP}.log"
mkdir -p perf/results
exec > >(tee "$LOG") 2>&1

# Ports (distinct from any other test nodes).
P1=38445; R1=38446
P2=38447; R2=38448
P3=38449; R3=38450
D1="$ROOT/n1"; D2="$ROOT/n2"; D3="$ROOT/n3"
PASS=0; FAIL=0

log()  { printf '\n=== %s ===\n' "$*"; }
ok()   { PASS=$((PASS+1)); echo "  PASS  $*"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL  $*"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }

# cli <datadir> <rpcport> <args...>
# Transport-level flakes (localhost connect resets under load) get 3
# bounded retries; RPC-level errors (rejected tx, bad auth) fail fast.
cli() {
  local attempt=1 out err
  while :; do
    err=$(mktemp)
    if out=$("$CLI" --datadir "$1" --rpc-port "$2" --json "${@:3}" 2>"$err"); then
      cat "$err" >&2; rm -f "$err"; printf '%s' "$out"; return 0
    fi
    if ! grep -qE "rpc transport|error sending request|connection refused|timed out" "$err" || [ "$attempt" -ge 3 ]; then
      cat "$err" >&2; rm -f "$err"; return 1
    fi
    rm -f "$err"; attempt=$((attempt + 1)); sleep 2
  done
}

# tip <datadir> <rpcport> → "height hash"
tip() {
  cli "$1" "$2" chain info | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["blocks"], d["bestblockhash"])'
}

# wait_tip <datadir> <rpcport> <height> <hash|-> <timeout_s> <label>
wait_tip() {
  local d=$1 r=$2 h=$3 want_hash=$4 tmo=$5 label=$6
  local deadline=$(( $(date +%s) + tmo )) out=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    out="$(tip "$d" "$r" 2>/dev/null || true)"
    local hh=${out%% *}; local hh2=${out##* }
    if [ "$hh" = "$h" ] && { [ "$want_hash" = "-" ] || [ "$hh2" = "$want_hash" ]; }; then
      ok "$label (height=$h)"; return 0
    fi
    sleep 2
  done
  bad "$label — timeout, last tip: ${out:-none} (wanted h=$h hash=$want_hash)"
  return 1
}

start_node() { # name datadir p2p rpc [connect]
  local name=$1 d=$2 p=$3 r=$4 c=${5:-}
  mkdir -p "$d"
  if [ -n "$c" ]; then
    "$NODE" --datadir "$d" --listen "127.0.0.1:$p" --rpc "127.0.0.1:$r" \
      --connect "$c" --log warn >"$d/node.log" 2>&1 &
  else
    "$NODE" --datadir "$d" --listen "127.0.0.1:$p" --rpc "127.0.0.1:$r" \
      --log warn >"$d/node.log" 2>&1 &
  fi
  echo $! > "$d/pid"
  # Wait for RPC to come up.
  local deadline=$(( $(date +%s) + 30 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    cli "$d" "$r" chain info >/dev/null 2>&1 && return 0
    sleep 1
  done
  bad "$name RPC never came up"; return 1
}

stop_node() { # datadir
  local d=$1
  [ -f "$d/pid" ] && kill "$(cat "$d/pid")" 2>/dev/null || true
  sleep 1
  [ -f "$d/pid" ] && kill -9 "$(cat "$d/pid")" 2>/dev/null || true
}

cleanup() {
  stop_node "$D1"; stop_node "$D2"; stop_node "$D3"
  echo "datadir: $ROOT  log: $LOG"
}
trap cleanup EXIT

echo "MiniBTC devnet demo — $(date)"
echo "commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

log "Phase 0: build binaries"
cargo build --bins -q && ok "cargo build --bins"

log "Phase 1: start 3 nodes + first convergence (120 blocks)"
start_node N1 "$D1" $P1 $R1
start_node N2 "$D2" $P2 $R2 "127.0.0.1:$P1"
start_node N3 "$D3" $P3 $R3 "127.0.0.1:$P1"
ok "3 nodes started (p2p $P1/$P2/$P3, rpc $R1/$R2/$R3)"

# Wallet A on N1's datadir.
WALLET_PASS="demo-pass-$$"
cli "$D1" $R1 wallet create --name alice --passphrase "$WALLET_PASS" >/dev/null
ADDR_A=$(cli "$D1" $R1 wallet address new --name alice --passphrase "$WALLET_PASS" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("address") or d)')
echo "  wallet A address: $ADDR_A"

T0=$(date +%s)
cli "$D1" $R1 mine generate 120 --address "$ADDR_A" >/dev/null
ok "mined 120 blocks on N1"

TIP1=$(tip "$D1" $R1); H1=${TIP1%% *}; HASH1=${TIP1##* }
wait_tip "$D1" $R1 "$H1" "$HASH1" 30 "N1 tip"
wait_tip "$D2" $R2 "$H1" "$HASH1" 120 "N2 converged to N1"
wait_tip "$D3" $R3 "$H1" "$HASH1" 120 "N3 converged to N1"
T1=$(date +%s)
echo "  convergence time for 120 blocks + 2 followers: $((T1-T0))s"

# Peer counts sanity.
for n in 1 2 3; do
  eval "d=\$D$n; r=\$R$n"
  peers=$(cli "$d" "$r" peers list | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else d.get("count",0))' 2>/dev/null || echo "?")
  echo "  N$n peers: $peers"
done

log "Phase 2: partition N3, extend N1 by 40"
stop_node "$D3"
cli "$D1" $R1 mine generate 40 --address "$ADDR_A" >/dev/null
H2=$(tip "$D1" $R1 | cut -d' ' -f1)
check "N1 height after +40" "$H2" "$((H1+40))"
wait_tip "$D2" $R2 "$H2" - 120 "N2 followed to $H2"

log "Phase 3: reconnect N3 — catch-up over 40+ blocks"
start_node N3 "$D3" $P3 $R3 "127.0.0.1:$P1"
T2=$(date +%s)
wait_tip "$D3" $R3 "$H2" "$(tip "$D1" $R1 | cut -d' ' -f2)" 180 "N3 caught up"
T3=$(date +%s)
echo "  N3 catch-up time: $((T3-T2))s for $((H2-H1)) missed blocks"
[ $((H2-H1)) -ge 50 ] || echo "  note: catch-up was $((H2-H1)) blocks"

log "Phase 4: deliberate fork — N3 mines 55 solo, most-work reorg"
# Isolate N3 (no --connect) and mine a heavier private fork.
stop_node "$D3"
start_node N3-iso "$D3" $P3 $R3   # no connect → solo
cli "$D3" $R3 mine generate 55 --address "$ADDR_A" >/dev/null
FORK_TIP=$(tip "$D3" $R3)
FH=${FORK_TIP%% *}; FHASH=${FORK_TIP##* }
echo "  N3 fork tip: height=$FH hash=$FHASH (network at $H2)"
check "N3 fork is ahead" "$((FH - H2))" "55"

# Reconnect N3 → its taller chain must win via most-work.
stop_node "$D3"
start_node N3 "$D3" $P3 $R3 "127.0.0.1:$P1"
HASH2=$(tip "$D1" $R1 | cut -d' ' -f2)
wait_tip "$D1" $R1 "$FH" "$FHASH" 240 "N1 reorged to N3 fork"
wait_tip "$D2" $R2 "$FH" "$FHASH" 240 "N2 reorged to N3 fork"
wait_tip "$D3" $R3 "$FH" "$FHASH" 60 "N3 stable on its chain"
ok "3-node convergence after most-work fork resolution"

log "Phase 5: two-wallet send through the live network"
cli "$D1" $R1 wallet create --name bob --passphrase "$WALLET_PASS" >/dev/null
ADDR_B=$(cli "$D1" $R1 wallet address new --name bob --passphrase "$WALLET_PASS" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("address") or d)')
echo "  wallet B address: $ADDR_B"

BAL_A_BEFORE=$(cli "$D1" $R1 wallet balance --name alice --passphrase "$WALLET_PASS" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("balance_sats") or d.get("total_sats") or 0)')
echo "  alice balance before: $BAL_A_BEFORE sats"

SEND_OUT=$(cli "$D1" $R1 wallet send --name alice --to "$ADDR_B" --amount 10 \
  --passphrase "$WALLET_PASS" 2>&1) || { bad "send failed: $SEND_OUT"; SEND_OUT=""; }
echo "  send result: $(echo "$SEND_OUT" | head -3 | tr '\n' ' ')"
TXID=$(echo "$SEND_OUT" | python3 -c 'import json,sys
try:
  d=json.load(sys.stdin); print(d.get("txid",""))
except Exception: print("")' 2>/dev/null || true)
echo "  txid: ${TXID:-unknown}"

# Confirm with one block on N1, then verify all nodes + B's balance.
cli "$D1" $R1 mine generate 1 --address "$ADDR_A" >/dev/null
FINAL_H=$(tip "$D1" $R1 | cut -d' ' -f1)
wait_tip "$D2" $R2 "$FINAL_H" - 120 "N2 saw payment block"
wait_tip "$D3" $R3 "$FINAL_H" - 120 "N3 saw payment block"

sleep 2
BAL_B=$(cli "$D1" $R1 wallet balance --name bob --passphrase "$WALLET_PASS" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("balance_sats") or d.get("total_sats") or 0)' 2>/dev/null || echo 0)
echo "  bob balance after: $BAL_B sats (expected ≥ 1_000_000_000)"
[ "${BAL_B:-0}" -ge 1000000000 ] && ok "wallet B received 10 BTC" || bad "wallet B balance $BAL_B"

log "Summary"
echo "  phases passed: $PASS   failed: $FAIL"
echo "  final height: $FINAL_H   log: $LOG"
[ "$FAIL" -eq 0 ]

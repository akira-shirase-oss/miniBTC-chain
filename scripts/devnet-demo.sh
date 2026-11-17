#!/usr/bin/env bash
# MiniBTC 3-node devnet demonstration + fork/reorg proof.
#
#   Phase 1  3 nodes connect; mine 120 blocks on N1 → all converge.
#   Phase 2  Partition N3; N1 mines 40 more → N2 follows, N3 stale.
#   Phase 3  Reconnect N3 → headers-first catch-up of 40 blocks.
#   Phase 4  Real competing fork. Isolate N3. N1 mines a 5-block branch
#            (N2 follows it); N3 mines a heavier 55-block branch paying a
#            different address. Reconnect N3 → N1 reorgs onto N3's branch,
#            orphaning its own 5 blocks, and N2 — connected only to N1, a
#            relay-only node — must follow the reorg through N1.
#   Phase 5  Two wallets: A sends 10 BTC to B through the live network;
#            one block confirms; B's balance reflects it.
#   Phase 6  Deep catch-up: a separate 2-node network on params with a
#            retarget window too long to reach (burst mining stays at the
#            easiest bits). N5 mines 600 blocks; a fresh N6 connects and
#            must sync all of them — far more than one getdata answer
#            (128 blocks) carries.
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
P5=38451; R5=38452
P6=38453; R6=38454
D1="$ROOT/n1"; D2="$ROOT/n2"; D3="$ROOT/n3"; D5="$ROOT/n5"; D6="$ROOT/n6"
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
  stop_node "$D1"; stop_node "$D2"; stop_node "$D3"; stop_node "$D5"; stop_node "$D6"
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

log "Phase 4: competing fork — N1 mines 5, isolated N3 mines 55, most-work reorg"
# A different payout for N3's branch, so its blocks can never coincide
# with N1's (any valid devnet P2PKH address works).
ADDR_FORK="mqmLVoDnuDpSH4FyWn8enX3ksHVEDGX4Ke"
stop_node "$D3"
start_node N3-iso "$D3" $P3 $R3   # no connect → solo

# N1's competing branch; N2 (relay-only, connected to N1) follows it.
cli "$D1" $R1 mine generate 5 --address "$ADDR_A" >/dev/null
N1BR=$(tip "$D1" $R1)
N1BH=${N1BR%% *}; N1BHASH=${N1BR##* }
check "N1 branch height" "$N1BH" "$((H2+5))"
wait_tip "$D2" $R2 "$N1BH" "$N1BHASH" 120 "N2 on N1's branch"

# N3's heavier private branch from the same fork point.
cli "$D3" $R3 mine generate 55 --address "$ADDR_FORK" >/dev/null
FORK_TIP=$(tip "$D3" $R3)
FH=${FORK_TIP%% *}; FHASH=${FORK_TIP##* }
echo "  N1 branch tip: height=$N1BH hash=$N1BHASH"
echo "  N3 branch tip: height=$FH hash=$FHASH (fork point $H2)"
check "N3 branch is ahead of the fork point" "$((FH - H2))" "55"
[ "$N1BHASH" != "$FHASH" ] && ok "the two branches differ" || bad "branches coincide"

# Reconnect N3 → its heavier branch must win; N1 orphans its 5 blocks
# and N2 must follow through N1 alone.
stop_node "$D3"
start_node N3 "$D3" $P3 $R3 "127.0.0.1:$P1"
wait_tip "$D1" $R1 "$FH" "$FHASH" 240 "N1 reorged from its own branch to N3's"
wait_tip "$D2" $R2 "$FH" "$FHASH" 240 "N2 (relay-only) followed the reorg through N1"
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
  --passphrase "$WALLET_PASS" --yes 2>&1) || { bad "send failed: $SEND_OUT"; SEND_OUT=""; }
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

log "Phase 6: deep catch-up — a fresh node 600 blocks behind"
stop_node "$D1"; stop_node "$D2"; stop_node "$D3"
DEEP_PARAMS="$ROOT/deep-params.json"
python3 - "$DEEP_PARAMS" <<'PY'
import json, sys
p = {
    "name": "minibtc-demo-deep", "devnet": True,
    "pow_limit_bits": 0x207fffff, "pow_target_spacing": 30,
    "pow_target_timespan_blocks": 1000000, "pow_clamp_factor": 4,
    "subsidy_start": 5000000000, "subsidy_halving_interval": 150,
    "max_money": 2100000000000000, "coinbase_maturity": 100,
    "max_future_time_secs": 7200, "median_time_span": 11,
    "max_block_size": 1000000, "max_block_txs": 10000,
    "max_block_sigops": 80000, "max_tx_io": 100000,
    "address_version": 0x6f, "p2p_magic": [77, 66, 84, 67],
    "p2p_port": 18445, "rpc_port": 18446, "grind_genesis_nonce": True,
}
json.dump(p, open(sys.argv[1], "w"))
PY
start_deep() { # datadir p2p rpc [connect]
  local d=$1 p=$2 r=$3 c=${4:-}
  mkdir -p "$d"
  if [ -n "$c" ]; then
    "$NODE" --datadir "$d" --listen "127.0.0.1:$p" --rpc "127.0.0.1:$r" \
      --params "$DEEP_PARAMS" --connect "$c" --log warn >"$d/node.log" 2>&1 &
  else
    "$NODE" --datadir "$d" --listen "127.0.0.1:$p" --rpc "127.0.0.1:$r" \
      --params "$DEEP_PARAMS" --log warn >"$d/node.log" 2>&1 &
  fi
  echo $! > "$d/pid"
  local deadline=$(( $(date +%s) + 30 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    cli "$d" "$r" --params "$DEEP_PARAMS" chain info >/dev/null 2>&1 && return 0
    sleep 1
  done
  bad "deep node RPC never came up"; return 1
}
start_deep "$D5" $P5 $R5
cli "$D5" $R5 --params "$DEEP_PARAMS" mine generate 600 --address "$ADDR_A" >/dev/null
DEEP_TIP=$(cli "$D5" $R5 --params "$DEEP_PARAMS" chain info \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["blocks"], d["bestblockhash"])')
DH=${DEEP_TIP%% *}; DHASH=${DEEP_TIP##* }
check "N5 mined 600 blocks" "$DH" "600"
T4=$(date +%s)
start_deep "$D6" $P6 $R6 "127.0.0.1:$P5"
deadline=$(( $(date +%s) + 300 )); got=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  got=$(cli "$D6" $R6 --params "$DEEP_PARAMS" chain info 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["blocks"], d["bestblockhash"])' 2>/dev/null || true)
  [ "$got" = "$DH $DHASH" ] && break
  sleep 2
done
if [ "$got" = "$DH $DHASH" ]; then
  ok "N6 caught up all 600 blocks ($(( $(date +%s) - T4 ))s)"
else
  bad "N6 deep catch-up stalled — last tip: ${got:-none} (wanted $DH)"
fi

log "Summary"
echo "  phases passed: $PASS   failed: $FAIL"
echo "  final height: $FINAL_H   log: $LOG"
[ "$FAIL" -eq 0 ]

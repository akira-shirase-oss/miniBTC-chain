# UI — explorer + wallet web UI (P13 / D-011)

Two separate binaries, deliberately split by trust level:

| Binary | Trust | Purpose |
| :--- | :--- | :--- |
| `apps/minibtc-explorer` | read-only | Browse/search the chain. Never touches keys. |
| `apps/minibtc-wallet-ui` | key-holding | Local wallet: unlock, balances, addresses, send. |

## Explorer (`minibtc-explorer`)

Routes (all GET, all HTML-escaped via `esc()`):

- `GET /` — block index, 25 per page; `?start=<height>` pages backward;
  pager links older/newer/latest. Header shows chain, tip, supply,
  difficulty, peers, mempool tx/byte counts, min relay fee.
- `GET /block/{hash|height}` — decoded header + transactions.
- `GET /tx/{txid}` — decoded ins/outs, fee, fee rate (sat/kvB),
  confirmations; prevouts and addresses link through.
- `GET /address/{addr}` — balance, UTXOs, full receive history with
  spent flags, total received, outputs-spent count.
- `GET /mempool` — fee-rate ordered table (txid, size, fee, sat/kvB,
  inputs).
- `GET /search?q=` — classifier: digits → block height; 64-hex → probe
  block then tx; base58 prefix → address; anything else → error page.
- `GET /healthz`.

Every page carries a search box. Dynamic chain data is untrusted and
always escaped before rendering.

## Wallet UI (`minibtc-wallet-ui`)

Default bind `127.0.0.1:18448`. Wallet create/restore stays CLI-only —
the UI manages existing `<datadir>/wallets/*.wallet` files.

### Session model

- `POST /unlock` (name + passphrase) → decrypts the keystore **in
  memory**, opens a server-side session, sets cookie
  `mb_wallet=<32B random>; HttpOnly; SameSite=Strict; Path=/`.
- Sessions: max 32, idle TTL `--session-ttl-secs` (default 1800),
  swept on every request. `POST /wallet/lock` destroys the session and
  expires the cookie.
- The passphrase is never persisted, logged, or echoed. Seeds/xprvs/
  private keys can never appear in any response — only addresses,
  balances, txids, summaries.
- Unlock is rate-limited per wallet name: 5 failures → 60 s lockout.

### CSRF / origin

- Every POST form carries a per-session `csrf` hidden field; handlers
  reject mismatches (tested live: wrong token → no state change).
- `Origin` header, when present, must match the listen socket
  (`127.0.0.1:port` or `localhost:port`).

### Send flow (two-step, human-gated)

1. `GET /wallet/send` → form (to, amount BTC-or-sats, fee rate sat/kvB).
2. `POST /wallet/send` → validates address/amount/fee, rescans the
   UTXO set (`scantxoutset`), `Wallet::build_and_sign`, stores a
   `PendingSend` draft, persists address indices (change may have been
   issued), redirects to review. **Nothing broadcasts here.**
3. `GET /wallet/review` → human-readable summary: to, amount, fee,
   fee rate, input count, txid + explicit confirm/cancel forms.
4. `POST /wallet/send/confirm` → CSRF check → `sendrawtransaction` →
   result page. Pending draft is consumed either way.

### Other routes

- `GET /wallet` — dashboard: mature/immature balance, indices, UTXO
  table (txid, vout, value, confirmations, coinbase/immature flags),
  recent addresses, actions (new address, send, lock). Rescans on load.
- `GET /wallet/addresses` — all issued receive addresses.
- `POST /wallet/address/new` — fresh receive address; indices
  persisted to `<name>.state.json`.
- `GET /healthz`.

### Audit

`<datadir>/wallet-ui-audit.jsonl` — one JSON object per line:
`{ts, event, wallet, detail}` for `unlock_ok`, `unlock_fail`, `lock`,
`new_address`, `send_draft`, `send_draft_fail`, `send_broadcast`,
`send_broadcast_fail`. No secrets, passphrases, or key material.

## Live verification (this machine, devnet)

- Unlock `webtest` → dashboard showed 150 BTC mature / 500 BTC immature.
- Send 5 BTC → review (fee 1 sat, 1 input, txid `30d1d5de…facd`) →
  confirm → mempool → **confirmed in block** (`confirmations: 1`).
- Negative paths verified: wrong CSRF → mutation rejected; wrong
  passphrase → error page + `unlock_fail` audit; foreign `Origin` →
  rejected; lock → session destroyed, `/wallet` redirects to `/`.
- `state.json` showed `next_change: 1` after the send — change-address
  indices persisted correctly.

## Tests

`cargo test -p minibtc-wallet-ui` — 7 unit tests: amount parsing,
fee-rate bounds, wallet-name validation, cookie parse/flags, Origin
check, HTML escaping, session-expiry sweep. Explorer adds
`classify_query_routes`.

## Load smoke (ab, this machine — laptop numbers, not capacity)

- Explorer `GET /mempool`: 2000 req, 20 conns — **4,117 req/s**, 0 fail.
- Wallet-ui `GET /wallet` (authed; full UTXO rescan per request):
  500 req, 10 conns — **2,067 req/s**, 0 fail.
- The RPC backend itself carries the committed 1M-req evidence
  (`perf/results/load-*.json`); these runs measure the thin HTML layer
  on top.

## Honest limits

- Localhost devnet tool: single-user, no TLS (HTTP on loopback),
  in-memory sessions die with the process.
- Each `/wallet` load rescans all UTXOs — fine at devnet scale.
- No wallet backup/restore UI, no mnemonic display, no password change —
  deliberately CLI-only surfaces.

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

Default bind `127.0.0.1:18448`. Manages `<datadir>/wallets/*.wallet`
files; create/restore are UI flows (see below).

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

### CSRF / origin / host

- Every POST form carries a per-session `csrf` hidden field; handlers
  reject mismatches (tested live: wrong token → no state change), and
  the token is compared without an early exit.
- `Origin` header, when present, must match the listen socket
  (`127.0.0.1:port` or `localhost:port`).
- `Host` must name this server (the bound address or `localhost:port`,
  ignoring case); anything else gets 421 before a handler runs (DNS
  rebinding, D-019), and a request with no `Host` gets 400.
- Every response carries a CSP with no script source and
  `frame-ancestors 'none'`, `nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
- `--listen` must be loopback unless `--allow-remote` is given. Serving
  is bounded: 64 connections, a 10 s header deadline, a 10 s write-stall
  deadline, 1,000 requests per connection, 45 s per request, 64 KiB form
  bodies (D-019).

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

### Wallet lifecycle (create / restore / unlock)

- `GET /` — landing: unlock form + links to create/restore; bounces
  to `/wallet` when a live session exists.
- `GET /new` → `POST /new` (name, passphrase ×2) → generates a
  12-word mnemonic, stages a `PendingCreate` (seed+phrase in
  `Zeroizing`, 10-min TTL, cap 8) → `GET /seed?t=` shows the phrase
  **once** with an explicit backup gate.
- `POST /seed/confirm` requires passphrase (re-asked) + `saved=yes`
  checkbox → only then `Keystore::encrypt` (0600) + `state.json` +
  session + redirect `/wallet`. `POST /seed/cancel` abandons —
  nothing is written.
- `GET /restore` → `POST /restore` (name, phrase, passphrase) →
  mnemonic checksum-validated → same encrypt+save+session path.
  Verified: restoring a phrase derives the identical first address.
- `POST /unlock` — existing wallets (rate-limited, audited).

### Watch-only file

Create, restore, unlock and every send also write
`<datadir>/wallets/<name>.watch.json`: the wallet's derived scripts (hashes
of public keys, no keys or seed) and the change scripts not yet issued. The
CLI's `wallet draft` (MCP `draft_payment`) builds unsigned payments from it
without the passphrase, and the MCP gate reads it to tell change from
payment. It maps every address to this wallet, so it is written owner-only
(0600) through a temp file and a rename (`minibtc_wallet::watch`), by the
CLI and this UI alike (D-015).

### Authed pages

- `GET /wallet` — dashboard: confirmed/immature balance hero, action
  bar (receive/send/addresses/activity), latest receive address, UTXO
  table. Rescans on every load.
- `GET /wallet/receive` — address front-and-center + new-address
  action. `GET /wallet/addresses` — all issued receive addresses.
- `GET /wallet/activity` — balance stats + UTXO list.
- `GET /wallet/send` → `POST /wallet/send` → `GET /wallet/review` →
  `POST /wallet/send/confirm` (broadcast) / `POST /wallet/send/cancel`.
- `POST /wallet/address/new`, `POST /wallet/lock`, `GET /healthz`.

### Audit

`<datadir>/wallet-ui-audit.jsonl` — one JSON object per line:
`{ts, event, wallet, detail}` for `unlock_ok`, `unlock_fail`, `lock`,
`new_address`, `send_draft`, `send_draft_fail`, `send_broadcast`,
`send_broadcast_fail`. No secrets, passphrases, or key material.

## Live verification (this machine, devnet)

- Create `webui2` via UI → seed shown once → confirm gate → keystore
  0600 + session; restore `webui2b` from the same phrase derived the
  identical first address `mwqgJfaQ…`; funded 2 BTC via CLI →
  dashboard showed 2.00000000 BTC / 1 UTXO. Earlier: unlock `webtest`
  → 150 BTC mature.
- Send 5 BTC → review (fee 1 sat, 1 input, txid `30d1d5de…facd`) →
  confirm → mempool → **confirmed in block** (`confirmations: 1`).
- Negative paths verified: wrong CSRF → mutation rejected; wrong
  passphrase → error page + `unlock_fail` audit; foreign `Origin` →
  rejected; lock → session destroyed, `/wallet` redirects to `/`.
- `state.json` showed `next_change: 1` after the send — change-address
  indices persisted correctly.

## Tests

`cargo test -p minibtc-wallet-ui` — unit tests for amount parsing,
fee-rate bounds, wallet-name validation, cookie parse/flags, Origin and
Host checks, HTML escaping and the session-expiry sweep, plus handler
tests through the real router: `POST /wallet/send/confirm` with a
missing, empty, wrong or truncated CSRF token, a foreign, look-alike or
`null` Origin, no or an unknown session, or a rebinding Host never calls
`sendrawtransaction` (a loopback stand-in RPC counts the calls), and
every response carries the security headers. `tests/bind.rs`: a
non-loopback `--listen` exits naming `--allow-remote`. Explorer adds
`classify_query_routes`.

## Load smoke (ab, this machine — laptop numbers, not capacity)

**Method (from `f510ad8` on): `ab -r -k`.** Every server now closes a
connection after 1,000 requests (`Connection: close` on the last answer,
D-019), and plain `ab -k` stops at its first receive error, so it aborts
as soon as its connections reach that cap. `-r` keeps ab going; expect
about one flagged request per capped connection (≈0.1% at 1,000
requests per connection), which is ab's HTTP/1.0 keep-alive handling of
the close, not a failed request (curl over one keep-alive connection
sees every answer complete and reconnects once per 1,000).

- Explorer `GET /mempool`: **100,000 req, 50 conns — 3,052 req/s, 0
  failures** (ab, sustained).
- Wallet-ui `GET /wallet` (authed; full UTXO rescan per request):
  **20,000 req, 10 conns — 1,360 req/s, 0 failures** (ab, sustained).
- Raw log: `perf/results/ui-load-6dc7c5a.txt`. Short-run spot checks
  earlier same session: 4,117 req/s explorer, 2,067 req/s wallet-ui.
- The RPC backend itself carries the committed 1M-req evidence
  (`perf/results/load-*.json`); these runs measure the thin HTML layer
  on top.

### 2026-11-17 at `3844afd` — 1,000,000 requests each (release build)

- Explorer `GET /mempool`, 50 conns: plain `ab -k` (the method above) **aborted at
  50,024 requests** — every connection reached the 1,000-request cap (`f510ad8`) at
  about the same time and ab stops at its first receive error. With `ab -r -k`:
  **1,000,000 complete, 34,565 req/s, p99 2 ms; 1,030 flagged (67 receive, 963
  length)**.
- Wallet-ui `GET /wallet`, 10 conns, 101 UTXOs rescanned per request: **1,000,000
  complete, 9,021 req/s, p99 2 ms; 994 flagged (3 receive, 991 length)**.
- Both flag about one request per capped-connection close (0.10%). curl over one
  keep-alive connection gets 1,002/1,002 complete answers with one reconnect at
  1,001, so the cap closes cleanly for HTTP/1.1; the flags fit ab's HTTP/1.0
  keep-alive handling, not proven server-side. No threshold is defined for the UI
  load. Raw: `perf/results/ui-load-3844afd.txt`.

## Honest limits

- Localhost devnet tool: single-user, no TLS (HTTP on loopback),
  in-memory sessions die with the process.
- Each `/wallet` load rescans all UTXOs — fine at devnet scale.
- No wallet backup/restore UI, no mnemonic display, no password change —
  deliberately CLI-only surfaces.

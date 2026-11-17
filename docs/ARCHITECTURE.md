# MiniBTC — architecture

Sources of truth and request paths. The blueprint's component table (§2) is
the contract; this document records how the pieces fit in *this* workspace.

## Components → crates

| Blueprint component | Crate | Notes |
| :--- | :--- | :--- |
| Crypto core | `crates/crypto` | `Hash256`, `Hash160` (SHA256+RIPEMD160), secp256k1 via `k256`, Base58Check. No I/O. |
| Primitives | `crates/primitives` | `OutPoint`, `Transaction`, `Block`, `BlockHeader`, CompactSize encoding. Canonical bytes → txid/block hash. |
| Script | `crates/script` | Bounded stack machine; P2PKH; sighash (SIGHASH_ALL first). |
| Consensus | `crates/consensus` | Pure validation rules + `ChainParams`. **No I/O, no clocks, no floats.** |
| Chain state | `crates/chainstate` | UTXO set, block index, connect/disconnect, undo data, reorgs. |
| Storage | `crates/storage` | redb database per datadir: blocks, UTXO set, tx/address indexes. Atomic commits. |
| Mempool | `crates/mempool` | Fee-rate ordering, policy caps, conflicts, bounded orphan pool. |
| P2P | `crates/p2p` | Framed TCP protocol, peer manager, gossip, headers-first sync. |
| Miner | `crates/miner` | Block templates + PoW search (async loop lives in the node). |
| Wallet | `crates/wallet` | BIP39/32/44, encrypted keystore, UTXO tracking, coin selection, signing. |
| RPC | `crates/rpc` | JSON-RPC 2.0 server + typed client; cookie auth; localhost default. |
| Node | `apps/minibtc-node` | Wires everything; owns chainstate, mempool, peers, miner, RPC. |
| CLI | `apps/minibtc-cli` | All blueprint §6 commands; human + `--json` output. |
| Explorer | `apps/minibtc-explorer` | Read-only axum UI over the node RPC (search, pagination, dashboard, watch-only address views). |
| Wallet UI | `apps/minibtc-wallet-ui` | Key-holding local web UI (D-011): passphrase→in-memory session, CSRF, audit, send flow. Separate binary so the explorer stays read-only. |
| MCP | `apps/minibtc-mcp` | rmcp server; RPC client only; audit log. Writes are gated (D-015): drafts are unsigned and built watch-only; the owner signs with `minibtc-cli wallet approve-draft` at a terminal; `request_send` broadcasts only that signed tx, capped from its bytes. |
| Attack lab | `tests/attacks` | One test per blueprint §8 row. |

## The life of a transaction (the path every feature must preserve)

1. Wallet selects UTXOs, builds tx (recipient + change), computes sighash
   per input, signs with the right keys.
2. CLI sends the signed tx to the node over RPC (`sendrawtransaction`).
3. Node validates: structure → inputs exist & unspent → scripts verify →
   conservation → fee policy. Accept → mempool.
4. Node gossips `inv`; peers `getdata`, validate independently, accept to
   their own mempools.
5. Miner selects by fee rate, builds block (coinbase + txs), finds nonce.
6. Block gossips; every node fully re-validates before connecting; UTXO set
   updates; reorgs restore via undo data.
7. Wallets see new outputs with 1 confirmation; each later block adds one.

## Dependency direction (enforced by check-architecture.sh)

```text
apps/* ──▶ rpc ──▶ {chainstate, mempool, wallet, p2p types}
              │
miner ──▶ mempool, primitives, consensus
p2p    ──▶ primitives, consensus
chainstate ──▶ storage, consensus, script, primitives, crypto
consensus ──▶ script, primitives, crypto
script   ──▶ primitives, crypto
primitives ──▶ crypto
crypto   ──▶ (external audited crates only)
```

Hard rules:

- `crypto`, `primitives`, `script`, `consensus` depend on **no I/O crate**
  (no tokio, axum, redb, std::fs, std::net, std::time::SystemTime in logic).
- `chainstate` may use `storage` but never tokio/axum.
- The node binary is the only place tokio meets chainstate; RPC methods are
  the only way external clients mutate state.

## Consistency story

- **UTXO set** is derived state, rebuildable by replaying blocks
  (`--reindex`). Reindex replays the stored blocks in height order through
  `consider_block` (recorded-tip path first, then by hash), so it always
  ends on the most-work valid chain; a stored block that fails is skipped
  with its descendants, never fatal, and the following snapshot writes it
  out. Blocks a failed reorg drops are deleted from disk immediately
  (`Chain::take_dropped` → `Store::delete_blocks`). Storage commits a block, its undo data and index updates in
  one redb transaction.
- **Block apply is atomic.** Connect applies a block's transactions to a
  `UtxoOverlay` (reads fall through to the UTXO set, writes stay in the
  overlay) and commits only when every transaction applied; a block
  rejected half-way leaves the set, tip and index untouched
  (`tests/attacks/tests/block_apply.rs`).
- **Block index** tracks every known header with height, cumulative work and
  status (valid / invalid / headers-only / assumevalid-none).
- **Side branches** are judged by their own history: on arrival a
  non-tip block gets the header rules from its parent (bits schedule,
  median-time-past) and every rule that needs no UTXO set; its
  transactions are checked during activation against the fork point's
  state plus the branch's earlier blocks.
- **Reorgs** run on one `UtxoOverlay`: undo the active blocks back to the
  fork (exact undo data), then validate and apply each branch block. The
  overlay is committed and the index switched only if the whole branch
  connected; otherwise the failing block and its descendants are marked
  invalid and the node keeps its old tip and UTXO set
  (`tests/attacks/tests/reorg.rs`).
- **Header sync** keeps no unbounded state. Each new header must link to a
  known block or header, carry a target within the pow limit that its hash
  meets, match the retarget schedule after its parent, and not be too far
  ahead. Accepted headers whose blocks have not connected are indexed per
  peer (at most `HEADERS_PER_PEER`) and leave when the block connects or
  the peer disconnects. A message may carry at most 2,000 headers and no
  repeats; an unsolicited message that adds nothing is penalised, so a
  replayed cheap header leads to a ban.
- **Block download** asks in `getdata` messages of at most 128 items (the
  most a peer serves per message; a larger request gets 128 blocks and a
  `reject`). An indexed header whose block is neither held, queued nor in
  flight is requested again — after each headers answer, when a peer's
  requests drain, and from the periodic sweep, where an expired request
  (60 s) goes to another peer when there is one.
- **Mempool** is local policy: removed on connect; after a reorg the
  disconnected blocks' transactions are re-validated against the new chain
  and re-admitted (oldest block first; conflicts and already-confirmed ones
  drop). The node's tx index covers the active chain only.
- **Wallet** state is local files under the datadir; it learns chain facts
  only through RPC.

## Process model

`minibtc-node` runs async tasks: P2P accept loop + per-peer tasks, RPC
server, optional miner loop, periodic flush. Shutdown: stop accepting →
drain peers/RPC → flush storage → exit. No detached `spawn` without tracking.

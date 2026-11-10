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
| MCP | `apps/minibtc-mcp` | rmcp server; RPC client only; gated writes; audit log. |
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
  (`--reindex`). Storage commits a block, its undo data and index updates in
  one redb transaction.
- **Block index** tracks every known header with height, cumulative work and
  status (valid / invalid / headers-only / assumevalid-none).
- **Reorgs** disconnect blocks in reverse using undo data (restores spent
  outputs, removes created ones), then connect the heavier branch.
- **Mempool** is local policy: removed on connect, re-added (re-validated)
  on disconnect.
- **Wallet** state is local files under the datadir; it learns chain facts
  only through RPC.

## Process model

`minibtc-node` runs async tasks: P2P accept loop + per-peer tasks, RPC
server, optional miner loop, periodic flush. Shutdown: stop accepting →
drain peers/RPC → flush storage → exit. No detached `spawn` without tracking.

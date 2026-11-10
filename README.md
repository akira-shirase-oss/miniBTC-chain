# MiniBTC

> **Status — complete + UI expansion (P13).** All phases P0–P12 per
> `docs/ROADMAP.md` are built and verified: 15/15 blueprint attack scenarios + wallet-entropy hardening tests, ~26M fuzz
> executions with zero crashes, 9/9 property invariants, 6M load ops all
> passing, and a 17/17-phase three-node devnet demo (fork reorg + two-wallet
> payment). P13 adds the enriched read-only explorer (search, pagination,
> dashboard stats, fee rates) and `minibtc-wallet-ui` — a local key-holding web
> wallet with passphrase→in-memory sessions, CSRF, audit logging, and a
> two-step build→review→confirm→broadcast send flow. Evidence under
> `perf/results/`.

A from-scratch Bitcoin-style blockchain in Rust: a full node that validates
every transaction and block, a P2P network, a miner, an HD wallet, a CLI, a
block explorer and an MCP server — all on its own private network with its own
genesis block. Never connected to real Bitcoin, never holding real value.

The contract is the blueprint: `Project_Blueprint` (`MiniBTC Project
Blueprint.md`, November 2026). When code and blueprint disagree, the blueprint
wins unless a `D-NNN` in `docs/DECISIONS.md` says otherwise.

## Layout

| Path | Contents |
| :--- | :--- |
| `crates/crypto` | Hashes, secp256k1 keys, signatures, Base58Check addresses |
| `crates/primitives` | Transaction, block, outpoint types + canonical encoding |
| `crates/script` | Bounded script interpreter (P2PKH) + sighash |
| `crates/consensus` | Pure validation rules + chain parameters |
| `crates/chainstate` | UTXO set, block index, connect/disconnect, reorgs |
| `crates/storage` | redb persistence: blocks, UTXO set, indexes, crash safety |
| `crates/mempool` | Fee-rate ordering, policy limits, conflicts, orphans |
| `crates/p2p` | Framed messages, peer manager, relay, headers-first sync |
| `crates/miner` | Block templates + Proof-of-Work |
| `crates/wallet` | BIP39/32/44, keystore, coin selection, tx building |
| `crates/rpc` | JSON-RPC 2.0 server + typed client |
| `apps/minibtc-node` | The node daemon |
| `apps/minibtc-cli` | The command-line client |
| `apps/minibtc-explorer` | Read-only web explorer (search, pagination, dashboard) |
| `apps/minibtc-wallet-ui` | Local web wallet: unlock sessions, send flow, audit (D-011) |
| `apps/minibtc-mcp` | MCP server for AI assistants |
| `tests/attacks` | The attack lab — one test per historic bug/attack (+ wallet-entropy suite) |
| `perf/` | Load scenarios and committed results (machine + commit) |

## What counts as done

The blueprint's definition: three or more nodes sharing one chain; two
wallets sending coins through the CLI; a deliberate fork resolved by
most-work; every Tier-1 security rule covered by a passing attack test; an AI
assistant inspecting the chain and drafting payments through MCP with
human-gated spending. Under the workspace standard that means executed
evidence — never a claim without a run.

## Documents

- `docs/END_GOAL.md` — what done means, scope, invariants, ship gate
- `docs/ARCHITECTURE.md` — components, paths, layout, consistency story
- `docs/ROADMAP.md` — P0–P13 order and proof gates
- `docs/DECISIONS.md` — deliberate deviations and open questions
- `docs/UI.md` — explorer + wallet web UI routes, session/CSRF model, send flow

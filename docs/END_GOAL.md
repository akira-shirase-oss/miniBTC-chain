# MiniBTC — end goal

## What the system is when shipped

A complete, private Bitcoin-style network running on this machine (and
optionally across machines):

- **`minibtc-node`** — a full node that independently validates every
  transaction and block against consensus rules, maintains the UTXO set,
  stores chain state durably, serves the P2P protocol and the RPC API, and
  can mine blocks paying a configured address.
- **`minibtc-cli`** — a human interface covering every node, wallet, chain,
  mempool, mining and peer operation in blueprint §6.
- **`minibtc-explorer`** — a read-only web UI: latest blocks, block detail,
  transaction detail, address balance and history.
- **`minibtc-mcp`** — an MCP server exposing the chain to AI assistants:
  read tools, explain tools, and write tools gated by human confirmation.
- **`minibtc-attacks`** — the attack lab: every row of blueprint §8 as an
  automated test.

## Scope

**In:** everything in blueprint phases 0–12 — consensus, chain state,
storage, mempool, P2P, miner, wallet (BIP39/32/44), RPC, CLI, explorer, MCP,
attack lab, hardening, load evidence.

**Out:** Bitcoin mainnet/testnet compatibility (never connected, never real
value); byte-for-byte Core wire compatibility (stretch only); SegWit,
timelocks, Taproot, Schnorr, broader Script (Tier-3, post-v1); production
capacity claims — laptop numbers are development observations.

## Non-negotiable invariants

1. **Consensus purity.** Validation rules are deterministic functions: no
   I/O, no clocks, no floats, checked arithmetic. Two honest nodes must
   never disagree on validity.
2. **No inflation, ever.** Sum of all outputs ≤ subsidy schedule + fees;
   every input spends an existing unspent output; no duplicate inputs; coinbase
   maturity 100 blocks; all money arithmetic checked.
3. **Bounded everything.** Message sizes, mempool, orphan pool, peer counts
   per IP/subnet, script resources, RPC bodies, wallet scans — every structure
   filled by untrusted input has a hard limit.
4. **Secrets never leak.** Seeds, private keys, passphrases and wallet files
   never appear in logs, errors, RPC responses, MCP output or committed
   fixtures.
5. **Crash honesty.** A kill at any point leaves the node restartable with a
   consistent chain; committed state is never half-applied; recovery replays
   or verifies, never guesses.
6. **Agents propose; humans dispose.** The MCP layer can read, explain and
   draft — it can never move funds without approval outside the model.

## The four required failure cases (drill obligations)

1. Kill the node mid-block-write; restart; state is consistent.
2. Feed a heavier fork; the node reorgs and ends with the same UTXO set as a
   fresh replay.
3. Send conflicting transactions to two nodes; only one is ever confirmed.
4. Submit every Tier-1 attack from blueprint §8; each is rejected by an
   automated test.

## Ship gate

The blueprint's definition of done, made executable:

- Three or more nodes on one machine share one chain (proven by a scripted
  multi-node run committed as evidence).
- Two wallets send coins to each other through the CLI on different nodes.
- A deliberate fork is resolved by the most-work rule, observed end to end.
- Every Tier-1 security rule has a passing attack test in `tests/attacks`.
- An AI assistant (via MCP) answers "why was this transaction rejected?"
  correctly and drafts a payment that only broadcasts after human approval.
- `scripts/check.sh` is green; load evidence ≥1M ops is committed under
  `perf/results/` with machine + commit.

# MiniBTC — roadmap

Phases mirror blueprint §5 (P0–P12). Each phase ends at a **proof gate**:
what must run and pass before the phase counts as done. Security work is
inside every phase; the attack lab formalizes it in P12.

| # | Phase | Gate |
| :- | :--- | :--- |
| P0 | Setup & foundations | Workspace compiles; contract docs committed; chain params load from config; check scripts green |
| P1 | Keys, signatures, addresses | Keypair+address CLI-able; checksum rejects typos; sign/verify round-trip; high-S rejected |
| P2 | Transactions & UTXOs | Spend of known UTXO accepted; double-spend, overspend, dup-input, overflow rejected |
| P3 | Script & sighash | Only owner spends P2PKH; post-sign output change invalidates sig; exec limits enforced |
| P4 | Blocks, Merkle, mining | Node mines a chain; blocks validate; devnet difficulty retargets on schedule; merkle-dup + coinbase-over-claim + timestamp + size/sigop attacks rejected |
| P5 | Chain state, storage, reorgs | Kill mid-write → consistent restart; heavier fork → reorg; UTXO set == fresh replay; maturity enforced |
| P6 | Mempool | Fee-rate ordering into blocks; reorg re-queues txs; min-fee/dust/ancestor/orphan/flood bounds proven |
| P7 | P2P network | 3 nodes converge; partition→reorg→converge; catch-up sync; eclipse + malformed-message defenses tested |
| P8 | Wallet | A→B send across nodes; seed restore; encrypted keystore; fresh change addresses; no secrets in logs |
| P9 | RPC & CLI | Full blueprint §6 demo runs from the CLI; auth + localhost + input validation proven |
| P10 | Explorer | Click block→tx→address→back; read-only; all data escaped |
| P11 | MCP server | explain_transaction answers correctly; draft→human-approve→broadcast flow works; all safety rules tested |
| P12 | Hardening & attack lab | All 15 §8 attacks automated + passing; fuzz targets; invariants property-tested; ≥1M-op load evidence committed |
| P13 | UI expansion (D-011) | Explorer: search/pagination/dashboard/richer pages, still read-only. Wallet UI: passphrase-gated in-memory sessions, CSRF, audit, build+sign+broadcast flow live-tested |

## Sequencing notes

- P1–P5 are the consensus core: nothing network-facing exists until blocks
  validate end to end. The node binary appears in P5 with `--mine` and
  `--reindex` only.
- P6–P7 add the network; P8 adds users; P9 exposes control; P10–P11 add
  visibility and agents; P12 proves it all.
- Every phase commits its own evidence: unit/integration/attack tests plus,
  where a traffic unit exists, a load scenario result under `perf/results/`.
- `docs/modules/` gains a module doc per area as it stabilizes.

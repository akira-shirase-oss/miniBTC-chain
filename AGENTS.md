# MiniBTC — agent instructions

A from-scratch Bitcoin-style blockchain in Rust: full node, P2P network,
miner, HD wallet, CLI, block explorer and MCP server on a private devnet.
Contract: `MiniBTC Project Blueprint.md` (see README for where it lives).
When code and blueprint disagree, the blueprint wins unless a `D-NNN` in
`docs/DECISIONS.md` says otherwise.

## Read first

1. `docs/END_GOAL.md` — what done means, scope in/out, invariants, ship gate.
2. `docs/ARCHITECTURE.md` — components, the life of a transaction, layout.
3. `docs/DECISIONS.md` — seeded decisions and open questions; record new
   decisions there, do not silently resolve an open question.
4. `docs/ROADMAP.md` — P0–P12 order and each phase's proof gate.
5. `docs/modules/` — per-area module docs as they land.

## Non-negotiables

1. **Consensus is pure.** `minibtc-consensus` (and the pure parts of
   `minibtc-script`, `minibtc-primitives`, `minibtc-chainstate`) carry no I/O,
   no clocks, no floats — checked arithmetic everywhere. An overflow is a
   consensus bug. `scripts/check-architecture.sh` enforces crate boundaries.
2. **Never write your own cryptography.** Audited crates only (`k256`,
   `sha2`, `ripemd`, `hmac`, `pbkdf2`, `bip39`, `bs58`). Understand them; do
   not reimplement primitives. BIP32 derivation is implemented per the
   blueprint's explicit instruction and verified against official vectors.
3. **Every peer, transaction and block is malicious until proven otherwise.**
   Bounded everything: message sizes, mempool, orphan pool, peers per IP,
   RPC bodies, script execution. Every I/O await has a deadline.
4. **Secrets stay secret.** Seeds, keys and passphrases never appear in logs,
   errors, RPC responses or MCP output. Keys are encrypted at rest.
5. **Honest states.** `unknown`/`uncertain` beats a reassuring lie. A feature
   counts when its failure behaviour is tested and its evidence is stored.

## Rust rules

- `export PATH="$(brew --prefix rustup)/bin:$PATH"` before every cargo command —
  Homebrew's cargo comes first on `PATH` and ignores the pinned toolchain.
- Typed errors (`thiserror`) in libraries; `anyhow` only in binaries. No
  `unwrap`/`expect` on external input. Deadlines on every I/O await.
- Modern idioms: edition 2024, `LazyLock`, let chains, `#[expect(.., reason)]`.
- Money is integer base units only — never floats, never unchecked `+`/`-`.

## Testing rule (workspace standard)

Every feature ships regression tests + a fixture/attack path + a load
scenario in the same change; every fixed bug gets a test that fails without
it. Security work is part of every phase, not a final step: Tier-1 consensus
rules each get an attack test the moment the rule lands. Load runs are
aggressive per the workspace rule: ≥1,000,000 ops (or the equivalent unit)
where a traffic unit exists; results committed under `perf/results/` with
machine + commit; misses are kept, never rerun until green; laptop numbers
are development observations, never production capacity.

## Verification

`scripts/check.sh` — toolchain check, `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets --locked -- -D warnings`,
`cargo test --workspace --locked`, `scripts/check-architecture.sh`,
`scripts/check-wallet-secrets.sh` (no secret material in logs/fixtures).
Run before every commit.

## Working rules

- Work phase by phase per `docs/ROADMAP.md`; commit at each proof gate.
- Commits stay local (no push — the remote is not set up yet).
- The journey is recorded in the build log at
  https://404human.dev (source: `akira-shirase-oss/minimal-portfolio`,
  `content/minibtc/`). Update it at each milestone.

# MiniBTC — decisions

Deliberate deviations from the blueprint, seeded open questions, and their
resolutions. When code and blueprint disagree: blueprint wins unless a
`D-NNN` below says otherwise. New decisions append here — never silently.

## Decisions

### D-001 — redb for storage (blueprint offered "RocksDB or sled")

`redb` 4.x: pure Rust, maintained, ACID transactions, single-file database
with column families. `sled` is still a 1.0 alpha; RocksDB pulls a C++ build.
For a learning chain the access pattern (point lookups + range scans +
atomic multi-table commits) fits redb exactly. Recorded as a deviation from
the letter of the spec, not its intent (durable, crash-safe KV).

### D-002 — k256 for secp256k1 (blueprint listed "secp256k1")

`k256` 0.14 is a pure-Rust secp256k1 implementation (the same curve, ECDSA,
RFC 6979 deterministic nonces). The `secp256k1` crate name refers to the
libsecp256k1 C binding; k256 avoids a C toolchain and is already proven in
this workspace family's prior `btcmini`. DER handling uses k256's `der`
support; strict-DER and low-S rules are enforced at our boundary and tested
against attack cases.

### D-003 — `apps/` for binaries (blueprint sketched `bins/`)

Workspace convention across akira-shirase-oss projects is `apps/`; binaries
are `apps/minibtc-{node,cli,explorer,mcp}`. Names and behaviour unchanged.

### D-004 — Money unit: integer base units, `COIN = 100_000_000`

All amounts are `u64` satoshi-style base units; CLI displays 8 decimals
(`--amount 1.5` = 150_000_000). Checked arithmetic only — an overflow is a
consensus bug, enforced by `clippy::arithmetic_side_effects` review and
typed `Amount` newtype where practical.

### D-005 — JSON-RPC 2.0 over HTTP POST `/rpc` (blueprint allowed either)

Matches Bitcoin Core's shape and gives the CLI/explorer/MCP one surface.
Auth: per-datadir `.cookie`-style token file (random 128-bit, `HttpOnly`
conceptually; sent as `Authorization: Bearer`). Binds `127.0.0.1` by default;
`--rpc-bind` is explicit opt-in for multi-machine devnets and is logged.

### D-006 — Devnet chain parameters are first-class config

`ChainParams` (subsidy, halving interval, powLimit, retarget interval &
timespan, coinbase maturity, max block weight/size, min relay fee, ports,
genesis message/time) loads from a TOML file per datadir with
`minibtc-node --params`. Defaults target a watchable devnet (fast blocks,
short retarget window); nothing assumes mainnet values.

### D-007 — Sighash scope: SIGHASH_ALL now, others reserved

Blueprint phase 3 requires SIGHASH_ALL; the sighash byte is carried in every
signature so ALL/NONE/SINGLE can be added without a wire change. Tier-3
sighash types are post-v1 per the blueprint's own phasing.

### D-008 — P2P protocol: Bitcoin-shaped but own magic

Message envelope mirrors Bitcoin Core (magic, command, length, checksum,
payload) with a MiniBTC-specific magic so our nodes can never handshake with
real Bitcoin nodes — an intentional safety property, not an accident.

## Open questions

- **Selfish mining measurement (P12):** blueprint marks it optional. Decide
  at P12 whether the simulation harness can attribute honest-vs-selfish
  revenue credibly on devnet hash rates; record the outcome either way.
- **`--connect` vs DNS seeds:** devnet uses explicit `--connect` peers and
  `addnode` RPC; no DNS seed infrastructure is planned.

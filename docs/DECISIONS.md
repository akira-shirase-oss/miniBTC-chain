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
consensus bug; `Sats` exposes checked ops and the attack lab's overflow
tests prove rejection. (The advisory `arithmetic_side_effects` lint was
set to `allow` at close-out: it cannot distinguish safe index math from
money math; `clippy::all = deny` + tests carry the invariant.)

### D-005 — JSON-RPC 2.0 over HTTP POST `/rpc` (blueprint allowed either)

Matches Bitcoin Core's shape and gives the CLI/explorer/MCP one surface.
Auth: per-datadir `.cookie`-style token file (random 128-bit, `HttpOnly`
conceptually; sent as `Authorization: Bearer`). Binds `127.0.0.1` by default;
`--rpc-bind` is explicit opt-in for multi-machine devnets and is logged.

### D-006 — Devnet chain parameters are first-class config

`ChainParams` (subsidy, halving interval, powLimit, retarget interval &
timespan, coinbase maturity, max block weight/size, min relay fee, ports,
genesis message/time) loads from a JSON file passed with `--params`
(node, CLI, MCP, wallet UI). The binary reads the file; consensus only
parses and validates the text (`ChainParams::from_json`), so the pure
crate never touches the filesystem. Defaults target a watchable devnet
(fast blocks, short retarget window); nothing assumes mainnet values.

### D-007 — Sighash scope: SIGHASH_ALL now, others reserved

Blueprint phase 3 requires SIGHASH_ALL; the sighash byte is carried in every
signature so ALL/NONE/SINGLE can be added without a wire change. Tier-3
sighash types are post-v1 per the blueprint's own phasing.

### D-008 — P2P protocol: Bitcoin-shaped but own magic

Message envelope mirrors Bitcoin Core (magic, command, length, checksum,
payload) with a MiniBTC-specific magic so our nodes can never handshake with
real Bitcoin nodes — an intentional safety property, not an accident.

### D-009 — Selfish mining: measured, profitable as theory predicts

The P12 optional item is resolved by simulation, not devnet hash rates:
`attack_selfish_mining_earns_above_hashrate` runs a seeded Eyal–Sirer-style
model (α=40% attacker, γ=50% race-win) over 60k rounds and asserts revenue
share exceeds hashrate share (~0.48 vs 0.40). Honest attribution: it is a
model of the strategy's economics, not a measurement on our chain's real
hashrate — recorded as such.

### D-010 — Peer discovery: explicit `--connect` + `addnode` only

No DNS seeds, no addr gossip bootstrap beyond what peers exchange. Devnet
nodes name each other; `peers`/`addnode` RPC covers re-seeding. The
eclipse-resistance limits (per-IP, per-/16, inbound cap) still apply to
whatever peers do connect.

### D-011 — UI expansion beyond the blueprint's read-only explorer

User-directed scope addition after P12 close-out. Two parts:

1. **Explorer enrichment** (same `minibtc-explorer` binary, still
   read-only): global search (txid/hash/height/address), paginated block
   index, dashboard stats, fee-rate columns, richer tx/address pages,
   watch-only address views. No write paths — unchanged contract.
2. **`minibtc-wallet-ui`** — a NEW separate binary. The blueprint gives
   the wallet a CLI, not a web UI; this extends it deliberately. It is
   key-holding by necessity, so the security contract is stricter than
   the explorer's: passphrase unlocks into an in-memory session only
   (never persisted, never logged), per-session CSRF tokens on every
   POST, SameSite=Strict HttpOnly cookies, localhost bind by default,
   audit log with no secrets, and seeds/xprvs/keys can never appear in
   any response. **Amended (user request):** wallet create and restore
   are now UI flows too — but with the same discipline the CLI uses:
   create is two-step (generate → seed shown ONCE behind an explicit
   "I saved it" gate → only then encrypt+save+unlock; the pending seed
   lives in a `Zeroizing` buffer with a 10-min TTL and writes nothing
   if abandoned), restore validates the mnemonic checksum then takes
   the identical encrypt+save+session path. The passphrase is asked
   twice during create (once to stage, once at the confirm gate) and
   is never stored.

### D-012 — Seed entropy source (Coldcard-class hardening)

`generate_mnemonic` delegates to the `bip39` crate, which draws
entropy from `rand_core`'s OS CSPRNG (`getrandom` → OS entropy pool).
That is the correct source — the Nov-2025 Coldcard disclosure (~1,816
BTC stolen; TRM Labs) was a *build-config* failure: a weak software
RNG path produced seeds with ~40 effective bits on older devices. The
encoding (128-bit BIP39 words) looked wide while the source was
narrow — silent entropy deficit.

MiniBTC's posture:

- Entropy comes only from the OS CSPRNG — never a seeded PRNG, never
  time/PID mixing.
- `tests/attacks/tests/wallet_entropy.rs` proves both directions:
  a simulated 32-bit-entropy source produces duplicate mnemonics at
  the birthday bound (8 collisions in 200k draws), while 8,192 real
  generated mnemonics are all unique with an unbiased first-word
  distribution.
- Honest limit, recorded: ~8k samples cannot distinguish 128-bit
  from ~40-bit entropy — that needs ~2^20 draws. The defense is the
  dependency choice itself, plus `cargo audit`/`cargo deny` in the
  verification chain for supply-chain drift.
- `mnemonic_from_entropy` exists as a legitimate restore path and as
  the attack lab's simulation hook — it performs only the spec'd
  encoding and does not assess entropy quality.

### D-013 — Proof-of-work schedule is a validation rule (2026-11-16)

Retargeting used to live only in the node's miner: validation checked
`hash <= target(bits)` but never which `bits` a block may claim. A peer
could choose any difficulty. Validation now matches Bitcoin Core's
`ContextualCheckBlockHeader`/`CheckProofOfWork`: `bits` must equal
`Chain::next_bits_after(parent)` (parent's bits inside a period; at a
boundary `next_bits_for_period`, i.e. span clamped to `[T/4, 4T]`,
target rescaled, capped at `pow_limit_bits`) and the target may not be
above the pow limit. The miner calls the same function. Two encoding
bugs were fixed with it: `encode_compact` now shifts a mantissa whose
top bit is set (Core's `GetCompact`; the sign bit used to swallow it),
`decode_compact` rejects negative encodings, and the retarget division
saturates instead of wrapping mod 2^256 (a slow period at the devnet
limit used to make mining *harder*). Consequence: devnet datadirs
written before this change may hold blocks whose bits no longer match
the schedule; `--reindex` would refuse them. Start such devnets fresh.
The devnet preset's `instant_difficulty` flag never disabled
retargeting (it only grinds the genesis nonce), so it is now named
`grind_genesis_nonce` (the old key still loads). Burst mining with
`mine generate` therefore keeps raising difficulty ×4 per 20 blocks; a
regtest-style "no retargeting" mode would have to be a new consensus
parameter applied by validation and the miner alike, which the blueprint's
"difficulty adjusts on schedule on devnet settings" milestone argues
against.

### D-014 — BIP34 coinbase height + BIP30 no-overwrite (2026-11-16)

The blueprint's Tier-1 table does not list either rule, and nothing in
it forbids them; both close a real hole. Without them two identical
coinbases (same payout, value and scriptSig — the old miner wrote the
height as a wrapping `u16`) share a txid, the second overwrites the
first's unspent coin, and disconnecting it deletes the original.

- **BIP34**: for every block at height ≥ 1 the coinbase scriptSig must
  start with `coinbase_height_prefix(height)`, byte-for-byte Bitcoin
  Core's `CScript() << nHeight` (OP_0 / OP_1..OP_16 / minimal
  script-number push). Genesis is exempt (it is never validated), so the
  genesis hash is unchanged. The miner and test fixtures use the same
  function.
- **BIP30**: always on (Core skips it after BIP34 activation for speed;
  MiniBTC keeps it because the check is a hash lookup). A tx whose
  outpoints already exist unspent — in the UTXO set or earlier in the
  same block — is rejected; the UTXO overlay also refuses to overwrite
  as a backstop.

Consequence: blocks mined before this change carry the old `0x02 <u16>`
height and fail BIP34, so older devnet datadirs cannot `--reindex`;
start them fresh (same note as D-013).

### D-015 — MCP spend gate: unsigned drafts, the signature is the approval (2026-11-16)

The first MCP gate signed the payment at draft time (the blueprint asks
for an unsigned draft), showed and capped the JSON fields stored next to
the hex rather than the hex itself, and treated `<id>.approved` — a
file any same-user process could write, minted by a command printed to
the model — as human approval. Now:

1. `draft_payment` runs `minibtc-cli wallet draft`, which builds an
   **unsigned** transaction from `<wallet>.watch.json` (public scripts
   only, refreshed whenever the owner uses the wallet with its
   passphrase). The child process gets no keystore passphrase; the MCP
   server never holds keys or the passphrase.
2. **Approval is the owner's signature.** `minibtc-cli wallet
   approve-draft` refuses to run unless stdin/stderr are a terminal,
   decodes the draft's bytes, shows every output (address, amount,
   change/payment) and the fee, reads the wallet passphrase from the
   terminal (never from a flag or the environment), and signs only when
   the owner types `sign`. The result, `<id>.signed.json`, cannot be
   produced without the wallet's keys.
3. `request_send` broadcasts only a signed transaction that is exactly
   the draft plus signatures (`minibtc_wallet::draft::matches_draft`),
   with input values fetched from the node, and applies the per-request
   and per-day caps to the spend decoded from those bytes (outputs that
   are not change, plus fee). Change means an output paying one of the
   wallet's own scripts from `<wallet>.watch.json`; the draft's
   `change_index` and the approval's `change_outputs` are display-only,
   because a process that can write the drafts directory could relabel
   them to dodge the caps.

**What the barrier is.** The barrier is the wallet passphrase, which
never enters the MCP process, the draft files or any environment the
agent controls. The terminal check is a guard against mistakes (a script
piping `sign` into the prompt), not a security boundary: any process can
allocate a pseudo-terminal and drive the prompt (the 2026-11-16 review did
it with Python's `pty`). Without the passphrase that gets it nowhere: a
wrong passphrase fails the keystore unlock and nothing is signed.

Honest limit: an agent that has a shell *and* the wallet passphrase (for
example exported in the same shell) can always run `minibtc-cli wallet
send` itself; no MCP gate can stop that. Keep the passphrase out of any
environment an agent can read. Every CLI passphrase prompt (and the
mnemonic prompt of `wallet restore`) reads with terminal echo off,
switched off before the prompt appears (`stty -echo`, restored on exit;
the read fails closed if echo cannot be disabled). Existing wallets need
one passphrase-unlocked command (e.g. `wallet balance`, or an unlock in the
wallet UI) to write their watch-only file. The file holds public data but
links every address to one wallet, so both the CLI and the wallet UI write
it owner-only (0600) via a temp file and an atomic rename.

## Open questions

- None blocking. Post-v1 candidates if revisited: SegWit/Taproot sighash
  types (D-007), DNS seed bootstrap (D-010), assumevalid-style headers
  sync shortcuts (not in blueprint scope).

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
*Corrected 2026-11-16 (D-019):* the flag is `--rpc <addr>` and the
credential is HTTP Basic from `.cookie`; until D-019 any address was bound
silently. A non-loopback `--rpc` now needs `--allow-remote-rpc` and is
logged.

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
switched off before the prompt appears (`stty -echo`; the read fails
closed if echo cannot be disabled). Echo is restored when the read ends
and also on Ctrl-C (a SIGINT handler registered at CLI startup turns it
back on, then exits with 130). Existing wallets need
one passphrase-unlocked command (e.g. `wallet balance`, or an unlock in the
wallet UI) to write their watch-only file. The file holds public data but
links every address to one wallet, so both the CLI and the wallet UI write
it owner-only (0600) via a temp file unique to each write and an atomic
rename. It is part of the trust base: the MCP gate counts an output as
change only if it pays a script listed there, so anything that can edit
files as the wallet's user can widen what counts as change and therefore
the spend caps. Such a process can equally broadcast an approved
`signed_hex` itself; the caps protect against the model, not against
same-user code.

### D-016 — What a failed reorg leaves behind (2026-11-16)

`Chain::reorg_to` validates the heavier branch block by block on one
UTXO overlay and commits only if the whole branch connects. When block
*k* fails:

- the node returns to its **old tip**, even if the valid prefix
  (blocks before *k*) has more work than the old tip. Bitcoin Core would
  stay on that prefix. MiniBTC can't reach that case today: blocks are
  processed one at a time and a reorg starts at the first branch block
  whose work exceeds the tip's, so every earlier prefix has at most the
  tip's work. Revisit if blocks are ever connected in batches (for
  example a parallel download that hands several blocks to
  `consider_block` at once).
- block *k* and all its descendants are dropped from the index, kept in
  a bounded invalid-hash cache and deleted from disk
  (`take_dropped` → `Store::delete_blocks`). The cache is forgotten on
  restart, which is safe because the blocks are gone from disk too.
- a side block whose branch never gets more work than the tip is never
  judged, so an invalid low-work side block stays in the index and on
  disk, during normal operation and after `--reindex` alike. That is by
  design (Bitcoin Core also stores side blocks it has not connected):
  judging every side block on arrival would let any peer make the node
  re-validate old forks for free. It is judged, and dropped if invalid,
  if its branch ever gets enough work to trigger a reorg.
- exception: a block that fails only "too far in the future"
  (`TimeTooNew`) is kept and nothing is marked invalid, because that
  verdict depends on the local clock (Core's `BLOCK_TIME_FUTURE` is
  never cached either). A later block on the branch retries the reorg.

### D-017 — Ban scope: by IP for public peers, by address for local ones (2026-11-16)

A peer whose score reaches the ban threshold is banned for an hour. For a
public address the ban covers the whole IP, as before: every connection
from it is dropped and new ones are refused. For a loopback, private
(RFC 1918, IPv6 unique-local) or link-local address it covers only that
exact IP and port. On a local devnet every node is 127.0.0.1 (or shares
one LAN prefix), so a per-IP ban for one misbehaving process used to cut
off every local peer for an hour.

Tradeoff, accepted: a local process that reconnects from a new port is
not refused by the ban (per-IP and per-subnet connection caps still
apply). Local addresses belong to the operator; the threat the ban
answers is a remote peer. The operator's `banpeer` RPC still bans a whole
IP, local or not.

### D-018 — Bans end the session; stalled block requests move on (2026-11-16)

Review round 4 found two gaps in the P2P layer:

1. **A ban did not close the connection** (F1). `PeerManager` removed the
   peer from the table and refused reconnects, but the session's reader
   kept decoding and handling everything the banned peer sent until it
   went quiet. Each session now registers a cancel token in the node; a
   ban by score, the operator's `banpeer` and the sweep's disconnects all
   cancel it, and the reader also stops after any message that leaves its
   peer unregistered. Live: the node now closes a header flooder's socket
   3.5 ms into the flood; before, it handled 16,299 messages over 20 s.
2. **A peer could withhold blocks for the whole request TTL** (F2). One
   that served real headers and no blocks held up to 2,048 requests — the
   lowest heights, so nothing connected — for 60 s with no penalty.
   `BlockRequests` now tracks, per peer, since when it has delivered
   nothing. Every 2 s the node withdraws the requests of peers past their
   stall window and asks other peers, scores the staller −25 (four stalls
   with no delivery in between reach the ban threshold), lets it hold
   only 128 requests and asks it only when no peer without strikes is
   connected. The window is 10 s, halved per consecutive stall, never
   below 2 s; a delivered block clears the strikes. Live, 3,000 blocks
   behind a withholder: first block at +9 s and done at +38 s (honest-only
   30 s), against +87 s and +111 s before (honest-only 40 s).

Tradeoff, accepted: an honest peer that cannot serve a requested block
(MiniBTC has no `notfound`) is scored −25 once per stall window and
bypassed; three good blocks (+10 each) more than cancel one stall.
Bitcoin Core also disconnects a peer that stalls its download window
after a short, adaptive timeout; MiniBTC's 10 s start is generous for
devnet block sizes on loopback and LAN links.

### D-019 — Local web surfaces: loopback unless opted in, bounded serving (2026-11-16)

The node RPC (a full-privilege credential), the explorer and the wallet
UI (unlocked keys) are local services. From this decision:

- **Binds.** A non-loopback `--rpc` (node) or `--listen` (wallet UI) is
  refused at startup, before the datadir is touched, unless
  `--allow-remote-rpc` / `--allow-remote` is given; with the flag the bind
  is logged as a warning. The explorer (read-only chain data) keeps its
  address as given.
- **Connections.** All three serve through `minibtc_rpc::http::serve_bounded`:
  at most 64 open connections (more are closed on accept) and a 10 s
  header-read deadline that also closes idle kept-alive sockets.
  `axum::serve` sets no timer, so hyper's default header timeout never
  applied and idle sockets were held forever.
- **Bodies.** The RPC checks credentials from the headers before reading
  any body byte (it used to buffer up to 8 MiB first), caps bodies at
  8 MiB (413) and gives an authenticated body 30 s (408). RPC handlers
  have no deadline: `generatetoaddress` may run for minutes (the client's
  mining timeout is 300 s). Explorer and wallet UI requests are answered
  503 after 45 s; wallet UI form bodies are capped at 64 KiB.
- **Wallet UI responses** carry `Content-Security-Policy: default-src
  'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors
  'none'; base-uri 'none'`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and
  `Cache-Control: no-store`, and a request whose `Host` is neither the
  bound address nor `localhost:<port>` gets 421 before any handler runs
  (DNS rebinding). Bound to an unspecified address with `--allow-remote`,
  any host on the right port is accepted. CSRF tokens are compared
  without an early exit.

The 64-connection cap is above the 50-connection `ab` runs recorded in
`docs/UI.md`; a load test with more concurrent connections will see
connections closed on accept, by design.

### D-020 — Secret files, MCP read-only mode, hosted CI (2026-11-16)

- **Owner-only from creation.** Keystores, `.cookie`, watch-only files,
  approved drafts and MCP drafts are written by
  `minibtc_wallet::owner_only::write_owner_only`: a fresh `O_EXCL` temp
  file created `0600`, the mode set again on the open handle (an error is
  fatal), fsync, rename over the target. A symlink planted at the target
  is replaced, never followed. The keystore used to be written with the
  umask's mode and chmodded afterwards by callers that ignored a failure;
  the node wrote `.cookie` the same way.
- **MCP `--read-only`** lists and runs only the read and explain tools;
  `draft_payment`, `request_send` and `mine_blocks` are refused before
  any argument is read or the node is called. `get_peers` returns each
  peer's user agent as `subver_untrusted`, control characters replaced,
  under a note that labels it untrusted.
- **CI.** `.github/workflows/ci.yml` runs `scripts/check.sh` on
  ubuntu-latest for every push and pull request with cargo-deny required
  (`MINIBTC_REQUIRE_DENY=1`), and checks advisories for the workspace and
  the fuzz lockfile daily. Actions are pinned to commit SHAs and kept
  current by Dependabot (weekly, grouped; cargo and github-actions);
  `scripts/check-workflows.sh` enforces pinning, a read-only token, no
  `pull_request_target`, no expression inside `run:` and no persisted
  checkout credentials. CI uses cargo-deny 0.20.2 (the newest release at
  least two weeks old); the maintainer's machine ran 0.21.0.

### D-021 — Push-only scriptSigs: mempool policy, not consensus (2026-11-16)

A scriptSig is not covered by its own signature, so anyone relaying a
payment can append a no-op (`OP_NOP`) to it: the spend still verifies
and the txid changes (third-party malleability; a wallet tracking the
original txid then sees it "disappear"). The mempool now refuses any
transaction with a scriptSig that is not push-only
(`minibtc_script::is_push_only`, Bitcoin Core's `IsPushOnly`) as
non-standard: no admission, no relay, no peer penalty. Consensus is
unchanged: such a transaction is still valid in a block, as in Bitcoin
for non-P2SH spends, so no datadir needs a reindex and `RULES_VERSION`
stays as it is. A miner that bypasses its own mempool could still
include one; making the rule consensus would be a soft fork with a
rules-version bump, left for a later decision.

### D-022 — Ask only announcers; `notfound`; never ban the best peer (2026-11-16)

D-018's stall scoring could be turned against honest peers. An attacker
announced headers with valid (cheap, devnet) proof of work and no blocks
behind them, and withheld; the victim then asked its honest peers for
those blocks, they stayed silent (there was no `notfound`), and each
silence was scored as withholding. Reconnecting from a new port reset the
attacker's own strikes (D-017 bans local peers by address), and the
honest peer was banned within minutes, leaving the victim with no peers.
Now:

- **Announcers.** The header index remembers every peer that announced
  an indexed header (sent it in `headers`, or named the block in an
  `inv`), up to 8 besides its source; a header passes to its next
  announcer when its source leaves. A missing block is asked only of
  peers that announced it, and a stall counts against a peer only for
  blocks it announced.
- **`notfound`.** A peer asked for blocks or transactions it lacks
  answers `notfound`; the requester withdraws those requests without a
  strike, stops counting that peer as an announcer (a header nobody
  announces any more is dropped) and asks the next announcer at once.
- **Protection.** The peer that delivered the most connected blocks,
  an outbound peer before any inbound one, is never scored for stalls:
  its requests still move elsewhere, but a node cannot be talked into
  banning the peer that actually serves it the chain. Invalid data still
  bans it.

D-017's trade-off with this attack, accepted: a local attacker still
sheds its score and strikes by reconnecting from a new port. That now
buys it only delays on blocks it alone announced (phantoms nobody else
has, so nothing the honest chain needs) and, for real blocks other peers
also announced, one stall window per reconnect before they are fetched
elsewhere; the fifth review measured that trickling evasion at 19 s
against 17 s for a 2,000-block sync.

## Open questions

- None blocking. Post-v1 candidates if revisited: SegWit/Taproot sighash
  types (D-007), DNS seed bootstrap (D-010), assumevalid-style headers
  sync shortcuts (not in blueprint scope).

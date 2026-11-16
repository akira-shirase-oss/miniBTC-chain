//! # minibtc-chainstate
//!
//! The chain's live state: the UTXO set, the block index, and the
//! connect/disconnect machinery that makes reorgs *exact*. Invariants:
//!
//! - The UTXO set always equals "genesis → tip" applied in order.
//! - Every connected block stores enough [`UndoData`] to be disconnected
//!   perfectly — spent outpoints restored, created outpoints removed.
//! - The active tip is always the chain with the most cumulative work;
//!   ties break toward the earlier-seen tip (Bitcoin's behavior).
//! - Coinbase outputs are unspendable until `params.coinbase_maturity`
//!   confirmations deep — checked at *connect* time, not mempool time.
//! - Applying a block is atomic: transactions are applied to a
//!   [`UtxoOverlay`] and the base set changes only when every transaction
//!   succeeded. A block rejected half-way leaves no trace.
//!
//! This crate owns memory state; `minibtc-storage` persists it. Both must
//! agree — the consistency test replays blocks into a fresh chain and
//! compares UTXO sets hash-for-hash.

use minibtc_consensus::{
    BlockContext, BlockError, ChainParams, UtxoView, is_retarget_height, next_bits_for_period,
    validate_block_in_context,
};
use minibtc_crypto::Hash256;
use minibtc_primitives::{Block, OutPoint, Transaction, TxOutput};
use std::collections::HashMap;

/// A UTXO entry: the output plus the context maturity/rules need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoEntry {
    /// The output itself (value + locking script).
    pub output: TxOutput,
    /// Block height that created it (for coinbase maturity).
    pub height: u32,
    /// Whether it came from a coinbase tx (maturity rules apply).
    pub coinbase: bool,
}

/// The UTXO set — `OutPoint → entry`. The heart of the ledger.
#[derive(Debug, Default)]
pub struct UtxoSet {
    map: HashMap<OutPoint, UtxoEntry>,
}

/// Read access to full UTXO entries (output + height + coinbase flag) —
/// what connect-time rules such as coinbase maturity need. Implemented by
/// the base [`UtxoSet`] and by every [`UtxoOverlay`] stacked on it.
pub trait CoinView {
    /// The unspent entry at `op`, if any.
    fn coin(&self, op: &OutPoint) -> Option<&UtxoEntry>;
}

impl CoinView for UtxoSet {
    fn coin(&self, op: &OutPoint) -> Option<&UtxoEntry> {
        self.map.get(op)
    }
}

/// A batch of UTXO changes produced by an overlay: `Some` = the outpoint
/// is (now) unspent with this entry, `None` = it is spent/removed.
#[derive(Debug, Default)]
pub struct UtxoChanges(HashMap<OutPoint, Option<UtxoEntry>>);

impl UtxoChanges {
    /// Number of touched outpoints.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether nothing was touched.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A scratch view over a [`CoinView`]: reads fall through to the base,
/// writes stay here. Blocks are applied to an overlay and the result is
/// committed with [`UtxoSet::commit`] only if the whole block applied —
/// so a failure at transaction *k* cannot leave transactions `0..k`
/// applied. Overlays stack (a block overlay over a reorg overlay).
#[derive(Debug)]
pub struct UtxoOverlay<'a, B: CoinView + ?Sized = UtxoSet> {
    base: &'a B,
    changes: HashMap<OutPoint, Option<UtxoEntry>>,
}

impl<B: CoinView + ?Sized> CoinView for UtxoOverlay<'_, B> {
    fn coin(&self, op: &OutPoint) -> Option<&UtxoEntry> {
        match self.changes.get(op) {
            Some(change) => change.as_ref(),
            None => self.base.coin(op),
        }
    }
}

impl<B: CoinView + ?Sized> UtxoView for UtxoOverlay<'_, B> {
    fn get(&self, op: &OutPoint) -> Option<TxOutput> {
        self.coin(op).map(|e| e.output.clone())
    }
}

impl<'a, B: CoinView + ?Sized> UtxoOverlay<'a, B> {
    /// An empty overlay over `base`.
    pub fn new(base: &'a B) -> Self {
        Self {
            base,
            changes: HashMap::new(),
        }
    }

    /// Spend `op`: returns the entry it held, or `MissingPrevout`.
    fn spend(&mut self, op: OutPoint) -> Result<UtxoEntry, ChainError> {
        let entry = self
            .coin(&op)
            .cloned()
            .ok_or(ChainError::MissingPrevout(op))?;
        self.changes.insert(op, None);
        Ok(entry)
    }

    /// Make `op` unspent with `entry` (create, or restore during undo).
    fn put(&mut self, op: OutPoint, entry: UtxoEntry) {
        self.changes.insert(op, Some(entry));
    }

    /// Remove `op` unconditionally (undo of a created output).
    fn erase(&mut self, op: OutPoint) {
        self.changes.insert(op, None);
    }

    /// Layer a child overlay's changes on top of this one.
    pub fn absorb(&mut self, changes: UtxoChanges) {
        self.changes.extend(changes.0);
    }

    /// The accumulated changes, to commit or drop.
    pub fn into_changes(self) -> UtxoChanges {
        UtxoChanges(self.changes)
    }

    /// Apply one transaction at `height`; returns its undo record. All
    /// inputs must exist (in the overlay or the base).
    pub fn apply_tx(
        &mut self,
        tx: &Transaction,
        txid: Hash256,
        height: u32,
        is_coinbase: bool,
    ) -> Result<UndoTx, ChainError> {
        let mut undo = UndoTx::default();
        if !is_coinbase {
            for inp in &tx.inputs {
                let entry = self.spend(inp.prev)?;
                undo.spent.push((inp.prev, entry));
            }
        }
        for (vout, out) in tx.outputs.iter().enumerate() {
            let op = OutPoint {
                txid,
                vout: vout as u32,
            };
            // BIP30 backstop: never overwrite an unspent coin (consensus
            // rejects this first; the set must not depend on that).
            if self.coin(&op).is_some() {
                return Err(ChainError::OutputExists(op));
            }
            self.put(
                op,
                UtxoEntry {
                    output: out.clone(),
                    height,
                    coinbase: is_coinbase,
                },
            );
            undo.created.push(op);
        }
        Ok(undo)
    }

    /// Reverse one transaction's application (exact, via its undo record).
    pub fn undo_tx(&mut self, undo: &UndoTx) {
        for op in &undo.created {
            self.erase(*op);
        }
        for (op, entry) in undo.spent.iter().rev() {
            self.put(*op, entry.clone());
        }
    }

    /// Apply every transaction of `block` at `height`, enforcing coinbase
    /// maturity against this view (so a coinbase created earlier in the
    /// same block is immature too). On error the overlay must be dropped:
    /// it may hold the effects of the transactions before the failure.
    pub fn apply_block(
        &mut self,
        block: &Block,
        height: u32,
        coinbase_maturity: u32,
    ) -> Result<UndoData, ChainError> {
        let mut undo = UndoData::default();
        for (i, tx) in block.txs.iter().enumerate() {
            let is_cb = i == 0;
            if !is_cb {
                self.check_maturity(tx, height, coinbase_maturity)?;
            }
            let u = self.apply_tx(tx, tx.txid(), height, is_cb)?;
            undo.txs.push(u);
        }
        Ok(undo)
    }

    /// Enforce coinbase maturity for every input of `tx` spent at
    /// `spend_height`. Missing prevouts are left to `apply_tx`.
    fn check_maturity(
        &self,
        tx: &Transaction,
        spend_height: u32,
        maturity: u32,
    ) -> Result<(), ChainError> {
        for inp in &tx.inputs {
            if let Some(entry) = self.coin(&inp.prev)
                && entry.coinbase
            {
                let depth = spend_height.saturating_sub(entry.height);
                if depth < maturity {
                    return Err(ChainError::ImmatureCoinbase { depth, maturity });
                }
            }
        }
        Ok(())
    }
}

/// What applying one transaction did — the unit of undo data.
#[derive(Clone, Debug, Default)]
pub struct UndoTx {
    /// Outpoints this tx spent, with their prior entries (to restore).
    pub spent: Vec<(OutPoint, UtxoEntry)>,
    /// Outpoints this tx created (to delete on disconnect).
    pub created: Vec<OutPoint>,
}

/// Undo data for a whole block — one [`UndoTx`] per transaction, in order.
#[derive(Clone, Debug, Default)]
pub struct UndoData {
    /// Per-transaction undo records.
    pub txs: Vec<UndoTx>,
}

impl UtxoSet {
    /// Look up an outpoint (unspent only — spent ones are removed).
    pub fn get(&self, op: &OutPoint) -> Option<&UtxoEntry> {
        self.map.get(op)
    }

    /// Number of UTXOs — for stats/tests.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// All entries (for wallet scanning / consistency hashing).
    pub fn iter(&self) -> impl Iterator<Item = (&OutPoint, &UtxoEntry)> {
        self.map.iter()
    }

    /// Insert an entry directly — used by storage load paths (the
    /// in-memory apply path stays `apply_tx`).
    pub fn insert(&mut self, op: OutPoint, entry: UtxoEntry) {
        self.map.insert(op, entry);
    }

    /// Remove an entry — used by storage/replay paths.
    pub fn remove(&mut self, op: &OutPoint) -> Option<UtxoEntry> {
        self.map.remove(op)
    }

    /// Deterministic fingerprint of the whole set — sorted serialization
    /// hashed. Used by the "reorg == fresh replay" consistency proof.
    pub fn fingerprint(&self) -> Hash256 {
        let mut items: Vec<(OutPoint, UtxoEntry)> =
            self.map.iter().map(|(k, v)| (*k, v.clone())).collect();
        items.sort_by_key(|(op, _)| (op.txid, op.vout));
        let mut w = minibtc_primitives::Writer::new();
        for (op, e) in items {
            w.hash256(&op.txid);
            w.u32(op.vout);
            w.u64(e.output.value.sats());
            w.prefixed_bytes(&e.output.script_pubkey);
            w.u32(e.height);
            w.u8(u8::from(e.coinbase));
        }
        minibtc_crypto::double_sha256(w.as_slice())
    }

    /// Apply one transaction at `height`; returns its undo record.
    /// `is_coinbase` marks the tx (its inputs are not spent — coinbase
    /// creates outputs from nothing).
    ///
    /// Atomic and panic-free: on `Err` (a missing prevout, which
    /// validation should have caught — defense in depth) the set is
    /// unchanged.
    pub fn apply_tx(
        &mut self,
        tx: &Transaction,
        txid: Hash256,
        height: u32,
        is_coinbase: bool,
    ) -> Result<UndoTx, ChainError> {
        let mut overlay = UtxoOverlay::new(&*self);
        let undo = overlay.apply_tx(tx, txid, height, is_coinbase)?;
        let changes = overlay.into_changes();
        self.commit(changes);
        Ok(undo)
    }

    /// Reverse one transaction's application.
    pub fn undo_tx(&mut self, undo: &UndoTx) {
        for op in &undo.created {
            self.map.remove(op);
        }
        for (op, entry) in undo.spent.iter().rev() {
            self.map.insert(*op, entry.clone());
        }
    }

    /// Write an overlay's changes into the set. Only called once the
    /// whole block (or reorg) the overlay holds has succeeded.
    pub fn commit(&mut self, changes: UtxoChanges) {
        for (op, change) in changes.0 {
            match change {
                Some(entry) => {
                    self.map.insert(op, entry);
                }
                None => {
                    self.map.remove(&op);
                }
            }
        }
    }
}

impl UtxoView for UtxoSet {
    fn get(&self, op: &OutPoint) -> Option<TxOutput> {
        self.map.get(op).map(|e| e.output.clone())
    }
}

/// Status of a block in the index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockStatus {
    /// On the active chain (tip's branch).
    Active,
    /// A valid side branch with less cumulative work.
    Inactive,
}

/// A block in the index — header for cheap access, full block for reorg.
#[derive(Clone, Debug)]
pub struct IndexedBlock {
    /// The full block (kept in memory; storage persists it separately).
    pub block: Block,
    /// Its height (genesis = 0).
    pub height: u32,
    /// Cumulative work from genesis to this block.
    pub cum_work: u128,
    /// Active or side-branch.
    pub status: BlockStatus,
}

/// Errors from chain operations.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// Block validation failed.
    #[error("block invalid: {0}")]
    InvalidBlock(#[from] BlockError),
    /// The block's prev_hash is unknown — we can't connect it yet.
    #[error("unknown prev block {0}")]
    UnknownPrev(Hash256),
    /// Applying a tx hit a missing prevout (should be caught by validation).
    #[error("missing prevout {0} during connect")]
    MissingPrevout(OutPoint),
    /// A transaction would overwrite an unspent output (BIP30).
    #[error("output {0} already exists unspent")]
    OutputExists(OutPoint),
    /// Tried to disconnect a non-tip block.
    #[error("can only disconnect the tip")]
    NotTip,
    /// A coinbase output was spent before maturity.
    #[error("coinbase spent at depth {depth} < maturity {maturity}")]
    ImmatureCoinbase {
        /// Actual depth at spend time.
        depth: u32,
        /// Required depth.
        maturity: u32,
    },
}

/// The chain: params + block index + UTXO set + tip.
#[derive(Debug)]
pub struct Chain {
    /// Consensus parameters.
    pub params: ChainParams,
    /// All known blocks by hash.
    pub blocks: HashMap<Hash256, IndexedBlock>,
    /// The UTXO set for the *active* chain.
    pub utxos: UtxoSet,
    /// Tip block hash.
    pub tip: Hash256,
    /// Genesis block hash (convenience).
    pub genesis: Hash256,
    /// Undo data per connected block — required for exact disconnects.
    pub undos: HashMap<Hash256, UndoData>,
}

impl Chain {
    /// Create a chain and connect the genesis block.
    pub fn new(params: ChainParams, genesis: Block) -> Result<Self, ChainError> {
        let genesis_hash = genesis.header.block_hash();
        let work = work_of(&genesis.header)?;
        let mut chain = Self {
            params,
            blocks: HashMap::new(),
            utxos: UtxoSet::default(),
            tip: genesis_hash,
            genesis: genesis_hash,
            undos: HashMap::new(),
        };
        // Genesis connects unconditionally: no prev to check, no PoW to
        // verify (it is definitionally valid), coinbase matures normally.
        let undo = chain.apply_block_at(&genesis, 0)?;
        chain.blocks.insert(
            genesis_hash,
            IndexedBlock {
                block: genesis,
                height: 0,
                cum_work: work,
                status: BlockStatus::Active,
            },
        );
        chain.undos.insert(genesis_hash, undo);
        Ok(chain)
    }

    /// Work contributed by a header's bits.
    fn header_work(&self, h: &minibtc_primitives::BlockHeader) -> Result<u128, ChainError> {
        minibtc_consensus::pow::work_units(h.bits)
            .map_err(|e| ChainError::InvalidBlock(BlockError::Pow(e)))
    }

    /// Connect `block` as the new tip — caller guarantees it builds on
    /// current tip and is fully validated. Applies UTXOs, stores undo.
    pub fn connect_tip(&mut self, block: Block) -> Result<(), ChainError> {
        let hash = block.header.block_hash();
        let parent = self
            .blocks
            .get(&block.header.prev_hash)
            .ok_or(ChainError::UnknownPrev(block.header.prev_hash))?;
        let height = parent.height.saturating_add(1);
        let work = self.header_work(&block.header)?;
        let cum_work = parent.cum_work.saturating_add(work);

        // Validate against current UTXO set, in the parent's context.
        let ctx = self.context_for(block.header.prev_hash)?;
        validate_block_in_context(&block, &self.utxos, &self.params, &ctx)?;

        let undo = self.apply_block_at(&block, height)?;
        self.blocks.insert(
            hash,
            IndexedBlock {
                block: block.clone(),
                height,
                cum_work,
                status: BlockStatus::Active,
            },
        );
        self.undos.insert(hash, undo);
        self.tip = hash;
        Ok(())
    }

    /// Apply block txs at an explicit height (used by connect_tip and
    /// reorg paths where height is already known). Atomic: the block is
    /// applied to an overlay and committed only if every tx applied, so
    /// an error leaves `self.utxos` exactly as it was.
    fn apply_block_at(&mut self, block: &Block, height: u32) -> Result<UndoData, ChainError> {
        let mut overlay = UtxoOverlay::new(&self.utxos);
        let undo = overlay.apply_block(block, height, self.params.coinbase_maturity)?;
        let changes = overlay.into_changes();
        self.utxos.commit(changes);
        Ok(undo)
    }

    /// Disconnect the current tip — restores UTXOs exactly.
    pub fn disconnect_tip(&mut self) -> Result<(), ChainError> {
        let tip_hash = self.tip;
        let rec = self
            .blocks
            .get(&tip_hash)
            .ok_or(ChainError::NotTip)?
            .clone();
        let undo = self.undos.remove(&tip_hash).ok_or(ChainError::NotTip)?;
        // Reverse txs in reverse order.
        for u in undo.txs.iter().rev() {
            self.utxos.undo_tx(u);
        }
        // Parent becomes tip.
        let parent_hash = rec.block.header.prev_hash;
        self.tip = parent_hash;
        if let Some(p) = self.blocks.get_mut(&parent_hash) {
            p.status = BlockStatus::Active;
        }
        // Mark disconnected block inactive.
        if let Some(b) = self.blocks.get_mut(&tip_hash) {
            b.status = BlockStatus::Inactive;
        }
        Ok(())
    }

    /// Consider a block that may or may not extend the tip — the reorg
    /// entry point. Validates, then either connects it (tip extension) or
    /// evaluates whether its branch has more work (reorg).
    pub fn consider_block(&mut self, block: Block) -> Result<(), ChainError> {
        let hash = block.header.block_hash();
        if self.blocks.contains_key(&hash) {
            return Ok(()); // already known
        }
        let parent_hash = block.header.prev_hash;
        let parent = self
            .blocks
            .get(&parent_hash)
            .ok_or(ChainError::UnknownPrev(parent_hash))?;
        let height = parent.height.saturating_add(1);
        let work = self.header_work(&block.header)?;
        let cum_work = parent.cum_work.saturating_add(work);

        // Full validation against the UTXO set *as of the parent* — for
        // side branches this is subtle: our utxos reflect the active tip,
        // not the parent. For MiniBTC devnet we validate side-branch txs
        // against the active set as an approximation and rely on connect
        // order during reorg for exactness — documented limitation; the
        // reorg path re-validates each block at connect time anyway via
        // apply (missing prevouts error there).
        let ctx = self.context_for(parent_hash)?;
        validate_block_in_context(&block, &self.utxos, &self.params, &ctx)?;

        if parent_hash == self.tip {
            // Direct extension.
            let undo = self.apply_block_at(&block, height)?;
            self.blocks.insert(
                hash,
                IndexedBlock {
                    block,
                    height,
                    cum_work,
                    status: BlockStatus::Active,
                },
            );
            self.undos.insert(hash, undo);
            self.tip = hash;
            return Ok(());
        }

        // Side branch: store it; reorg only if it beats the tip's work.
        self.blocks.insert(
            hash,
            IndexedBlock {
                block,
                height,
                cum_work,
                status: BlockStatus::Inactive,
            },
        );
        self.maybe_reorg(hash)
    }

    /// If `candidate`'s branch has more cumulative work than the tip,
    /// reorg: disconnect tip back to the fork point, connect the other
    /// branch forward. UTXOs end up exactly equal to fresh replay.
    fn maybe_reorg(&mut self, candidate: Hash256) -> Result<(), ChainError> {
        // Walk candidate back to find fork point with active chain.
        let tip_work = self.blocks.get(&self.tip).map(|r| r.cum_work).unwrap_or(0);
        let cand_work = self.blocks.get(&candidate).map(|r| r.cum_work).unwrap_or(0);
        if cand_work <= tip_work {
            return Ok(()); // no reorg — candidate stays inactive
        }
        // Find fork point: walk both back until common ancestor.
        let fork = self.find_fork(candidate)?;
        let fork_height = self.blocks.get(&fork).map(|r| r.height).unwrap_or(0);

        // Disconnect active tip down to fork.
        while self.tip != fork {
            self.disconnect_tip()?;
        }
        // Connect candidate's branch from fork forward.
        let mut branch: Vec<Hash256> = Vec::new();
        let mut cur = candidate;
        loop {
            branch.push(cur);
            let rec = self.blocks.get(&cur).ok_or(ChainError::NotTip)?;
            if rec.block.header.prev_hash == fork {
                break;
            }
            cur = rec.block.header.prev_hash;
            if branch.len() > 100_000 {
                return Err(ChainError::NotTip); // absurd depth guard
            }
        }
        branch.reverse();
        for h in branch {
            let blk = self
                .blocks
                .get(&h)
                .map(|r| r.block.clone())
                .ok_or(ChainError::NotTip)?;
            self.connect_tip(blk)?;
        }
        let _ = fork_height;
        Ok(())
    }

    /// Find the last common ancestor of `candidate` and the active tip.
    fn find_fork(&self, candidate: Hash256) -> Result<Hash256, ChainError> {
        // Mark active-chain hashes in a set (active branch only).
        let mut active_ancestors = std::collections::HashSet::new();
        let mut cur = self.tip;
        loop {
            active_ancestors.insert(cur);
            let rec = self.blocks.get(&cur).ok_or(ChainError::NotTip)?;
            if rec.block.header.prev_hash == cur {
                break; // genesis self-check
            }
            let prev = rec.block.header.prev_hash;
            if prev == self.genesis || !self.blocks.contains_key(&prev) {
                active_ancestors.insert(prev);
                break;
            }
            cur = prev;
        }
        // Walk candidate back until hitting an active ancestor.
        let mut cur = candidate;
        loop {
            if active_ancestors.contains(&cur) {
                return Ok(cur);
            }
            let rec = self.blocks.get(&cur).ok_or(ChainError::NotTip)?;
            let prev = rec.block.header.prev_hash;
            if prev == cur || !self.blocks.contains_key(&prev) {
                return Err(ChainError::NotTip);
            }
            cur = prev;
        }
    }

    /// Adjusted time: median of last 11 block times + local clock offset.
    /// For the in-memory chain we use wall clock via `std::time` — this is
    /// the ONE place chainstate touches a clock, isolated for tests.
    fn adjusted_time(&self) -> u32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        // Median-time-past adjustment (simplified: no peer offsets yet —
        // p2p layer will feed offsets later).
        now
    }

    /// The context a block whose parent is `parent` is validated in —
    /// height, required bits, median-time-past, all from the parent's own
    /// ancestry (never the active tip's).
    pub fn context_for(&self, parent: Hash256) -> Result<BlockContext, ChainError> {
        let rec = self
            .blocks
            .get(&parent)
            .ok_or(ChainError::UnknownPrev(parent))?;
        Ok(BlockContext {
            height: u64::from(rec.height) + 1,
            expected_bits: self.next_bits_after(parent)?,
            median_time_past: self.median_time_past_at(parent).unwrap_or(0),
            adjusted_time: self.adjusted_time(),
        })
    }

    /// The compact bits a block built on `parent` must carry — Bitcoin
    /// Core's `GetNextWorkRequired`: the parent's bits, except at a period
    /// boundary, where the target is rescaled by how long the period took
    /// (parent time − time of the period's first block). The miner and
    /// validation both use this, so they can never disagree.
    pub fn next_bits_after(&self, parent: Hash256) -> Result<u32, ChainError> {
        let rec = self
            .blocks
            .get(&parent)
            .ok_or(ChainError::UnknownPrev(parent))?;
        let height = u64::from(rec.height) + 1;
        if !is_retarget_height(&self.params, height) {
            return Ok(rec.block.header.bits);
        }
        // First block of the period: interval − 1 blocks before the parent.
        let first_height = rec
            .height
            .saturating_add(1)
            .saturating_sub(self.params.pow_target_timespan_blocks);
        let first = self
            .ancestor_at(parent, first_height)
            .ok_or(ChainError::UnknownPrev(parent))?;
        let span = u64::from(
            rec.block
                .header
                .time
                .saturating_sub(first.block.header.time),
        );
        next_bits_for_period(&self.params, rec.block.header.bits, span)
            .map_err(|e| ChainError::InvalidBlock(BlockError::Pow(e)))
    }

    /// The ancestor of `from` (inclusive) at `height`, walking the index.
    pub fn ancestor_at(&self, from: Hash256, height: u32) -> Option<&IndexedBlock> {
        let mut cur = self.blocks.get(&from)?;
        while cur.height > height {
            cur = self.blocks.get(&cur.block.header.prev_hash)?;
        }
        (cur.height == height).then_some(cur)
    }

    /// Median of up to `median_time_span` past block times (newest first)
    /// at the tip. Public so the miner/RPC can compute candidate timestamps.
    pub fn median_time_past(&self) -> Option<u32> {
        self.median_time_past_at(self.tip)
    }

    /// Median time of `from` and its ancestors (up to `median_time_span`).
    pub fn median_time_past_at(&self, from: Hash256) -> Option<u32> {
        let mut times: Vec<u32> = Vec::with_capacity(self.params.median_time_span);
        let mut cur = from;
        loop {
            let rec = self.blocks.get(&cur)?;
            times.push(rec.block.header.time);
            if times.len() >= self.params.median_time_span {
                break;
            }
            let prev = rec.block.header.prev_hash;
            if prev == cur || !self.blocks.contains_key(&prev) {
                break;
            }
            cur = prev;
        }
        minibtc_consensus::median_time_past(&times, self.params.median_time_span)
    }

    /// Height of the tip.
    pub fn height(&self) -> u32 {
        self.blocks.get(&self.tip).map(|r| r.height).unwrap_or(0)
    }

    /// Cumulative work of the tip.
    pub fn tip_work(&self) -> u128 {
        self.blocks.get(&self.tip).map(|r| r.cum_work).unwrap_or(0)
    }
}

fn work_of(h: &minibtc_primitives::BlockHeader) -> Result<u128, ChainError> {
    minibtc_consensus::pow::work_units(h.bits)
        .map_err(|e| ChainError::InvalidBlock(BlockError::Pow(e)))
}

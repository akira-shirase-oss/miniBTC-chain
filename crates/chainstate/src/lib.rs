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
//!
//! This crate owns memory state; `minibtc-storage` persists it. Both must
//! agree — the consistency test replays blocks into a fresh chain and
//! compares UTXO sets hash-for-hash.

use minibtc_consensus::{BlockError, ChainParams, UtxoView, validate_block_with_time};
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
    /// Panics-free: returns `Err` on any inconsistency — callers treat
    /// that as "this block is invalid", which validation should have
    /// caught earlier (defense in depth).
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
                let entry = self
                    .map
                    .remove(&inp.prev)
                    .ok_or(ChainError::MissingPrevout(inp.prev))?;
                undo.spent.push((inp.prev, entry));
            }
        }
        for (vout, out) in tx.outputs.iter().enumerate() {
            let op = OutPoint {
                txid,
                vout: vout as u32,
            };
            self.map.insert(
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

    /// Reverse one transaction's application.
    pub fn undo_tx(&mut self, _tx: &Transaction, txid: Hash256, undo: &UndoTx) {
        for op in &undo.created {
            self.map.remove(op);
        }
        let _ = txid;
        for (op, entry) in undo.spent.iter().rev() {
            self.map.insert(*op, entry.clone());
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

    /// Enforce coinbase maturity for every input of `tx`.
    fn check_maturity(&self, tx: &Transaction, spend_height: u32) -> Result<(), ChainError> {
        for inp in &tx.inputs {
            if let Some(entry) = self.utxos.get(&inp.prev)
                && entry.coinbase
            {
                let depth = spend_height.saturating_sub(entry.height);
                if depth < self.params.coinbase_maturity {
                    return Err(ChainError::ImmatureCoinbase {
                        depth,
                        maturity: self.params.coinbase_maturity,
                    });
                }
            }
            // Missing prevouts are validation's job; here we only check
            // maturity for entries that exist.
        }
        Ok(())
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

        // Validate against current UTXO set (blockval needs a view).
        let adjusted = Some(self.adjusted_time());
        let mtp = self.median_time_past();
        validate_block_with_time(
            &block,
            &self.utxos,
            &self.params,
            u64::from(height),
            adjusted,
            mtp,
        )?;

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
    /// reorg paths where height is already known).
    fn apply_block_at(&mut self, block: &Block, height: u32) -> Result<UndoData, ChainError> {
        let mut undo = UndoData::default();
        for (i, tx) in block.txs.iter().enumerate() {
            let is_cb = i == 0;
            if !is_cb {
                self.check_maturity(tx, height)?;
            }
            let txid = tx.txid();
            let u = self.utxos.apply_tx(tx, txid, height, is_cb)?;
            undo.txs.push(u);
        }
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
        for (i, tx) in rec.block.txs.iter().enumerate().rev() {
            let txid = tx.txid();
            if let Some(u) = undo.txs.get(i) {
                self.utxos.undo_tx(tx, txid, u);
            }
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
        let adjusted = Some(self.adjusted_time());
        let mtp = self.median_time_past();
        validate_block_with_time(
            &block,
            &self.utxos,
            &self.params,
            u64::from(height),
            adjusted,
            mtp,
        )?;

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

    /// Median of up to `median_time_span` past block times (newest first).
    /// Public so the miner/RPC can compute candidate timestamps.
    pub fn median_time_past(&self) -> Option<u32> {
        let mut times: Vec<u32> = Vec::with_capacity(self.params.median_time_span);
        let mut cur = self.tip;
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

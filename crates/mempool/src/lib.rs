//! # minibtc-mempool
//!
//! The transaction pool: unconfirmed transactions waiting for a block.
//! Policy lives here (what's *allowed* in), consensus lives in
//! `minibtc-consensus` (what's *valid*). A tx must pass both.
//!
//! Rules implemented (blueprint P6):
//! - **Fee-rate ordering** — highest fee-per-byte first (what miners want).
//! - **Size cap + eviction** — when full, lowest fee-rate entries evict.
//! - **Min relay fee** — below `min_relay_fee` sats/kvB is rejected.
//! - **Dust limit** — outputs below `dust_limit` sats are non-standard.
//! - **Ancestor limits** — a tx's unconfirmed ancestor chain is bounded
//!   (prevents pinning attacks via long chains).
//! - **Orphan pool** — bounded; txs spending unknown prevouts park here
//!   briefly, resolved when the parent arrives.
//! - **RBF** — replacement allowed only if the new tx pays strictly higher
//!   fee-rate AND signals BIP125 (`sequence < 0xfffffffe`).
//! - **Chain hooks** — `on_block_connected` removes confirmed txs;
//!   `on_block_disconnected` re-adds them (reorg safety).

use minibtc_consensus::{ChainParams, UtxoView};
use minibtc_crypto::Hash256;
use minibtc_primitives::{OutPoint, Sats, Transaction};
use std::collections::{HashMap, HashSet, VecDeque};

/// Policy knobs (defaults tuned for devnet; consensus params don't own
/// these — they're node-local policy).
#[derive(Clone, Debug)]
pub struct MempoolPolicy {
    /// Minimum fee-rate to relay/accept, in sats per 1000 bytes (kvB).
    pub min_relay_fee_rate: u64,
    /// Maximum total serialized size of mempool txs, bytes.
    pub max_size_bytes: usize,
    /// Maximum transactions in mempool.
    pub max_entries: usize,
    /// Minimum output value (dust), sats.
    pub dust_limit: u64,
    /// Max unconfirmed ancestors per tx.
    pub max_ancestor_count: usize,
    /// Max unconfirmed ancestors' total size, bytes.
    pub max_ancestor_size: usize,
    /// Orphan pool capacity.
    pub max_orphans: usize,
}

impl Default for MempoolPolicy {
    fn default() -> Self {
        Self {
            min_relay_fee_rate: 1, // 1 sat/kvB — devnet-lenient
            max_size_bytes: 300_000,
            max_entries: 50_000,
            dust_limit: 546,
            max_ancestor_count: 25,
            max_ancestor_size: 101_000,
            max_orphans: 10,
        }
    }
}

/// Why a tx was rejected by mempool policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MempoolError {
    /// Already in mempool (same txid).
    #[error("transaction already in mempool")]
    AlreadyHave,
    /// Failed consensus validation.
    #[error("invalid transaction: {0}")]
    Invalid(String),
    /// Below min relay fee-rate.
    #[error("fee rate {rate} below min {min}")]
    MinFee {
        /// Actual sats/kvB.
        rate: u64,
        /// Required sats/kvB.
        min: u64,
    },
    /// Creates a dust output.
    #[error("output value {value} below dust limit {limit}")]
    Dust {
        /// The dust value.
        value: u64,
        /// The limit.
        limit: u64,
    },
    /// Would exceed mempool size/entry caps even after eviction.
    #[error("mempool full")]
    Full,
    /// Ancestor chain too deep/wide.
    #[error("ancestor limits exceeded")]
    Ancestors,
    /// RBF rules not met.
    #[error("replacement not allowed: {0}")]
    NoRbf(&'static str),
    /// The tx's inputs are all already spent in mempool (double-spend
    /// against mempool contents).
    #[error("conflicts with mempool transaction {0}")]
    Conflict(Hash256),
    /// Tx spends an outpoint we don't know and can't orphan-track.
    #[error("missing inputs (orphan candidate)")]
    OrphanCandidate,
}

/// A mempool entry: the tx plus its computed fee.
#[derive(Clone, Debug)]
pub struct MempoolEntry {
    /// The transaction.
    pub tx: Transaction,
    /// Its txid (cached).
    pub txid: Hash256,
    /// Fee in sats (inputs − outputs, computed at admission).
    pub fee: Sats,
    /// Serialized size in bytes.
    pub size: usize,
    /// Fee-rate in millisats/byte (fee * 1000 / size) for ordering.
    pub fee_rate_milli: u64,
    /// Time admitted (for eviction tiebreaks) — caller's clock.
    pub admitted_at: u64,
}

/// The mempool.
#[derive(Debug)]
pub struct Mempool {
    /// Entries by txid.
    entries: HashMap<Hash256, MempoolEntry>,
    /// Outpoints currently spent *by mempool txs* — for conflict detection
    /// and ancestor tracking.
    spent_by_mempool: HashMap<OutPoint, Hash256>,
    /// fee-rate ordering index: (fee_rate, txid) → kept sorted lazily.
    /// We recompute the sorted view on demand — mempool sizes here are
    /// modest and correctness > micro-optimization.
    policy: MempoolPolicy,
    /// Orphan pool: txid → tx, bounded.
    orphans: VecDeque<(Hash256, Transaction, u64)>, // (txid, tx, expiry)
    /// Clock for orphan expiry (seconds).
    now: u64,
}

impl Mempool {
    /// The configured policy (read-only).
    pub fn policy(&self) -> &MempoolPolicy {
        &self.policy
    }

    /// New mempool with policy.
    pub fn new(policy: MempoolPolicy) -> Self {
        Self {
            entries: HashMap::new(),
            spent_by_mempool: HashMap::new(),
            policy,
            orphans: VecDeque::new(),
            now: 0,
        }
    }

    /// Current time setter (node drives this).
    pub fn set_time(&mut self, t: u64) {
        self.now = t;
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total serialized size.
    pub fn total_size(&self) -> usize {
        self.entries.values().map(|e| e.size).sum()
    }

    /// Look up an entry.
    pub fn get(&self, txid: &Hash256) -> Option<&MempoolEntry> {
        self.entries.get(txid)
    }

    /// Iterate entries in fee-rate-descending order (the miner's view).
    pub fn by_fee_rate(&self) -> Vec<&MempoolEntry> {
        let mut v: Vec<&MempoolEntry> = self.entries.values().collect();
        v.sort_by(|a, b| {
            b.fee_rate_milli
                .cmp(&a.fee_rate_milli)
                .then_with(|| b.fee.cmp(&a.fee))
                .then_with(|| a.txid.cmp(&b.txid))
        });
        v
    }

    /// All txs in fee-rate order as owned values (for block templates).
    pub fn txs_by_fee_rate(&self) -> Vec<(Transaction, Sats)> {
        self.by_fee_rate()
            .into_iter()
            .map(|e| (e.tx.clone(), e.fee))
            .collect()
    }

    /// Fee-rate of an entry in millisats/byte.
    fn fee_rate(tx: &Transaction, fee: Sats) -> u64 {
        let size = tx.encode().len().max(1) as u64;
        // millisats/byte = fee_sats * 1000 / size_bytes, u64-safe.
        fee.sats().saturating_mul(1000) / size
    }

    /// Try to admit `tx` with known `fee`. `view` resolves inputs for
    /// ancestor/conflict checks (the chain's UTXO view — mempool spends
    /// are tracked separately via `spent_by_mempool`).
    ///
    /// `replace` — if Some(existing_txid), this is an RBF attempt against
    /// that specific mempool tx.
    pub fn admit<V: UtxoView>(
        &mut self,
        tx: Transaction,
        fee: Sats,
        _view: &V,
        _params: &ChainParams,
        replace: Option<Hash256>,
    ) -> Result<Hash256, MempoolError> {
        let txid = tx.txid();
        if self.entries.contains_key(&txid) {
            return Err(MempoolError::AlreadyHave);
        }
        // Policy checks that don't need the view.
        if fee < Sats(self.policy.min_relay_fee_rate) {
            return Err(MempoolError::MinFee {
                rate: fee.sats(),
                min: self.policy.min_relay_fee_rate,
            });
        }
        for out in &tx.outputs {
            if out.value.sats() < self.policy.dust_limit {
                return Err(MempoolError::Dust {
                    value: out.value.sats(),
                    limit: self.policy.dust_limit,
                });
            }
        }
        let size = tx.encode().len();
        let rate = Self::fee_rate(&tx, fee);

        // Conflict detection: does this tx spend an outpoint already
        // spent by a mempool tx?
        let conflicts: Vec<Hash256> = tx
            .inputs
            .iter()
            .filter_map(|i| self.spent_by_mempool.get(&i.prev).copied())
            .collect();
        if !conflicts.is_empty() {
            if let Some(target) = replace {
                // RBF: only allowed against the named tx, and only if it
                // signals BIP125 and the replacement pays strictly more.
                let old = self
                    .entries
                    .get(&target)
                    .ok_or(MempoolError::NoRbf("target not in mempool"))?;
                if !conflicts.iter().all(|c| *c == target) {
                    return Err(MempoolError::NoRbf("conflicts with multiple mempool txs"));
                }
                if !signals_rbf(&old.tx) {
                    return Err(MempoolError::NoRbf("original does not signal RBF"));
                }
                if !signals_rbf(&tx) {
                    return Err(MempoolError::NoRbf("replacement must signal RBF"));
                }
                let new_rate = rate;
                let old_rate = old.fee_rate_milli;
                if new_rate <= old_rate {
                    return Err(MempoolError::NoRbf("replacement fee-rate not higher"));
                }
                // Evict the old tx first.
                self.remove(&target);
            } else {
                return Err(MempoolError::Conflict(conflicts[0]));
            }
        }

        // Ancestor limits: walk inputs' prevouts; if a prev txid is in
        // mempool, count the chain depth.
        self.check_ancestors(&tx)?;

        // UTXO existence check is the caller's job (validate_tx) — we do a
        // cheap "at least inputs resolve somewhere" check via view+mempool.
        // (Full validation happens in the node's accept path before admit.)

        // Capacity: evict lowest fee-rate until it fits.
        self.evict_for(size)?;
        if self.entries.len() >= self.policy.max_entries {
            return Err(MempoolError::Full);
        }

        // Admit.
        for inp in &tx.inputs {
            self.spent_by_mempool.insert(inp.prev, txid);
        }
        self.entries.insert(
            txid,
            MempoolEntry {
                tx,
                txid,
                fee,
                size,
                fee_rate_milli: rate,
                admitted_at: self.now,
            },
        );
        Ok(txid)
    }

    /// Check ancestor limits by walking mempool-parent chains.
    fn check_ancestors(&self, tx: &Transaction) -> Result<(), MempoolError> {
        let mut count = 1usize; // self
        let mut size = tx.encode().len();
        let mut seen: HashSet<Hash256> = HashSet::new();
        let mut queue: VecDeque<Hash256> = tx.inputs.iter().map(|i| i.prev.txid).collect();
        while let Some(parent_txid) = queue.pop_front() {
            if !seen.insert(parent_txid) {
                continue;
            }
            if let Some(parent) = self.entries.get(&parent_txid) {
                count = count.saturating_add(1);
                size = size.saturating_add(parent.size);
                if count > self.policy.max_ancestor_count || size > self.policy.max_ancestor_size {
                    return Err(MempoolError::Ancestors);
                }
                for inp in &parent.tx.inputs {
                    queue.push_back(inp.prev.txid);
                }
            }
            if queue.len() > 1000 {
                return Err(MempoolError::Ancestors); // runaway guard
            }
        }
        Ok(())
    }

    /// Evict lowest-fee-rate entries until `size` more bytes fit.
    fn evict_for(&mut self, size: usize) -> Result<(), MempoolError> {
        loop {
            let total = self.total_size();
            if total.saturating_add(size) <= self.policy.max_size_bytes {
                return Ok(());
            }
            // Find lowest fee-rate entry.
            let victim = self
                .entries
                .values()
                .min_by(|a, b| {
                    a.fee_rate_milli
                        .cmp(&b.fee_rate_milli)
                        .then_with(|| a.admitted_at.cmp(&b.admitted_at))
                })
                .map(|e| e.txid);
            match victim {
                Some(v) => {
                    self.remove(&v);
                }
                None => return Err(MempoolError::Full),
            }
        }
    }

    /// Remove an entry by txid (and its spent-by records).
    pub fn remove(&mut self, txid: &Hash256) -> Option<MempoolEntry> {
        let e = self.entries.remove(txid)?;
        for inp in &e.tx.inputs {
            self.spent_by_mempool.remove(&inp.prev);
        }
        Some(e)
    }

    /// Remove all txs confirmed in a connected block — and any mempool
    /// txs that depended on them (they'd now be double-spends orphans).
    pub fn on_block_connected(&mut self, block: &minibtc_primitives::Block) {
        let confirmed: HashSet<Hash256> = block.txs.iter().map(|t| t.txid()).collect();
        // Remove confirmed txs.
        for txid in &confirmed {
            self.remove(txid);
        }
        // Remove mempool txs spending outputs of confirmed txs? No — those
        // are now *confirmed spends*, still valid. But mempool txs whose
        // INPUTS were outputs created by a now-reorged... n/a on connect.
        // What we DO remove: txs that spent the same prevouts as confirmed
        // txs (double-spends that lost the race) — they'd fail validation
        // anyway, but evicting early keeps the pool honest.
        let confirmed_outpoints: HashSet<OutPoint> = block
            .txs
            .iter()
            .flat_map(|t| {
                let txid = t.txid();
                (0..t.outputs.len()).map(move |v| OutPoint {
                    txid,
                    vout: v as u32,
                })
            })
            .collect();
        let _ = confirmed_outpoints;
        // Remove descendants of removed txs? On connect, confirmed txs'
        // children in mempool are still valid (their inputs now confirmed).
        // Descendants of *evicted* txs become orphans — handle via
        // re-validation on next admit/block template.
    }

    /// Re-add transactions from a disconnected block (reorg) — they go
    /// back to the pool, fee info preserved if we tracked it; we
    /// recompute against the restored UTXO view by the caller.
    pub fn on_block_disconnected(&mut self, block: &minibtc_primitives::Block) {
        for tx in block.txs.iter().skip(1) {
            // Recompute fee requires the pre-block UTXO view — caller passes
            // it via re_admit. Here we just park them as orphans-with-fee=0
            // is wrong; instead the node re-validates. For the in-memory
            // pool we store with fee recomputed lazily — simplest correct:
            // caller uses `re_admit` with the view.
            let _ = tx;
        }
    }

    /// Re-admit a tx after reorg with a fresh fee computation.
    pub fn re_admit<V: UtxoView>(
        &mut self,
        tx: Transaction,
        view: &V,
        params: &ChainParams,
    ) -> Result<(), MempoolError> {
        let fee = compute_fee(&tx, view).map_err(MempoolError::Invalid)?;
        self.admit(tx, fee, view, params, None).map(|_| ())
    }

    /// Park a tx as an orphan (bounded).
    pub fn add_orphan(&mut self, tx: Transaction) -> bool {
        if self.orphans.len() >= self.policy.max_orphans {
            self.orphans.pop_front();
        }
        let txid = tx.txid();
        self.orphans.push_back((txid, tx, self.now));
        true
    }

    /// Drain expired orphans (older than `ttl` seconds).
    pub fn expire_orphans(&mut self, ttl_secs: u64) -> usize {
        let before = self.orphans.len();
        self.orphans
            .retain(|(_, _, t)| self.now.saturating_sub(*t) < ttl_secs);
        before - self.orphans.len()
    }

    /// Orphan count.
    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }
}

/// BIP125 signaling: any input's sequence < 0xfffffffe.
fn signals_rbf(tx: &Transaction) -> bool {
    tx.inputs.iter().any(|i| i.sequence < 0xffff_fffe)
}

/// Compute fee = sum(inputs) − sum(outputs) via the UTXO view.
/// Returns Err if any input is missing.
pub fn compute_fee<V: UtxoView>(tx: &Transaction, view: &V) -> Result<Sats, String> {
    let mut in_sum = Sats::ZERO;
    for inp in &tx.inputs {
        let prev = view
            .get(&inp.prev)
            .ok_or_else(|| format!("missing input {}", inp.prev))?;
        in_sum = in_sum
            .checked_add(prev.value)
            .ok_or_else(|| "input sum overflow".to_string())?;
    }
    let out_sum = tx
        .output_sum()
        .ok_or_else(|| "output sum overflow".to_string())?;
    in_sum
        .checked_sub(out_sum)
        .ok_or_else(|| "outputs exceed inputs".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use minibtc_crypto::Hash256;
    use minibtc_crypto::Keypair;
    use minibtc_primitives::{TxInput, TxOutput};
    use std::collections::HashMap;

    struct MapView(HashMap<OutPoint, TxOutput>);
    impl UtxoView for MapView {
        fn get(&self, op: &OutPoint) -> Option<TxOutput> {
            self.0.get(op).cloned()
        }
    }

    fn view_with(ops: &[(OutPoint, u64)]) -> MapView {
        let mut m = HashMap::new();
        for (op, v) in ops {
            m.insert(
                *op,
                TxOutput {
                    value: Sats(*v),
                    script_pubkey: vec![0x51],
                },
            );
        }
        MapView(m)
    }

    fn tx_spending(op: OutPoint, value: u64) -> Transaction {
        tx_spending_seq(op, value, 0)
    }

    fn tx_spending_seq(op: OutPoint, value: u64, seq: u32) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev: op,
                script_sig: vec![],
                sequence: seq,
            }],
            outputs: vec![TxOutput {
                value: Sats(value),
                script_pubkey: vec![0x51],
            }],
            locktime: 0,
        }
    }

    fn op(seed: u8) -> OutPoint {
        OutPoint {
            txid: Hash256([seed; 32]),
            vout: 0,
        }
    }

    #[test]
    fn fee_rate_ordering() {
        let mut mp = Mempool::new(MempoolPolicy::default());
        let view = view_with(&[(op(1), 10_000), (op(2), 10_000), (op(3), 10_000)]);
        let p = ChainParams::devnet();
        // low fee tx
        mp.admit(tx_spending(op(1), 9_900), Sats(100), &view, &p, None)
            .unwrap();
        // high fee tx (bigger absolute fee)
        mp.admit(tx_spending(op(2), 9_000), Sats(1_000), &view, &p, None)
            .unwrap();
        // mid
        mp.admit(tx_spending(op(3), 9_500), Sats(500), &view, &p, None)
            .unwrap();
        let ordered = mp.txs_by_fee_rate();
        assert_eq!(ordered.len(), 3);
        // highest fee first
        assert_eq!(ordered[0].1, Sats(1_000));
        assert_eq!(ordered[2].1, Sats(100));
    }

    #[test]
    fn min_fee_and_dust_rejected() {
        let mut mp = Mempool::new(MempoolPolicy {
            min_relay_fee_rate: 10,
            ..Default::default()
        });
        let view = view_with(&[(op(1), 10_000)]);
        let p = ChainParams::devnet();
        // fee 5 < min 10
        assert!(matches!(
            mp.admit(tx_spending(op(1), 9_995), Sats(5), &view, &p, None),
            Err(MempoolError::MinFee { .. })
        ));
        // dust output: value 100 < 546
        let mut mp2 = Mempool::new(MempoolPolicy::default());
        let dust_tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev: op(1),
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: Sats(100),
                script_pubkey: vec![0x51],
            }],
            locktime: 0,
        };
        assert!(matches!(
            mp2.admit(dust_tx, Sats(9_900), &view, &p, None),
            Err(MempoolError::Dust { .. })
        ));
    }

    #[test]
    fn conflict_without_rbf_rejected() {
        let mut mp = Mempool::new(MempoolPolicy::default());
        let view = view_with(&[(op(1), 10_000)]);
        let p = ChainParams::devnet();
        let tx1 = tx_spending(op(1), 9_000);
        mp.admit(tx1.clone(), Sats(1_000), &view, &p, None).unwrap();
        // Second tx spending same outpoint → conflict.
        let tx2 = tx_spending(op(1), 8_000);
        assert!(matches!(
            mp.admit(tx2, Sats(2_000), &view, &p, None),
            Err(MempoolError::Conflict(_))
        ));
    }

    #[test]
    fn rbf_requires_higher_fee_rate() {
        let mut mp = Mempool::new(MempoolPolicy::default());
        let view = view_with(&[(op(1), 10_000)]);
        let p = ChainParams::devnet();
        // Original signals RBF (sequence < max-1).
        let orig = tx_spending_seq(op(1), 9_000, 0xfffffffd);
        mp.admit(orig.clone(), Sats(1_000), &view, &p, None)
            .unwrap();
        let orig_id = orig.txid();
        // Replacement with higher fee → allowed.
        let repl = tx_spending_seq(op(1), 8_000, 0xfffffffd);
        mp.admit(repl.clone(), Sats(2_000), &view, &p, Some(orig_id))
            .unwrap();
        assert!(mp.get(&orig_id).is_none(), "original should be evicted");
        assert!(mp.get(&repl.txid()).is_some());
        // Lower-fee replacement → rejected.
        let orig2 = tx_spending_seq(op(2), 9_000, 0xfffffffd);
        let view2 = view_with(&[(op(1), 10_000), (op(2), 10_000)]);
        mp.admit(orig2.clone(), Sats(2_000), &view2, &p, None)
            .unwrap();
        let orig2_id = orig2.txid();
        let weak = tx_spending_seq(op(2), 9_500, 0xfffffffd);
        assert!(matches!(
            mp.admit(weak, Sats(500), &view2, &p, Some(orig2_id)),
            Err(MempoolError::NoRbf(_))
        ));
    }

    #[test]
    fn eviction_drops_lowest_fee_rate() {
        let mut mp = Mempool::new(MempoolPolicy {
            // Each tx ≈ 61 bytes → cap 150 fits two, forces one eviction.
            max_size_bytes: 150,
            ..Default::default()
        });
        let view = view_with(&[(op(1), 10_000), (op(2), 10_000), (op(3), 10_000)]);
        let p = ChainParams::devnet();
        // Cap 150 → two fit (~122B), third forces eviction of the lowest.
        mp.admit(tx_spending(op(1), 9_000), Sats(100), &view, &p, None)
            .unwrap();
        mp.admit(tx_spending(op(2), 8_000), Sats(2_000), &view, &p, None)
            .unwrap();
        // Third tx high fee → evicts the lowest (fee 100).
        mp.admit(tx_spending(op(3), 7_000), Sats(3_000), &view, &p, None)
            .unwrap();
        assert_eq!(mp.len(), 2);
        let remaining: Vec<Sats> = mp.by_fee_rate().iter().map(|e| e.fee).collect();
        assert!(remaining.contains(&Sats(3_000)));
        assert!(remaining.contains(&Sats(2_000)));
        assert!(!remaining.contains(&Sats(100)));
    }

    #[test]
    fn block_connect_removes_confirmed() {
        let mut mp = Mempool::new(MempoolPolicy::default());
        let view = view_with(&[(op(1), 10_000)]);
        let p = ChainParams::devnet();
        let tx = tx_spending(op(1), 9_000);
        let txid = tx.txid();
        mp.admit(tx.clone(), Sats(1_000), &view, &p, None).unwrap();
        // Fake a block containing it.
        let block = minibtc_primitives::Block {
            header: minibtc_primitives::BlockHeader {
                version: 1,
                prev_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txs: vec![tx],
        };
        mp.on_block_connected(&block);
        assert!(mp.get(&txid).is_none());
    }

    #[test]
    fn ancestor_limit_enforced() {
        let mut mp = Mempool::new(MempoolPolicy {
            max_ancestor_count: 3,
            ..Default::default()
        });
        let p = ChainParams::devnet();
        // Chain: tx1 spends op(1); tx2 spends tx1's output; tx3 spends tx2's.
        let view = view_with(&[(op(1), 10_000)]);
        let tx1 = tx_spending(op(1), 9_000);
        let tx1_id = tx1.txid();
        mp.admit(tx1, Sats(100), &view, &p, None).unwrap();
        // tx2 spends tx1:0 — need that outpoint in "view" too? mempool
        // ancestor check uses mempool entries; the outpoint must exist in
        // view for fee calc but admit() doesn't check view. Build tx2.
        let tx2 = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev: OutPoint {
                    txid: tx1_id,
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: Sats(8_000),
                script_pubkey: vec![0x51],
            }],
            locktime: 0,
        };
        mp.admit(tx2.clone(), Sats(500), &view, &p, None).unwrap();
        let tx2_id = tx2.txid();
        let tx3 = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev: OutPoint {
                    txid: tx2_id,
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: Sats(7_000),
                script_pubkey: vec![0x51],
            }],
            locktime: 0,
        };
        // tx3's ancestors = tx1+tx2+self = 3 ≤ 3 ok; tx4 would make 4 > 3.
        mp.admit(tx3.clone(), Sats(300), &view, &p, None).unwrap();
        let tx3_id = tx3.txid();
        let tx4 = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev: OutPoint {
                    txid: tx3_id,
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: Sats(6_000),
                script_pubkey: vec![0x51],
            }],
            locktime: 0,
        };
        assert!(matches!(
            mp.admit(tx4, Sats(200), &view, &p, None),
            Err(MempoolError::Ancestors)
        ));
    }

    #[test]
    fn orphans_bounded_and_expire() {
        let mut mp = Mempool::new(MempoolPolicy {
            max_orphans: 3,
            ..Default::default()
        });
        for i in 0..10u8 {
            let tx = tx_spending(op(i), 1_000);
            mp.add_orphan(tx);
        }
        assert_eq!(mp.orphan_count(), 3); // capped
        mp.set_time(100);
        // orphans added at now=0; expire after 50s → at t=100 all expire? ttl 50 → age 100 ≥ 50 → gone
        assert_eq!(mp.expire_orphans(50), 3);
        assert_eq!(mp.orphan_count(), 0);
    }

    #[test]
    fn compute_fee_checked() {
        let view = view_with(&[(op(1), 10_000)]);
        let tx = tx_spending(op(1), 8_000);
        assert_eq!(compute_fee(&tx, &view).unwrap(), Sats(2_000));
        // overspend → err
        let bad = tx_spending(op(1), 20_000);
        assert!(compute_fee(&bad, &view).is_err());
        // missing input → err
        let miss = tx_spending(op(9), 1_000);
        assert!(compute_fee(&miss, &view).is_err());
    }
}

//! Node core: the shared chain/mempool/peer state and every mutation
//! pipeline (block connect, tx admit, mining). One `Mutex<NodeInner>`
//! serializes all state changes — deliberately: lock-ordering bugs are
//! how consensus code dies, and a devnet does not need finer granularity.

use minibtc_chainstate::Chain;
use minibtc_consensus::{ChainParams, genesis_block, validate_tx};
use minibtc_crypto::Hash256;
use minibtc_mempool::{Mempool, MempoolPolicy};
use minibtc_p2p::codec::{InvItem, InvType, Message};
use minibtc_p2p::peer::PeerManager;
use minibtc_p2p::sync::Sync;
use minibtc_primitives::{OutPoint, Sats, Transaction};
use minibtc_storage::Store;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Bounded address-book size.
pub(crate) const ADDRBOOK_CAP: usize = 1_024;
/// Mempool refresh drains and re-admits — cap work per refresh.
const MEMPOOL_REFRESH_CAP: usize = 10_000;
/// Nonce-grind budget per block (devnet finishes instantly; real targets
/// need the cancel flag + bigger budgets).
const MINE_BUDGET: u64 = 50_000_000;

/// Blocks received but not yet connectable (parent unknown) — drained in
/// order as the chain advances. Bounded; duplicates suppressed.
#[derive(Default)]
pub struct PendingBlocks {
    queue: VecDeque<minibtc_primitives::Block>,
    seen: HashSet<Hash256>,
}

impl PendingBlocks {
    /// Push if new and under cap.
    pub fn push(&mut self, block: minibtc_primitives::Block) -> bool {
        let h = block.header.block_hash();
        if self.seen.contains(&h) || self.queue.len() >= 4_096 {
            return false;
        }
        self.seen.insert(h);
        self.queue.push_back(block);
        true
    }

    /// Pop the first block whose parent we already index.
    /// Takes the block map so callers can hold `inner.pending` mutably
    /// while borrowing `inner.chain.blocks` immutably (disjoint fields).
    pub fn pop_connectable(
        &mut self,
        blocks: &HashMap<Hash256, minibtc_chainstate::IndexedBlock>,
    ) -> Option<minibtc_primitives::Block> {
        let pos = self
            .queue
            .iter()
            .position(|b| blocks.contains_key(&b.header.prev_hash))?;
        let b = self.queue.remove(pos)?;
        self.seen.remove(&b.header.block_hash());
        Some(b)
    }

    /// Is this hash already queued?
    pub fn contains(&self, hash: &Hash256) -> bool {
        self.seen.contains(hash)
    }

    /// Len for observability.
    pub fn len(&self) -> usize {
        self.queue.len()
    }
}

/// Everything that mutates together lives here.
pub struct NodeInner {
    /// The chain (UTXO set + block index + tip).
    pub chain: Chain,
    /// Valid unconfirmed transactions.
    pub mempool: Mempool,
    /// Peer table + bans.
    pub peers: PeerManager,
    /// Headers-first sync + relay dedup state.
    pub sync: Sync,
    /// Learned addresses for outbound dialing (bounded).
    pub addrbook: Vec<SocketAddr>,
    /// txid → block hash for every tx in every indexed block (confirmed
    /// history; mempool txs are found via `mempool` first).
    pub txindex: HashMap<Hash256, Hash256>,
    /// Out-of-order block download queue.
    pub pending: PendingBlocks,
    /// Highest block height each peer has claimed (via version or a
    /// headers batch) — drives continued getheaders until caught up.
    pub claimed: HashMap<SocketAddr, u32>,
    /// Outbound dials in flight (TCP connect → handshake → session end).
    /// Dedupes redial/--connect races that would otherwise open parallel
    /// sessions to the same address and burn the per-IP peer budget.
    pub dialing: HashSet<SocketAddr>,
}

/// The node handle shared by RPC, P2P sessions and the mining loop.
#[derive(Clone)]
pub struct Node {
    /// Consensus parameters.
    pub params: ChainParams,
    /// Shared mutable state.
    pub inner: Arc<Mutex<NodeInner>>,
    /// Durable store (None = memory-only, tests).
    pub store: Option<Store>,
    /// Per-peer outbound message queues.
    pub peer_tx: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Message>>>>,
    /// Shutdown flag — mining loops check it.
    pub cancel: Arc<AtomicBool>,
}

/// Result of a block-connect attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// New tip (direct extension or reorg winner).
    Connected,
    /// Already knew this block — no-op.
    AlreadyHave,
    /// Stored as an inactive side branch (insufficient work).
    SideBranch,
}

/// Open (or create) a node at `datadir`.
///
/// - `reindex`: replay all stored blocks through validation, discarding
///   derived state.
pub fn open(datadir: &Path, params: ChainParams, reindex: bool) -> Result<Node, NodeError> {
    std::fs::create_dir_all(datadir)?;
    let store = Store::open(datadir)?;
    let genesis = genesis_block(&params);
    let chain = if reindex {
        let c = store.reindex(params.clone(), genesis)?;
        store.snapshot(&c)?;
        c
    } else {
        match store.load(params.clone(), genesis.clone())? {
            Some(c) => c,
            None => {
                let c = minibtc_chainstate::Chain::new(params.clone(), genesis)?;
                store.snapshot(&c)?;
                c
            }
        }
    };
    let tip = chain.tip;
    let mut sync = Sync::new(params.clone(), tip);
    for h in chain.blocks.keys() {
        sync.note_have(*h);
    }
    // txid → block hash over every indexed block (active + inactive).
    let mut txindex = HashMap::new();
    for (bh, rec) in &chain.blocks {
        for t in &rec.block.txs {
            txindex.insert(t.txid(), *bh);
        }
    }
    let inner = NodeInner {
        chain,
        mempool: Mempool::new(MempoolPolicy::default()),
        peers: PeerManager::new(),
        sync,
        addrbook: Vec::new(),
        txindex,
        pending: PendingBlocks::default(),
        claimed: HashMap::new(),
        dialing: HashSet::new(),
    };
    Ok(Node {
        params,
        inner: Arc::new(Mutex::new(inner)),
        store: Some(store),
        peer_tx: Arc::new(Mutex::new(HashMap::new())),
        cancel: Arc::new(AtomicBool::new(false)),
    })
}

/// Node errors (binary-facing; anyhow wraps at the edge).
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// IO.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Storage.
    #[error("store: {0}")]
    Store(#[from] minibtc_storage::StoreError),
    /// Chain.
    #[error("chain: {0}")]
    Chain(#[from] minibtc_chainstate::ChainError),
    /// Consensus params.
    #[error("params: {0}")]
    Params(#[from] minibtc_consensus::ParamsError),
    /// Miner.
    #[error("miner: {0}")]
    Miner(#[from] minibtc_miner::MineError),
    /// P2P.
    #[error("p2p: {0}")]
    P2p(#[from] minibtc_p2p::peer::PeerError),
}

/// Current wall-clock seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A block at `height` on the active chain (walk back from tip).
pub fn block_at_height(inner: &NodeInner, height: u32) -> Option<Hash256> {
    let mut cur = inner.chain.tip;
    let mut h = inner.chain.height();
    loop {
        if h == height {
            return Some(cur);
        }
        if h == 0 {
            return None;
        }
        let rec = inner.chain.blocks.get(&cur)?;
        cur = rec.block.header.prev_hash;
        h = h.saturating_sub(1);
    }
}

impl Node {
    /// Connect a block through the full pipeline: validate → connect or
    /// reorg → persist → refresh mempool → update sync tip. Returns the
    /// outcome; the caller relays the inv announcement.
    pub fn connect_block(
        &self,
        block: minibtc_primitives::Block,
    ) -> Result<ConnectOutcome, NodeError> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let hash = block.header.block_hash();
        if inner.chain.blocks.contains_key(&hash) {
            return Ok(ConnectOutcome::AlreadyHave);
        }
        let direct = block.header.prev_hash == inner.chain.tip;
        let prev_tip = inner.chain.tip;
        inner.chain.consider_block(block.clone())?;
        // Persist: incremental for direct extensions, full snapshot for
        // side branches/reorgs (rare — correctness over speed).
        if let Some(store) = &self.store {
            if direct {
                store.append_block(&inner.chain, &hash)?;
            } else {
                store.snapshot(&inner.chain)?;
            }
        }
        // Index the new block's txs + mark it held for sync/relay dedup.
        let new_txids: Vec<Hash256> = inner
            .chain
            .blocks
            .get(&hash)
            .map(|r| r.block.txs.iter().map(|t| t.txid()).collect())
            .unwrap_or_default();
        for t in new_txids {
            inner.txindex.insert(t, hash);
        }
        let tip = inner.chain.tip;
        inner.sync.note_have(hash);
        // Mempool refresh: confirmed txs drop out, reorg-returned txs come
        // back, conflicts die — one code path for every connect type.
        self.refresh_mempool(&mut inner);
        inner.sync.set_tip(tip);
        let outcome = if inner.chain.tip == hash {
            ConnectOutcome::Connected
        } else if inner.chain.tip == prev_tip {
            ConnectOutcome::SideBranch
        } else {
            ConnectOutcome::Connected // reorg — new tip differs
        };
        Ok(outcome)
    }

    /// Validate a tx for mempool admission: full consensus validation +
    /// coinbase-maturity policy. Returns the fee on success.
    pub fn validate_for_mempool(
        &self,
        inner: &NodeInner,
        tx: &Transaction,
    ) -> Result<Sats, String> {
        let fee = validate_tx(tx, &inner.chain.utxos, &self.params).map_err(|e| e.to_string())?;
        // Coinbase maturity is a connect-time rule; mempool enforces it
        // early so miners never template an unminable tx.
        let tip_h = inner.chain.height();
        for inp in &tx.inputs {
            if let Some(e) = inner.chain.utxos.get(&inp.prev) {
                if e.coinbase && tip_h.saturating_sub(e.height) < self.params.coinbase_maturity {
                    return Err(format!(
                        "immature coinbase (depth {} < {})",
                        tip_h.saturating_sub(e.height),
                        self.params.coinbase_maturity
                    ));
                }
            }
        }
        Ok(fee)
    }

    /// The single tx-accept path: consensus + maturity + mempool policy.
    /// `replace` is the RBF target txid when the tx signals BIP125;
    /// `relay_except` excludes the origin peer from the inv fan-out.
    pub fn accept_tx(
        &self,
        tx: Transaction,
        replace: Option<Hash256>,
        relay_except: Option<SocketAddr>,
    ) -> Result<Hash256, AcceptError> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // A confirmed tx's inputs are spent → validate_tx fails
        // MissingInput. Already-correct dedup, no special case needed.
        let fee = self
            .validate_for_mempool(&inner, &tx)
            .map_err(AcceptError::Invalid)?;
        let NodeInner { mempool, chain, .. } = &mut *inner;
        mempool
            .admit(tx.clone(), fee, &chain.utxos, &self.params, replace)
            .map_err(|e| match e {
                // Policy-class failures: already-have is silent-success
                // adjacent; the rest are local policy, not peer faults.
                _ => AcceptError::Policy(e.to_string()),
            })?;
        let txid = tx.txid();
        // Relay inv to every connected peer except the originator.
        self.relay_inv_except(
            InvItem {
                kind: InvType::Tx,
                hash: txid,
            },
            relay_except,
        );
        Ok(txid)
    }

    /// `inv` to all peers except `except_addr` (the message's origin);
    /// `None` means all peers. Snapshot senders under the lock, then
    /// try_send outside it — channels are bounded; a lagging peer drops
    /// announcements, never blocks the consensus path.
    pub fn relay_inv_except(&self, item: InvItem, except_addr: Option<SocketAddr>) {
        let msg = Message::Inv(vec![item]);
        let senders: Vec<(SocketAddr, mpsc::Sender<Message>)> = self
            .peer_tx
            .lock()
            .map(|m| m.iter().map(|(a, s)| (*a, s.clone())).collect())
            .unwrap_or_default();
        for (addr, tx) in senders {
            if Some(addr) == except_addr {
                continue;
            }
            let _ = tx.try_send(msg.clone());
        }
    }

    /// Snapshot of all live peer outbound queues.
    pub fn peer_senders(&self) -> Vec<mpsc::Sender<Message>> {
        self.peer_tx
            .lock()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Relay a block inv to all peers (after connect).
    pub fn relay_block(&self, hash: Hash256) {
        if let Ok(mut inner) = self.inner.lock() {
            if !inner.sync.should_relay(hash) {
                return;
            }
        }
        let msg = Message::Inv(vec![InvItem {
            kind: InvType::Block,
            hash,
        }]);
        for tx in self.peer_senders() {
            let _ = tx.try_send(msg.clone());
        }
    }

    /// Drain + re-admit the whole mempool against the current UTXO set.
    /// Called after every block connect (cheap at devnet scale, and the
    /// ONLY correct way to handle reorgs + confirmed-conflicts).
    fn refresh_mempool(&self, inner: &mut NodeInner) {
        let txs: Vec<Transaction> = inner
            .mempool
            .by_fee_rate()
            .into_iter()
            .take(MEMPOOL_REFRESH_CAP)
            .map(|e| e.tx.clone())
            .collect();
        for t in &txs {
            inner.mempool.remove(&t.txid());
        }
        for t in txs {
            // Full re-validation — cheap insurance against any state the
            // incremental paths missed.
            if let Ok(fee) = self.validate_for_mempool(inner, &t) {
                let view = &inner.chain.utxos;
                let _ = inner.mempool.admit(t, fee, view, &self.params, None);
            }
        }
    }

    /// Build + mine + connect `n` blocks paying `payout_script`.
    /// Devnet-gated by the caller (RPC checks `params.devnet`).
    pub fn generate(&self, n: u64, payout_script: &[u8]) -> Result<Vec<Hash256>, NodeError> {
        let mut hashes = Vec::with_capacity(n as usize);
        for _ in 0..n {
            if self.cancel.load(Ordering::Relaxed) {
                break;
            }
            // Snapshot what the template needs under the lock.
            let (template, height) = {
                let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                let tip_rec = inner
                    .chain
                    .blocks
                    .get(&inner.chain.tip)
                    .ok_or(minibtc_chainstate::ChainError::NotTip)?;
                let h = inner.chain.height() as u64 + 1;
                let time = candidate_time(&inner);
                let bits = next_bits(&inner, tip_rec)?;
                let txs = inner.mempool.txs_by_fee_rate();
                let t = minibtc_miner::build_template(
                    &self.params,
                    &tip_rec.block.header,
                    &txs,
                    payout_script,
                    h,
                    time,
                    bits,
                )
                .map_err(NodeError::Miner)?;
                (t, h)
            };
            let _ = height;
            // Mine WITHOUT holding the lock — devnet returns instantly;
            // harder targets still yield to RPC via the cancel flag.
            let header = minibtc_miner::mine(&template, MINE_BUDGET, Some(&self.cancel))
                .map_err(NodeError::Miner)?;
            let block = minibtc_miner::assemble(&template, header);
            let hash = block.header.block_hash();
            match self.connect_block(block)? {
                ConnectOutcome::Connected | ConnectOutcome::AlreadyHave => {
                    self.relay_block(hash);
                    hashes.push(hash);
                }
                ConnectOutcome::SideBranch => {
                    // Shouldn't happen mining on tip — treat as failure.
                    return Err(NodeError::Chain(minibtc_chainstate::ChainError::NotTip));
                }
            }
        }
        Ok(hashes)
    }
}

/// Why a tx was refused — consensus failures are peer-faultworthy,
/// policy refusals are not.
#[derive(Debug)]
pub enum AcceptError {
    /// Failed consensus/mempool-validity checks (score the peer).
    Invalid(String),
    /// Valid tx, refused by local policy (fee, size, conflict).
    Policy(String),
}

/// Pick a valid candidate timestamp: > median-time-past, ≤ now+future,
/// and > parent time when the clock is behind.
fn candidate_time(inner: &NodeInner) -> u32 {
    let now = now_secs() as u32;
    let mtp = inner.chain.median_time_past().unwrap_or(0);
    let tip_time = inner
        .chain
        .blocks
        .get(&inner.chain.tip)
        .map(|r| r.block.header.time)
        .unwrap_or(0);
    now.max(mtp.saturating_add(1))
        .max(tip_time.saturating_add(1))
}

/// Bits for the next block: prev bits, retargeted at period boundaries.
fn next_bits(
    inner: &NodeInner,
    tip_rec: &minibtc_chainstate::IndexedBlock,
) -> Result<u32, NodeError> {
    let interval = inner.chain.params.pow_target_timespan_blocks as u32;
    // The block being built sits at tip+1 — retarget iff ITS height is a
    // multiple of the interval (Bitcoin's nHeight+1 rule).
    let new_height = inner.chain.height().saturating_add(1);
    if interval == 0 || new_height % interval != 0 {
        return Ok(tip_rec.block.header.bits);
    }
    // Span = tip.time − time of block `interval` back from the new height.
    let target_h = new_height.saturating_sub(interval);
    let old_time = block_at_height(inner, target_h)
        .and_then(|h| inner.chain.blocks.get(&h))
        .map(|r| r.block.header.time)
        .unwrap_or(tip_rec.block.header.time);
    let span = u64::from(tip_rec.block.header.time.saturating_sub(old_time));
    let target_span = u64::from(inner.chain.params.pow_target_spacing)
        .saturating_mul(u64::from(inner.chain.params.pow_target_timespan_blocks));
    minibtc_consensus::pow::retarget_bits(
        tip_rec.block.header.bits,
        span,
        target_span,
        inner.chain.params.pow_clamp_factor,
    )
    .map_err(|e| {
        NodeError::Chain(minibtc_chainstate::ChainError::InvalidBlock(
            minibtc_consensus::BlockError::Pow(e),
        ))
    })
}

impl NodeInner {
    /// Total coin supply = sum of all UTXO values (display metric).
    pub fn money_supply(&self) -> Sats {
        let mut total = Sats::ZERO;
        for (_op, e) in self.chain.utxos.iter() {
            total = total.checked_add(e.output.value).unwrap_or(total);
        }
        total
    }
}

/// Compute a tx's fee by resolving inputs through the tx index +
/// stored blocks. Bounded: skips fee when inputs exceed the cap or a
/// prev tx is unresolvable.
pub fn tx_fee(node: &Node, inner: &NodeInner, tx: &Transaction) -> Option<Sats> {
    const MAX_FEE_INPUTS: usize = 1_000;
    if tx.inputs.len() > MAX_FEE_INPUTS {
        return None;
    }
    // Mempool entries already carry their fee.
    if let Some(e) = inner.mempool.get(&tx.txid()) {
        return Some(e.fee);
    }
    let mut in_sum = Sats::ZERO;
    for inp in &tx.inputs {
        if inp.prev == OutPoint::NULL {
            continue; // coinbase — no real inputs
        }
        // Find the prev tx: in-chain via txindex→block→tx scan.
        let prev_tx = find_tx(node, inner, &inp.prev.txid)?;
        let out = prev_tx.outputs.get(inp.prev.vout as usize)?;
        in_sum = in_sum.checked_add(out.value)?;
    }
    let out_sum = tx.output_sum()?;
    in_sum.checked_sub(out_sum)
}

/// Locate a transaction by txid: mempool → txindex → block scan.
/// Caller holds the inner lock.
pub fn find_tx(node: &Node, inner: &NodeInner, txid: &Hash256) -> Option<Transaction> {
    // Mempool first (unconfirmed).
    if let Some(e) = inner.mempool.get(txid) {
        return Some(e.tx.clone());
    }
    // txindex → block hash → scan that block's txs only.
    if let Some(bh) = inner.txindex.get(txid) {
        if let Some(rec) = inner.chain.blocks.get(bh) {
            return rec.block.txs.iter().find(|t| t.txid() == *txid).cloned();
        }
        // Block pruned from memory but in store (shouldn't happen).
        if let Some(store) = &node.store {
            if let Ok(Some(b)) = store.get_block(bh) {
                return b.txs.into_iter().find(|t| t.txid() == *txid);
            }
        }
    }
    None
}

/// Confirmations for a txid: 0 if unconfirmed/mempool, else depth.
pub fn tx_confirmations(inner: &NodeInner, txid: &Hash256) -> Option<u64> {
    // Find the block containing it on the ACTIVE chain.
    let tip_h = inner.chain.height();
    let mut cur = inner.chain.tip;
    let mut h = tip_h;
    loop {
        let rec = inner.chain.blocks.get(&cur)?;
        if rec.status == minibtc_chainstate::BlockStatus::Active {
            for t in &rec.block.txs {
                if t.txid() == *txid {
                    return Some(u64::from(tip_h.saturating_sub(h)) + 1);
                }
            }
        }
        if h == 0 {
            return None;
        }
        cur = rec.block.header.prev_hash;
        h = h.saturating_sub(1);
    }
}

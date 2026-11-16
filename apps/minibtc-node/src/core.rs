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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Bounded address-book size.
pub(crate) const ADDRBOOK_CAP: usize = 1_024;
/// Mempool refresh drains and re-admits — cap work per refresh.
const MEMPOOL_REFRESH_CAP: usize = 10_000;
/// Nonce-grind budget per block (devnet finishes instantly; real targets
/// need the cancel flag + bigger budgets).
const MINE_BUDGET: u64 = 50_000_000;

/// Most blocks the out-of-order queue holds.
pub(crate) const PENDING_MAX_BLOCKS: usize = 1_024;
/// Most serialized bytes the out-of-order queue holds (blocks are up to
/// `max_block_size`, so the count cap alone allowed ~1 GB).
pub(crate) const PENDING_MAX_BYTES: usize = 32 * 1024 * 1024;
/// A queued block whose parent never arrives is dropped after this.
pub(crate) const PENDING_TTL: Duration = Duration::from_secs(10 * 60);
/// Most block requests (getdata) tracked at once, all peers together.
pub(crate) const REQUESTS_MAX: usize = 16_384;
/// Most block requests tracked for one peer — one peer's junk `inv`s can
/// no longer fill the table and crowd out everyone else's requests.
pub(crate) const REQUESTS_PER_PEER: usize = 2_048;
/// A block request not answered within this is forgotten.
pub(crate) const REQUEST_TTL: Duration = Duration::from_secs(5 * 60);

/// One queued block plus what the caps need.
struct PendingEntry {
    block: minibtc_primitives::Block,
    hash: Hash256,
    bytes: usize,
    queued_at: Instant,
}

/// Blocks received but not yet connectable (parent unknown) — drained in
/// order as the chain advances. Bounded by count *and* bytes, entries
/// expire, duplicates are suppressed. Only blocks this node requested (or
/// whose parent is already known) are queued — see `net::handle_block`.
#[derive(Default)]
pub struct PendingBlocks {
    queue: VecDeque<PendingEntry>,
    seen: HashSet<Hash256>,
    bytes: usize,
}

impl PendingBlocks {
    /// Queue `block` if it is new and fits under both caps (after dropping
    /// expired entries). Returns whether it was queued.
    pub fn push(&mut self, block: minibtc_primitives::Block, now: Instant) -> bool {
        self.expire(now);
        let hash = block.header.block_hash();
        let bytes = block.encode().len();
        if self.seen.contains(&hash)
            || self.queue.len() >= PENDING_MAX_BLOCKS
            || self.bytes.saturating_add(bytes) > PENDING_MAX_BYTES
        {
            return false;
        }
        self.seen.insert(hash);
        self.bytes = self.bytes.saturating_add(bytes);
        self.queue.push_back(PendingEntry {
            block,
            hash,
            bytes,
            queued_at: now,
        });
        true
    }

    /// Drop entries older than `PENDING_TTL` (the queue is in arrival
    /// order, so expired entries are at the front).
    pub fn expire(&mut self, now: Instant) {
        while let Some(front) = self.queue.front()
            && now.saturating_duration_since(front.queued_at) > PENDING_TTL
        {
            if let Some(e) = self.queue.pop_front() {
                self.forget(&e);
            }
        }
    }

    fn forget(&mut self, e: &PendingEntry) {
        self.seen.remove(&e.hash);
        self.bytes = self.bytes.saturating_sub(e.bytes);
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
            .position(|e| blocks.contains_key(&e.block.header.prev_hash))?;
        let e = self.queue.remove(pos)?;
        self.forget(&e);
        Some(e.block)
    }

    /// Is this hash already queued?
    pub fn contains(&self, hash: &Hash256) -> bool {
        self.seen.contains(hash)
    }

    /// Len for observability.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Queued bytes for observability.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// Blocks this node asked a peer for (getdata), so a block that arrives
/// unasked cannot take a slot in the out-of-order queue. Bounded per peer
/// and in total; entries expire lazily from a time-ordered queue, so every
/// operation is O(1) amortised under the node lock (it used to `retain`
/// the whole table on each call).
#[derive(Default)]
pub struct BlockRequests {
    by_hash: HashMap<Hash256, (SocketAddr, Instant)>,
    /// (requested_at, hash) in request order; an entry is stale when the
    /// hash was taken or re-requested since.
    order: VecDeque<(Instant, Hash256)>,
    per_peer: HashMap<SocketAddr, usize>,
}

impl BlockRequests {
    /// Record that `hash` was requested from `peer` at `now`. Skipped when
    /// that peer is at `REQUESTS_PER_PEER` or the table is full; the block
    /// can still arrive once its parent is known, and the next headers
    /// round asks again. Re-requesting from the same peer is a no-op; from
    /// another peer it moves the request there.
    pub fn note(&mut self, hash: Hash256, peer: SocketAddr, now: Instant) {
        self.expire(now);
        if let Some((asked, _)) = self.by_hash.get(&hash) {
            if *asked == peer {
                return;
            }
            let old = *asked;
            self.by_hash.remove(&hash);
            self.dec(old);
        }
        let mine = self.per_peer.get(&peer).copied().unwrap_or(0);
        if mine >= REQUESTS_PER_PEER || self.by_hash.len() >= REQUESTS_MAX {
            return;
        }
        self.by_hash.insert(hash, (peer, now));
        *self.per_peer.entry(peer).or_insert(0) += 1;
        self.order.push_back((now, hash));
        if self.order.len() > 2 * REQUESTS_MAX {
            // Drop stale queue entries (re-pointed requests), amortised.
            let by_hash = &self.by_hash;
            self.order
                .retain(|(t, h)| by_hash.get(h).is_some_and(|(_, at)| at == t));
        }
    }

    /// Whether `hash` was requested from `peer` (and not expired);
    /// consumes the request.
    pub fn take(&mut self, hash: &Hash256, peer: SocketAddr, now: Instant) -> bool {
        self.expire(now);
        match self.by_hash.get(hash) {
            Some((asked, _)) if *asked == peer => {
                self.by_hash.remove(hash);
                self.dec(peer);
                true
            }
            _ => false,
        }
    }

    /// Forget requests older than `REQUEST_TTL` — pops from the front of
    /// the time-ordered queue only.
    pub fn expire(&mut self, now: Instant) {
        while let Some(&(at, hash)) = self.order.front() {
            if now.saturating_duration_since(at) <= REQUEST_TTL {
                break;
            }
            self.order.pop_front();
            if let Some(&(peer, t)) = self.by_hash.get(&hash)
                && t == at
            {
                self.by_hash.remove(&hash);
                self.dec(peer);
            }
        }
    }

    /// Drop every request to `peer` (on disconnect). O(n), once per
    /// session end.
    pub fn forget_peer(&mut self, peer: &SocketAddr) {
        self.by_hash.retain(|_, (p, _)| p != peer);
        self.per_peer.remove(peer);
    }

    fn dec(&mut self, peer: SocketAddr) {
        if let Some(n) = self.per_peer.get_mut(&peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_peer.remove(&peer);
            }
        }
    }

    /// Outstanding requests for observability.
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }
}

/// Context-free checks a block must pass before it may touch sync state
/// or the pending queue: merkle root (with CVE-2012-2459 mutation), a
/// target that decodes and is not above the pow limit, and a hash that
/// meets it. Cheap and lock-free; full validation happens at connect.
pub fn precheck_block(
    params: &ChainParams,
    block: &minibtc_primitives::Block,
) -> Result<(), String> {
    minibtc_primitives::check_merkle_root(&block.header, &block.txs)
        .map_err(|e| format!("merkle: {e}"))?;
    minibtc_consensus::checked_target(block.header.bits, params)
        .map_err(|e| format!("pow: {e}"))?;
    let target =
        minibtc_consensus::target_for_bits(block.header.bits).map_err(|e| format!("pow: {e}"))?;
    if !block.header.check_pow(&target) {
        return Err("pow: hash above target".to_string());
    }
    Ok(())
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
    /// Blocks requested from peers (only these may wait in `pending`).
    pub requests: BlockRequests,
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
    // txid → block hash for the ACTIVE chain only: a tx that exists only
    // in a side or orphaned block is not confirmed.
    let mut txindex = HashMap::new();
    for (bh, rec) in &chain.blocks {
        if rec.status == minibtc_chainstate::BlockStatus::Active {
            for t in &rec.block.txs {
                txindex.insert(t.txid(), *bh);
            }
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
        requests: BlockRequests::default(),
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

/// A memory-only node (no datadir, no store) for in-process tests.
#[cfg(test)]
pub(crate) fn in_memory(params: ChainParams) -> Node {
    let genesis = genesis_block(&params);
    let chain = minibtc_chainstate::Chain::new(params.clone(), genesis)
        .unwrap_or_else(|e| panic!("genesis: {e:?}"));
    let tip = chain.tip;
    let mut sync = Sync::new(params.clone(), tip);
    sync.note_have(tip);
    let inner = NodeInner {
        chain,
        mempool: Mempool::new(MempoolPolicy::default()),
        peers: PeerManager::new(),
        sync,
        addrbook: Vec::new(),
        txindex: HashMap::new(),
        pending: PendingBlocks::default(),
        requests: BlockRequests::default(),
        claimed: HashMap::new(),
        dialing: HashSet::new(),
    };
    Node {
        params,
        inner: Arc::new(Mutex::new(inner)),
        store: None,
        peer_tx: Arc::new(Mutex::new(HashMap::new())),
        cancel: Arc::new(AtomicBool::new(false)),
    }
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
        let considered = inner.chain.consider_block(block.clone());
        // A failed reorg drops the invalid block and its descendants from
        // the index; delete them from disk too, or a restart loads them back.
        let dropped = inner.chain.take_dropped();
        if let Some(store) = &self.store
            && !dropped.is_empty()
        {
            store.delete_blocks(&dropped)?;
        }
        considered?;
        // Persist: incremental for a tip extension, block + meta only for a
        // side branch that changed nothing else, full snapshot only for a
        // reorg (which needs more work than the tip — it costs PoW).
        if let Some(store) = &self.store {
            if direct {
                store.append_block(&inner.chain, &hash)?;
            } else if inner.chain.tip == prev_tip {
                store.put_side_block(&inner.chain, &hash)?;
            } else {
                store.snapshot(&inner.chain)?;
            }
        }
        // The tx index covers the active chain only. A tip extension adds
        // the block; a reorg removes the disconnected blocks' entries and
        // adds the connected ones; a side block changes nothing.
        let reorg = inner.chain.take_reorg();
        if let Some(r) = &reorg {
            for d in &r.disconnected {
                let txids: Vec<Hash256> = inner
                    .chain
                    .blocks
                    .get(d)
                    .map(|rec| rec.block.txs.iter().map(|t| t.txid()).collect())
                    .unwrap_or_default();
                for t in txids {
                    if inner.txindex.get(&t) == Some(d) {
                        inner.txindex.remove(&t);
                    }
                }
            }
            for c in r.connected.clone() {
                index_block_txs(&mut inner, c);
            }
        } else if direct {
            index_block_txs(&mut inner, hash);
        }
        let tip = inner.chain.tip;
        inner.sync.note_have(hash);
        // Mempool refresh: confirmed txs drop out, conflicts die.
        self.refresh_mempool(&mut inner);
        // Then the reorged-out blocks' transactions go back in (oldest
        // block first), each re-validated against the new chain.
        if let Some(r) = &reorg {
            let NodeInner { mempool, chain, .. } = &mut *inner;
            for d in r.disconnected.iter().rev() {
                if let Some(rec) = chain.blocks.get(d) {
                    let block = rec.block.clone();
                    mempool.on_block_disconnected(&block, &chain.utxos, &self.params, |tx| {
                        validate_against_chain(chain, &self.params, tx)
                    });
                }
            }
        }
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
        validate_against_chain(&inner.chain, &self.params, tx)
    }
}

/// Index every transaction of block `hash` (an active-chain block).
fn index_block_txs(inner: &mut NodeInner, hash: Hash256) {
    let txids: Vec<Hash256> = inner
        .chain
        .blocks
        .get(&hash)
        .map(|r| r.block.txs.iter().map(|t| t.txid()).collect())
        .unwrap_or_default();
    for t in txids {
        inner.txindex.insert(t, hash);
    }
}

/// Full consensus validation of a mempool candidate against the active
/// chain plus the coinbase-maturity rule at the next height. Returns the
/// fee.
fn validate_against_chain(
    chain: &Chain,
    params: &ChainParams,
    tx: &Transaction,
) -> Result<Sats, String> {
    let fee = validate_tx(tx, &chain.utxos, params).map_err(|e| e.to_string())?;
    // Coinbase maturity is a connect-time rule; mempool enforces it
    // early so miners never template an unminable tx.
    let tip_h = chain.height();
    for inp in &tx.inputs {
        if let Some(e) = chain.utxos.get(&inp.prev)
            && e.coinbase
            && tip_h.saturating_sub(e.height) < params.coinbase_maturity
        {
            return Err(format!(
                "immature coinbase (depth {} < {})",
                tip_h.saturating_sub(e.height),
                params.coinbase_maturity
            ));
        }
    }
    Ok(fee)
}

impl Node {
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
            // Policy-class failures: already-have is silent-success
            // adjacent; the rest are local policy, not peer faults.
            .map_err(|e| AcceptError::Policy(e.to_string()))?;
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
        if let Ok(mut inner) = self.inner.lock()
            && !inner.sync.should_relay(hash)
        {
            return;
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
                // The schedule validation enforces — one implementation.
                let bits = inner.chain.next_bits_after(inner.chain.tip)?;
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
        if let Some(store) = &node.store
            && let Ok(Some(b)) = store.get_block(bh)
        {
            return b.txs.into_iter().find(|t| t.txid() == *txid);
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

#[cfg(test)]
mod tests {
    use super::*;
    use minibtc_primitives::{Block, BlockHeader, OutPoint, Sats, Transaction, TxInput, TxOutput};

    /// A block of roughly `script_len` bytes with a distinct hash.
    fn block(seed: u32, script_len: usize) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_hash: Hash256([0xEE; 32]), // parent never known
                merkle_root: Hash256::ZERO,
                time: seed,
                bits: 0x207f_ffff,
                nonce: seed,
            },
            txs: vec![Transaction {
                version: 1,
                inputs: vec![TxInput {
                    prev: OutPoint::NULL,
                    script_sig: vec![0x51],
                    sequence: 0,
                }],
                outputs: vec![TxOutput {
                    value: Sats(1),
                    script_pubkey: vec![0x6a; script_len],
                }],
                locktime: 0,
            }],
        }
    }

    #[test]
    fn precheck_refuses_bad_pow_and_mutated_merkle() {
        let params = ChainParams::devnet();
        let mut good = block(1, 10);
        good.header.merkle_root = minibtc_primitives::merkle_root(&good.txs);
        let target = minibtc_consensus::target_for_bits(good.header.bits).unwrap();
        while !good.header.check_pow(&target) {
            good.header.nonce += 1;
        }
        assert_eq!(precheck_block(&params, &good), Ok(()));

        let mut bad_pow = good.clone();
        while bad_pow.header.check_pow(&target) {
            bad_pow.header.nonce += 1;
        }
        assert!(precheck_block(&params, &bad_pow).is_err());

        let mut mutated = good.clone();
        mutated.txs.push(good.txs[0].clone());
        mutated.txs.push(good.txs[0].clone());
        // [t, t, t] keeps no honest root; any list with an identical pair
        // at a pair position is refused before it can be queued.
        mutated.header.merkle_root = minibtc_primitives::merkle_root(&mutated.txs);
        assert!(precheck_block(&params, &mutated).is_err());

        let mut too_easy = good.clone();
        let mut hard = ChainParams::devnet();
        hard.pow_limit_bits = 0x1f7f_ffff;
        too_easy.header.bits = 0x207f_ffff;
        assert!(precheck_block(&hard, &too_easy).is_err());
    }

    fn hash_n(i: usize) -> Hash256 {
        let mut x = [0u8; 32];
        x[..8].copy_from_slice(&(i as u64).to_le_bytes());
        Hash256(x)
    }

    #[test]
    fn one_peer_cannot_crowd_out_other_peers_requests() {
        // An attacker announcing junk hashes must not fill the table so
        // that an honest peer's requests stop being recorded.
        let t0 = Instant::now();
        let attacker: SocketAddr = "10.6.6.6:1".parse().unwrap();
        let honest: SocketAddr = "10.1.1.1:1".parse().unwrap();
        let mut r = BlockRequests::default();
        for i in 0..(REQUESTS_MAX + 100) {
            r.note(hash_n(i), attacker, t0);
        }
        let h = Hash256([0xAB; 32]);
        r.note(h, honest, t0);
        assert!(r.take(&h, honest, t0), "honest request must be recorded");
    }

    #[test]
    fn request_expiry_is_exact_and_lazy() {
        let t0 = Instant::now();
        let a: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let mut r = BlockRequests::default();
        for i in 0..100 {
            r.note(hash_n(i), a, t0);
        }
        let t1 = t0 + Duration::from_secs(60);
        for i in 100..150 {
            r.note(hash_n(i), a, t1);
        }
        r.expire(t0 + REQUEST_TTL + Duration::from_secs(1));
        assert_eq!(r.len(), 50, "only the first batch expired");
        assert!(!r.take(&hash_n(5), a, t1 + Duration::from_secs(1)));
        assert!(r.take(&hash_n(120), a, t1 + Duration::from_secs(1)));
        // Re-noting a hash does not duplicate it.
        r.note(hash_n(130), a, t1);
        r.note(hash_n(130), a, t1);
        assert_eq!(r.len(), 49);
    }

    #[test]
    fn pending_queue_caps_blocks_and_bytes() {
        let now = Instant::now();
        let mut q = PendingBlocks::default();
        // ~1 MB blocks: the byte cap binds long before the count cap.
        let mut queued = 0usize;
        for i in 0..64u32 {
            if q.push(block(i, 1_000_000), now) {
                queued += 1;
            }
        }
        assert!(queued < 64, "byte cap must refuse some 1 MB blocks");
        assert!(q.bytes() <= PENDING_MAX_BYTES);
        // Small blocks: the count cap binds.
        let mut q = PendingBlocks::default();
        for i in 0..(PENDING_MAX_BLOCKS as u32 + 10) {
            q.push(block(i, 10), now);
        }
        assert_eq!(q.len(), PENDING_MAX_BLOCKS);
    }

    #[test]
    fn pending_entries_expire() {
        let t0 = Instant::now();
        let mut q = PendingBlocks::default();
        assert!(q.push(block(1, 10), t0));
        let later = t0 + PENDING_TTL + Duration::from_secs(1);
        q.expire(later);
        assert_eq!(q.len(), 0, "orphan must expire");
        assert_eq!(q.bytes(), 0);
        assert!(!q.contains(&block(1, 10).header.block_hash()));
        // Its hash is free again.
        assert!(q.push(block(1, 10), later));
    }

    #[test]
    fn only_requested_blocks_count_as_requested() {
        let t0 = Instant::now();
        let a: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:1".parse().unwrap();
        let h = Hash256([7; 32]);
        let mut r = BlockRequests::default();
        assert!(!r.take(&h, a, t0), "never requested");
        r.note(h, a, t0);
        assert!(!r.take(&h, b, t0), "requested from someone else");
        assert!(r.take(&h, a, t0), "requested from this peer");
        assert!(!r.take(&h, a, t0), "a request is consumed once");
        r.note(h, a, t0);
        let late = t0 + REQUEST_TTL + Duration::from_secs(1);
        assert!(!r.take(&h, a, late), "requests expire");
        // Bounded per peer and in total.
        let mut r = BlockRequests::default();
        for i in 0..(REQUESTS_MAX + 100) {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&(i as u64).to_le_bytes());
            r.note(Hash256(x), a, t0);
        }
        assert_eq!(r.len(), REQUESTS_PER_PEER);
        let mut r = BlockRequests::default();
        for i in 0..(REQUESTS_MAX + 100) {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let peer = SocketAddr::from(([10, 0, (i / REQUESTS_PER_PEER) as u8, 1], 1));
            r.note(Hash256(x), peer, t0);
        }
        assert_eq!(r.len(), REQUESTS_MAX);
    }
}

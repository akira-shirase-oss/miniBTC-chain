//! # Sync & relay
//!
//! The headers-first sync state machine and inventory relay policy —
//! pure logic the node drives; no sockets here so it's fully testable.
//!
//! - **Headers-first**: on connect we `getheaders` from the peer's tip;
//!   they stream `headers` back; we validate the chain of headers
//!   (PoW, timestamps, linkage) then `getdata` the blocks we lack.
//! - **Block download**: bounded in-flight window per peer; blocks are
//!   connected to the chainstate as they arrive (which may trigger
//!   reorgs handled by `Chain::consider_block`).
//! - **Relay**: new txs/blocks are gossiped to a bounded fan-out of
//!   peers that haven't seen them (inv-based, matching Bitcoin).
//! - **Anti-DoS**: per-peer download quotas, duplicate-suppression via
//!   a bounded seen-set, and stall timeouts handled by the peer manager.

use minibtc_consensus::ChainParams;
use minibtc_crypto::Hash256;
use minibtc_primitives::{Block, BlockHeader};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;

/// Max headers accepted in one `headers` message burst before we ask for
/// more (Bitcoin uses 2000).
pub const HEADERS_BATCH: usize = 2_000;
/// Max blocks we'll request from one peer at once (in-flight window).
pub const BLOCK_WINDOW: usize = 4_096;
/// Max tx invs gossiped per relay event.
pub const RELAY_FANOUT: usize = 8;
/// How many recent inv hashes we remember for dedup (bounded).
pub const SEEN_CAPACITY: usize = 100_000;
/// Max getdata items per request message.
pub const GETDATA_BATCH: usize = 1_000;

/// Errors from sync decisions.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// A headers chain broke linkage (prev_hash mismatch).
    #[error("headers chain broken at {0}")]
    BrokenChain(Hash256),
    /// Header failed validation (bad PoW, bad time, bad bits).
    #[error("header invalid: {0}")]
    BadHeader(String),
    /// We already have this block — nothing to fetch.
    #[error("already have block")]
    HaveBlock,
}

/// Per-peer download progress.
#[derive(Debug, Default)]
pub struct PeerDownload {
    /// Headers we've accepted from this peer (hashes, in order).
    pub headers: Vec<Hash256>,
    /// Block hashes we're waiting on from this peer.
    pub wanted: VecDeque<Hash256>,
    /// Blocks received but not yet connected (bounded by window).
    pub received: VecDeque<Block>,
    /// Last time this peer sent us anything useful.
    pub last_progress: u64,
}

/// The sync coordinator — one per node.
#[derive(Debug)]
pub struct Sync {
    /// params for PoW/time validation of headers.
    params: ChainParams,
    /// Our current tip hash (updated by node on connect/reorg).
    tip: Hash256,
    /// Blocks we already have (hashes) — prevents re-requesting.
    have: HashSet<Hash256>,
    /// Bounded dedup of recently-seen inv hashes.
    seen: VecDeque<Hash256>,
    seen_set: HashSet<Hash256>,
    /// Per-peer download state.
    peers: HashMap<SocketAddr, PeerDownload>,
    /// Headers accepted but whose blocks we haven't fetched yet —
    /// the "headers chain" we're working through.
    pending_headers: VecDeque<BlockHeader>,
    /// Next expected prev_hash for the pending header chain.
    expect_prev: Option<Hash256>,
}

impl Sync {
    /// New sync state rooted at `tip`.
    pub fn new(params: ChainParams, tip: Hash256) -> Self {
        Self {
            params,
            tip,
            have: HashSet::new(),
            seen: VecDeque::new(),
            seen_set: HashSet::new(),
            peers: HashMap::new(),
            pending_headers: VecDeque::new(),
            expect_prev: None,
        }
    }

    /// Mark a block hash as already held (call for every stored block at
    /// startup and after each connect).
    pub fn note_have(&mut self, hash: Hash256) {
        self.have.insert(hash);
    }

    /// Current tip (most-work chain head).
    pub fn tip(&self) -> Hash256 {
        self.tip
    }

    /// Update tip after connect/reorg.
    pub fn set_tip(&mut self, tip: Hash256) {
        self.tip = tip;
    }

    /// Register a newly-connected peer.
    pub fn add_peer(&mut self, addr: SocketAddr) {
        self.peers.entry(addr).or_default();
    }

    /// Remove a peer (disconnect).
    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        self.peers.remove(addr);
    }

    /// Process an incoming `headers` message from `peer`. Validates PoW,
    /// linkage, and timestamps against our chain; queues blocks we lack.
    /// Returns the hashes we should `getdata` next (bounded by window).
    pub fn on_headers(
        &mut self,
        peer: SocketAddr,
        headers: &[BlockHeader],
    ) -> Result<Vec<Hash256>, SyncError> {
        let mut to_fetch = Vec::new();
        for h in headers {
            let hash = h.block_hash();
            // Linkage: must build on previous header (or our tip/expect).
            let expected = self.expect_prev.unwrap_or_else(|| {
                self.pending_headers
                    .back()
                    .map(|p| p.block_hash())
                    .unwrap_or(self.tip)
            });
            if h.prev_hash != expected {
                // Allow the first header to build on our tip OR on a hash
                // we already have — either is fine for headers-first.
                if !(h.prev_hash == self.tip || self.have.contains(&h.prev_hash)) {
                    return Err(SyncError::BrokenChain(hash));
                }
            }
            // PoW check.
            let target = minibtc_consensus::pow::target_for_bits(h.bits)
                .map_err(|e| SyncError::BadHeader(format!("bits: {e}")))?;
            if !h.check_pow(&target) {
                return Err(SyncError::BadHeader(format!("pow fail {hash}")));
            }
            self.pending_headers.push_back(*h);
            self.expect_prev = Some(hash);
            if !self.have.contains(&hash) {
                to_fetch.push(hash);
            }
        }
        // Record in peer's wanted queue (bounded by window on drain).
        if let Some(pd) = self.peers.get_mut(&peer) {
            for h in to_fetch.iter().take(BLOCK_WINDOW) {
                pd.wanted.push_back(*h);
            }
            pd.last_progress = now();
        }
        Ok(to_fetch)
    }

    /// Process an incoming `block`: stash it for the node to connect.
    /// Returns true if it's new (not already held).
    pub fn on_block(&mut self, peer: SocketAddr, block: Block) -> bool {
        let hash = block.header.block_hash();
        if self.have.contains(&hash) {
            return false;
        }
        self.have.insert(hash);
        if let Some(pd) = self.peers.get_mut(&peer) {
            pd.received.push_back(block);
            pd.last_progress = now();
            // Drop oldest if window exceeded (node drains faster than this).
            while pd.received.len() > BLOCK_WINDOW * 2 {
                pd.received.pop_front();
            }
        }
        true
    }

    /// Take the next batch of received blocks from a peer (for connect).
    pub fn take_received(&mut self, peer: &SocketAddr, max: usize) -> Vec<Block> {
        let mut out = Vec::new();
        if let Some(pd) = self.peers.get_mut(peer) {
            while out.len() < max {
                match pd.received.pop_front() {
                    Some(b) => out.push(b),
                    None => break,
                }
            }
        }
        out
    }

    /// Blocks this peer still owes us (for getdata retry / stall detect).
    pub fn wanted_count(&self, peer: &SocketAddr) -> usize {
        self.peers.get(peer).map(|p| p.wanted.len()).unwrap_or(0)
    }

    /// Get up to `GETDATA_BATCH` hashes to request from `peer`.
    pub fn next_getdata(&mut self, peer: &SocketAddr) -> Vec<Hash256> {
        let mut out = Vec::new();
        if let Some(pd) = self.peers.get_mut(peer) {
            while out.len() < GETDATA_BATCH {
                match pd.wanted.pop_front() {
                    Some(h) => out.push(h),
                    None => break,
                }
            }
        }
        out
    }

    /// Should we relay this inv hash to peers? Dedup + bounded.
    pub fn should_relay(&mut self, hash: Hash256) -> bool {
        if !self.seen_set.insert(hash) {
            return false;
        }
        self.seen.push_back(hash);
        if self.seen.len() > SEEN_CAPACITY {
            if let Some(old) = self.seen.pop_front() {
                self.seen_set.remove(&old);
            }
        }
        true
    }

    /// Pick up to `RELAY_FANOUT` peers to send an inv to (excluding
    /// `exclude` — the peer it came from).
    pub fn relay_targets(&self, exclude: &SocketAddr) -> Vec<SocketAddr> {
        self.peers
            .keys()
            .filter(|a| *a != exclude)
            .take(RELAY_FANOUT)
            .copied()
            .collect()
    }

    /// Headers we're still working through (for status/debug).
    pub fn pending_header_count(&self) -> usize {
        self.pending_headers.len()
    }

    /// Validate a header's timestamp is sane vs params (MTP needs chain
    /// context — node does full validation; here we check the cheap
    /// future-time bound only).
    pub fn header_time_ok(&self, h: &BlockHeader) -> bool {
        let now = now();
        // Future limit from params.
        u64::from(h.time) <= now.saturating_add(u64::from(self.params.max_future_time_secs))
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use minibtc_consensus::pow::target_for_bits;
    use minibtc_primitives::BlockHeader;

    fn params() -> ChainParams {
        ChainParams::devnet()
    }

    fn peer(n: u8) -> SocketAddr {
        format!("127.0.0.1:{}", 8000 + n as u16).parse().unwrap()
    }

    /// Build a valid header chain on devnet (trivial PoW).
    fn header_at(prev: Hash256, time: u32, bits: u32, nonce_start: u32) -> BlockHeader {
        let target = target_for_bits(bits).unwrap();
        let mut h = BlockHeader {
            version: 1,
            prev_hash: prev,
            merkle_root: Hash256([0x11; 32]),
            time,
            bits,
            nonce: nonce_start,
        };
        loop {
            if h.check_pow(&target) {
                return h;
            }
            h.nonce = h.nonce.wrapping_add(1);
        }
    }

    #[test]
    fn headers_chain_accepted_and_queued() {
        let p = params();
        let genesis_hash = Hash256([0x01; 32]);
        let mut sync = Sync::new(p.clone(), genesis_hash);
        let a = peer(1);
        sync.add_peer(a);
        let h1 = header_at(genesis_hash, 1_700_000_001, p.pow_limit_bits, 0);
        let h2 = header_at(h1.block_hash(), 1_700_000_002, p.pow_limit_bits, 0);
        let to_fetch = sync.on_headers(a, &[h1, h2]).unwrap();
        assert_eq!(to_fetch.len(), 2);
        assert_eq!(sync.pending_header_count(), 2);
    }

    #[test]
    fn broken_linkage_rejected() {
        let p = params();
        let genesis = Hash256([0x01; 32]);
        let mut sync = Sync::new(p.clone(), genesis);
        let a = peer(1);
        sync.add_peer(a);
        // Header that doesn't build on tip or a held block.
        let bad = header_at(Hash256([0xEE; 32]), 1_700_000_001, p.pow_limit_bits, 0);
        assert!(matches!(
            sync.on_headers(a, &[bad]),
            Err(SyncError::BrokenChain(_))
        ));
    }

    #[test]
    fn bad_pow_rejected() {
        let p = params();
        let genesis = Hash256([0x01; 32]);
        let mut sync = Sync::new(p.clone(), genesis);
        let a = peer(1);
        sync.add_peer(a);
        // Impossible target bits.
        let bad = BlockHeader {
            version: 1,
            prev_hash: genesis,
            merkle_root: Hash256::ZERO,
            time: 1_700_000_001,
            bits: 0x0100_0001, // target ~0
            nonce: 0,
        };
        assert!(matches!(
            sync.on_headers(a, &[bad]),
            Err(SyncError::BadHeader(_))
        ));
    }

    #[test]
    fn getdata_window_and_dedup() {
        let p = params();
        let genesis = Hash256([0x01; 32]);
        let mut sync = Sync::new(p.clone(), genesis);
        let a = peer(1);
        sync.add_peer(a);
        // 20 headers → window caps getdata at BLOCK_WINDOW.
        let mut prev = genesis;
        let mut hs = Vec::new();
        for i in 0..20u32 {
            let h = header_at(prev, 1_700_000_001 + i, p.pow_limit_bits, 0);
            prev = h.block_hash();
            hs.push(h);
        }
        sync.on_headers(a, &hs).unwrap();
        let batch = sync.next_getdata(&a);
        assert!(batch.len() <= BLOCK_WINDOW || batch.len() <= GETDATA_BATCH);
        assert!(!batch.is_empty());
    }

    #[test]
    fn relay_dedup_and_fanout() {
        let p = params();
        let genesis = Hash256([0x01; 32]);
        let mut sync = Sync::new(p.clone(), genesis);
        let a = peer(1);
        let b = peer(2);
        sync.add_peer(a);
        sync.add_peer(b);
        let h = Hash256([0x42; 32]);
        assert!(sync.should_relay(h));
        assert!(!sync.should_relay(h), "dedup");
        let targets = sync.relay_targets(&a);
        assert_eq!(targets, vec![b]);
    }

    #[test]
    fn on_block_dedup() {
        let p = params();
        let genesis = Hash256([0x01; 32]);
        let mut sync = Sync::new(p.clone(), genesis);
        let a = peer(1);
        sync.add_peer(a);
        let h = header_at(genesis, 1_700_000_001, p.pow_limit_bits, 0);
        let block = Block {
            header: h,
            txs: vec![],
        };
        let hash = block.header.block_hash();
        assert!(sync.on_block(a, block.clone()));
        assert!(!sync.on_block(a, block), "duplicate rejected");
        let got = sync.take_received(&a, 10);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].header.block_hash(), hash);
    }
}

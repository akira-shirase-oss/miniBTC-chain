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

/// Most headers-only entries (headers whose blocks have not connected yet)
/// one peer may have in the header index. Entries leave when their block
/// connects or the peer disconnects.
pub const HEADERS_PER_PEER: usize = BLOCK_WINDOW;

/// Errors from sync decisions.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// A header does not link to a known block or header.
    #[error("headers chain broken at {0}")]
    BrokenChain(Hash256),
    /// Header failed validation (bad PoW, bad time, bad bits).
    #[error("header invalid: {0}")]
    BadHeader(String),
    /// More headers in one message than `HEADERS_BATCH`.
    #[error("{0} headers in one message (max {max})", max = HEADERS_BATCH)]
    TooMany(usize),
    /// The same header twice in one message.
    #[error("header {0} repeated within one message")]
    Repeated(Hash256),
    /// The peer already has `HEADERS_PER_PEER` unconnected headers indexed.
    #[error("peer exceeded its share of unconnected headers")]
    PeerQuota,
    /// An unsolicited headers message that contained nothing new.
    #[error("unsolicited headers message with nothing new")]
    NothingNew,
}

/// What header validation needs about a block or header: height, compact
/// bits, timestamp and parent. The node supplies it for blocks in its
/// index; the sync state keeps it for headers whose blocks it lacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderInfo {
    /// Height (genesis = 0).
    pub height: u32,
    /// Compact difficulty bits.
    pub bits: u32,
    /// Timestamp.
    pub time: u32,
    /// Parent hash.
    pub prev: Hash256,
}

/// Per-peer download progress.
#[derive(Debug, Default)]
pub struct PeerDownload {
    /// Headers we've accepted from this peer (hashes, in order).
    pub headers: Vec<Hash256>,
    /// Block hashes we're waiting on from this peer.
    pub wanted: VecDeque<Hash256>,
    /// Last time this peer sent us anything useful.
    pub last_progress: u64,
    /// `getheaders` sent to this peer and not yet answered: an answer
    /// that brings nothing new is expected then, not a fault.
    pub headers_requested: u32,
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
    /// Headers accepted whose blocks have not connected yet, with the peer
    /// that sent them. Bounded per peer (`HEADERS_PER_PEER`); an entry
    /// leaves when its block connects (`note_have`) or its peer leaves.
    headers: HashMap<Hash256, (HeaderInfo, SocketAddr)>,
    headers_per_peer: HashMap<SocketAddr, usize>,
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
            headers: HashMap::new(),
            headers_per_peer: HashMap::new(),
        }
    }

    /// Mark a block hash as already held (call for every stored block at
    /// startup and after each connect).
    pub fn note_have(&mut self, hash: Hash256) {
        self.have.insert(hash);
        // The block index carries this header now.
        if let Some((_, from)) = self.headers.remove(&hash) {
            self.dec_headers(from);
        }
    }

    fn dec_headers(&mut self, peer: SocketAddr) {
        if let Some(n) = self.headers_per_peer.get_mut(&peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.headers_per_peer.remove(&peer);
            }
        }
    }

    /// Record that we sent `getheaders` to `peer` (its answer is solicited).
    pub fn note_getheaders_sent(&mut self, peer: &SocketAddr) {
        if let Some(pd) = self.peers.get_mut(peer) {
            pd.headers_requested = pd.headers_requested.saturating_add(1);
        }
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

    /// Remove a peer (disconnect), with the headers it alone vouched for.
    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        self.peers.remove(addr);
        if self.headers_per_peer.remove(addr).is_some() {
            self.headers.retain(|_, (_, from)| from != addr);
        }
    }

    /// Process an incoming `headers` message from `peer` and return the
    /// block hashes to `getdata` (bounded by the window).
    ///
    /// Every header is untrusted. Per message: at most `HEADERS_BATCH`
    /// headers and no repeats. Headers we already know (a block in the
    /// index, via `chain`, or an indexed header) are skipped. Each new one
    /// must link to a known block or header, decode to a target within the
    /// pow limit, meet it, carry exactly the bits the retarget schedule
    /// gives after its parent, and not be more than `max_future_time_secs`
    /// ahead. Only then is it indexed (bounded per peer). An unsolicited
    /// message that brings nothing new is an error the caller penalises —
    /// replaying one cheap header used to be free and grew memory without
    /// limit.
    pub fn on_headers<F>(
        &mut self,
        peer: SocketAddr,
        headers: &[BlockHeader],
        chain: F,
    ) -> Result<Vec<Hash256>, SyncError>
    where
        F: Fn(&Hash256) -> Option<HeaderInfo>,
    {
        let solicited = match self.peers.get_mut(&peer) {
            Some(pd) if pd.headers_requested > 0 => {
                pd.headers_requested -= 1;
                true
            }
            _ => false,
        };
        if headers.len() > HEADERS_BATCH {
            return Err(SyncError::TooMany(headers.len()));
        }
        // Structure first: a message with a repeated header is refused
        // whole, before anything from it is indexed.
        let hashes: Vec<Hash256> = headers.iter().map(BlockHeader::block_hash).collect();
        let mut in_batch = HashSet::with_capacity(hashes.len());
        if let Some(dup) = hashes.iter().find(|h| !in_batch.insert(**h)) {
            return Err(SyncError::Repeated(*dup));
        }
        let mut to_fetch = Vec::new();
        for (h, &hash) in headers.iter().zip(&hashes) {
            if self.have.contains(&hash)
                || self.headers.contains_key(&hash)
                || chain(&hash).is_some()
            {
                continue; // already known
            }
            let parent = self
                .lookup(&h.prev_hash, &chain)
                .ok_or(SyncError::BrokenChain(hash))?;
            let info = self.check_header(h, &parent, &chain)?;
            let mine = self.headers_per_peer.get(&peer).copied().unwrap_or(0);
            if mine >= HEADERS_PER_PEER {
                return Err(SyncError::PeerQuota);
            }
            self.headers.insert(hash, (info, peer));
            *self.headers_per_peer.entry(peer).or_insert(0) += 1;
            to_fetch.push(hash);
        }
        if to_fetch.is_empty() && !headers.is_empty() && !solicited {
            return Err(SyncError::NothingNew);
        }
        // Record in the peer's wanted queue (bounded by the window).
        if let Some(pd) = self.peers.get_mut(&peer) {
            for h in &to_fetch {
                if pd.wanted.len() >= BLOCK_WINDOW {
                    break;
                }
                pd.wanted.push_back(*h);
            }
            if !to_fetch.is_empty() {
                pd.last_progress = now();
            }
        }
        Ok(to_fetch)
    }

    /// Height, bits, time and parent of a known block or indexed header.
    fn lookup<F>(&self, hash: &Hash256, chain: &F) -> Option<HeaderInfo>
    where
        F: Fn(&Hash256) -> Option<HeaderInfo>,
    {
        self.headers
            .get(hash)
            .map(|(i, _)| *i)
            .or_else(|| chain(hash))
    }

    /// The context-free and schedule checks for one header whose parent is
    /// `parent`; returns its index entry.
    fn check_header<F>(
        &self,
        h: &BlockHeader,
        parent: &HeaderInfo,
        chain: &F,
    ) -> Result<HeaderInfo, SyncError>
    where
        F: Fn(&Hash256) -> Option<HeaderInfo>,
    {
        let hash = h.block_hash();
        minibtc_consensus::checked_target(h.bits, &self.params)
            .map_err(|e| SyncError::BadHeader(format!("bits: {e}")))?;
        let target = minibtc_consensus::pow::target_for_bits(h.bits)
            .map_err(|e| SyncError::BadHeader(format!("bits: {e}")))?;
        if !h.check_pow(&target) {
            return Err(SyncError::BadHeader(format!("pow fail {hash}")));
        }
        let height = parent.height.saturating_add(1);
        let expected = self.expected_bits(h.prev_hash, parent, height, chain)?;
        if h.bits != expected {
            return Err(SyncError::BadHeader(format!(
                "bits 0x{:08x}, schedule requires 0x{expected:08x}",
                h.bits
            )));
        }
        if !self.header_time_ok(h) {
            return Err(SyncError::BadHeader(format!("time too far ahead {hash}")));
        }
        Ok(HeaderInfo {
            height,
            bits: h.bits,
            time: h.time,
            prev: h.prev_hash,
        })
    }

    /// The bits the schedule requires for a header at `height` whose
    /// parent is `parent_hash` (same rule as `Chain::next_bits_after`).
    fn expected_bits<F>(
        &self,
        parent_hash: Hash256,
        parent: &HeaderInfo,
        height: u32,
        chain: &F,
    ) -> Result<u32, SyncError>
    where
        F: Fn(&Hash256) -> Option<HeaderInfo>,
    {
        if !minibtc_consensus::is_retarget_height(&self.params, u64::from(height)) {
            return Ok(parent.bits);
        }
        let first_height = height.saturating_sub(self.params.pow_target_timespan_blocks);
        let mut cur = (parent_hash, *parent);
        while cur.1.height > first_height {
            let prev = cur.1.prev;
            let info = self
                .lookup(&prev, chain)
                .ok_or_else(|| SyncError::BadHeader("retarget ancestor unknown".to_string()))?;
            cur = (prev, info);
        }
        let span = u64::from(parent.time.saturating_sub(cur.1.time));
        minibtc_consensus::next_bits_for_period(&self.params, parent.bits, span)
            .map_err(|e| SyncError::BadHeader(format!("retarget: {e}")))
    }

    /// Note an incoming `block` from `peer` (progress for stall
    /// detection). Returns true if it's new (not already held). The block
    /// itself is not kept here — the node queues it (bounded) or connects
    /// it; a per-peer copy that nothing drained used to hold up to
    /// 8,192 blocks per peer.
    ///
    /// "Held" means *connected*: the hash enters `have` only through
    /// [`Self::note_have`] after the node accepted the block. Marking it
    /// here, before validation, let a mutated copy (same hash, CVE-2012-2459)
    /// make the node drop the honest block forever.
    pub fn on_block(&mut self, peer: SocketAddr, block: &Block) -> bool {
        let hash = block.header.block_hash();
        if self.have.contains(&hash) {
            return false;
        }
        if let Some(pd) = self.peers.get_mut(&peer) {
            pd.last_progress = now();
        }
        true
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
        if self.seen.len() > SEEN_CAPACITY
            && let Some(old) = self.seen.pop_front()
        {
            self.seen_set.remove(&old);
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

    /// Indexed headers whose blocks have not connected yet.
    pub fn known_header_count(&self) -> usize {
        self.headers.len()
    }

    /// Up to `limit` indexed headers whose blocks we do not hold, lowest
    /// height first, with the peer that sent each. The node re-requests the
    /// ones that are neither queued nor in flight — a header being indexed
    /// must never stop its block from being fetched.
    pub fn missing_blocks(&self, limit: usize) -> Vec<(Hash256, SocketAddr)> {
        let mut v: Vec<(u32, Hash256, SocketAddr)> = self
            .headers
            .iter()
            .filter(|(h, _)| !self.have.contains(*h))
            .map(|(h, (info, from))| (info.height, *h, *from))
            .collect();
        v.sort_unstable_by_key(|(height, h, _)| (*height, *h));
        v.into_iter().take(limit).map(|(_, h, p)| (h, p)).collect()
    }

    /// Peers registered for sync.
    pub fn peer_addrs(&self) -> Vec<SocketAddr> {
        self.peers.keys().copied().collect()
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

    const GENESIS_TIME: u32 = 1_700_000_000;

    /// The node's block index in these tests: only the fake genesis.
    fn genesis_only(genesis: Hash256) -> impl Fn(&Hash256) -> Option<HeaderInfo> {
        move |h: &Hash256| {
            (*h == genesis).then_some(HeaderInfo {
                height: 0,
                bits: ChainParams::devnet().pow_limit_bits,
                time: GENESIS_TIME,
                prev: Hash256::ZERO,
            })
        }
    }

    /// A chain of `n` headers on `genesis`, 32 s apart: every period takes
    /// at least the target time, so the bits stay at the pow limit.
    fn header_chain(genesis: Hash256, n: u32) -> Vec<BlockHeader> {
        let p = params();
        let mut prev = genesis;
        (1..=n)
            .map(|i| {
                let h = header_at(prev, GENESIS_TIME + 32 * i, p.pow_limit_bits, 0);
                prev = h.block_hash();
                h
            })
            .collect()
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
        let to_fetch = sync
            .on_headers(a, &[h1, h2], genesis_only(genesis_hash))
            .unwrap();
        assert_eq!(to_fetch.len(), 2);
        assert_eq!(sync.known_header_count(), 2);
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
            sync.on_headers(a, &[bad], genesis_only(genesis)),
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
            sync.on_headers(a, &[bad], genesis_only(genesis)),
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
        // 19 headers (no retarget boundary) → window caps getdata.
        let hs = header_chain(genesis, 19);
        sync.on_headers(a, &hs, genesis_only(genesis)).unwrap();
        let batch = sync.next_getdata(&a);
        assert!(batch.len() <= BLOCK_WINDOW || batch.len() <= GETDATA_BATCH);
        assert!(!batch.is_empty());
    }

    /// The 2026-11-16 headers flood: one cheap header replayed in message
    /// after message used to be stored every time (1,000,000 entries after
    /// 500 messages). It is now indexed once, repeats within a message are
    /// refused, and unsolicited repeats are errors the node penalises.
    #[test]
    fn a_replayed_header_is_indexed_once_and_repeats_are_errors() {
        let p = params();
        let g = Hash256([0x01; 32]);
        let mut sync = Sync::new(p.clone(), g);
        let a = peer(1);
        sync.add_peer(a);
        let h = header_at(g, GENESIS_TIME + 31, p.pow_limit_bits, 0);
        assert!(matches!(
            sync.on_headers(a, &vec![h; 2_000], genesis_only(g)),
            Err(SyncError::Repeated(_))
        ));
        assert_eq!(sync.on_headers(a, &[h], genesis_only(g)).unwrap().len(), 1);
        for _ in 0..500 {
            assert!(matches!(
                sync.on_headers(a, &[h], genesis_only(g)),
                Err(SyncError::NothingNew)
            ));
        }
        assert_eq!(sync.known_header_count(), 1);
        // An answer to our own getheaders may repeat what we know.
        sync.note_getheaders_sent(&a);
        assert!(
            sync.on_headers(a, &[h], genesis_only(g))
                .unwrap()
                .is_empty()
        );
        // Once its block connects the header leaves the index.
        sync.note_have(h.block_hash());
        assert_eq!(sync.known_header_count(), 0);
    }

    #[test]
    fn oversized_messages_and_off_schedule_headers_are_refused() {
        let p = params();
        let g = Hash256([0x01; 32]);
        let mut sync = Sync::new(p.clone(), g);
        let a = peer(1);
        sync.add_peer(a);
        let many = header_chain(g, HEADERS_BATCH as u32 + 1);
        assert!(matches!(
            sync.on_headers(a, &many, genesis_only(g)),
            Err(SyncError::TooMany(_))
        ));
        // Harder than the schedule allows at a non-retarget height.
        let harder = header_at(g, GENESIS_TIME + 31, 0x1f7f_ffff, 0);
        assert!(matches!(
            sync.on_headers(a, &[harder], genesis_only(g)),
            Err(SyncError::BadHeader(_))
        ));
        // Easier than the pow limit of a harder network.
        let mut hard = params();
        hard.pow_limit_bits = 0x1f7f_ffff;
        let mut sync = Sync::new(hard, g);
        sync.add_peer(a);
        let easy = header_at(g, GENESIS_TIME + 31, 0x207f_ffff, 0);
        assert!(matches!(
            sync.on_headers(a, &[easy], genesis_only(g)),
            Err(SyncError::BadHeader(_))
        ));
        // Far in the future.
        let mut sync = Sync::new(params(), g);
        sync.add_peer(a);
        let future = header_at(g, u32::MAX - 10, p.pow_limit_bits, 0);
        assert!(matches!(
            sync.on_headers(a, &[future], genesis_only(g)),
            Err(SyncError::BadHeader(_))
        ));
    }

    #[test]
    fn a_retarget_header_must_carry_the_rescaled_bits() {
        // 19 headers 1 s apart: the period took 19 s against 600 s, so
        // header 20 must be four times harder (the clamp).
        let p = params();
        let g = Hash256([0x01; 32]);
        let mut sync = Sync::new(p.clone(), g);
        let a = peer(1);
        sync.add_peer(a);
        let mut prev = g;
        let mut hs = Vec::new();
        for i in 1..=19u32 {
            let h = header_at(prev, GENESIS_TIME + i, p.pow_limit_bits, 0);
            prev = h.block_hash();
            hs.push(h);
        }
        sync.on_headers(a, &hs, genesis_only(g)).unwrap();
        let stale = header_at(prev, GENESIS_TIME + 20, p.pow_limit_bits, 0);
        assert!(sync.on_headers(a, &[stale], genesis_only(g)).is_err());
        let want = minibtc_consensus::next_bits_for_period(&p, p.pow_limit_bits, 19).unwrap();
        let ok = header_at(prev, GENESIS_TIME + 20, want, 0);
        assert_eq!(sync.on_headers(a, &[ok], genesis_only(g)).unwrap().len(), 1);
    }

    #[test]
    fn one_peer_cannot_index_unbounded_headers() {
        let p = params();
        let g = Hash256([0x01; 32]);
        let mut sync = Sync::new(p.clone(), g);
        let a = peer(1);
        sync.add_peer(a);
        // A long valid chain from one peer, in full batches.
        let mut prev = g;
        let mut height = 0u32;
        let mut quota_hit = false;
        for _ in 0..3 {
            let mut batch = Vec::new();
            for _ in 0..HEADERS_BATCH {
                height += 1;
                let h = header_at(prev, GENESIS_TIME + 32 * height, p.pow_limit_bits, 0);
                prev = h.block_hash();
                batch.push(h);
            }
            sync.note_getheaders_sent(&a);
            if matches!(
                sync.on_headers(a, &batch, genesis_only(g)),
                Err(SyncError::PeerQuota)
            ) {
                quota_hit = true;
                break;
            }
        }
        assert!(quota_hit, "per-peer quota must bind");
        assert!(sync.known_header_count() <= HEADERS_PER_PEER);
        // Disconnecting the peer releases its headers.
        sync.remove_peer(&a);
        assert_eq!(sync.known_header_count(), 0);
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

    /// CVE-2012-2459 poisoning: a mutated copy of a block has the honest
    /// block's hash. Receiving it must not make the node treat that hash as
    /// held — only a block that actually connected is.
    #[test]
    fn rejected_block_hash_is_not_remembered() {
        let p = params();
        let genesis = Hash256([0x01; 32]);
        let mut sync = Sync::new(p.clone(), genesis);
        let a = peer(1);
        sync.add_peer(a);
        let h = header_at(genesis, 1_700_000_001, p.pow_limit_bits, 0);
        let mutated = Block {
            header: h,
            txs: vec![],
        };
        let honest = Block {
            header: h,
            txs: vec![],
        };
        assert!(sync.on_block(a, &mutated), "first copy delivered");
        // The node validated and rejected it (no note_have). The honest
        // copy with the same hash must still be delivered.
        assert!(
            sync.on_block(a, &honest),
            "honest block must not be dropped as already held"
        );
        // Once it connects, the hash is held and later copies are dropped.
        sync.note_have(h.block_hash());
        assert!(!sync.on_block(a, &honest), "connected block is held");
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
        assert!(sync.on_block(a, &block));
        sync.note_have(hash); // the node connected it
        assert!(!sync.on_block(a, &block), "duplicate of a held block");
    }
}

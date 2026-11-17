//! P2P network driver: TCP listener, outbound dialer, per-peer sessions,
//! message dispatch into the node core, headers-first sync, and relay.
//!
//! Every peer is untrusted: bounded channels, handshake + stall timeouts,
//! peer-manager scoring/ban/diversity limits, and dedup'd relay.

use crate::core::{ADDRBOOK_CAP, Node, NodeInner};
use minibtc_consensus::ChainParams;
use minibtc_crypto::Hash256;
use minibtc_p2p::codec::{self, Message};
use minibtc_p2p::peer::{SCORE_BAD_BLOCK, SCORE_BAD_MESSAGE, SCORE_GOOD_BLOCK, SCORE_TIMEOUT};
use minibtc_primitives::Block;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::timeout;

/// Per-peer outbound queue depth — a stalled peer drops announcements.
const PEER_QUEUE: usize = 256;
/// getdata batch per request.
const GETDATA_BATCH: usize = 64;
/// getdata serve cap per message (peer-request bound). The requester asks
/// in chunks of at most this, and the server answers anything beyond it
/// with a `reject` instead of dropping it silently.
const SERVE_BATCH: usize = 128;
/// Most missing blocks one refill pass re-requests.
const REFILL_LIMIT: usize = 4_096;
/// Stall timeout: no message for this long → disconnect.
const STALL_TIMEOUT: Duration = Duration::from_secs(120);
/// Maintenance sweep interval.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Redial interval for the address book.
const REDIAL_INTERVAL: Duration = Duration::from_secs(60);

/// Ping interval per session — keeps `last_msg` fresh on idle links so
/// the 35s read timeout and 120s stall sweep never fire on a live peer.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
/// Our protocol version (MiniBTC wire version).
pub const PROTOCOL_VERSION: i32 = 70_015;
/// User agent string.
const USER_AGENT: &str = "/MiniBTC:0.1.0/";
/// Max addr entries learned per `addr` message.
const ADDR_LEARN_CAP: usize = 100;
/// Penalty for an unsolicited headers message that adds nothing (ten of
/// them reach the ban threshold).
const SCORE_USELESS_HEADERS: i32 = -10;
/// Max inv items processed per message.
const INV_PROCESS_CAP: usize = 1_024;
/// Accepted sockets allowed to be mid-handshake at once. Further inbound
/// connections are closed immediately instead of each holding a task, a
/// socket and (once admitted) a peer slot for the handshake timeout.
const MAX_PENDING_HANDSHAKES: usize = 16;

/// Start the P2P subsystem: listener + dialer + maintenance sweeps.
/// Returns when `node.cancel` is set or the listener fails to bind.
pub async fn run(node: Node, listen: SocketAddr, connect: Vec<SocketAddr>) {
    let listener = match TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(%listen, "p2p bind failed: {e}");
            return;
        }
    };
    tracing::info!(%listen, "p2p listening");

    // Seed the addrbook with explicit peers so `redial_addrbook`
    // retries them after a dropped session — otherwise a --connect
    // peer that times out is gone until restart.
    {
        let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        for addr in &connect {
            if !inner.addrbook.contains(addr) && inner.addrbook.len() < ADDRBOOK_CAP {
                inner.addrbook.push(*addr);
            }
        }
    }

    // Outbound dials for explicit seeds.
    for addr in connect {
        let n = node.clone();
        tokio::spawn(async move {
            dial_and_session(n, addr).await;
        });
    }

    // Accept loop. A permit from `handshakes` is taken before a session
    // task exists and held until its handshake ends.
    let accept_node = node.clone();
    let handshakes = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    let accept = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sleep_if_cancelled(&accept_node) => break,
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            let Ok(permit) = handshakes.clone().try_acquire_owned() else {
                                tracing::debug!(%addr, "too many pending handshakes; closing");
                                drop(stream);
                                continue;
                            };
                            let n = accept_node.clone();
                            tokio::spawn(async move {
                                accept_session(n, stream, addr, permit).await;
                            });
                        }
                        Err(e) => {
                            tracing::warn!("accept error: {e}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    });

    // Periodic: sweep stalled/unhandshaken peers + redial addrbook.
    let maint_node = node.clone();
    let maintenance = tokio::spawn(async move {
        let mut sweep_tick = tokio::time::interval(SWEEP_INTERVAL);
        let mut redial_tick = tokio::time::interval(REDIAL_INTERVAL);
        loop {
            tokio::select! {
                _ = sleep_if_cancelled(&maint_node) => break,
                _ = sweep_tick.tick() => sweep(&maint_node).await,
                _ = redial_tick.tick() => redial_addrbook(&maint_node).await,
            }
        }
    });

    let _ = tokio::join!(accept, maintenance);
}

/// Sleep-poll until cancel is set (select arm helper).
async fn sleep_if_cancelled(node: &Node) {
    loop {
        if node.cancel.load(Ordering::Relaxed) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Disconnect a peer by addr: drop its queue entry so the session's
/// writer ends, score it, and remove from tables.
fn disconnect(node: &Node, addr: SocketAddr) {
    node.peer_tx.lock().ok().map(|mut m| m.remove(&addr));
    let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
    inner.peers.remove(&addr);
    inner.sync.remove_peer(&addr);
    inner.requests.forget_peer(&addr);
    // Drop the TCP side too: the session notices its queue closed and
    // exits; the peer table entry is already gone.
}

/// Sweep: disconnect stalled + over-handshake-timeout peers, and expire
/// queued orphan blocks and unanswered block requests.
async fn sweep(node: &Node) {
    let bad: Vec<SocketAddr> = {
        let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        inner.pending.expire(now);
        // Expired requests are asked again, from another peer if possible.
        let expired: HashMap<Hash256, SocketAddr> =
            inner.requests.expire(now).into_iter().collect();
        let asks = refill_requests(&mut inner, None, &expired);
        drop(inner);
        send_refill(node, None, asks);
        let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .peers
            .snapshot()
            .into_iter()
            .filter(|(_, p)| {
                p.last_msg.elapsed() > STALL_TIMEOUT
                    || (!p.handshaken && p.connected_at.elapsed() > codec::HANDSHAKE_TIMEOUT)
            })
            .map(|(a, _)| a)
            .collect()
    };
    for addr in bad {
        tracing::info!(%addr, "disconnecting stalled/unhandshaken peer");
        disconnect(node, addr);
    }
}

/// Dial up to a few addrbook entries not already connected.
async fn redial_addrbook(node: &Node) {
    let seeds: Vec<SocketAddr> = {
        let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        let connected: HashSet<SocketAddr> = inner.peers.addrs().into_iter().collect();
        inner
            .addrbook
            .iter()
            .copied()
            .filter(|a| !connected.contains(a) && !inner.dialing.contains(a))
            .take(4)
            .collect()
    };
    for addr in seeds {
        let n = node.clone();
        tokio::spawn(async move {
            dial_and_session(n, addr).await;
        });
    }
}

/// Outbound dial → session. Admission checks happen before dialing.
async fn dial_and_session(node: Node, addr: SocketAddr) {
    {
        let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.peers.is_banned(&addr) {
            return;
        }
        // One dial per address, end to end: registered peers and
        // in-flight dials both block a duplicate.
        if inner.peers.get(&addr).is_some() || !inner.dialing.insert(addr) {
            return;
        }
        // admit() reserves the slot until the session ends.
        if let Err(e) = inner.peers.admit(addr, true) {
            inner.dialing.remove(&addr);
            tracing::debug!(%addr, "dial rejected: {e}");
            return;
        }
    }
    let stream = match timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.dialing.remove(&addr);
            inner.peers.remove(&addr); // release the reservation
            return;
        }
    };
    let _ = stream.set_nodelay(true);
    session(node.clone(), stream, addr, true, None).await;
    node.inner
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .dialing
        .remove(&addr);
}

/// Inbound accept path. `permit` bounds concurrent pre-handshake sockets.
pub async fn accept_session(
    node: Node,
    stream: TcpStream,
    addr: SocketAddr,
    permit: OwnedSemaphorePermit,
) {
    {
        let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.peers.is_banned(&addr) {
            return;
        }
        // admit() reserves the slot: concurrent handshakes count against
        // the per-IP, per-/16 and inbound caps from this moment.
        if let Err(e) = inner.peers.admit(addr, false) {
            tracing::debug!(%addr, "inbound rejected: {e}");
            return;
        }
    }
    let _ = stream.set_nodelay(true);
    session(node, stream, addr, false, Some(permit)).await;
}

/// Our `version` message payload — `start_height` is our real tip so a
/// taller peer knows to serve us headers (headers-first sync trigger).
fn our_version_msg(params: &ChainParams, start_height: i32) -> Message {
    Message::Version {
        version: PROTOCOL_VERSION,
        services: 0,
        timestamp: i64::from(codec::now_secs()),
        addr_recv: minibtc_p2p::codec::NetAddress {
            services: 0,
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: params.p2p_port,
        },
        addr_from: minibtc_p2p::codec::NetAddress {
            services: 0,
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 0,
        },
        nonce: 0,
        user_agent: USER_AGENT.to_string(),
        start_height,
        relay: true,
    }
}

/// One peer connection end-to-end: handshake → message loop → cleanup.
/// The caller has reserved `addr`'s slot (admit); every exit releases it.
/// `handshake_permit` (inbound only) is released once the handshake ends.
async fn session(
    node: Node,
    stream: TcpStream,
    addr: SocketAddr,
    outbound: bool,
    handshake_permit: Option<OwnedSemaphorePermit>,
) {
    let params = node.params.clone();
    let (mut rd, mut wr) = tokio::io::split(stream);

    // --- Handshake: both sides send `version` first ---
    let our_height = {
        let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.chain.height().min(i32::MAX as u32) as i32
    };
    let our_version = our_version_msg(&params, our_height);
    if timeout(
        codec::HANDSHAKE_TIMEOUT,
        codec::write_message(&mut wr, &our_version, &params),
    )
    .await
    .map_or(true, |r| r.is_err())
    {
        cleanup(&node, addr).await;
        return;
    }
    let their_version = match timeout(codec::HANDSHAKE_TIMEOUT, codec::recv(&mut rd, &params)).await
    {
        Ok(Ok(m @ Message::Version { .. })) => m,
        _ => {
            cleanup(&node, addr).await;
            return;
        }
    };

    // Fill the reserved slot (caps were applied when it was reserved).
    {
        let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = inner.peers.register(addr, outbound, &their_version) {
            tracing::debug!(%addr, "register rejected: {e}");
            inner.peers.remove(&addr);
            return;
        }
    }

    // Verack exchange.
    if codec::write_message(&mut wr, &Message::Verack, &params)
        .await
        .is_err()
    {
        cleanup(&node, addr).await;
        return;
    }
    match timeout(codec::HANDSHAKE_TIMEOUT, codec::recv(&mut rd, &params)).await {
        Ok(Ok(Message::Verack)) => {}
        _ => {
            cleanup(&node, addr).await;
            return;
        }
    }

    // Handshake complete: free the pre-handshake permit.
    drop(handshake_permit);
    {
        let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.peers.mark_handshaken(&addr);
        inner.sync.add_peer(addr);
    }
    tracing::debug!(%addr, outbound, "peer handshake complete");

    // If the peer announced a higher start height, request headers.
    if let Message::Version { start_height, .. } = their_version {
        let our_h = {
            let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.chain.height()
        };
        if i64::from(start_height) > i64::from(our_h) {
            let locator = {
                let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.sync.note_getheaders_sent(&addr);
                sync_locator(&inner)
            };
            let _ = codec::write_message(
                &mut wr,
                &Message::GetHeaders {
                    locator,
                    stop: Hash256::ZERO,
                },
                &params,
            )
            .await;
        }
    }

    // --- Message loop ---
    // Outbound queue: RPC/P2P producers push; the writer drains.
    let (tx, mut rx) = mpsc::channel::<Message>(PEER_QUEUE);
    node.peer_tx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(addr, tx.clone());

    // Writer task owns `wr` (params cloned — reader keeps its own).
    // Keepalive: ping every KEEPALIVE_INTERVAL of writer-idle time so
    // quiet sessions stay alive (pong refreshes the peer's last_msg).
    let writer_params = params.clone();
    let writer = tokio::spawn(async move {
        let mut keepalive = tokio::time::interval_at(
            tokio::time::Instant::now() + KEEPALIVE_INTERVAL,
            KEEPALIVE_INTERVAL,
        );
        let mut nonce: u64 = 1;
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    let Some(msg) = msg else { break };
                    if codec::write_message(&mut wr, &msg, &writer_params)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                _ = keepalive.tick() => {
                    if codec::write_message(&mut wr, &Message::Ping(nonce), &writer_params)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    nonce = nonce.wrapping_add(1);
                }
            }
        }
    });

    // Reader loop.
    loop {
        match timeout(
            codec::IO_TIMEOUT + Duration::from_secs(5),
            codec::recv(&mut rd, &params),
        )
        .await
        {
            Ok(Ok(msg)) => {
                {
                    let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
                    inner.peers.touch(&addr);
                }
                if !handle_message(&node, addr, msg, &tx).await {
                    break;
                }
            }
            Ok(Err(e)) => {
                tracing::debug!(%addr, "wire error: {e}");
                {
                    let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
                    inner.peers.score(&addr, SCORE_TIMEOUT);
                }
                break;
            }
            Err(_) => {
                // Read timeout — sweep also catches stalls; disconnect now.
                break;
            }
        }
    }

    // --- Cleanup ---
    node.peer_tx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&addr);
    writer.abort();
    cleanup(&node, addr).await;
}

/// Remove peer state on session end.
async fn cleanup(node: &Node, addr: SocketAddr) {
    let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
    inner.peers.remove(&addr);
    inner.sync.remove_peer(&addr);
    inner.requests.forget_peer(&addr);
}

/// A locator from our tip.
fn sync_locator(inner: &NodeInner) -> Vec<Hash256> {
    locator_from(inner, inner.chain.tip)
}

/// The locator for continuing header sync with `peer`: from the best
/// header it sent us while that block has not connected (it is ahead of
/// us, possibly on another branch), else from our tip. Building it only
/// from our tip made every answer repeat the first 2,000 headers past the
/// fork, so a fork deeper than that on both sides never resolved.
fn peer_locator(inner: &NodeInner, peer: &SocketAddr) -> Vec<Hash256> {
    match inner.sync.best_header(peer) {
        Some(h) if !inner.chain.blocks.contains_key(&h) => locator_from(inner, h),
        _ => sync_locator(inner),
    }
}

/// Bitcoin-style block locator starting at `start` (a block in the index
/// or an indexed header): ten hashes one apart, then the step doubles,
/// always ending with genesis. At most 64 entries (the codec allows 128),
/// which reaches back far beyond any chain this devnet can build.
fn locator_from(inner: &NodeInner, start: Hash256) -> Vec<Hash256> {
    let genesis = inner.chain.genesis;
    let prev_of = |h: &Hash256| -> Option<Hash256> {
        inner
            .chain
            .blocks
            .get(h)
            .map(|r| r.block.header.prev_hash)
            .or_else(|| inner.sync.header_info(h).map(|i| i.prev))
    };
    let mut loc = Vec::new();
    let mut cur = start;
    let mut step = 1usize;
    while loc.len() < 63 {
        loc.push(cur);
        if cur == genesis {
            break;
        }
        if loc.len() >= 10 {
            step = step.saturating_mul(2);
        }
        for _ in 0..step {
            match prev_of(&cur) {
                Some(p) if p != Hash256::ZERO && cur != genesis => cur = p,
                _ => {
                    cur = genesis;
                    break;
                }
            }
        }
    }
    if loc.last() != Some(&genesis) {
        loc.push(genesis);
    }
    loc
}

/// Handle one inbound message. Returns false to end the session.
async fn handle_message(
    node: &Node,
    addr: SocketAddr,
    msg: Message,
    reply: &mpsc::Sender<Message>,
) -> bool {
    match msg {
        Message::Version { .. } | Message::Verack => {
            // Post-handshake duplicates are protocol violations.
            let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.peers.score(&addr, SCORE_BAD_MESSAGE);
            false
        }
        Message::Ping(nonce) => {
            let _ = reply.try_send(Message::Pong(nonce));
            true
        }
        Message::Pong(_) => true,

        Message::Inv(items) => {
            handle_inv(node, addr, &items, reply).await;
            true
        }

        Message::GetData(items) => {
            handle_getdata(node, addr, &items, reply).await;
            true
        }

        Message::Tx(tx) => {
            let txid = tx.txid();
            match node.accept_tx(tx, None, Some(addr)) {
                Ok(_) => {}
                Err(crate::core::AcceptError::Invalid(e)) => {
                    tracing::debug!(%addr, %txid, "invalid tx: {e}");
                    let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
                    inner.peers.score(&addr, SCORE_BAD_MESSAGE);
                }
                Err(crate::core::AcceptError::Policy(e)) => {
                    tracing::debug!(%addr, %txid, "policy reject: {e}");
                }
            }
            true
        }

        Message::Block(block) => {
            handle_block(node, addr, block, reply).await;
            true
        }

        Message::Headers { headers, .. } => {
            let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
            // Headers extend our tip sequentially (on_headers enforces
            // linkage), so the batch's last header sits at
            // tip_height_at_receipt + len(headers).
            let base_h = inner.chain.height();
            let NodeInner { sync, chain, .. } = &mut *inner;
            let lookup = |h: &Hash256| {
                chain.blocks.get(h).map(|r| minibtc_p2p::sync::HeaderInfo {
                    height: r.height,
                    bits: r.block.header.bits,
                    time: r.block.header.time,
                    prev: r.block.header.prev_hash,
                })
            };
            match sync.on_headers(addr, &headers, lookup) {
                Ok(_) => {
                    let claimed_h = base_h.saturating_add(headers.len() as u32);
                    inner
                        .claimed
                        .entry(addr)
                        .and_modify(|c| *c = (*c).max(claimed_h))
                        .or_insert(claimed_h);
                    // Drain the whole wanted queue — chunked getdata — then
                    // ask for indexed headers whose blocks went missing
                    // (for example served past a peer's per-getdata limit).
                    let want = drain_wanted(&mut inner, addr);
                    let asks = refill_requests(&mut inner, Some(addr), &HashMap::new());
                    // A full batch means there is more: continue right after
                    // its last header (not from our tip, which may be on
                    // another branch below the batch).
                    let more = (headers.len() == minibtc_p2p::sync::HEADERS_BATCH).then(|| {
                        inner.sync.note_getheaders_sent(&addr);
                        peer_locator(&inner, &addr)
                    });
                    drop(inner);
                    send_getdata(reply, want);
                    send_refill(node, Some((addr, reply)), asks);
                    if let Some(locator) = more {
                        let _ = reply.try_send(Message::GetHeaders {
                            locator,
                            stop: Hash256::ZERO,
                        });
                    }
                }
                Err(e) => {
                    tracing::debug!(%addr, "bad headers: {e}");
                    // Unsolicited nothing-new batches cost less than invalid
                    // ones but still add up to a ban; every other error is
                    // a protocol violation.
                    let penalty = match e {
                        minibtc_p2p::sync::SyncError::NothingNew => SCORE_USELESS_HEADERS,
                        _ => SCORE_BAD_MESSAGE,
                    };
                    inner.peers.score(&addr, penalty);
                }
            }
            true
        }

        Message::GetHeaders { locator, stop } => {
            // Serve headers building on the requester's locator, in
            // forward (oldest→newest) order — the wire convention.
            let headers = {
                let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
                active_headers(&inner, &locator, stop, 2_000)
            };
            let count = headers.len() as u32;
            let _ = reply.try_send(Message::Headers { count, headers });
            true
        }

        Message::Addr(addrs) => {
            learn_addrs(node, &addrs);
            true
        }

        Message::Reject { .. } => {
            // Peer declined our request — mild signal, no ban.
            let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.peers.score(&addr, -5);
            true
        }
    }
}

/// Process an `inv`: request what we don't have (bounded).
async fn handle_inv(
    node: &Node,
    addr: SocketAddr,
    items: &[minibtc_p2p::codec::InvItem],
    reply: &mpsc::Sender<Message>,
) {
    use minibtc_p2p::codec::InvType;
    let mut want: Vec<minibtc_p2p::codec::InvItem> = Vec::new();
    {
        let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        for item in items.iter().take(INV_PROCESS_CAP) {
            match item.kind {
                InvType::Tx => {
                    let have = inner.mempool.get(&item.hash).is_some()
                        || inner.txindex.contains_key(&item.hash);
                    if !have {
                        want.push(*item);
                    }
                }
                InvType::Block
                    if !inner.chain.blocks.contains_key(&item.hash)
                        && !inner.pending.contains(&item.hash) =>
                {
                    want.push(*item);
                }
                InvType::Block => {}
                _ => {}
            }
            if want.len() >= GETDATA_BATCH {
                break;
            }
        }
        // Remember which blocks we asked this peer for: only those may wait
        // in the out-of-order queue.
        let now = std::time::Instant::now();
        for item in want.iter().filter(|i| i.kind == InvType::Block) {
            inner.requests.note(item.hash, addr, now);
        }
    }
    if !want.is_empty() {
        let _ = reply.try_send(Message::GetData(want));
    }
}

/// Serve a `getdata`: txs from mempool/index, blocks from the block index.
/// At most `SERVE_BATCH` items per message; the rest is answered with a
/// `reject` so the requester knows (it also re-requests missing blocks on
/// its own). Replies wait for room in the peer's queue (bounded, with a
/// deadline) instead of being dropped when it is momentarily full.
async fn handle_getdata(
    node: &Node,
    _addr: SocketAddr,
    items: &[minibtc_p2p::codec::InvItem],
    reply: &mpsc::Sender<Message>,
) {
    use minibtc_p2p::codec::InvType;
    let mut out: Vec<Message> = Vec::new();
    {
        let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        for item in items.iter().take(SERVE_BATCH) {
            match item.kind {
                InvType::Tx => {
                    if let Some(tx) = crate::core::find_tx(node, &inner, &item.hash) {
                        out.push(Message::Tx(tx));
                    }
                }
                InvType::Block => {
                    if let Some(rec) = inner.chain.blocks.get(&item.hash) {
                        out.push(Message::Block(rec.block.clone()));
                    }
                }
                _ => {}
            }
        }
    }
    if items.len() > SERVE_BATCH {
        out.push(Message::Reject {
            message: "getdata".to_string(),
            code: 0x41, // Bitcoin's REJECT_NONSTANDARD: valid, but over our limit
            reason: format!(
                "served the first {SERVE_BATCH} of {} items; ask again for the rest",
                items.len()
            ),
        });
    }
    for m in out {
        match timeout(codec::IO_TIMEOUT, reply.send(m)).await {
            Ok(Ok(())) => {}
            _ => break, // peer gone or not reading: the session ends
        }
    }
}

/// Request blocks for indexed headers that are neither held, queued nor in
/// flight. Each goes to `prefer` (the peer just heard from), else the peer
/// that sent the header, else any other sync peer — but not to the peer in
/// `avoid` that let an earlier request for it expire, unless no one else
/// is connected. Returns the hashes to ask each peer for.
fn refill_requests(
    inner: &mut NodeInner,
    prefer: Option<SocketAddr>,
    avoid: &HashMap<Hash256, SocketAddr>,
) -> HashMap<SocketAddr, Vec<Hash256>> {
    let now = std::time::Instant::now();
    let peers = inner.sync.peer_addrs();
    let mut asks: HashMap<SocketAddr, Vec<Hash256>> = HashMap::new();
    for (hash, source) in inner.sync.missing_blocks(REFILL_LIMIT) {
        if inner.pending.contains(&hash) || inner.requests.is_requested(&hash) {
            continue;
        }
        let failed = avoid.get(&hash);
        let candidates = prefer
            .into_iter()
            .chain(std::iter::once(source))
            .chain(peers.iter().copied())
            .filter(|p| peers.contains(p));
        let mut fallback = None;
        let mut pick = None;
        for p in candidates {
            if Some(&p) == failed {
                fallback.get_or_insert(p);
                continue;
            }
            pick = Some(p);
            break;
        }
        let Some(peer) = pick.or(fallback) else {
            continue;
        };
        if inner.requests.note(hash, peer, now) {
            asks.entry(peer).or_default().push(hash);
        }
    }
    asks
}

/// Send refill requests: through `reply` for `current`, through the peer
/// queues for everyone else.
fn send_refill(
    node: &Node,
    current: Option<(SocketAddr, &mpsc::Sender<Message>)>,
    asks: HashMap<SocketAddr, Vec<Hash256>>,
) {
    if asks.is_empty() {
        return;
    }
    let senders: HashMap<SocketAddr, mpsc::Sender<Message>> =
        node.peer_tx.lock().map(|m| m.clone()).unwrap_or_default();
    for (peer, hashes) in asks {
        match current {
            Some((addr, reply)) if addr == peer => send_getdata(reply, hashes),
            _ => {
                if let Some(tx) = senders.get(&peer) {
                    send_getdata(tx, hashes);
                }
            }
        }
    }
}

/// Queue an inbound block and drain whatever became connectable.
async fn handle_block(node: &Node, addr: SocketAddr, block: Block, reply: &mpsc::Sender<Message>) {
    // Context-free checks first (cheap, no lock): merkle root + mutation
    // and proof of work. A mutated block (CVE-2012-2459) shares the honest
    // block's hash, so it is dropped here without its hash entering `have`
    // or the pending queue — the honest copy can still arrive and connect.
    if let Err(e) = crate::core::precheck_block(&node.params, &block) {
        tracing::debug!(%addr, "block failed precheck: {e}");
        let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.peers.score(&addr, SCORE_BAD_BLOCK);
        return;
    }
    {
        let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        let hash = block.header.block_hash();
        // Only a block we asked this peer for may wait for its parent; an
        // unasked block is processed only if it can connect right now.
        let requested = inner.requests.take(&hash, addr, now);
        let parent_known = inner.chain.blocks.contains_key(&block.header.prev_hash);
        if !requested && !parent_known {
            tracing::debug!(%addr, %hash, "dropping unrequested orphan block");
            return;
        }
        // sync.on_block records per-peer progress and returns false for
        // blocks already connected; `have` is set only after a connect.
        if !inner.sync.on_block(addr, &block) {
            return;
        }
        if !inner.pending.push(block, now) {
            return; // queue full (count or bytes) or already queued
        }
        // An orphan means this peer is on a branch we have not seen: ask it
        // for the headers between our chain and its block (Bitcoin Core
        // does the same). Without this a reorg never reaches a node that
        // hears about it only through a relay — the relay announces only
        // the new tip blocks, whose ancestors we never requested.
        if !parent_known {
            let locator = sync_locator(&inner);
            inner.sync.note_getheaders_sent(&addr);
            let _ = reply.try_send(Message::GetHeaders {
                locator,
                stop: Hash256::ZERO,
            });
        }
    }
    drain_pending(node, addr, reply).await;
}

/// Connect pending blocks whose parents are known, in arrival order.
/// Stops at the first unconnectable gap — later arrivals retry on the
/// next block/headers event.
async fn drain_pending(node: &Node, origin: SocketAddr, reply: &mpsc::Sender<Message>) {
    loop {
        let next = {
            let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
            let NodeInner { pending, chain, .. } = &mut *inner;
            pending.pop_connectable(&chain.blocks)
        };
        let Some(block) = next else { break };
        let hash = block.header.block_hash();
        match node.connect_block(block) {
            Ok(crate::core::ConnectOutcome::Connected) => {
                node.relay_block(hash);
                let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.peers.score(&origin, SCORE_GOOD_BLOCK);
            }
            Ok(crate::core::ConnectOutcome::SideBranch) => {
                let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.peers.score(&origin, SCORE_GOOD_BLOCK);
            }
            Ok(crate::core::ConnectOutcome::AlreadyHave) => {}
            Err(e) => {
                tracing::debug!(%origin, "block rejected: {e}");
                let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.peers.score(&origin, SCORE_BAD_BLOCK);
                break;
            }
        }
    }
    // Pending drained — pull the next wanted batch, and if the peer
    // claims more height than we have, ask for the next headers batch.
    let (want, asks, need_headers) = {
        let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        let want = drain_wanted(&mut inner, origin);
        // Nothing left in flight to this peer: re-request indexed headers
        // whose blocks never arrived.
        let asks = if inner.requests.in_flight(&origin) == 0 {
            refill_requests(&mut inner, Some(origin), &HashMap::new())
        } else {
            HashMap::new()
        };
        let our_h = inner.chain.height();
        let claimed = inner.claimed.get(&origin).copied().unwrap_or(0);
        (want, asks, claimed > our_h)
    };
    send_getdata(reply, want);
    send_refill(node, Some((origin, reply)), asks);
    if need_headers {
        let locator = {
            let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.sync.note_getheaders_sent(&origin);
            peer_locator(&inner, &origin)
        };
        let _ = reply.try_send(Message::GetHeaders {
            locator,
            stop: Hash256::ZERO,
        });
    }
}

/// Pop all wanted block hashes for `peer`, chunked for getdata, and
/// record them as requested from that peer.
fn drain_wanted(inner: &mut NodeInner, peer: SocketAddr) -> Vec<Hash256> {
    let mut out = Vec::new();
    loop {
        let batch = inner.sync.next_getdata(&peer);
        if batch.is_empty() {
            break;
        }
        out.extend(batch);
        if out.len() >= 8_192 {
            break; // sanity cap — wanted is already window-bounded
        }
    }
    let now = std::time::Instant::now();
    for h in &out {
        inner.requests.note(*h, peer, now);
    }
    out
}

/// Send wanted hashes as GetData messages of at most `SERVE_BATCH` items —
/// the most a peer serves per message.
fn send_getdata(reply: &mpsc::Sender<Message>, want: Vec<Hash256>) {
    for chunk in want.chunks(SERVE_BATCH) {
        let items: Vec<minibtc_p2p::codec::InvItem> = chunk
            .iter()
            .map(|h| minibtc_p2p::codec::InvItem {
                kind: minibtc_p2p::codec::InvType::Block,
                hash: *h,
            })
            .collect();
        if reply.try_send(Message::GetData(items)).is_err() {
            break;
        }
    }
}

/// Learn addresses from an `addr` message (bounded, dedup'd, global-ish).
fn learn_addrs(node: &Node, addrs: &[(minibtc_p2p::codec::NetAddress, u32)]) {
    let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
    for (a, _ts) in addrs.iter().take(ADDR_LEARN_CAP) {
        let ip = a.ip;
        // Skip unspecified/loopback/multicast for outbound dialing.
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
            continue;
        }
        let sa = SocketAddr::new(ip, a.port);
        if inner.peers.is_banned(&sa) || inner.addrbook.contains(&sa) {
            continue;
        }
        if inner.addrbook.len() >= ADDRBOOK_CAP {
            break;
        }
        inner.addrbook.push(sa);
    }
}

/// Active-chain headers after `locator`'s match point, in forward
/// (oldest→newest) order, honoring `stop`. Returns up to `cap` headers.
fn active_headers(
    inner: &NodeInner,
    locator: &[Hash256],
    stop: Hash256,
    cap: usize,
) -> Vec<minibtc_primitives::BlockHeader> {
    // Collect the active chain tip→genesis, then reverse to forward order.
    let mut chain_hdrs: Vec<minibtc_primitives::BlockHeader> = Vec::new();
    let mut cur = inner.chain.tip;
    while let Some(rec) = inner.chain.blocks.get(&cur) {
        if rec.status != minibtc_chainstate::BlockStatus::Active {
            break;
        }
        chain_hdrs.push(rec.block.header);
        if rec.block.header.prev_hash == Hash256::ZERO {
            break;
        }
        cur = rec.block.header.prev_hash;
    }
    chain_hdrs.reverse(); // genesis → tip

    // Find the locator match: the newest locator hash present on chain.
    let mut start = 0usize;
    'outer: for lh in locator.iter().take(128) {
        for (i, h) in chain_hdrs.iter().enumerate().rev() {
            if h.block_hash() == *lh {
                start = i + 1;
                break 'outer;
            }
        }
    }

    // Genesis is implicit knowledge — never serve it as a "new" header.
    let start = start.max(1);
    let mut out = Vec::new();
    for h in chain_hdrs.iter().skip(start) {
        if h.block_hash() == stop {
            break;
        }
        out.push(*h);
        if out.len() >= cap {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    //! In-process network: real `handle_message` on memory-only nodes,
    //! one bounded channel per directed link, and a pump that delivers
    //! messages until the network is quiet. A link can be held to
    //! simulate a partition (its messages wait until it is released).

    use super::*;
    use crate::core::in_memory;
    use std::collections::{HashMap, HashSet};

    struct TestNet {
        nodes: Vec<Node>,
        addrs: Vec<SocketAddr>,
        /// (from, to) → receiver of messages `from` sends to `to`.
        links: Vec<((usize, usize), mpsc::Receiver<Message>)>,
        /// (from, to) → sender used as `reply` when `to` handles a message
        /// from `from` — i.e. the channel to → from.
        senders: HashMap<(usize, usize), mpsc::Sender<Message>>,
        held: HashSet<(usize, usize)>,
    }

    impl TestNet {
        fn new(n: usize) -> Self {
            Self::with_params(n, ChainParams::devnet())
        }

        /// Devnet with a retarget window too long to reach: burst-mined
        /// blocks keep the easiest bits, so thousands can be mined quickly.
        fn no_retarget(n: usize) -> Self {
            let mut p = ChainParams::devnet();
            p.name = "minibtc-no-retarget-test".to_string();
            p.pow_target_timespan_blocks = 1_000_000;
            Self::with_params(n, p)
        }

        fn with_params(n: usize, params: ChainParams) -> Self {
            Self {
                nodes: (0..n).map(|_| in_memory(params.clone())).collect(),
                addrs: (0..n)
                    .map(|i| SocketAddr::from(([10, 0, i as u8 + 1, 1], 18_445)))
                    .collect(),
                links: Vec::new(),
                senders: HashMap::new(),
                held: HashSet::new(),
            }
        }

        /// Connect `a` and `b` (both directions), as a finished handshake.
        fn connect(&mut self, a: usize, b: usize) {
            for (from, to) in [(a, b), (b, a)] {
                let (tx, rx) = mpsc::channel::<Message>(4_096);
                // `from` sends to `to` through `tx`: register it in from's
                // peer table under to's address.
                self.nodes[from]
                    .peer_tx
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(self.addrs[to], tx.clone());
                self.senders.insert((from, to), tx);
                self.links.push(((from, to), rx));
                let mut inner = self.nodes[from]
                    .inner
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let v = our_version_msg(&self.nodes[from].params, 0);
                inner
                    .peers
                    .register(self.addrs[to], true, &v)
                    .unwrap_or_else(|e| panic!("register: {e:?}"));
                inner.peers.mark_handshaken(&self.addrs[to]);
                inner.sync.add_peer(self.addrs[to]);
            }
        }

        /// Node `a` asks `b` for headers, as a session does after the
        /// handshake when `b` claims a higher start height.
        fn ask_headers(&self, a: usize, b: usize) {
            let locator = {
                let mut inner = self.nodes[a]
                    .inner
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                inner.sync.note_getheaders_sent(&self.addrs[b]);
                sync_locator(&inner)
            };
            self.senders[&(a, b)]
                .try_send(Message::GetHeaders {
                    locator,
                    stop: Hash256::ZERO,
                })
                .unwrap_or_else(|e| panic!("queue getheaders: {e}"));
        }

        fn hold(&mut self, a: usize, b: usize) {
            self.held.insert((a, b));
            self.held.insert((b, a));
        }

        fn release(&mut self, a: usize, b: usize) {
            self.held.remove(&(a, b));
            self.held.remove(&(b, a));
        }

        /// Deliver messages until quiet, dropping those `drop_msg` selects
        /// (a lossy link).
        async fn pump_dropping<F>(&mut self, mut drop_msg: F)
        where
            F: FnMut(usize, usize, &Message) -> bool,
        {
            for _ in 0..10_000 {
                let mut delivered = false;
                for i in 0..self.links.len() {
                    let (from, to) = self.links[i].0;
                    if self.held.contains(&(from, to)) {
                        continue;
                    }
                    while let Ok(msg) = self.links[i].1.try_recv() {
                        delivered = true;
                        if drop_msg(from, to, &msg) {
                            continue;
                        }
                        let reply = self.senders[&(to, from)].clone();
                        let node = self.nodes[to].clone();
                        handle_message(&node, self.addrs[from], msg, &reply).await;
                    }
                }
                if !delivered {
                    return;
                }
            }
            panic!("network never went quiet");
        }

        /// Run node `i`'s periodic sweep as if `REQUEST_TTL` had passed:
        /// expired block requests are asked again.
        fn sweep_after_ttl(&self, i: usize) {
            let node = &self.nodes[i];
            let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
            let later = std::time::Instant::now() + crate::core::REQUEST_TTL * 2;
            let expired: HashMap<Hash256, SocketAddr> =
                inner.requests.expire(later).into_iter().collect();
            let asks = refill_requests(&mut inner, None, &expired);
            drop(inner);
            send_refill(node, None, asks);
        }

        /// Deliver messages until no link carries any (bounded rounds).
        async fn pump(&mut self) {
            for _ in 0..10_000 {
                let mut delivered = false;
                for i in 0..self.links.len() {
                    let (from, to) = self.links[i].0;
                    if self.held.contains(&(from, to)) {
                        continue;
                    }
                    while let Ok(msg) = self.links[i].1.try_recv() {
                        delivered = true;
                        let reply = self.senders[&(to, from)].clone();
                        let node = self.nodes[to].clone();
                        handle_message(&node, self.addrs[from], msg, &reply).await;
                    }
                }
                if !delivered {
                    return;
                }
            }
            panic!("network never went quiet");
        }

        fn tip(&self, i: usize) -> (Hash256, u32) {
            let inner = self.nodes[i]
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            (inner.chain.tip, inner.chain.height())
        }

        /// Mine `n` blocks on node `i`, paying a key unique to that node
        /// (otherwise two nodes mining in the same second build identical
        /// blocks and there is no fork at all).
        fn mine(&self, i: usize, n: u64) {
            let key = minibtc_crypto::Keypair::from_secret_bytes(&[i as u8 + 1; 32])
                .unwrap_or_else(|e| panic!("key: {e:?}"));
            let payout = minibtc_script::Script::p2pkh(&key.public_key().key_hash()).0;
            self.nodes[i]
                .generate(n, &payout)
                .unwrap_or_else(|e| panic!("mine: {e:?}"));
        }
    }

    /// A signed spend of node `i`'s coinbase at `height` (paid to the
    /// node's own key by `mine`).
    fn spend_coinbase(net: &TestNet, i: usize, height: u32) -> minibtc_primitives::Transaction {
        use minibtc_primitives::{OutPoint, Sats, Transaction, TxInput, TxOutput};
        let key = minibtc_crypto::Keypair::from_secret_bytes(&[i as u8 + 1; 32])
            .unwrap_or_else(|e| panic!("key: {e:?}"));
        let inner = net.nodes[i].inner.lock().unwrap_or_else(|e| e.into_inner());
        let at = crate::core::block_at_height(&inner, height)
            .unwrap_or_else(|| panic!("no block at {height}"));
        let cb = inner.chain.blocks[&at].block.txs[0].clone();
        let prev_spk = cb.outputs[0].script_pubkey.clone();
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev: OutPoint {
                    txid: cb.txid(),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: Sats(cb.outputs[0].value.sats() - 10_000),
                script_pubkey: prev_spk.clone(),
            }],
            locktime: 0,
        };
        let sig = minibtc_script::sighash::sign_input(&tx, 0, &prev_spk, &key)
            .unwrap_or_else(|e| panic!("sign: {e:?}"));
        tx.inputs[0].script_sig = minibtc_script::Script::p2pkh_spend(&sig, &key.public_key()).0;
        tx
    }

    #[tokio::test]
    async fn reorged_out_transactions_return_to_the_mempool() {
        let mut net = TestNet::new(2);
        net.connect(0, 1);
        net.mine(0, 101); // N1's coinbase at height 1 is now mature
        net.pump().await;
        assert_eq!(net.tip(1), net.tip(0));

        // Partition, then N1 confirms T in one block; N2 mines two without it.
        net.hold(0, 1);
        let t = spend_coinbase(&net, 0, 1);
        let txid = t.txid();
        net.nodes[0]
            .accept_tx(t, None, None)
            .unwrap_or_else(|e| panic!("accept: {e:?}"));
        net.mine(0, 1);
        {
            let inner = net.nodes[0].inner.lock().unwrap_or_else(|e| e.into_inner());
            assert!(inner.mempool.get(&txid).is_none(), "T confirmed on N1");
            assert!(inner.txindex.contains_key(&txid));
        }
        net.mine(1, 2);
        net.release(0, 1);
        net.pump().await;
        assert_eq!(net.tip(0), net.tip(1), "N1 reorged onto N2's branch");

        let inner = net.nodes[0].inner.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            inner.mempool.get(&txid).is_some(),
            "a reorged-out transaction must go back to the mempool"
        );
        assert!(
            !inner.txindex.contains_key(&txid),
            "txindex must not point at a block that left the active chain"
        );
        assert_eq!(crate::core::tx_confirmations(&inner, &txid), None);
    }

    #[tokio::test]
    async fn a_peer_replaying_one_header_is_banned_and_stores_nothing() {
        // The live 2026-11-16 flood: one header mined once (about two
        // hashes at the devnet limit) sent over and over.
        let net = TestNet::new(1);
        let node = net.nodes[0].clone();
        let attacker = SocketAddr::from(([10, 66, 6, 6], 18_445));
        let (reply, mut rx) = mpsc::channel::<Message>(4_096);
        let genesis = {
            let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
            let v = our_version_msg(&node.params, 0);
            inner.peers.register(attacker, false, &v).unwrap();
            inner.peers.mark_handshaken(&attacker);
            inner.sync.add_peer(attacker);
            inner.chain.blocks[&inner.chain.genesis].block.header
        };
        let target = minibtc_consensus::target_for_bits(genesis.bits).unwrap();
        let mut h = minibtc_primitives::BlockHeader {
            version: 1,
            prev_hash: genesis.block_hash(),
            merkle_root: Hash256([0x42; 32]),
            time: genesis.time + 31,
            bits: genesis.bits,
            nonce: 0,
        };
        while !h.check_pow(&target) {
            h.nonce += 1;
        }
        let flood = Message::Headers {
            count: 2_000,
            headers: vec![h; 2_000],
        };
        let single = Message::Headers {
            count: 1,
            headers: vec![h],
        };
        let mut sent = 0usize;
        for i in 0..200 {
            if node
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .peers
                .is_banned(&attacker)
            {
                break;
            }
            let msg = if i % 2 == 0 {
                flood.clone()
            } else {
                single.clone()
            };
            handle_message(&node, attacker, msg, &reply).await;
            sent += 1;
            while rx.try_recv().is_ok() {}
        }
        let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            inner.peers.is_banned(&attacker),
            "the replaying peer must be banned (sent {sent} messages)"
        );
        assert!(sent <= 20, "banned within a few messages, took {sent}");
        assert!(inner.sync.known_header_count() <= 1, "nothing accumulates");
    }

    #[tokio::test]
    async fn a_node_1000_blocks_behind_catches_up() {
        // The serving side answers at most SERVE_BATCH blocks per getdata.
        // A node far behind must still get every block: more than 128 used
        // to leave it stuck at height 128 for good.
        let mut net = TestNet::no_retarget(2);
        net.mine(0, 1_000);
        assert_eq!(net.tip(0).1, 1_000);
        net.connect(0, 1);
        net.ask_headers(1, 0);
        net.pump().await;
        assert_eq!(
            net.tip(1),
            net.tip(0),
            "the node must catch up all 1,000 blocks"
        );
    }

    #[tokio::test]
    async fn a_fork_deeper_than_one_headers_batch_resolves() {
        // Both branches are longer than one headers answer (2,000). N1 must
        // learn all 2,350 headers of the heavier branch, not the same first
        // 2,000 again and again.
        let mut net = TestNet::no_retarget(2);
        net.mine(0, 2_150);
        net.mine(1, 2_350);
        net.connect(0, 1);
        net.ask_headers(0, 1);
        net.pump().await;
        assert_eq!(net.tip(1).1, 2_350);
        assert_eq!(
            net.tip(0),
            net.tip(1),
            "N1 must reorg onto the heavier 2,350-block branch"
        );
    }

    #[tokio::test]
    async fn blocks_lost_in_transit_are_requested_again() {
        // 300 blocks behind; the link drops the first 40 blocks it carries.
        // The headers stay indexed, so only a re-request after the request
        // expires can recover them.
        let mut net = TestNet::no_retarget(2);
        net.mine(0, 300);
        net.connect(0, 1);
        net.ask_headers(1, 0);
        let mut dropped = 0;
        net.pump_dropping(|from, _to, msg| {
            if from == 0 && matches!(msg, Message::Block(_)) && dropped < 40 {
                dropped += 1;
                return true;
            }
            false
        })
        .await;
        assert!(net.tip(1).1 < 300, "the lossy link must have stalled sync");
        net.sweep_after_ttl(1);
        net.pump().await;
        assert_eq!(
            net.tip(1),
            net.tip(0),
            "lost blocks must be requested again"
        );
    }

    #[tokio::test]
    async fn an_oversized_getdata_is_served_up_to_the_limit_and_rejected_past_it() {
        let net = TestNet::no_retarget(1);
        net.mine(0, 200);
        let node = net.nodes[0].clone();
        let items: Vec<minibtc_p2p::codec::InvItem> = {
            let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
            (1..=200u32)
                .map(|h| minibtc_p2p::codec::InvItem {
                    kind: minibtc_p2p::codec::InvType::Block,
                    hash: crate::core::block_at_height(&inner, h).unwrap(),
                })
                .collect()
        };
        let (reply, mut rx) = mpsc::channel::<Message>(1_024);
        let asker = SocketAddr::from(([10, 1, 2, 3], 1));
        handle_getdata(&node, asker, &items, &reply).await;
        let mut blocks = 0;
        let mut rejects = 0;
        while let Ok(m) = rx.try_recv() {
            match m {
                Message::Block(_) => blocks += 1,
                Message::Reject { .. } => rejects += 1,
                _ => {}
            }
        }
        assert_eq!(blocks, SERVE_BATCH);
        assert_eq!(rejects, 1, "the unserved rest is not dropped silently");
    }

    #[tokio::test]
    async fn reorg_reaches_a_node_connected_only_through_a_relay() {
        // N3 — N1 — N2: N2 hears about N3's blocks only through N1.
        let mut net = TestNet::new(3);
        net.connect(0, 1);
        net.connect(0, 2);
        net.mine(0, 5);
        net.pump().await;
        assert_eq!(net.tip(1), net.tip(0));
        assert_eq!(net.tip(2), net.tip(0));

        // Partition N1 | N3. N1 mines 2 (N2 follows), N3 mines 4.
        net.hold(0, 2);
        net.mine(0, 2);
        net.mine(2, 4);
        net.pump().await;
        assert_eq!(net.tip(1), net.tip(0), "N2 follows N1 during the split");
        assert_eq!(net.tip(0).1, 7);
        assert_eq!(net.tip(2).1, 9);

        // Heal: N1 reorgs onto N3's heavier branch; N2 must follow through N1.
        net.release(0, 2);
        net.pump().await;

        assert_eq!(net.tip(0), net.tip(2), "N1 reorged onto the heavier branch");
        assert_eq!(
            net.tip(1),
            net.tip(2),
            "the relay-only node must reach the same tip"
        );
    }
}

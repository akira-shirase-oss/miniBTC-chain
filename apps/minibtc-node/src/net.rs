//! P2P network driver: TCP listener, outbound dialer, per-peer sessions,
//! message dispatch into the node core, headers-first sync, and relay.
//!
//! Every peer is untrusted: bounded channels, handshake + stall timeouts,
//! peer-manager scoring/ban/diversity limits, and dedup'd relay.

use crate::core::{Node, NodeInner, ADDRBOOK_CAP};
use minibtc_consensus::ChainParams;
use minibtc_crypto::Hash256;
use minibtc_p2p::codec::{self, Message};
use minibtc_p2p::peer::{
    SCORE_BAD_BLOCK, SCORE_BAD_MESSAGE, SCORE_GOOD_BLOCK, SCORE_TIMEOUT,
};
use minibtc_primitives::Block;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Per-peer outbound queue depth — a stalled peer drops announcements.
const PEER_QUEUE: usize = 256;
/// getdata batch per request.
const GETDATA_BATCH: usize = 64;
/// getdata serve cap per message (peer-request bound).
const SERVE_BATCH: usize = 128;
/// Stall timeout: no message for this long → disconnect.
const STALL_TIMEOUT: Duration = Duration::from_secs(120);
/// Maintenance sweep interval.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Redial interval for the address book.
const REDIAL_INTERVAL: Duration = Duration::from_secs(60);
/// Our protocol version (MiniBTC wire version).
pub const PROTOCOL_VERSION: i32 = 70_015;
/// User agent string.
const USER_AGENT: &str = "/MiniBTC:0.1.0/";
/// Max addr entries learned per `addr` message.
const ADDR_LEARN_CAP: usize = 100;
/// Max inv items processed per message.
const INV_PROCESS_CAP: usize = 1_024;

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

    // Outbound dials for explicit seeds.
    for addr in connect {
        let n = node.clone();
        tokio::spawn(async move {
            dial_and_session(n, addr).await;
        });
    }

    // Accept loop.
    let accept_node = node.clone();
    let accept = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sleep_if_cancelled(&accept_node) => break,
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            let n = accept_node.clone();
                            tokio::spawn(async move {
                                accept_session(n, stream, addr).await;
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
    // Drop the TCP side too: the session notices its queue closed and
    // exits; the peer table entry is already gone.
}

/// Sweep: disconnect stalled + over-handshake-timeout peers.
async fn sweep(node: &Node) {
    let bad: Vec<SocketAddr> = {
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
            .filter(|a| !connected.contains(a))
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
        let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.peers.is_banned(&addr.ip()) {
            return;
        }
        if let Err(e) = inner.peers.admit(addr, true) {
            tracing::debug!(%addr, "dial rejected: {e}");
            return;
        }
    }
    let stream = match timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return,
    };
    let _ = stream.set_nodelay(true);
    session(node, stream, addr, true).await;
}

/// Inbound accept path.
pub async fn accept_session(node: Node, stream: TcpStream, addr: SocketAddr) {
    {
        let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.peers.is_banned(&addr.ip()) {
            return;
        }
        if let Err(e) = inner.peers.admit(addr, false) {
            tracing::debug!(%addr, "inbound rejected: {e}");
            return;
        }
    }
    let _ = stream.set_nodelay(true);
    session(node, stream, addr, false).await;
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
async fn session(node: Node, stream: TcpStream, addr: SocketAddr, outbound: bool) {
    let params = node.params.clone();
    let (mut rd, mut wr) = tokio::io::split(stream);

    // --- Handshake: both sides send `version` first ---
    let our_height = {
        let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.chain.height().min(i32::MAX as u32) as i32
    };
    let our_version = our_version_msg(&params, our_height);
    if codec::write_message(&mut wr, &our_version, &params).await.is_err() {
        return;
    }
    let their_version = match timeout(
        codec::HANDSHAKE_TIMEOUT,
        codec::recv(&mut rd, &params),
    )
    .await
    {
        Ok(Ok(m @ Message::Version { .. })) => m,
        _ => return,
    };

    // Register the peer (diversity/ban already checked at admit()).
    {
        let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = inner.peers.register(addr, outbound, &their_version) {
            tracing::debug!(%addr, "register rejected: {e}");
            return;
        }
    }

    // Verack exchange.
    if codec::write_message(&mut wr, &Message::Verack, &params).await.is_err() {
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

    // Handshake complete.
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
                let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
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
    node
        .peer_tx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(addr, tx.clone());

    // Writer task owns `wr` (params cloned — reader keeps its own).
    let writer_params = params.clone();
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if codec::write_message(&mut wr, &msg, &writer_params).await.is_err() {
                break;
            }
        }
    });

    // Reader loop.
    loop {
        match timeout(codec::IO_TIMEOUT + Duration::from_secs(5), codec::recv(&mut rd, &params))
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
    node
        .peer_tx
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
}

/// Build a getheaders locator: tip + a few ancestors (bounded).
fn sync_locator(inner: &NodeInner) -> Vec<Hash256> {
    let mut loc = Vec::new();
    let mut cur = inner.chain.tip;
    let h = inner.chain.height();
    // Exponential-ish step back for a useful locator.
    let mut step = 1u32;
    loop {
        if h == 0 || loc.len() >= 16 {
            break;
        }
        loc.push(cur);
        let target = h.saturating_sub(step);
        // Walk back `step` blocks.
        let mut walk = h;
        while walk > target {
            match inner.chain.blocks.get(&cur) {
                Some(rec) => {
                    cur = rec.block.header.prev_hash;
                    walk = walk.saturating_sub(1);
                }
                None => break,
            }
        }
        step = step.saturating_mul(2);
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
            handle_block(node, addr, block).await;
            true
        }

        Message::Headers { headers, .. } => {
            let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
            match inner.sync.on_headers(addr, &headers) {
                Ok(_) => {
                    // Queue wanted blocks and request the next batch.
                    let want = inner.sync.next_getdata(&addr);
                    drop(inner);
                    if !want.is_empty() {
                        let _ = reply.try_send(Message::GetData(
                            want.into_iter()
                                .map(|h| minibtc_p2p::codec::InvItem {
                                    kind: minibtc_p2p::codec::InvType::Block,
                                    hash: h,
                                })
                                .collect(),
                        ));
                    }
                }
                Err(e) => {
                    tracing::debug!(%addr, "bad headers: {e}");
                    inner.peers.score(&addr, SCORE_BAD_MESSAGE);
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
    _addr: SocketAddr,
    items: &[minibtc_p2p::codec::InvItem],
    reply: &mpsc::Sender<Message>,
) {
    use minibtc_p2p::codec::InvType;
    let mut want: Vec<minibtc_p2p::codec::InvItem> = Vec::new();
    {
        let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        for item in items.iter().take(INV_PROCESS_CAP) {
            match item.kind {
                InvType::Tx => {
                    let have = inner.mempool.get(&item.hash).is_some()
                        || inner.txindex.contains_key(&item.hash);
                    if !have {
                        want.push(*item);
                    }
                }
                InvType::Block => {
                    if !inner.chain.blocks.contains_key(&item.hash)
                        && !inner.pending.contains(&item.hash)
                    {
                        want.push(*item);
                    }
                }
                _ => {}
            }
            if want.len() >= GETDATA_BATCH {
                break;
            }
        }
    }
    if !want.is_empty() {
        let _ = reply.try_send(Message::GetData(want));
    }
}

/// Serve a `getdata`: txs from mempool/index, blocks from the block index.
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
    for m in out {
        if reply.try_send(m).is_err() {
            break;
        }
    }
}

/// Queue an inbound block and drain whatever became connectable.
async fn handle_block(node: &Node, addr: SocketAddr, block: Block) {
    {
        let mut inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        // sync.on_block marks `have` (headers dedup) and per-peer progress;
        // returns false for duplicates.
        if !inner.sync.on_block(addr, block.clone()) {
            return;
        }
        if !inner.pending.push(block) {
            return; // queue full — already counted as `have`
        }
    }
    drain_pending(node, addr).await;
}

/// Connect pending blocks whose parents are known, in arrival order.
/// Stops at the first unconnectable gap — later arrivals retry on the
/// next block/headers event.
async fn drain_pending(node: &Node, origin: SocketAddr) {
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
        if inner.peers.is_banned(&ip) || inner.addrbook.contains(&sa) {
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
    loop {
        let Some(rec) = inner.chain.blocks.get(&cur) else { break };
        if rec.status != minibtc_chainstate::BlockStatus::Active {
            break;
        }
        chain_hdrs.push(rec.block.header.clone());
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
        out.push(h.clone());
        if out.len() >= cap {
            break;
        }
    }
    out
}

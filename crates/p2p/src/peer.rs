//! # Peer manager
//!
//! Owns outbound + inbound TCP connections: the version/verack handshake,
//! per-peer scoring, banning, timeouts, and eclipse-resistance limits.
//!
//! Threat model (blueprint P7): every peer is untrusted. Controls:
//! - **Handshake deadline** — `HANDSHAKE_TIMEOUT` to complete version+verack.
//! - **Per-IP connection cap** — one connection per IP by default.
//! - **Subnet diversity** — limit peers per /16 (IPv4) so one attacker
//!   can't fill the table with adjacent addresses.
//! - **Inbound cap** — small; most peers should be outbound.
//! - **Outbound cap** — bounded fan-out.
//! - **Scoring + banning** — peers that send invalid data or stall get
//!   score deductions; below threshold → banned for `ban_secs`.
//! - **Nonce self-check** — a peer whose version nonce equals ours is
//!   ourselves → disconnect.
//! - **Message deadlines** — every read/write bounded by `IO_TIMEOUT`.

use crate::codec::{self, HANDSHAKE_TIMEOUT, Message, NetAddress, WireError};
use minibtc_consensus::ChainParams;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

/// How many peers we allow total (outbound + inbound).
pub const MAX_PEERS: usize = 32;
/// Max inbound (untrusted-dialing-us) connections.
pub const MAX_INBOUND: usize = 8;
/// Max connections from a single IP.
pub const MAX_PER_IP: usize = 2;
/// Max connections per IPv4 /16 subnet — eclipse resistance.
pub const MAX_PER_SUBNET: usize = 4;
/// How long a ban lasts.
pub const BAN_SECS: u64 = 60 * 60; // 1 hour
/// Score at which a peer is banned.
pub const BAN_SCORE: i32 = -100;
/// Misbehavior deductions.
pub const SCORE_BAD_MESSAGE: i32 = -20;
pub const SCORE_BAD_BLOCK: i32 = -50;
pub const SCORE_STALL: i32 = -10;
/// Good behavior rewards.
pub const SCORE_GOOD_BLOCK: i32 = 10;
/// Orphan/timeout penalty.
pub const SCORE_TIMEOUT: i32 = -30;

/// Peer manager errors.
#[derive(Debug, Error)]
pub enum PeerError {
    /// Network error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Wire/protocol error.
    #[error("wire: {0}")]
    Wire(#[from] WireError),
    /// Peer table full.
    #[error("peer table full")]
    Full,
    /// This IP/subnet is at its connection cap.
    #[error("connection limit for address")]
    AddrLimit,
    /// The address is currently banned.
    #[error("address banned")]
    Banned,
    /// Handshake failed (timeout, bad version, self-connect).
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// Peer not found.
    #[error("unknown peer")]
    UnknownPeer,
}

/// Per-peer state tracked by the manager.
#[derive(Clone, Debug)]
pub struct PeerState {
    /// Remote socket address.
    pub addr: SocketAddr,
    /// Whether we dialed them (outbound) or they dialed us.
    pub outbound: bool,
    /// Protocol version they reported.
    pub version: i32,
    /// Services bitfield.
    pub services: u64,
    /// Their claimed start height.
    pub start_height: i32,
    /// User agent.
    pub user_agent: String,
    /// Behavior score — negative → ban.
    pub score: i32,
    /// When connected.
    pub connected_at: Instant,
    /// Last message time (stall detection).
    pub last_msg: Instant,
    /// Whether handshake completed.
    pub handshaken: bool,
    /// Banned-until timestamp (unix secs), 0 = not banned.
    pub banned_until: u64,
}

/// The peer table + ban list.
#[derive(Debug)]
pub struct PeerManager {
    /// Live peers by socket addr.
    peers: HashMap<SocketAddr, PeerState>,
    /// Banned IPs → ban expiry (unix secs).
    bans: HashMap<IpAddr, u64>,
    /// Our own handshake nonce — for self-connection detection.
    our_nonce: u64,
    /// Connection limits.
    max_peers: usize,
    max_inbound: usize,
    max_per_ip: usize,
    max_per_subnet: usize,
    /// Clock.
    now: fn() -> u64,
}

impl PeerManager {
    /// New manager with default limits.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            bans: HashMap::new(),
            our_nonce: rand_nonce(),
            max_peers: MAX_PEERS,
            max_inbound: MAX_INBOUND,
            max_per_ip: MAX_PER_IP,
            max_per_subnet: MAX_PER_SUBNET,
            now: || codec::now_secs() as u64,
        }
    }

    /// Our nonce (set into outgoing version messages).
    pub fn our_nonce(&self) -> u64 {
        self.our_nonce
    }

    /// Live peer count.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Look up a peer.
    pub fn get(&self, addr: &SocketAddr) -> Option<&PeerState> {
        self.peers.get(addr)
    }

    /// All peer addrs (for RPC `getpeerinfo`).
    pub fn addrs(&self) -> Vec<SocketAddr> {
        self.peers.keys().copied().collect()
    }

    /// Is this IP banned right now?
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        match self.bans.get(ip) {
            Some(&until) => until > (self.now)(),
            None => false,
        }
    }

    /// Ban an IP for `BAN_SECS` from now.
    pub fn ban(&mut self, ip: IpAddr) {
        self.bans.insert(ip, (self.now)().saturating_add(BAN_SECS));
        // Drop live connections from it.
        self.peers.retain(|a, _| a.ip() != ip);
    }

    /// Unban an IP.
    pub fn unban(&mut self, ip: &IpAddr) {
        self.bans.remove(ip);
    }

    /// Check whether a new connection from `addr` is allowed: not banned,
    /// under per-IP/per-subnet/total/inbound caps.
    pub fn admit(&self, addr: SocketAddr, outbound: bool) -> Result<(), PeerError> {
        if self.is_banned(&addr.ip()) {
            return Err(PeerError::Banned);
        }
        if self.peers.len() >= self.max_peers {
            return Err(PeerError::Full);
        }
        let ip_count = self.peers.keys().filter(|a| a.ip() == addr.ip()).count();
        if ip_count >= self.max_per_ip {
            return Err(PeerError::AddrLimit);
        }
        // Subnet diversity (IPv4 /16).
        if let IpAddr::V4(v4) = addr.ip() {
            let subnet = (v4.octets()[0], v4.octets()[1]);
            let subnet_count = self
                .peers
                .keys()
                .filter(|a| match a.ip() {
                    IpAddr::V4(o) => (o.octets()[0], o.octets()[1]) == subnet,
                    _ => false,
                })
                .count();
            if subnet_count >= self.max_per_subnet {
                return Err(PeerError::AddrLimit);
            }
        }
        if !outbound {
            let inbound = self.peers.values().filter(|p| !p.outbound).count();
            if inbound >= self.max_inbound {
                return Err(PeerError::AddrLimit);
            }
        }
        Ok(())
    }

    /// Record a peer after handshake completes.
    pub fn register(
        &mut self,
        addr: SocketAddr,
        outbound: bool,
        msg: &Message,
    ) -> Result<(), PeerError> {
        let Message::Version {
            version,
            services,
            start_height,
            user_agent,
            nonce,
            ..
        } = msg
        else {
            return Err(PeerError::Handshake("expected version".into()));
        };
        if *nonce == self.our_nonce {
            return Err(PeerError::Handshake("self-connection".into()));
        }
        self.peers.insert(
            addr,
            PeerState {
                addr,
                outbound,
                version: *version,
                services: *services,
                start_height: *start_height,
                user_agent: user_agent.clone(),
                score: 0,
                connected_at: Instant::now(),
                last_msg: Instant::now(),
                handshaken: false,
                banned_until: 0,
            },
        );
        Ok(())
    }

    /// Mark handshake complete.
    pub fn mark_handshaken(&mut self, addr: &SocketAddr) {
        if let Some(p) = self.peers.get_mut(addr) {
            p.handshaken = true;
        }
    }

    /// Update last-message time (call on every inbound message).
    pub fn touch(&mut self, addr: &SocketAddr) {
        if let Some(p) = self.peers.get_mut(addr) {
            p.last_msg = Instant::now();
        }
    }

    /// Apply a score delta; ban if it crosses the threshold.
    pub fn score(&mut self, addr: &SocketAddr, delta: i32) {
        let ban_ip = if let Some(p) = self.peers.get_mut(addr) {
            p.score = p.score.saturating_add(delta);
            p.score <= BAN_SCORE
        } else {
            false
        };
        if ban_ip {
            let ip = addr.ip();
            self.ban(ip);
        }
    }

    /// Current score of a peer.
    pub fn score_of(&self, addr: &SocketAddr) -> Option<i32> {
        self.peers.get(addr).map(|p| p.score)
    }

    /// Snapshot of all peers (addr, state) — for RPC `getpeerinfo` and
    /// the maintenance sweep. Bounded by `max_peers`.
    pub fn snapshot(&self) -> Vec<(SocketAddr, PeerState)> {
        self.peers.iter().map(|(a, p)| (*a, p.clone())).collect()
    }

    /// Remove a peer (disconnect).
    pub fn remove(&mut self, addr: &SocketAddr) -> Option<PeerState> {
        self.peers.remove(addr)
    }

    /// Peers that haven't sent anything in `stall_after` — candidates for
    /// timeout disconnection.
    pub fn stalled(&self, stall_after: Duration) -> Vec<SocketAddr> {
        let now = Instant::now();
        self.peers
            .values()
            .filter(|p| now.duration_since(p.last_msg) > stall_after)
            .map(|p| p.addr)
            .collect()
    }

    /// Peers whose handshake never completed in `handshake_after`.
    pub fn unhandshaken(&self, handshake_after: Duration) -> Vec<SocketAddr> {
        let now = Instant::now();
        self.peers
            .values()
            .filter(|p| !p.handshaken && now.duration_since(p.connected_at) > handshake_after)
            .map(|p| p.addr)
            .collect()
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Random nonce from OS entropy (getrandom via crypto crate isn't
/// exposed; use std's thread rng seeded by OS — for a nonce this is
/// fine, it's not secret).
fn rand_nonce() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut h = RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.write_usize(std::process::id() as usize);
    h.finish()
}

/// Perform the outbound handshake on an established stream:
/// send `version`, await their `version`, reply `verack`, await their
/// `verack`. Returns their version message for registration.
///
/// `params` supplies magic + our user agent + start height + nonce.
pub async fn outbound_handshake<S>(
    stream: &mut S,
    params: &ChainParams,
    nonce: u64,
    user_agent: &str,
    start_height: i32,
    our_addr: NetAddress,
    their_addr: NetAddress,
) -> Result<Message, PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = Message::Version {
        version: 70016,
        services: 0,
        timestamp: codec::now_secs() as i64,
        addr_recv: their_addr,
        addr_from: our_addr,
        nonce,
        user_agent: user_agent.to_string(),
        start_height,
        relay: true,
    };
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        codec::write_message(stream, &version, params),
    )
    .await
    .map_err(|_| PeerError::Handshake("version send timeout".into()))??;

    // Await their version.
    let their_version = tokio::time::timeout(HANDSHAKE_TIMEOUT, codec::recv(stream, params))
        .await
        .map_err(|_| PeerError::Handshake("version recv timeout".into()))??;
    if !matches!(their_version, Message::Version { .. }) {
        return Err(PeerError::Handshake("expected version".into()));
    }
    // verack both ways.
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        codec::write_message(stream, &Message::Verack, params),
    )
    .await
    .map_err(|_| PeerError::Handshake("verack send timeout".into()))??;
    let ack = tokio::time::timeout(HANDSHAKE_TIMEOUT, codec::recv(stream, params))
        .await
        .map_err(|_| PeerError::Handshake("verack recv timeout".into()))??;
    match ack {
        Message::Verack => Ok(their_version),
        _ => Err(PeerError::Handshake("expected verack".into())),
    }
}

/// Inbound handshake: await their `version`, send ours, `verack` both
/// ways. Returns their version message.
pub async fn inbound_handshake<S>(
    stream: &mut S,
    params: &ChainParams,
    nonce: u64,
    user_agent: &str,
    start_height: i32,
    their_addr: NetAddress,
    our_addr: NetAddress,
) -> Result<Message, PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let their_version = tokio::time::timeout(HANDSHAKE_TIMEOUT, codec::recv(stream, params))
        .await
        .map_err(|_| PeerError::Handshake("version recv timeout".into()))??;
    if !matches!(their_version, Message::Version { .. }) {
        return Err(PeerError::Handshake("expected version".into()));
    }
    let version = Message::Version {
        version: 70016,
        services: 0,
        timestamp: codec::now_secs() as i64,
        addr_recv: their_addr,
        addr_from: our_addr,
        nonce,
        user_agent: user_agent.to_string(),
        start_height,
        relay: true,
    };
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        codec::write_message(stream, &version, params),
    )
    .await
    .map_err(|_| PeerError::Handshake("version send timeout".into()))??;
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        codec::write_message(stream, &Message::Verack, params),
    )
    .await
    .map_err(|_| PeerError::Handshake("verack send timeout".into()))??;
    let ack = tokio::time::timeout(HANDSHAKE_TIMEOUT, codec::recv(stream, params))
        .await
        .map_err(|_| PeerError::Handshake("verack recv timeout".into()))??;
    match ack {
        Message::Verack => Ok(their_version),
        _ => Err(PeerError::Handshake("expected verack".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Message;
    use std::net::Ipv4Addr;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
    }

    fn version_msg() -> Message {
        Message::Version {
            version: 70016,
            services: 0,
            timestamp: 0,
            addr_recv: NetAddress {
                services: 0,
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 1,
            },
            addr_from: NetAddress {
                services: 0,
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 1,
            },
            nonce: 999,
            user_agent: "test".into(),
            start_height: 0,
            relay: true,
        }
    }

    #[test]
    fn admit_enforces_caps() {
        let mut pm = PeerManager::new();
        pm.max_per_ip = 1;
        pm.admit(addr(1), true).unwrap();
        // Can't register twice — admit checks live table; simulate by
        // inserting via register.
        pm.register(addr(1), true, &version_msg()).unwrap();
        assert!(matches!(pm.admit(addr(2), true), Err(PeerError::AddrLimit)));
    }

    #[test]
    fn subnet_diversity_limit() {
        let mut pm = PeerManager::new();
        pm.max_per_subnet = 2;
        pm.max_per_ip = 10;
        // Two peers in 10.0.x.x /16.
        for p in [1u16, 2] {
            let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, p as u8)), 8333);
            pm.register(a, true, &version_msg()).unwrap();
        }
        // Third in same /16 → denied even though different IP.
        let a3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 9)), 8333);
        assert!(matches!(pm.admit(a3, true), Err(PeerError::AddrLimit)));
        // Different /16 → ok.
        let a4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 9)), 8333);
        assert!(pm.admit(a4, true).is_ok());
    }

    #[test]
    fn inbound_cap() {
        let mut pm = PeerManager::new();
        pm.max_inbound = 1;
        let a1 = addr(1);
        pm.register(a1, false, &version_msg()).unwrap();
        let a2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)), 8333);
        assert!(matches!(pm.admit(a2, false), Err(PeerError::AddrLimit)));
        // Outbound still allowed.
        assert!(pm.admit(a2, true).is_ok());
    }

    #[test]
    fn ban_blocks_and_expires() {
        let mut pm = PeerManager::new();
        let a = addr(1);
        pm.register(a, true, &version_msg()).unwrap();
        pm.ban(a.ip());
        assert!(pm.is_banned(&a.ip()));
        assert!(matches!(pm.admit(a, true), Err(PeerError::Banned)));
        assert!(pm.get(&a).is_none(), "ban drops live conns");
        pm.unban(&a.ip());
        assert!(!pm.is_banned(&a.ip()));
    }

    #[test]
    fn score_bans_at_threshold() {
        let mut pm = PeerManager::new();
        let a = addr(1);
        pm.register(a, true, &version_msg()).unwrap();
        for _ in 0..6 {
            pm.score(&a, SCORE_BAD_MESSAGE); // -20 × 6 = -120 ≤ -100
        }
        assert!(pm.is_banned(&a.ip()));
    }

    #[test]
    fn self_nonce_rejected() {
        let mut pm = PeerManager::new();
        let mut m = version_msg();
        if let Message::Version { nonce, .. } = &mut m {
            *nonce = pm.our_nonce();
        }
        let a = addr(1);
        assert!(matches!(
            pm.register(a, true, &m),
            Err(PeerError::Handshake(_))
        ));
    }

    #[test]
    fn stalled_and_unhandshaken_detection() {
        let mut pm = PeerManager::new();
        let a = addr(1);
        pm.register(a, true, &version_msg()).unwrap();
        // Not handshaken, just connected → appears in unhandshaken.
        assert!(pm.unhandshaken(Duration::from_secs(0)).contains(&a));
        pm.mark_handshaken(&a);
        assert!(!pm.unhandshaken(Duration::from_secs(0)).contains(&a));
    }

    #[tokio::test]
    async fn handshake_roundtrip_over_duplex() {
        use tokio::io::duplex;
        let p = ChainParams::devnet();
        let (mut client, mut server) = duplex(8192);
        let na = NetAddress {
            services: 0,
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 1,
        };
        let p2 = p.clone();
        let c = tokio::spawn(async move {
            outbound_handshake(&mut client, &p2, 111, "test/1", 5, na, na).await
        });
        let s = inbound_handshake(&mut server, &p, 222, "test/1", 5, na, na);
        let (cr, sr) = tokio::join!(c, s);
        assert!(cr.unwrap().is_ok());
        assert!(sr.is_ok());
    }
}

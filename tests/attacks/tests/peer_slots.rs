//! Eclipse resistance must hold under concurrent handshakes.
//!
//! The per-IP, per-/16 and inbound caps were checked when a connection
//! was admitted, but the slot was only taken when the handshake finished
//! (`register`, which re-checked nothing). An attacker opening many
//! connections at once had every one admitted against the same empty
//! table, then registered them all. Admission must reserve the slot, and
//! registration must never exceed a cap.

use minibtc_p2p::codec::{Message, NetAddress};
use minibtc_p2p::peer::{MAX_INBOUND, MAX_PER_IP, MAX_PER_SUBNET, PeerError, PeerManager};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn version(nonce: u64) -> Message {
    Message::Version {
        version: 70_015,
        services: 0,
        timestamp: 0,
        addr_recv: NetAddress {
            services: 0,
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0,
        },
        addr_from: NetAddress {
            services: 0,
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0,
        },
        nonce,
        user_agent: "/attacker/".to_string(),
        start_height: 0,
        relay: true,
    }
}

#[test]
fn concurrent_admissions_cannot_exceed_the_per_ip_cap() {
    // All admissions happen before any handshake completes.
    let mut pm = PeerManager::new();
    let ip = [8, 8, 8, 8];
    let mut admitted = 0usize;
    for port in 1..=10u16 {
        if pm.admit(SocketAddr::from((ip, port)), false).is_ok() {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, MAX_PER_IP,
        "per-IP cap must hold before handshakes finish"
    );
}

#[test]
fn concurrent_admissions_cannot_exceed_subnet_or_inbound_caps() {
    let mut pm = PeerManager::new();
    let mut admitted = 0usize;
    for i in 0..20u8 {
        if pm
            .admit(SocketAddr::from(([10, 9, i, 1], 18_445)), false)
            .is_ok()
        {
            admitted += 1;
        }
    }
    assert_eq!(admitted, MAX_PER_SUBNET, "/16 cap must hold");

    let mut pm = PeerManager::new();
    let mut inbound = 0usize;
    for i in 0..(MAX_INBOUND as u8 + 8) {
        if pm
            .admit(SocketAddr::from(([20 + i, 1, 1, 1], 18_445)), false)
            .is_ok()
        {
            inbound += 1;
        }
    }
    assert_eq!(inbound, MAX_INBOUND, "inbound cap must hold");
}

#[test]
fn registration_never_exceeds_a_cap() {
    // A handshake that completes without (or after) admission must still
    // respect the caps — register used to insert unconditionally.
    let mut pm = PeerManager::new();
    let ip = [9, 9, 9, 9];
    let mut registered = 0usize;
    for port in 1..=5u16 {
        if pm
            .register(
                SocketAddr::from((ip, port)),
                false,
                &version(u64::from(port)),
            )
            .is_ok()
        {
            registered += 1;
        }
    }
    assert_eq!(registered, MAX_PER_IP);
}

#[test]
fn a_reserved_slot_is_filled_by_registration_and_freed_on_release() {
    let mut pm = PeerManager::new();
    let a = SocketAddr::from(([1, 2, 3, 4], 1));
    let b = SocketAddr::from(([1, 2, 3, 4], 2));
    let c = SocketAddr::from(([1, 2, 3, 4], 3));
    pm.admit(a, false).unwrap();
    pm.admit(b, false).unwrap();
    assert!(matches!(pm.admit(c, false), Err(PeerError::AddrLimit)));
    // Completing a's handshake uses a's reservation, not a new slot.
    pm.register(a, false, &version(1)).unwrap();
    assert_eq!(pm.len(), 2);
    // A failed handshake releases its reservation.
    pm.remove(&b);
    pm.admit(c, false).unwrap();
}

#[test]
fn a_misbehaving_local_peer_does_not_cut_off_other_local_peers() {
    // On a loopback devnet every node is 127.0.0.1. Banning the IP for one
    // bad process used to drop and refuse every local peer for an hour.
    let mut pm = PeerManager::new();
    let bad = SocketAddr::from(([127, 0, 0, 1], 5_001));
    let good = SocketAddr::from(([127, 0, 0, 1], 5_002));
    pm.register(bad, false, &version(1)).unwrap();
    pm.register(good, false, &version(2)).unwrap();
    for _ in 0..6 {
        pm.score(&bad, minibtc_p2p::peer::SCORE_BAD_MESSAGE);
    }
    assert!(pm.get(&bad).is_none(), "the bad peer is dropped");
    assert!(
        pm.get(&good).is_some(),
        "another local peer must stay connected"
    );
    assert!(
        matches!(pm.admit(bad, false), Err(PeerError::Banned)),
        "the same address stays banned"
    );
    pm.remove(&good);
    assert!(
        pm.admit(SocketAddr::from(([127, 0, 0, 1], 5_003)), false)
            .is_ok(),
        "a different local address is not banned"
    );
}

#[test]
fn a_misbehaving_public_peer_is_banned_by_ip() {
    let mut pm = PeerManager::new();
    let bad = SocketAddr::from(([8, 8, 4, 4], 1));
    let same_ip = SocketAddr::from(([8, 8, 4, 4], 2));
    pm.register(bad, false, &version(1)).unwrap();
    pm.register(same_ip, false, &version(2)).unwrap();
    for _ in 0..6 {
        pm.score(&bad, minibtc_p2p::peer::SCORE_BAD_MESSAGE);
    }
    assert!(
        pm.get(&same_ip).is_none(),
        "every connection from the IP is dropped"
    );
    assert!(matches!(
        pm.admit(SocketAddr::from(([8, 8, 4, 4], 3)), false),
        Err(PeerError::Banned)
    ));
}
